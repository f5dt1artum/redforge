import json
import threading
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

from redforge.server import Handler
from redforge.service import ScopeViolationError, Service


def make_request(**overrides):
    request = {
        "id": "req-1",
        "target": "app.example.com",
        "route": "/login",
        "earliest_ms": 0,
        "depends_on": [],
    }
    request.update(overrides)
    return request


def schedule_payload(**overrides):
    payload = {
        "allow": ["*.example.com", "10.0.0.0/8"],
        "deny": [],
        "policy": {
            "window_ms": 1000,
            "max_requests": 2,
            "group_by": "target",
        },
        "requests": [make_request()],
    }
    payload.update(overrides)
    return payload


class ScheduleServiceTest(unittest.TestCase):
    def setUp(self):
        self.service = Service()

    def schedule(self, **overrides):
        return self.service.schedule_requests(schedule_payload(**overrides))[
            "schedule"
        ]

    def test_single_request_runs_at_earliest(self):
        (item,) = self.schedule(
            requests=[make_request(earliest_ms=250)]
        )
        self.assertEqual(item["scheduled_ms"], 250)
        self.assertEqual(item["window_start_ms"], 0)
        self.assertEqual(item["target"], "app.example.com")
        self.assertEqual(item["route"], "/login")
        self.assertEqual(item["depends_on"], [])

    def test_empty_requests_returns_empty_schedule(self):
        self.assertEqual(self.schedule(requests=[]), [])

    def test_requests_under_limit_keep_their_earliest_times(self):
        items = self.schedule(
            requests=[
                make_request(id="a", earliest_ms=100),
                make_request(id="b", earliest_ms=200),
            ]
        )
        self.assertEqual(
            [(i["id"], i["scheduled_ms"], i["window_start_ms"]) for i in items],
            [("a", 100, 0), ("b", 200, 0)],
        )

    def test_full_window_bumps_to_next_window_start(self):
        items = self.schedule(
            requests=[
                make_request(id="a", earliest_ms=100),
                make_request(id="b", earliest_ms=200),
                make_request(id="c", earliest_ms=300),
            ]
        )
        self.assertEqual(
            [(i["id"], i["scheduled_ms"], i["window_start_ms"]) for i in items],
            [
                ("a", 100, 0),
                ("b", 200, 0),
                ("c", 1000, 1000),
            ],
        )

    def test_sorting_by_scheduled_ms_keeps_input_order_on_ties(self):
        policy = {
            "window_ms": 1000,
            "max_requests": 3,
            "group_by": "target",
        }
        items = self.schedule(
            policy=policy,
            requests=[
                make_request(id="a", earliest_ms=0),
                # b is placed after its dependency c in topological order,
                # but the output tie-break must use input position.
                make_request(id="b", earliest_ms=0, depends_on=["c"]),
                make_request(id="c", earliest_ms=0),
            ],
        )
        self.assertEqual([i["id"] for i in items], ["a", "b", "c"])

    def test_window_boundary_floor(self):
        items = self.schedule(
            policy={
                "window_ms": 1000,
                "max_requests": 1,
                "group_by": "target",
            },
            requests=[
                make_request(id="a", earliest_ms=999),
                make_request(id="b", earliest_ms=1000),
            ],
        )
        self.assertEqual(
            [(i["id"], i["scheduled_ms"], i["window_start_ms"]) for i in items],
            [("a", 999, 0), ("b", 1000, 1000)],
        )

    def test_target_grouping_shares_quota_across_routes(self):
        items = self.schedule(
            requests=[
                make_request(id="a", route="/a", earliest_ms=10),
                make_request(id="b", route="/b", earliest_ms=20),
                make_request(id="c", route="/c", earliest_ms=30),
            ]
        )
        # Third request on the same target is bumped regardless of route.
        self.assertEqual(items[2]["id"], "c")
        self.assertEqual(items[2]["scheduled_ms"], 1000)
        self.assertEqual(items[2]["window_start_ms"], 1000)

    def test_target_route_grouping_splits_quota_case_sensitively(self):
        policy = {
            "window_ms": 1000,
            "max_requests": 1,
            "group_by": "target_route",
        }
        items = self.schedule(
            policy=policy,
            requests=[
                make_request(id="a", route="/a", earliest_ms=10),
                make_request(id="b", route="/b", earliest_ms=20),
            ],
        )
        self.assertEqual(
            [(i["id"], i["scheduled_ms"]) for i in items],
            [("a", 10), ("b", 20)],
        )
        # Routes differing only in case are distinct groups.
        items = self.schedule(
            policy=policy,
            requests=[
                make_request(id="a", route="/Login", earliest_ms=10),
                make_request(id="b", route="/login", earliest_ms=20),
            ],
        )
        self.assertEqual(
            [(i["id"], i["scheduled_ms"]) for i in items],
            [("a", 10), ("b", 20)],
        )
        # Same route twice: the second is bumped.
        items = self.schedule(
            policy=policy,
            requests=[
                make_request(id="a", route="/login", earliest_ms=10),
                make_request(id="b", route="/login", earliest_ms=20),
            ],
        )
        self.assertEqual(
            [(i["id"], i["scheduled_ms"], i["window_start_ms"]) for i in items],
            [("a", 10, 0), ("b", 1000, 1000)],
        )

    def test_normalized_targets_share_quota(self):
        items = self.schedule(
            requests=[
                make_request(id="a", target="APP.Example.COM.", earliest_ms=10),
                make_request(id="b", target="app.example.com", earliest_ms=20),
                make_request(id="c", target="app.example.com", earliest_ms=30),
            ]
        )
        self.assertTrue(all(i["target"] == "app.example.com" for i in items))
        self.assertEqual(
            [(i["id"], i["scheduled_ms"]) for i in items],
            [("a", 10), ("b", 20), ("c", 1000)],
        )

    def test_dependency_pushes_behind_dependent_scheduled_time(self):
        items = self.schedule(
            requests=[
                make_request(id="a", earliest_ms=0),
                make_request(
                    id="b", earliest_ms=0, depends_on=["a"]
                ),
            ]
        )
        by_id = {item["id"]: item for item in items}
        self.assertGreaterEqual(
            by_id["b"]["scheduled_ms"], by_id["a"]["scheduled_ms"]
        )
        self.assertEqual(by_id["a"]["scheduled_ms"], 0)
        self.assertEqual(by_id["b"]["scheduled_ms"], 0)

    def test_dependency_waits_for_bumped_dependent(self):
        policy = {
            "window_ms": 1000,
            "max_requests": 1,
            "group_by": "target",
        }
        items = self.schedule(
            policy=policy,
            requests=[
                make_request(id="a", earliest_ms=0),
                make_request(id="b", earliest_ms=0),
                make_request(id="c", earliest_ms=0, depends_on=["b"]),
            ],
        )
        by_id = {item["id"]: item for item in items}
        # b is bumped to 1000; c cannot run before b, and with max_requests
        # of 1 the window at 1000 is already taken by b, so c lands at 2000.
        self.assertEqual(by_id["a"]["scheduled_ms"], 0)
        self.assertEqual(by_id["b"]["scheduled_ms"], 1000)
        self.assertEqual(by_id["c"]["scheduled_ms"], 2000)
        self.assertEqual(by_id["c"]["window_start_ms"], 2000)

    def test_dependency_candidate_can_land_inside_a_partially_filled_window(self):
        policy = {
            "window_ms": 1000,
            "max_requests": 2,
            "group_by": "target",
        }
        items = self.schedule(
            policy=policy,
            requests=[
                make_request(id="a", earliest_ms=0),
                make_request(id="b", earliest_ms=1500),
                make_request(
                    id="c", earliest_ms=0, depends_on=["b"]
                ),
            ],
        )
        by_id = {item["id"]: item for item in items}
        # c's candidate is max(0, 1500); window 1000 already holds b once,
        # so c takes the second slot at exactly 1500.
        self.assertEqual(by_id["c"]["scheduled_ms"], 1500)
        self.assertEqual(by_id["c"]["window_start_ms"], 1000)

    def test_depends_on_echoed_in_input_order(self):
        items = self.schedule(
            requests=[
                make_request(id="a", earliest_ms=0),
                make_request(id="b", earliest_ms=0),
                make_request(
                    id="c", earliest_ms=0, depends_on=["a", "b"]
                ),
            ]
        )
        self.assertEqual(items[-1]["depends_on"], ["a", "b"])

    def test_stable_topological_order_then_output_sort(self):
        policy = {
            "window_ms": 1000,
            "max_requests": 10,
            "group_by": "target",
        }
        items = self.schedule(
            policy=policy,
            requests=[
                make_request(id="a", earliest_ms=5, depends_on=["c"]),
                make_request(id="b", earliest_ms=0),
                make_request(id="c", earliest_ms=3),
            ],
        )
        # c runs first (dependency), then a waits for c: sorted output is
        # c(3), b(0? no—b earliest is 0) -> b at 0, c at 3, a at 5.
        self.assertEqual(
            [i["id"] for i in items], ["b", "c", "a"]
        )

    def test_response_item_shape(self):
        (item,) = self.schedule(requests=[make_request()])
        self.assertEqual(
            set(item),
            {
                "id",
                "target",
                "route",
                "scheduled_ms",
                "window_start_ms",
                "depends_on",
            },
        )

    def test_result_is_stable(self):
        requests = [
            make_request(id=f"r{i}", earliest_ms=i * 100) for i in range(6)
        ]
        first = self.schedule(requests=[dict(r) for r in requests])
        second = self.schedule(requests=[dict(r) for r in requests])
        self.assertEqual(first, second)

    def test_scope_violation_raises_after_structure_ok(self):
        with self.assertRaises(ScopeViolationError):
            self.schedule(requests=[make_request(target="evil.net")])
        with self.assertRaises(ScopeViolationError):
            self.schedule(deny=["app.example.com"])
        with self.assertRaises(ScopeViolationError):
            self.schedule(allow=["10.0.0.0/8"])

    def test_empty_requests_still_validates_policy_and_scope_rules(self):
        # A bad policy with empty requests is still a 400.
        with self.assertRaises(ValueError):
            self.schedule(
                requests=[],
                policy={"window_ms": 0, "max_requests": 1, "group_by": "target"},
            )
        # Malformed allow/deny rules with empty requests are still a 400.
        with self.assertRaises(ValueError):
            self.schedule(requests=[], allow=["bad_host"])

    def test_validation_errors(self):
        bad_payloads = [
            None,
            [],
            {},
            {"allow": [], "deny": [], "policy": {}},
            schedule_payload(extra=1),
            schedule_payload(allow="*.example.com"),
            schedule_payload(deny=["bad_host"]),
            schedule_payload(allow=["10.0.0.0/33"]),
            # policy
            schedule_payload(policy=[]),
            schedule_payload(policy={}),
            schedule_payload(policy={"window_ms": 1000}),
            schedule_payload(
                policy={
                    "window_ms": 1000,
                    "max_requests": 2,
                    "group_by": "target",
                    "extra": 1,
                }
            ),
            schedule_payload(
                policy={"window_ms": 0, "max_requests": 2, "group_by": "target"}
            ),
            schedule_payload(
                policy={
                    "window_ms": -1,
                    "max_requests": 2,
                    "group_by": "target",
                }
            ),
            schedule_payload(
                policy={
                    "window_ms": True,
                    "max_requests": 2,
                    "group_by": "target",
                }
            ),
            schedule_payload(
                policy={
                    "window_ms": "1000",
                    "max_requests": 2,
                    "group_by": "target",
                }
            ),
            schedule_payload(
                policy={"window_ms": 1000, "max_requests": 0, "group_by": "target"}
            ),
            schedule_payload(
                policy={
                    "window_ms": 1000,
                    "max_requests": 1.5,
                    "group_by": "target",
                }
            ),
            schedule_payload(
                policy={
                    "window_ms": 1000,
                    "max_requests": 2,
                    "group_by": "route",
                }
            ),
            schedule_payload(
                policy={"window_ms": 1000, "max_requests": 2, "group_by": 1}
            ),
            # requests
            schedule_payload(requests={}),
            schedule_payload(requests=[{"id": "a"}]),
            schedule_payload(requests=[make_request(extra=1)]),
            schedule_payload(requests=[make_request(id="")]),
            schedule_payload(requests=[make_request(id=1)]),
            schedule_payload(requests=[make_request(target="*.example.com")]),
            schedule_payload(requests=[make_request(target="bad_host")]),
            schedule_payload(requests=[make_request(route="")]),
            schedule_payload(requests=[make_request(route="login")]),
            schedule_payload(requests=[make_request(route=1)]),
            schedule_payload(requests=[make_request(earliest_ms=-1)]),
            schedule_payload(requests=[make_request(earliest_ms=1.5)]),
            schedule_payload(requests=[make_request(earliest_ms=True)]),
            schedule_payload(requests=[make_request(earliest_ms="0")]),
            schedule_payload(requests=[make_request(depends_on={})]),
            schedule_payload(requests=[make_request(depends_on=[""])]),
            schedule_payload(requests=[make_request(depends_on=[1])]),
            schedule_payload(
                requests=[make_request(depends_on=["a", "a"])]
            ),
            schedule_payload(
                requests=[
                    make_request(id="dup"),
                    make_request(id="dup"),
                ]
            ),
            # unknown / self / cyclic dependencies
            schedule_payload(
                requests=[make_request(id="a", depends_on=["ghost"])]
            ),
            schedule_payload(
                requests=[make_request(id="a", depends_on=["a"])]
            ),
            schedule_payload(
                requests=[
                    make_request(id="a", depends_on=["b"]),
                    make_request(id="b", depends_on=["a"]),
                ]
            ),
            schedule_payload(
                requests=[
                    make_request(id="a", depends_on=["c"]),
                    make_request(id="b", depends_on=["a"]),
                    make_request(id="c", depends_on=["b"]),
                ]
            ),
        ]
        for payload in bad_payloads:
            with self.subTest(payload=repr(payload)[:80]):
                with self.assertRaises(ValueError):
                    self.service.schedule_requests(payload)

    def test_structure_error_takes_precedence_over_scope(self):
        # Out-of-scope target plus a duplicate id: the structural error
        # wins (ValueError), never a scope violation.
        with self.assertRaises(ValueError):
            self.schedule(
                requests=[
                    make_request(id="x", target="evil.net"),
                    make_request(id="x", target="evil.net"),
                ]
            )
        # A dependency cycle with an out-of-scope target is also a 400.
        with self.assertRaises(ValueError):
            self.schedule(
                requests=[
                    make_request(
                        id="a", target="evil.net", depends_on=["b"]
                    ),
                    make_request(
                        id="b", target="evil.net", depends_on=["a"]
                    ),
                ]
            )


class ScheduleHttpTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        cls.port = cls.server.server_address[1]
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def request(self, method, path, body=None, headers=None):
        url = f"http://127.0.0.1:{self.port}{path}"
        req = urllib.request.Request(
            url, method=method, data=body, headers=headers or {}
        )
        try:
            with urllib.request.urlopen(req) as resp:
                return resp.status, json.loads(resp.read())
        except urllib.error.HTTPError as exc:
            status, payload = exc.code, json.loads(exc.read())
            exc.close()
            return status, payload

    def post_schedule(self, payload):
        return self.request(
            "POST", "/v1/requests/schedule", json.dumps(payload).encode()
        )

    def test_schedule_ok(self):
        status, payload = self.post_schedule(
            schedule_payload(
                requests=[
                    make_request(id="a", earliest_ms=100),
                    make_request(id="b", earliest_ms=200),
                ]
            )
        )
        self.assertEqual(status, 200)
        self.assertEqual(list(payload), ["schedule"])
        first, second = payload["schedule"]
        self.assertEqual(
            set(first),
            {
                "id",
                "target",
                "route",
                "scheduled_ms",
                "window_start_ms",
                "depends_on",
            },
        )
        self.assertEqual(first["id"], "a")
        self.assertEqual(first["scheduled_ms"], 100)
        self.assertEqual(second["scheduled_ms"], 200)

    def test_empty_requests_ok(self):
        status, payload = self.post_schedule(schedule_payload(requests=[]))
        self.assertEqual(status, 200)
        self.assertEqual(payload, {"schedule": []})

    def test_scope_violation_403(self):
        status, payload = self.post_schedule(
            schedule_payload(requests=[make_request(target="evil.net")])
        )
        self.assertEqual(status, 403)
        self.assertEqual(payload["error"]["code"], "scope_violation")
        self.assertNotIn("schedule", payload)

    def test_invalid_request_400(self):
        status, payload = self.post_schedule({"allow": [], "deny": []})
        self.assertEqual(status, 400)
        self.assertEqual(payload["error"]["code"], "invalid_request")

    def test_malformed_json_400(self):
        status, payload = self.request(
            "POST", "/v1/requests/schedule", b"{nope"
        )
        self.assertEqual(status, 400)
        self.assertEqual(payload["error"]["code"], "invalid_request")

    def test_oversized_body_413(self):
        import http.client

        conn = http.client.HTTPConnection("127.0.0.1", self.port)
        conn.putrequest("POST", "/v1/requests/schedule")
        conn.putheader("Content-Length", str(1024 * 1024 + 1))
        conn.endheaders()
        resp = conn.getresponse()
        payload = json.loads(resp.read())
        conn.close()
        self.assertEqual(resp.status, 413)
        self.assertEqual(payload["error"]["code"], "request_too_large")

    def test_method_not_allowed_405(self):
        for method in ("GET", "PUT", "DELETE", "PATCH"):
            with self.subTest(method=method):
                status, payload = self.request(
                    method, "/v1/requests/schedule"
                )
                self.assertEqual(status, 405)
                self.assertEqual(payload["error"]["code"], "method_not_allowed")

    def test_unknown_route_404(self):
        status, payload = self.request(
            "POST", "/v1/requests/nope", b"{}"
        )
        self.assertEqual(status, 404)
        self.assertEqual(payload["error"]["code"], "not_found")


if __name__ == "__main__":
    unittest.main()
