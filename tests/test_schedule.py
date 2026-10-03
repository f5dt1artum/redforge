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
        "policy": {"window_ms": 1000, "max_requests": 2, "group_by": "target"},
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

    def test_empty_requests(self):
        self.assertEqual(self.schedule(requests=[]), [])

    def test_single_request_scheduled_at_earliest(self):
        (item,) = self.schedule(requests=[make_request(earliest_ms=500)])
        self.assertEqual(
            item,
            {
                "id": "req-1",
                "target": "app.example.com",
                "route": "/login",
                "scheduled_ms": 500,
                "window_start_ms": 0,
                "depends_on": [],
            },
        )

    def test_window_capacity_pushes_to_next_window_start(self):
        requests = [
            make_request(id="r1", earliest_ms=100),
            make_request(id="r2", earliest_ms=200),
            make_request(id="r3", earliest_ms=300),
        ]
        schedule = self.schedule(requests=requests)
        self.assertEqual(
            [(item["id"], item["scheduled_ms"], item["window_start_ms"]) for item in schedule],
            [("r1", 100, 0), ("r2", 200, 0), ("r3", 1000, 1000)],
        )

    def test_full_window_skips_until_capacity(self):
        policy = {"window_ms": 1000, "max_requests": 1, "group_by": "target"}
        requests = [make_request(id=f"r{i}", earliest_ms=0) for i in range(3)]
        schedule = self.schedule(policy=policy, requests=requests)
        self.assertEqual(
            [(item["id"], item["scheduled_ms"]) for item in schedule],
            [("r0", 0), ("r1", 1000), ("r2", 2000)],
        )

    def test_same_level_prefers_earlier_input_position(self):
        policy = {"window_ms": 1000, "max_requests": 1, "group_by": "target"}
        requests = [
            make_request(id="late-in-alphabet", earliest_ms=0),
            make_request(id="early-in-alphabet", earliest_ms=0),
        ]
        schedule = self.schedule(policy=policy, requests=requests)
        by_id = {item["id"]: item["scheduled_ms"] for item in schedule}
        self.assertEqual(by_id["late-in-alphabet"], 0)
        self.assertEqual(by_id["early-in-alphabet"], 1000)

    def test_dependency_waits_for_scheduled_time(self):
        requests = [
            make_request(id="a", earliest_ms=1500),
            make_request(id="b", earliest_ms=0, depends_on=["a"]),
        ]
        schedule = self.schedule(requests=requests)
        by_id = {item["id"]: item for item in schedule}
        self.assertEqual(by_id["a"]["scheduled_ms"], 1500)
        # Candidate is max(0, 1500) = 1500, landing in window [1000, 2000).
        self.assertEqual(by_id["b"]["scheduled_ms"], 1500)
        self.assertEqual(by_id["b"]["window_start_ms"], 1000)

    def test_dependency_chain_resolves_out_of_input_order(self):
        policy = {"window_ms": 1000, "max_requests": 10, "group_by": "target"}
        requests = [
            make_request(id="c", depends_on=["b"]),
            make_request(id="a", earliest_ms=250),
            make_request(id="b", depends_on=["a"]),
        ]
        schedule = self.schedule(policy=policy, requests=requests)
        by_id = {item["id"]: item["scheduled_ms"] for item in schedule}
        self.assertEqual(by_id, {"a": 250, "b": 250, "c": 250})

    def test_depends_on_keeps_input_order(self):
        requests = [
            make_request(id="a"),
            make_request(id="b"),
            make_request(id="c", depends_on=["b", "a"]),
        ]
        schedule = self.schedule(requests=requests)
        by_id = {item["id"]: item for item in schedule}
        self.assertEqual(by_id["c"]["depends_on"], ["b", "a"])

    def test_target_grouping_shares_limit_across_routes(self):
        policy = {"window_ms": 1000, "max_requests": 2, "group_by": "target"}
        requests = [
            make_request(id="r1", route="/a", earliest_ms=0),
            make_request(id="r2", route="/b", earliest_ms=0),
            make_request(id="r3", route="/c", earliest_ms=0),
        ]
        schedule = self.schedule(policy=policy, requests=requests)
        self.assertEqual(
            [item["scheduled_ms"] for item in schedule], [0, 0, 1000]
        )

    def test_target_route_grouping_splits_routes_case_sensitively(self):
        policy = {
            "window_ms": 1000,
            "max_requests": 1,
            "group_by": "target_route",
        }
        requests = [
            make_request(id="r1", route="/Login", earliest_ms=0),
            make_request(id="r2", route="/login", earliest_ms=0),
            make_request(id="r3", route="/login", earliest_ms=0),
        ]
        schedule = self.schedule(policy=policy, requests=requests)
        by_id = {item["id"]: item["scheduled_ms"] for item in schedule}
        self.assertEqual(by_id, {"r1": 0, "r2": 0, "r3": 1000})

    def test_normalized_target_groups_together(self):
        policy = {"window_ms": 1000, "max_requests": 1, "group_by": "target"}
        requests = [
            make_request(id="r1", target="APP.Example.COM.", earliest_ms=0),
            make_request(id="r2", target="app.example.com", earliest_ms=0),
        ]
        schedule = self.schedule(policy=policy, requests=requests)
        self.assertEqual(
            [(item["target"], item["scheduled_ms"]) for item in schedule],
            [("app.example.com", 0), ("app.example.com", 1000)],
        )

    def test_output_sorted_by_scheduled_ms_then_input_order(self):
        requests = [
            make_request(id="late", target="api.example.com", earliest_ms=500),
            make_request(id="tie-1", target="app.example.com", earliest_ms=100),
            make_request(id="tie-2", target="web.example.com", earliest_ms=100),
            make_request(id="early", target="db.example.com", earliest_ms=0),
        ]
        schedule = self.schedule(requests=requests)
        self.assertEqual(
            [item["id"] for item in schedule],
            ["early", "tie-1", "tie-2", "late"],
        )

    def test_result_is_stable(self):
        requests = [
            make_request(id="b", depends_on=["a"]),
            make_request(id="a", earliest_ms=100),
            make_request(id="c", earliest_ms=200),
        ]
        first = self.schedule(requests=requests)
        second = self.schedule(requests=requests)
        self.assertEqual(first, second)

    def test_scope_violation_raises_after_structure_ok(self):
        with self.assertRaises(ScopeViolationError):
            self.schedule(requests=[make_request(target="evil.net")])
        with self.assertRaises(ScopeViolationError):
            self.schedule(deny=["app.example.com"])
        with self.assertRaises(ScopeViolationError):
            self.schedule(allow=["10.0.0.0/8"])

    def test_empty_requests_still_validates_policy_and_rules(self):
        with self.assertRaises(ValueError):
            self.schedule(
                requests=[],
                policy={"window_ms": 0, "max_requests": 1, "group_by": "target"},
            )
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
                policy={"window_ms": True, "max_requests": 2, "group_by": "target"}
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
                policy={"window_ms": 1000, "max_requests": 2, "group_by": "route"}
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
            schedule_payload(requests=[make_request(depends_on="a")]),
            schedule_payload(requests=[make_request(depends_on=[""])]),
            schedule_payload(requests=[make_request(depends_on=[1])]),
            schedule_payload(requests=[make_request(depends_on=["a", "a"])]),
            schedule_payload(
                requests=[make_request(id="dup"), make_request(id="dup")]
            ),
            # dependency graph
            schedule_payload(requests=[make_request(depends_on=["ghost"])]),
            schedule_payload(requests=[make_request(id="a", depends_on=["a"])]),
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
        # A dependency cycle is structural too.
        with self.assertRaises(ValueError):
            self.schedule(
                requests=[
                    make_request(id="a", target="evil.net", depends_on=["b"]),
                    make_request(id="b", depends_on=["a"]),
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
                    make_request(id="b", depends_on=["a"]),
                ]
            )
        )
        self.assertEqual(status, 200)
        self.assertEqual(list(payload), ["schedule"])
        self.assertEqual(len(payload["schedule"]), 2)
        for item in payload["schedule"]:
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


if __name__ == "__main__":
    unittest.main()
