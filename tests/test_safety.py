import json
import threading
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

from redforge.server import Handler
from redforge.service import ScopeViolationError, Service


def make_action(**overrides):
    action = {
        "id": "act-1",
        "target": "app.example.com",
        "kind": "discovery",
        "scheduled_ms": 0,
    }
    action.update(overrides)
    return action


def safety_payload(**overrides):
    payload = {
        "allow": ["*.example.com", "10.0.0.0/8"],
        "deny": [],
        "policy": {
            "enabled": True,
            "window_ms": 1000,
            "max_actions_per_target": 2,
            "blocked_kinds": [],
        },
        "actions": [make_action()],
    }
    payload.update(overrides)
    return payload


class SafetyServiceTest(unittest.TestCase):
    def setUp(self):
        self.service = Service()

    def evaluate(self, **overrides):
        return self.service.evaluate_safety(safety_payload(**overrides))

    def decisions(self, **overrides):
        return self.evaluate(**overrides)["decisions"]

    def test_single_action_allowed(self):
        result = self.evaluate()
        (decision,) = result["decisions"]
        self.assertEqual(
            decision,
            {
                "id": "act-1",
                "target": "app.example.com",
                "kind": "discovery",
                "scheduled_ms": 0,
                "status": "allowed",
                "reason": None,
            },
        )
        self.assertEqual(
            result["summary"], {"total": 1, "allowed": 1, "blocked": 0}
        )

    def test_empty_actions_empty_decisions_and_zero_summary(self):
        result = self.evaluate(actions=[])
        self.assertEqual(result["decisions"], [])
        self.assertEqual(
            result["summary"], {"total": 0, "allowed": 0, "blocked": 0}
        )

    def test_disabled_policy_blocks_everything_as_emergency_stop(self):
        actions = [
            make_action(id="a", kind="discovery"),
            make_action(id="b", target="db.example.com", kind="credential"),
        ]
        result = self.evaluate(
            policy={
                "enabled": False,
                "window_ms": 1000,
                "max_actions_per_target": 100,
                "blocked_kinds": ["exploitation"],
            },
            actions=actions,
        )
        self.assertEqual(
            [(d["id"], d["status"], d["reason"]) for d in result["decisions"]],
            [
                ("a", "blocked", "emergency_stop"),
                ("b", "blocked", "emergency_stop"),
            ],
        )
        self.assertEqual(
            result["summary"], {"total": 2, "allowed": 0, "blocked": 2}
        )

    def test_blocked_kind_match_blocks_without_consuming_quota(self):
        # Limit is 1: blocked_kind actions must not take the slot, so the
        # later non-blocked action is still allowed.
        actions = [
            make_action(id="a", kind="exploitation", scheduled_ms=0),
            make_action(id="b", kind="discovery", scheduled_ms=10),
            make_action(id="c", kind="discovery", scheduled_ms=20),
        ]
        result = self.evaluate(
            policy={
                "enabled": True,
                "window_ms": 1000,
                "max_actions_per_target": 1,
                "blocked_kinds": ["exploitation"],
            },
            actions=actions,
        )
        self.assertEqual(
            [(d["id"], d["status"], d["reason"]) for d in result["decisions"]],
            [
                ("a", "blocked", "blocked_kind"),
                ("b", "allowed", None),
                ("c", "blocked", "action_limit"),
            ],
        )
        self.assertEqual(
            result["summary"], {"total": 3, "allowed": 1, "blocked": 2}
        )

    def test_emergency_stop_does_not_consume_quota_either(self):
        actions = [make_action(id="a"), make_action(id="b")]
        result = self.evaluate(
            policy={
                "enabled": False,
                "window_ms": 1000,
                "max_actions_per_target": 1,
                "blocked_kinds": [],
            },
            actions=actions,
        )
        self.assertTrue(
            all(d["reason"] == "emergency_stop" for d in result["decisions"])
        )

    def test_action_limit_per_target_window(self):
        actions = [
            make_action(id="a", scheduled_ms=0),
            make_action(id="b", scheduled_ms=999),
            make_action(id="c", scheduled_ms=999),
            make_action(id="d", scheduled_ms=1000),
        ]
        result = self.evaluate(actions=actions)
        self.assertEqual(
            [(d["id"], d["status"], d["reason"]) for d in result["decisions"]],
            [
                ("a", "allowed", None),
                ("b", "allowed", None),
                ("c", "blocked", "action_limit"),
                ("d", "allowed", None),
            ],
        )
        self.assertEqual(
            result["summary"], {"total": 4, "allowed": 3, "blocked": 1}
        )

    def test_quota_is_per_normalized_target(self):
        actions = [
            make_action(id="a", target="APP.Example.COM."),
            make_action(id="b", target="app.example.com"),
            make_action(id="c", target="db.example.com"),
        ]
        decisions = self.decisions(actions=actions)
        self.assertEqual(
            [d["target"] for d in decisions],
            ["app.example.com", "app.example.com", "db.example.com"],
        )
        self.assertEqual(
            [(d["id"], d["status"]) for d in decisions],
            [("a", "allowed"), ("b", "allowed"), ("c", "allowed")],
        )

    def test_quota_counts_in_input_order(self):
        # Same scheduled_ms: input order decides who gets the single slot.
        actions = [
            make_action(id="a", scheduled_ms=500),
            make_action(id="b", scheduled_ms=500),
            make_action(id="c", scheduled_ms=500),
        ]
        decisions = self.decisions(
            policy={
                "enabled": True,
                "window_ms": 1000,
                "max_actions_per_target": 2,
                "blocked_kinds": [],
            },
            actions=actions,
        )
        self.assertEqual(
            [(d["id"], d["status"], d["reason"]) for d in decisions],
            [
                ("a", "allowed", None),
                ("b", "allowed", None),
                ("c", "blocked", "action_limit"),
            ],
        )

    def test_window_start_floor(self):
        decisions = self.decisions(
            policy={
                "enabled": True,
                "window_ms": 1000,
                "max_actions_per_target": 1,
                "blocked_kinds": [],
            },
            actions=[
                make_action(id="a", scheduled_ms=999),
                make_action(id="b", scheduled_ms=1000),
            ],
        )
        self.assertEqual(
            [(d["id"], d["status"]) for d in decisions],
            [("a", "allowed"), ("b", "allowed")],
        )

    def test_all_kinds_accepted(self):
        kinds = [
            "discovery",
            "verification",
            "exploitation",
            "credential",
            "privilege",
        ]
        actions = [
            make_action(id=f"k{i}", kind=kind, target=f"h{i}.example.com")
            for i, kind in enumerate(kinds)
        ]
        decisions = self.decisions(actions=actions)
        self.assertEqual([d["status"] for d in decisions], ["allowed"] * 5)

    def test_decision_shape(self):
        decision = self.decisions()[0]
        self.assertEqual(
            set(decision),
            {"id", "target", "kind", "scheduled_ms", "status", "reason"},
        )
        result = self.evaluate()
        self.assertEqual(set(result), {"decisions", "summary"})
        self.assertEqual(set(result["summary"]), {"total", "allowed", "blocked"})

    def test_result_is_deterministic(self):
        actions = [
            make_action(id=f"a{i}", scheduled_ms=i * 250) for i in range(8)
        ]
        first = self.evaluate(actions=[dict(a) for a in actions])
        second = self.evaluate(actions=[dict(a) for a in actions])
        self.assertEqual(first, second)

    def test_scope_violation_raises_after_structure_ok(self):
        with self.assertRaises(ScopeViolationError):
            self.evaluate(actions=[make_action(target="evil.net")])
        with self.assertRaises(ScopeViolationError):
            self.evaluate(deny=["app.example.com"])
        with self.assertRaises(ScopeViolationError):
            self.evaluate(allow=["10.0.0.0/8"])

    def test_empty_actions_still_validates_policy_and_scope_rules(self):
        with self.assertRaises(ValueError):
            self.evaluate(
                actions=[],
                policy={
                    "enabled": True,
                    "window_ms": 0,
                    "max_actions_per_target": 1,
                    "blocked_kinds": [],
                },
            )
        with self.assertRaises(ValueError):
            self.evaluate(actions=[], allow=["bad_host"])

    def test_validation_errors(self):
        bad_payloads = [
            None,
            [],
            {},
            {"allow": [], "deny": [], "policy": {}},
            safety_payload(extra=1),
            safety_payload(allow="*.example.com"),
            safety_payload(deny=["bad_host"]),
            safety_payload(allow=["10.0.0.0/33"]),
            # policy
            safety_payload(policy=[]),
            safety_payload(policy={}),
            safety_payload(policy={"enabled": True}),
            safety_payload(
                policy={
                    "enabled": True,
                    "window_ms": 1000,
                    "max_actions_per_target": 2,
                    "blocked_kinds": [],
                    "extra": 1,
                }
            ),
            safety_payload(
                policy={
                    "enabled": "yes",
                    "window_ms": 1000,
                    "max_actions_per_target": 2,
                    "blocked_kinds": [],
                }
            ),
            safety_payload(
                policy={
                    "enabled": 1,
                    "window_ms": 1000,
                    "max_actions_per_target": 2,
                    "blocked_kinds": [],
                }
            ),
            safety_payload(
                policy={
                    "enabled": True,
                    "window_ms": 0,
                    "max_actions_per_target": 2,
                    "blocked_kinds": [],
                }
            ),
            safety_payload(
                policy={
                    "enabled": True,
                    "window_ms": -1,
                    "max_actions_per_target": 2,
                    "blocked_kinds": [],
                }
            ),
            safety_payload(
                policy={
                    "enabled": True,
                    "window_ms": True,
                    "max_actions_per_target": 2,
                    "blocked_kinds": [],
                }
            ),
            safety_payload(
                policy={
                    "enabled": True,
                    "window_ms": 1.5,
                    "max_actions_per_target": 2,
                    "blocked_kinds": [],
                }
            ),
            safety_payload(
                policy={
                    "enabled": True,
                    "window_ms": 1000,
                    "max_actions_per_target": 0,
                    "blocked_kinds": [],
                }
            ),
            safety_payload(
                policy={
                    "enabled": True,
                    "window_ms": 1000,
                    "max_actions_per_target": False,
                    "blocked_kinds": [],
                }
            ),
            safety_payload(
                policy={
                    "enabled": True,
                    "window_ms": 1000,
                    "max_actions_per_target": 2,
                    "blocked_kinds": {},
                }
            ),
            safety_payload(
                policy={
                    "enabled": True,
                    "window_ms": 1000,
                    "max_actions_per_target": 2,
                    "blocked_kinds": ["nope"],
                }
            ),
            safety_payload(
                policy={
                    "enabled": True,
                    "window_ms": 1000,
                    "max_actions_per_target": 2,
                    "blocked_kinds": ["credential", 1],
                }
            ),
            safety_payload(
                policy={
                    "enabled": True,
                    "window_ms": 1000,
                    "max_actions_per_target": 2,
                    "blocked_kinds": ["credential", "credential"],
                }
            ),
            # actions
            safety_payload(actions={}),
            safety_payload(actions=[{"id": "a"}]),
            safety_payload(actions=[make_action(extra=1)]),
            safety_payload(actions=[make_action(id="")]),
            safety_payload(actions=[make_action(id=1)]),
            safety_payload(actions=[make_action(target="*.example.com")]),
            safety_payload(actions=[make_action(target="bad_host")]),
            safety_payload(actions=[make_action(target=1)]),
            safety_payload(actions=[make_action(kind="nope")]),
            safety_payload(actions=[make_action(kind=1)]),
            safety_payload(actions=[make_action(kind="DISCOVERY")]),
            safety_payload(actions=[make_action(scheduled_ms=-1)]),
            safety_payload(actions=[make_action(scheduled_ms=1.5)]),
            safety_payload(actions=[make_action(scheduled_ms=True)]),
            safety_payload(actions=[make_action(scheduled_ms="0")]),
            safety_payload(
                actions=[make_action(id="dup"), make_action(id="dup")]
            ),
        ]
        for payload in bad_payloads:
            with self.subTest(payload=repr(payload)[:80]):
                with self.assertRaises(ValueError):
                    self.service.evaluate_safety(payload)

    def test_structure_error_takes_precedence_over_scope(self):
        # Out-of-scope target plus a duplicate id: the structural error wins.
        with self.assertRaises(ValueError):
            self.evaluate(
                actions=[
                    make_action(id="x", target="evil.net"),
                    make_action(id="x", target="evil.net"),
                ]
            )
        # Bad policy with an out-of-scope target is also a 400.
        with self.assertRaises(ValueError):
            self.evaluate(
                policy={
                    "enabled": True,
                    "window_ms": 0,
                    "max_actions_per_target": 1,
                    "blocked_kinds": [],
                },
                actions=[make_action(target="evil.net")],
            )


class SafetyHttpTest(unittest.TestCase):
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

    def post_safety(self, payload):
        return self.request(
            "POST",
            "/v1/exercises/safety-evaluate",
            json.dumps(payload).encode(),
        )

    def test_safety_ok(self):
        status, payload = self.post_safety(
            safety_payload(
                actions=[
                    make_action(id="a", scheduled_ms=0),
                    make_action(id="b", scheduled_ms=2000),
                ]
            )
        )
        self.assertEqual(status, 200)
        self.assertEqual(list(payload), ["decisions", "summary"])
        self.assertEqual(
            [d["id"] for d in payload["decisions"]], ["a", "b"]
        )
        self.assertEqual(
            payload["summary"], {"total": 2, "allowed": 2, "blocked": 0}
        )

    def test_empty_actions_ok(self):
        status, payload = self.post_safety(safety_payload(actions=[]))
        self.assertEqual(status, 200)
        self.assertEqual(payload["decisions"], [])
        self.assertEqual(
            payload["summary"], {"total": 0, "allowed": 0, "blocked": 0}
        )

    def test_blocked_decision_shape(self):
        status, payload = self.post_safety(
            safety_payload(
                policy={
                    "enabled": True,
                    "window_ms": 1000,
                    "max_actions_per_target": 1,
                    "blocked_kinds": ["discovery"],
                },
                actions=[make_action()],
            )
        )
        self.assertEqual(status, 200)
        self.assertEqual(
            payload["decisions"][0],
            {
                "id": "act-1",
                "target": "app.example.com",
                "kind": "discovery",
                "scheduled_ms": 0,
                "status": "blocked",
                "reason": "blocked_kind",
            },
        )

    def test_scope_violation_403(self):
        status, payload = self.post_safety(
            safety_payload(actions=[make_action(target="evil.net")])
        )
        self.assertEqual(status, 403)
        self.assertEqual(payload["error"]["code"], "scope_violation")
        self.assertNotIn("decisions", payload)

    def test_invalid_request_400(self):
        status, payload = self.post_safety({"allow": [], "deny": []})
        self.assertEqual(status, 400)
        self.assertEqual(payload["error"]["code"], "invalid_request")

    def test_malformed_json_400(self):
        status, payload = self.request(
            "POST", "/v1/exercises/safety-evaluate", b"{nope"
        )
        self.assertEqual(status, 400)
        self.assertEqual(payload["error"]["code"], "invalid_request")

    def test_oversized_body_413(self):
        import http.client

        conn = http.client.HTTPConnection("127.0.0.1", self.port)
        conn.putrequest("POST", "/v1/exercises/safety-evaluate")
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
                    method, "/v1/exercises/safety-evaluate"
                )
                self.assertEqual(status, 405)
                self.assertEqual(payload["error"]["code"], "method_not_allowed")

    def test_unknown_route_404(self):
        status, payload = self.request(
            "POST", "/v1/exercises/nope", b"{}"
        )
        self.assertEqual(status, 404)
        self.assertEqual(payload["error"]["code"], "not_found")

    def test_healthz_still_works(self):
        status, payload = self.request("GET", "/healthz")
        self.assertEqual(status, 200)
        self.assertEqual(payload["status"], "ok")


if __name__ == "__main__":
    unittest.main()
