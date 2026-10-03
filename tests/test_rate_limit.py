import json
import threading
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

from redforge.server import Handler
from redforge.service import ScopeViolationError, Service


def make_attempt(**overrides):
    attempt = {
        "id": "att-1",
        "target": "app.example.com",
        "route": "/login",
        "identity": "user-a",
        "timestamp_ms": 1000,
    }
    attempt.update(overrides)
    return attempt


def analyze_payload(**overrides):
    payload = {
        "allow": ["*.example.com", "10.0.0.0/8"],
        "deny": [],
        "policy": {"window_ms": 1000, "max_requests": 2, "group_by": "target"},
        "attempts": [make_attempt()],
    }
    payload.update(overrides)
    return payload


def burst(identity, count, *, target="app.example.com", route="/login", base=0):
    tag = f"{identity}-{target}-{route}-{base}"
    return [
        make_attempt(
            id=f"{tag}-{i}",
            target=target,
            route=route,
            identity=identity,
            timestamp_ms=base + i,
        )
        for i in range(count)
    ]


class RateLimitAnalysisServiceTest(unittest.TestCase):
    def setUp(self):
        self.service = Service()

    def analyze(self, **overrides):
        return self.service.analyze_rate_limit(analyze_payload(**overrides))[
            "alerts"
        ]

    def test_empty_attempts(self):
        self.assertEqual(self.analyze(attempts=[]), [])

    def test_at_limit_is_not_an_alert(self):
        self.assertEqual(self.analyze(attempts=burst("user-a", 2)), [])

    def test_direct_excess_single_identity(self):
        attempts = burst("user-a", 3)
        (alert,) = self.analyze(attempts=attempts)
        self.assertEqual(alert["kind"], "direct_excess")
        self.assertEqual(alert["target"], "app.example.com")
        self.assertIsNone(alert["route"])
        self.assertEqual(alert["window_start_ms"], 0)
        self.assertEqual(alert["window_end_ms"], 1000)
        self.assertEqual(alert["total_requests"], 3)
        self.assertEqual(
            alert["identity_counts"], [{"identity": "user-a", "count": 3}]
        )
        self.assertEqual(
            alert["attempt_ids"], [attempt["id"] for attempt in attempts]
        )

    def test_distributed_bypass_requires_two_identities_under_limit(self):
        attempts = burst("user-a", 2) + burst("user-b", 2)
        (alert,) = self.analyze(attempts=attempts)
        self.assertEqual(alert["kind"], "distributed_bypass")
        self.assertEqual(alert["total_requests"], 4)
        self.assertEqual(
            alert["identity_counts"],
            [{"identity": "user-a", "count": 2}, {"identity": "user-b", "count": 2}],
        )

    def test_identity_over_limit_forces_direct_excess(self):
        attempts = burst("user-a", 3) + burst("user-b", 1)
        (alert,) = self.analyze(attempts=attempts)
        self.assertEqual(alert["kind"], "direct_excess")

    def test_window_start_floors_timestamp(self):
        attempts = [
            make_attempt(id="a", timestamp_ms=1999),
            make_attempt(id="b", timestamp_ms=1500),
            make_attempt(id="c", timestamp_ms=1000),
        ]
        (alert,) = self.analyze(attempts=attempts)
        self.assertEqual(alert["window_start_ms"], 1000)
        self.assertEqual(alert["window_end_ms"], 2000)

    def test_separate_windows_alert_separately(self):
        attempts = burst("user-a", 3, base=0) + burst("user-a", 3, base=5000)
        alerts = self.analyze(attempts=attempts)
        self.assertEqual(
            [a["window_start_ms"] for a in alerts], [0, 5000]
        )

    def test_attempt_ids_sorted_by_timestamp_then_input_order(self):
        attempts = [
            make_attempt(id="late", timestamp_ms=500),
            make_attempt(id="tie-1", timestamp_ms=100),
            make_attempt(id="early", timestamp_ms=0),
            make_attempt(id="tie-2", timestamp_ms=100),
        ]
        (alert,) = self.analyze(attempts=attempts)
        self.assertEqual(
            alert["attempt_ids"], ["early", "tie-1", "tie-2", "late"]
        )

    def test_identity_counts_first_occurrence_order(self):
        attempts = [
            make_attempt(id="1", identity="user-b", timestamp_ms=0),
            make_attempt(id="2", identity="user-a", timestamp_ms=1),
            make_attempt(id="3", identity="user-b", timestamp_ms=2),
        ]
        (alert,) = self.analyze(attempts=attempts)
        self.assertEqual(
            alert["identity_counts"],
            [{"identity": "user-b", "count": 2}, {"identity": "user-a", "count": 1}],
        )

    def test_group_by_target_merges_routes_with_null_route(self):
        attempts = burst("user-a", 2, route="/a") + burst("user-a", 1, route="/b")
        (alert,) = self.analyze(attempts=attempts)
        self.assertIsNone(alert["route"])
        self.assertEqual(alert["total_requests"], 3)

    def test_group_by_target_route_splits_routes_case_sensitively(self):
        policy = {"window_ms": 1000, "max_requests": 2, "group_by": "target_route"}
        attempts = (
            burst("user-a", 2, route="/Login")
            + burst("user-a", 2, route="/login")
            + burst("user-a", 3, route="/logout")
        )
        alerts = self.analyze(policy=policy, attempts=attempts)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["route"], "/logout")
        self.assertEqual(alerts[0]["total_requests"], 3)

    def test_alert_ordering_by_window_target_then_route_position(self):
        policy = {"window_ms": 1000, "max_requests": 1, "group_by": "target_route"}
        attempts = [
            # First occurrence order: other.example.com, /b; app, /a.
            make_attempt(
                id="o1", target="other.example.com", route="/b",
                identity="u", timestamp_ms=0,
            ),
            make_attempt(
                id="a1", target="app.example.com", route="/a",
                identity="u", timestamp_ms=0,
            ),
            # Window 1000: app appears first here but window sorts first.
            make_attempt(
                id="a2", target="app.example.com", route="/a",
                identity="u", timestamp_ms=1000,
            ),
            make_attempt(
                id="a3", target="app.example.com", route="/a",
                identity="u", timestamp_ms=1001,
            ),
            make_attempt(
                id="o2", target="other.example.com", route="/b",
                identity="u", timestamp_ms=1,
            ),
            # Second app request in window 0 so that group also alerts.
            make_attempt(
                id="a4", target="app.example.com", route="/a",
                identity="u", timestamp_ms=2,
            ),
        ]
        alerts = self.analyze(policy=policy, attempts=attempts)
        self.assertEqual(
            [(a["window_start_ms"], a["target"], a["route"]) for a in alerts],
            [
                (0, "other.example.com", "/b"),
                (0, "app.example.com", "/a"),
                (1000, "app.example.com", "/a"),
            ],
        )

    def test_normalized_target_in_alert(self):
        (alert,) = self.analyze(
            attempts=burst("user-a", 3, target="APP.Example.COM.")
        )
        self.assertEqual(alert["target"], "app.example.com")

    def test_alert_shape(self):
        (alert,) = self.analyze(attempts=burst("user-a", 3))
        self.assertEqual(
            set(alert),
            {
                "target",
                "route",
                "window_start_ms",
                "window_end_ms",
                "total_requests",
                "identity_counts",
                "kind",
                "attempt_ids",
            },
        )

    def test_response_is_stable(self):
        payload = analyze_payload(attempts=burst("user-a", 2) + burst("user-b", 2))
        first = self.service.analyze_rate_limit(payload)
        second = self.service.analyze_rate_limit(payload)
        self.assertEqual(first, second)

    def test_scope_violation_raises_after_structure_ok(self):
        with self.assertRaises(ScopeViolationError):
            self.analyze(attempts=[make_attempt(target="evil.net")])
        with self.assertRaises(ScopeViolationError):
            self.analyze(deny=["app.example.com"])
        with self.assertRaises(ScopeViolationError):
            self.analyze(allow=["10.0.0.0/8"])

    def test_structure_error_takes_precedence_over_scope(self):
        with self.assertRaises(ValueError):
            self.analyze(
                attempts=[
                    make_attempt(id="x", target="evil.net"),
                    make_attempt(id="x", target="evil.net"),
                ]
            )

    def test_validation_errors(self):
        bad_payloads = [
            None,
            [],
            {},
            {"allow": [], "deny": [], "policy": {}},
            analyze_payload(extra=1),
            analyze_payload(allow="*.example.com"),
            analyze_payload(deny=["bad_host"]),
            # policy
            analyze_payload(policy=[]),
            analyze_payload(policy={}),
            analyze_payload(policy={"window_ms": 1000, "max_requests": 2}),
            analyze_payload(
                policy={
                    "window_ms": 1000,
                    "max_requests": 2,
                    "group_by": "target",
                    "extra": 1,
                }
            ),
            analyze_payload(
                policy={"window_ms": 0, "max_requests": 2, "group_by": "target"}
            ),
            analyze_payload(
                policy={"window_ms": -1, "max_requests": 2, "group_by": "target"}
            ),
            analyze_payload(
                policy={"window_ms": True, "max_requests": 2, "group_by": "target"}
            ),
            analyze_payload(
                policy={"window_ms": 1000, "max_requests": 0, "group_by": "target"}
            ),
            analyze_payload(
                policy={"window_ms": 1000, "max_requests": "2", "group_by": "target"}
            ),
            analyze_payload(
                policy={"window_ms": 1000, "max_requests": 2, "group_by": "route"}
            ),
            analyze_payload(
                policy={"window_ms": 1000, "max_requests": 2, "group_by": "Target"}
            ),
            # attempts
            analyze_payload(attempts={}),
            analyze_payload(attempts=[{"id": "a"}]),
            analyze_payload(attempts=[make_attempt(extra=1)]),
            analyze_payload(attempts=[make_attempt(id="")]),
            analyze_payload(attempts=[make_attempt(id=1)]),
            analyze_payload(attempts=[make_attempt(target="*.example.com")]),
            analyze_payload(attempts=[make_attempt(target="bad_host")]),
            analyze_payload(attempts=[make_attempt(route="")]),
            analyze_payload(attempts=[make_attempt(route="login")]),
            analyze_payload(attempts=[make_attempt(route=1)]),
            analyze_payload(attempts=[make_attempt(identity="")]),
            analyze_payload(attempts=[make_attempt(identity=1)]),
            analyze_payload(attempts=[make_attempt(timestamp_ms=-1)]),
            analyze_payload(attempts=[make_attempt(timestamp_ms="0")]),
            analyze_payload(attempts=[make_attempt(timestamp_ms=True)]),
            analyze_payload(attempts=[make_attempt(timestamp_ms=1.5)]),
            analyze_payload(
                attempts=[make_attempt(id="dup"), make_attempt(id="dup")]
            ),
        ]
        for payload in bad_payloads:
            with self.subTest(payload=repr(payload)[:80]):
                with self.assertRaises(ValueError):
                    self.service.analyze_rate_limit(payload)


class RateLimitAnalysisHttpTest(unittest.TestCase):
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

    def post_analyze(self, payload):
        return self.request(
            "POST", "/v1/requests/rate-limit-analyze", json.dumps(payload).encode()
        )

    def test_analyze_ok(self):
        status, payload = self.post_analyze(
            analyze_payload(attempts=burst("user-a", 2) + burst("user-b", 2))
        )
        self.assertEqual(status, 200)
        self.assertEqual(list(payload), ["alerts"])
        (alert,) = payload["alerts"]
        self.assertEqual(alert["kind"], "distributed_bypass")
        self.assertEqual(alert["total_requests"], 4)

    def test_empty_attempts_ok(self):
        status, payload = self.post_analyze(analyze_payload(attempts=[]))
        self.assertEqual(status, 200)
        self.assertEqual(payload, {"alerts": []})

    def test_scope_violation_403(self):
        status, payload = self.post_analyze(
            analyze_payload(attempts=[make_attempt(target="evil.net")])
        )
        self.assertEqual(status, 403)
        self.assertEqual(payload["error"]["code"], "scope_violation")
        self.assertNotIn("alerts", payload)

    def test_invalid_request_400(self):
        status, payload = self.post_analyze({"allow": [], "deny": []})
        self.assertEqual(status, 400)
        self.assertEqual(payload["error"]["code"], "invalid_request")

    def test_malformed_json_400(self):
        status, payload = self.request(
            "POST", "/v1/requests/rate-limit-analyze", b"{nope"
        )
        self.assertEqual(status, 400)
        self.assertEqual(payload["error"]["code"], "invalid_request")

    def test_oversized_body_413(self):
        import http.client

        conn = http.client.HTTPConnection("127.0.0.1", self.port)
        conn.putrequest("POST", "/v1/requests/rate-limit-analyze")
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
                    method, "/v1/requests/rate-limit-analyze"
                )
                self.assertEqual(status, 405)
                self.assertEqual(payload["error"]["code"], "method_not_allowed")


if __name__ == "__main__":
    unittest.main()
