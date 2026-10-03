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
        "port": 22,
        "transport": "tcp",
        "service": "ssh",
        "username": "root",
        "secret": "a-reasonably-strong-secret",
        "authenticated": True,
    }
    attempt.update(overrides)
    return attempt


def analyze_payload(**overrides):
    payload = {
        "allow": ["*.example.com", "10.0.0.0/8"],
        "deny": [],
        "policy": {"min_length": 8, "weak_secrets": ["password", "123456"]},
        "attempts": [make_attempt()],
    }
    payload.update(overrides)
    return payload


class CredentialAnalysisServiceTest(unittest.TestCase):
    def setUp(self):
        self.service = Service()

    def analyze(self, **overrides):
        return self.service.analyze_credentials(analyze_payload(**overrides))[
            "findings"
        ]

    def test_empty_attempts(self):
        self.assertEqual(self.analyze(attempts=[]), [])

    def test_unauthenticated_attempt_yields_nothing(self):
        self.assertEqual(
            self.analyze(
                attempts=[
                    make_attempt(id="a", secret="", authenticated=False),
                    make_attempt(id="b", secret="root", authenticated=False),
                    make_attempt(id="c", secret="password", authenticated=False),
                ]
            ),
            [],
        )

    def test_empty_secret_is_critical_and_also_short(self):
        (finding,) = self.analyze(attempts=[make_attempt(secret="")])
        self.assertEqual(
            finding["weakness_codes"], ["empty_secret", "short_secret"]
        )
        self.assertEqual(finding["severity"], "critical")

    def test_username_equals_secret_is_case_sensitive(self):
        # Use values at least min_length long so short_secret cannot mask
        # the username comparison.
        (finding,) = self.analyze(
            attempts=[make_attempt(username="Administrator", secret="Administrator")]
        )
        self.assertEqual(finding["weakness_codes"], ["username_equals_secret"])
        self.assertEqual(finding["severity"], "critical")
        self.assertEqual(
            self.analyze(
                attempts=[
                    make_attempt(username="Administrator", secret="administrator")
                ]
            ),
            [],
        )

    def test_dictionary_secret_is_high(self):
        (finding,) = self.analyze(attempts=[make_attempt(secret="password")])
        self.assertEqual(finding["weakness_codes"], ["dictionary_secret"])
        self.assertEqual(finding["severity"], "high")

    def test_short_secret_is_medium(self):
        (finding,) = self.analyze(
            attempts=[make_attempt(secret="short")],
        )
        self.assertEqual(finding["weakness_codes"], ["short_secret"])
        self.assertEqual(finding["severity"], "medium")

    def test_length_counts_unicode_code_points(self):
        # "é😀" is two code points (though several encoded units); with
        # min_length 3 it is short, with min_length 2 it is not.
        (finding,) = self.analyze(
            policy={"min_length": 3, "weak_secrets": []},
            attempts=[make_attempt(secret="é😀")],
        )
        self.assertEqual(finding["weakness_codes"], ["short_secret"])
        self.assertEqual(
            self.analyze(
                policy={"min_length": 2, "weak_secrets": []},
                attempts=[make_attempt(secret="é😀")],
            ),
            [],
        )

    def test_weakness_code_order_and_max_severity(self):
        # A non-empty secret equal to the username and a dictionary entry,
        # and shorter than min_length, hits three codes at once. They keep
        # the fixed order and the critical username code sets the severity.
        (combo,) = self.analyze(
            policy={"min_length": 8, "weak_secrets": ["abc"]},
            attempts=[make_attempt(username="abc", secret="abc")],
        )
        self.assertEqual(
            combo["weakness_codes"],
            ["username_equals_secret", "dictionary_secret", "short_secret"],
        )
        self.assertEqual(combo["severity"], "critical")

        # An empty secret can only ever pair with short_secret: usernames
        # and weak_secret entries are both required non-empty.
        (empty,) = self.analyze(
            attempts=[make_attempt(secret="")],
        )
        self.assertEqual(empty["weakness_codes"], ["empty_secret", "short_secret"])
        self.assertEqual(empty["severity"], "critical")

        # dictionary (high) outranks short (medium).
        (dicthigh,) = self.analyze(attempts=[make_attempt(secret="123456")])
        self.assertEqual(
            dicthigh["weakness_codes"], ["dictionary_secret", "short_secret"]
        )
        self.assertEqual(dicthigh["severity"], "high")

    def test_findings_keep_attempt_order_and_skip_clean(self):
        findings = self.analyze(
            attempts=[
                make_attempt(id="clean-1"),
                make_attempt(id="empty", secret=""),
                make_attempt(id="clean-2", secret="another-strong-one"),
                make_attempt(id="dict", secret="password"),
            ]
        )
        self.assertEqual([f["attempt_id"] for f in findings], ["empty", "dict"])

    def test_finding_shape_and_normalized_target(self):
        (finding,) = self.analyze(
            attempts=[
                make_attempt(
                    target="APP.Example.COM.",
                    port=443,
                    transport="udp",
                    service="ldap",
                    username="svc",
                    secret="",
                )
            ]
        )
        self.assertEqual(
            set(finding),
            {
                "attempt_id",
                "target",
                "port",
                "transport",
                "service",
                "username",
                "severity",
                "weakness_codes",
            },
        )
        self.assertEqual(finding["attempt_id"], "att-1")
        self.assertEqual(finding["target"], "app.example.com")
        self.assertEqual(finding["port"], 443)
        self.assertEqual(finding["transport"], "udp")
        self.assertEqual(finding["service"], "ldap")
        self.assertEqual(finding["username"], "svc")

    def test_response_never_contains_secret(self):
        marker = "UNIQUE-SECRET-MARKER-xyz"
        result = self.service.analyze_credentials(
            analyze_payload(
                policy={"min_length": 8, "weak_secrets": [marker]},
                attempts=[
                    make_attempt(id="a", secret=marker),
                    make_attempt(id="b", secret=marker + "-suffix"),
                ],
            )
        )
        self.assertNotIn(marker, json.dumps(result))

    def test_scope_violation_raises_after_structure_ok(self):
        with self.assertRaises(ScopeViolationError):
            self.analyze(attempts=[make_attempt(target="evil.net")])
        with self.assertRaises(ScopeViolationError):
            self.analyze(deny=["app.example.com"])
        with self.assertRaises(ScopeViolationError):
            self.analyze(allow=["10.0.0.0/8"])

    def test_scope_violation_message_has_no_secret(self):
        marker = "SCOPE-SECRET-MARKER"
        try:
            self.service.analyze_credentials(
                analyze_payload(
                    attempts=[
                        make_attempt(target="evil.net", secret=marker)
                    ]
                )
            )
        except ScopeViolationError as exc:
            self.assertNotIn(marker, str(exc))
        else:
            self.fail("expected ScopeViolationError")

    def test_validation_errors(self):
        bad_payloads = [
            None,
            [],
            {},
            {"allow": [], "deny": [], "policy": {}},
            analyze_payload(extra=1),
            analyze_payload(allow="*.example.com"),
            analyze_payload(deny=["bad_host"]),
            analyze_payload(allow=["10.0.0.0/33"]),
            # policy
            analyze_payload(policy=[]),
            analyze_payload(policy={}),
            analyze_payload(policy={"min_length": 8}),
            analyze_payload(
                policy={"min_length": 8, "weak_secrets": [], "extra": 1}
            ),
            analyze_payload(policy={"min_length": 0, "weak_secrets": []}),
            analyze_payload(policy={"min_length": 129, "weak_secrets": []}),
            analyze_payload(policy={"min_length": "8", "weak_secrets": []}),
            analyze_payload(policy={"min_length": True, "weak_secrets": []}),
            analyze_payload(
                policy={"min_length": 8, "weak_secrets": "password"}
            ),
            analyze_payload(
                policy={"min_length": 8, "weak_secrets": [""]}
            ),
            analyze_payload(
                policy={"min_length": 8, "weak_secrets": [1]}
            ),
            analyze_payload(
                policy={"min_length": 8, "weak_secrets": ["a", "a"]}
            ),
            # attempts
            analyze_payload(attempts={}),
            analyze_payload(attempts=[{"id": "a"}]),
            analyze_payload(attempts=[make_attempt(extra=1)]),
            analyze_payload(attempts=[make_attempt(id="")]),
            analyze_payload(attempts=[make_attempt(id=1)]),
            analyze_payload(attempts=[make_attempt(target="*.example.com")]),
            analyze_payload(attempts=[make_attempt(target="bad_host")]),
            analyze_payload(attempts=[make_attempt(port=0)]),
            analyze_payload(attempts=[make_attempt(port=65536)]),
            analyze_payload(attempts=[make_attempt(port="22")]),
            analyze_payload(attempts=[make_attempt(port=True)]),
            analyze_payload(attempts=[make_attempt(transport="icmp")]),
            analyze_payload(attempts=[make_attempt(service="")]),
            analyze_payload(attempts=[make_attempt(service=1)]),
            analyze_payload(attempts=[make_attempt(username="")]),
            analyze_payload(attempts=[make_attempt(secret=None)]),
            analyze_payload(attempts=[make_attempt(secret=1)]),
            analyze_payload(attempts=[make_attempt(authenticated="yes")]),
            analyze_payload(
                attempts=[make_attempt(id="dup"), make_attempt(id="dup")]
            ),
        ]
        for payload in bad_payloads:
            with self.subTest(payload=repr(payload)[:80]):
                with self.assertRaises(ValueError):
                    self.service.analyze_credentials(payload)

    def test_structure_error_takes_precedence_over_scope(self):
        # Out-of-scope target plus a duplicate id: the structural error
        # wins (ValueError), never a scope violation.
        with self.assertRaises(ValueError):
            self.analyze(
                attempts=[
                    make_attempt(id="x", target="evil.net"),
                    make_attempt(id="x", target="evil.net"),
                ]
            )

    def test_duplicate_weak_secret_error_hides_value(self):
        marker = "DUP-WEAK-MARKER"
        try:
            self.service.analyze_credentials(
                analyze_payload(
                    policy={"min_length": 8, "weak_secrets": [marker, marker]}
                )
            )
        except ValueError as exc:
            self.assertNotIn(marker, str(exc))
        else:
            self.fail("expected ValueError")


class CredentialAnalysisHttpTest(unittest.TestCase):
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
            "POST", "/v1/credentials/analyze", json.dumps(payload).encode()
        )

    def test_analyze_ok(self):
        status, payload = self.post_analyze(
            analyze_payload(
                attempts=[
                    make_attempt(id="clean"),
                    make_attempt(id="empty", secret=""),
                ]
            )
        )
        self.assertEqual(status, 200)
        self.assertEqual(list(payload), ["findings"])
        (finding,) = payload["findings"]
        self.assertEqual(finding["attempt_id"], "empty")
        self.assertEqual(finding["target"], "app.example.com")
        self.assertEqual(finding["severity"], "critical")
        self.assertNotIn("secret", finding)

    def test_empty_attempts_ok(self):
        status, payload = self.post_analyze(analyze_payload(attempts=[]))
        self.assertEqual(status, 200)
        self.assertEqual(payload, {"findings": []})

    def test_secret_absent_from_http_response(self):
        marker = "HTTP-SECRET-MARKER"
        status, payload = self.post_analyze(
            analyze_payload(
                policy={"min_length": 8, "weak_secrets": [marker]},
                attempts=[make_attempt(secret=marker)],
            )
        )
        self.assertEqual(status, 200)
        raw = json.dumps(payload)
        self.assertNotIn(marker, raw)

    def test_scope_violation_403(self):
        status, payload = self.post_analyze(
            analyze_payload(attempts=[make_attempt(target="evil.net")])
        )
        self.assertEqual(status, 403)
        self.assertEqual(payload["error"]["code"], "scope_violation")
        self.assertNotIn("findings", payload)

    def test_invalid_request_400(self):
        status, payload = self.post_analyze({"allow": [], "deny": []})
        self.assertEqual(status, 400)
        self.assertEqual(payload["error"]["code"], "invalid_request")

    def test_malformed_json_400(self):
        status, payload = self.request(
            "POST", "/v1/credentials/analyze", b"{nope"
        )
        self.assertEqual(status, 400)
        self.assertEqual(payload["error"]["code"], "invalid_request")

    def test_oversized_body_413(self):
        import http.client

        conn = http.client.HTTPConnection("127.0.0.1", self.port)
        conn.putrequest("POST", "/v1/credentials/analyze")
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
                status, payload = self.request(method, "/v1/credentials/analyze")
                self.assertEqual(status, 405)
                self.assertEqual(payload["error"]["code"], "method_not_allowed")


if __name__ == "__main__":
    unittest.main()
