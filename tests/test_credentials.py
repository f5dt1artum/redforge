import json
import threading
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

from redforge.server import Handler
from redforge.service import ScopeViolationError, Service


def make_policy(**overrides):
    policy = {
        "min_length": 8,
        "weak_secrets": ["password", "letmein"],
    }
    policy.update(overrides)
    return policy


def make_attempt(**overrides):
    attempt = {
        "id": "at-1",
        "target": "app.example.com",
        "port": 22,
        "transport": "tcp",
        "service": "ssh",
        "username": "root",
        "secret": "Sup3r$ecret!",
        "authenticated": True,
    }
    attempt.update(overrides)
    return attempt


def credentials_payload(**overrides):
    payload = {
        "allow": ["*.example.com"],
        "deny": [],
        "policy": make_policy(),
        "attempts": [make_attempt()],
    }
    payload.update(overrides)
    return payload


class CredentialsServiceTest(unittest.TestCase):
    def setUp(self):
        self.service = Service()

    def findings(self, **overrides):
        return self.service.analyze_credentials(
            credentials_payload(**overrides)
        )["findings"]

    def test_strong_secret_no_finding(self):
        self.assertEqual(self.findings(), [])

    def test_empty_secret_hits_empty_and_short(self):
        (finding,) = self.findings(attempts=[make_attempt(secret="")])
        self.assertEqual(
            finding["weakness_codes"], ["empty_secret", "short_secret"]
        )
        self.assertEqual(finding["severity"], "critical")

    def test_username_equals_secret_case_sensitive(self):
        (finding,) = self.findings(
            attempts=[make_attempt(username="Admin", secret="Admin")]
        )
        self.assertEqual(
            finding["weakness_codes"],
            ["username_equals_secret", "short_secret"],
        )
        self.assertEqual(finding["severity"], "critical")
        # Different case does not hit username_equals_secret.
        (finding,) = self.findings(
            attempts=[make_attempt(username="AdminUs", secret="adminus")]
        )
        self.assertEqual(finding["weakness_codes"], ["short_secret"])
        self.assertEqual(
            self.findings(
                attempts=[
                    make_attempt(username="AdminUser1", secret="adminuser12")
                ]
            ),
            [],
        )

    def test_dictionary_secret(self):
        (finding,) = self.findings(
            attempts=[make_attempt(secret="password")]
        )
        # "password" has exactly min_length code points: not short.
        self.assertEqual(finding["weakness_codes"], ["dictionary_secret"])
        self.assertEqual(finding["severity"], "high")
        (finding,) = self.findings(
            attempts=[make_attempt(secret="letmein")]
        )
        self.assertEqual(
            finding["weakness_codes"], ["dictionary_secret", "short_secret"]
        )

    def test_short_secret_only(self):
        (finding,) = self.findings(attempts=[make_attempt(secret="Ab1!xy")])
        self.assertEqual(finding["weakness_codes"], ["short_secret"])
        self.assertEqual(finding["severity"], "medium")

    def test_multiple_codes_in_order(self):
        policy = make_policy(min_length=8, weak_secrets=["root"])
        (finding,) = self.findings(
            policy=policy,
            attempts=[make_attempt(username="root", secret="root")],
        )
        self.assertEqual(
            finding["weakness_codes"],
            [
                "username_equals_secret",
                "dictionary_secret",
                "short_secret",
            ],
        )
        self.assertEqual(finding["severity"], "critical")

    def test_min_length_counts_unicode_code_points(self):
        # 4 code points but 5 UTF-16 code units / more bytes: still short.
        attempts = [make_attempt(secret="é" * 4 + "abcd1234")]
        self.assertEqual(self.findings(attempts=attempts), [])
        attempts = [make_attempt(secret="é" * 7)]
        (finding,) = self.findings(attempts=attempts)
        self.assertEqual(finding["weakness_codes"], ["short_secret"])
        # Boundary: exactly min_length code points is not short.
        attempts = [make_attempt(secret="a" * 8)]
        self.assertEqual(self.findings(attempts=attempts), [])

    def test_unauthenticated_produces_no_finding(self):
        self.assertEqual(
            self.findings(
                attempts=[make_attempt(secret="", authenticated=False)]
            ),
            [],
        )

    def test_empty_attempts_returns_empty_findings(self):
        self.assertEqual(self.findings(attempts=[]), [])

    def test_finding_shape_and_order(self):
        attempts = [
            make_attempt(id="a", secret="ok-secret-1"),
            make_attempt(
                id="b",
                target="DB.Example.COM.",
                port=5432,
                transport="udp",
                service="postgres",
                username="db",
                secret="password",
            ),
            make_attempt(id="c", secret="", authenticated=False),
            make_attempt(id="d", secret="x"),
        ]
        findings = self.findings(attempts=attempts)
        self.assertEqual([f["attempt_id"] for f in findings], ["b", "d"])
        finding = findings[0]
        self.assertEqual(
            list(finding),
            [
                "attempt_id",
                "target",
                "port",
                "transport",
                "service",
                "username",
                "severity",
                "weakness_codes",
            ],
        )
        self.assertEqual(finding["target"], "db.example.com")
        self.assertEqual(finding["port"], 5432)
        self.assertEqual(finding["transport"], "udp")
        self.assertEqual(finding["service"], "postgres")
        self.assertEqual(finding["username"], "db")
        self.assertNotIn("secret", finding)

    def test_scope_violation_raises(self):
        with self.assertRaises(ScopeViolationError):
            self.findings(attempts=[make_attempt(target="evil.net")])
        with self.assertRaises(ScopeViolationError):
            self.findings(deny=["app.example.com"])

    def test_empty_allow_denies_everything(self):
        with self.assertRaises(ScopeViolationError):
            self.findings(allow=[])

    def test_structure_errors_before_scope_gate(self):
        bad_payloads = [
            None,
            [],
            {},
            {"allow": [], "deny": [], "policy": make_policy()},
            credentials_payload(extra=1),
            credentials_payload(allow="*.example.com"),
            credentials_payload(policy="x"),
            credentials_payload(attempts="x"),
            # policy
            credentials_payload(policy={}),
            credentials_payload(policy=make_policy(extra=1)),
            credentials_payload(policy=make_policy(min_length=0)),
            credentials_payload(policy=make_policy(min_length=129)),
            credentials_payload(policy=make_policy(min_length="8")),
            credentials_payload(policy=make_policy(min_length=True)),
            credentials_payload(policy=make_policy(min_length=8.0)),
            credentials_payload(policy=make_policy(weak_secrets=[])),
            credentials_payload(policy=make_policy(weak_secrets="x")),
            credentials_payload(policy=make_policy(weak_secrets=[""])),
            credentials_payload(policy=make_policy(weak_secrets=[1])),
            credentials_payload(
                policy=make_policy(weak_secrets=["a", "b", "a"])
            ),
            # attempts
            credentials_payload(attempts=[{"id": "a"}]),
            credentials_payload(attempts=[make_attempt(extra=1)]),
            credentials_payload(attempts=[make_attempt(id="")]),
            credentials_payload(attempts=[make_attempt(id=1)]),
            credentials_payload(attempts=[make_attempt(target="*.example.com")]),
            credentials_payload(attempts=[make_attempt(target="bad_host")]),
            credentials_payload(attempts=[make_attempt(target="")]),
            credentials_payload(attempts=[make_attempt(port=0)]),
            credentials_payload(attempts=[make_attempt(port=65536)]),
            credentials_payload(attempts=[make_attempt(port="22")]),
            credentials_payload(attempts=[make_attempt(port=True)]),
            credentials_payload(attempts=[make_attempt(transport="icmp")]),
            credentials_payload(attempts=[make_attempt(transport=None)]),
            credentials_payload(attempts=[make_attempt(service="")]),
            credentials_payload(attempts=[make_attempt(service=1)]),
            credentials_payload(attempts=[make_attempt(username="")]),
            credentials_payload(attempts=[make_attempt(username=1)]),
            credentials_payload(attempts=[make_attempt(secret=None)]),
            credentials_payload(attempts=[make_attempt(secret=1)]),
            credentials_payload(attempts=[make_attempt(authenticated="yes")]),
            credentials_payload(attempts=[make_attempt(authenticated=1)]),
            credentials_payload(
                attempts=[make_attempt(), make_attempt()]
            ),
            # Malformed policy plus an out-of-scope attempt: 400 wins.
            {
                "allow": ["*.example.com"],
                "deny": [],
                "policy": make_policy(min_length=0),
                "attempts": [make_attempt(target="evil.net")],
            },
            # Malformed attempt plus an out-of-scope attempt: 400 wins.
            {
                "allow": ["*.example.com"],
                "deny": [],
                "policy": make_policy(),
                "attempts": [
                    make_attempt(id="bad", port=0),
                    make_attempt(id="ok", target="evil.net"),
                ],
            },
        ]
        for payload in bad_payloads:
            with self.subTest(payload=repr(payload)[:100]):
                with self.assertRaises(ValueError):
                    self.service.analyze_credentials(payload)

    def test_errors_do_not_leak_secrets(self):
        secret = "t0p-secret-value"
        weak = "weak-list-entry"
        payload = credentials_payload(
            policy=make_policy(weak_secrets=[weak, weak]),
            attempts=[make_attempt(secret=secret)],
        )
        try:
            self.service.analyze_credentials(payload)
        except ValueError as exc:
            message = str(exc)
        else:
            self.fail("expected ValueError")
        self.assertNotIn(secret, message)
        self.assertNotIn(weak, message)


class CredentialsHttpTest(unittest.TestCase):
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

    def post_credentials(self, payload):
        return self.request(
            "POST",
            "/v1/credentials/analyze",
            json.dumps(payload).encode(),
        )

    def test_analyze_ok(self):
        status, payload = self.post_credentials(
            credentials_payload(
                attempts=[
                    make_attempt(id="a", secret="password"),
                    make_attempt(id="b", secret="fine-secret-1"),
                ]
            )
        )
        self.assertEqual(status, 200)
        self.assertEqual(list(payload), ["findings"])
        (finding,) = payload["findings"]
        self.assertEqual(finding["attempt_id"], "a")
        self.assertEqual(finding["target"], "app.example.com")
        self.assertEqual(finding["severity"], "high")
        self.assertEqual(
            finding["weakness_codes"], ["dictionary_secret"]
        )
        self.assertNotIn("password", json.dumps(payload))

    def test_empty_attempts_ok(self):
        status, payload = self.post_credentials(
            credentials_payload(attempts=[])
        )
        self.assertEqual(status, 200)
        self.assertEqual(payload, {"findings": []})

    def test_scope_violation_403(self):
        status, payload = self.post_credentials(
            credentials_payload(
                attempts=[make_attempt(target="evil.net")]
            )
        )
        self.assertEqual(status, 403)
        self.assertEqual(payload["error"]["code"], "scope_violation")
        self.assertNotIn("findings", payload)

    def test_invalid_request_400(self):
        status, payload = self.post_credentials({"allow": [], "deny": []})
        self.assertEqual(status, 400)
        self.assertEqual(payload["error"]["code"], "invalid_request")

    def test_duplicate_attempt_id_400(self):
        status, payload = self.post_credentials(
            credentials_payload(
                attempts=[make_attempt(), make_attempt()]
            )
        )
        self.assertEqual(status, 400)
        self.assertEqual(payload["error"]["code"], "invalid_request")

    def test_duplicate_weak_secret_400_no_leak(self):
        status, payload = self.post_credentials(
            credentials_payload(
                policy=make_policy(weak_secrets=["s3cr3t", "s3cr3t"])
            )
        )
        self.assertEqual(status, 400)
        self.assertEqual(payload["error"]["code"], "invalid_request")
        self.assertNotIn("s3cr3t", json.dumps(payload))

    def test_malformed_json_400(self):
        status, payload = self.request(
            "POST", "/v1/credentials/analyze", b"{nope"
        )
        self.assertEqual(status, 400)
        self.assertEqual(payload["error"]["code"], "invalid_request")

    def test_method_not_allowed_405(self):
        for method in ("GET", "PUT", "DELETE"):
            with self.subTest(method=method):
                status, payload = self.request(
                    method, "/v1/credentials/analyze"
                )
                self.assertEqual(status, 405)
                self.assertEqual(payload["error"]["code"], "method_not_allowed")

    def test_unknown_route_404(self):
        status, payload = self.post_credentials(credentials_payload())
        self.assertEqual(status, 200)
        # Sanity: an unrelated unknown path still 404s.
        not_found = self.request("POST", "/v1/credentials/unknown", b"{}")
        self.assertEqual(not_found[0], 404)


if __name__ == "__main__":
    unittest.main()
