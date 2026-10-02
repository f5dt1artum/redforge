import json
import threading
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

from redforge.server import Handler
from redforge.service import Service


def decide(service, allow, deny, targets):
    return service.evaluate_scope(
        {"allow": allow, "deny": deny, "targets": targets}
    )["decisions"]


class ScopeEvaluationTest(unittest.TestCase):
    def setUp(self):
        self.service = Service()

    def test_ip_and_cidr_normalization(self):
        (d1, d2, d3) = decide(
            self.service,
            ["10.0.0.0/8", "2001:DB8::/32"],
            [],
            ["10.1.2.3", "2001:0DB8:0:0::1", "10.0.0.1/24"],
        )
        self.assertTrue(d1["allowed"])
        self.assertEqual(d1["matched_rule"], "10.0.0.0/8")
        self.assertEqual(d2["normalized"], "2001:db8::1")
        self.assertTrue(d2["allowed"])
        # CIDR target normalized to its network address and contained.
        self.assertEqual(d3["normalized"], "10.0.0.0/24")
        self.assertTrue(d3["allowed"])

    def test_hostname_normalization_and_exact_match(self):
        (d1, d2) = decide(
            self.service,
            ["Example.COM."],
            [],
            ["example.com", "www.example.com"],
        )
        self.assertEqual(d1["normalized"], "example.com")
        self.assertTrue(d1["allowed"])
        self.assertEqual(d1["matched_rule"], "example.com")
        self.assertFalse(d2["allowed"])
        self.assertEqual(d2["reason"], "no_allow_match")
        self.assertIsNone(d2["matched_rule"])

    def test_idna_hostname(self):
        (d,) = decide(self.service, ["bücher.de"], [], ["BÜCHER.de"])
        self.assertEqual(d["normalized"], "xn--bcher-kva.de")
        self.assertTrue(d["allowed"])

    def test_wildcard_matches_subdomains_only(self):
        decisions = decide(
            self.service,
            ["*.Example.com"],
            [],
            ["a.example.com", "a.b.example.com", "example.com"],
        )
        self.assertTrue(decisions[0]["allowed"])
        self.assertEqual(decisions[0]["matched_rule"], "*.example.com")
        self.assertTrue(decisions[1]["allowed"])
        self.assertFalse(decisions[2]["allowed"])
        self.assertEqual(decisions[2]["reason"], "no_allow_match")

    def test_deny_wins_over_allow(self):
        (d,) = decide(
            self.service,
            ["10.0.0.0/8"],
            ["10.1.2.3"],
            ["10.1.2.3"],
        )
        self.assertFalse(d["allowed"])
        self.assertEqual(d["reason"], "deny_match")
        self.assertEqual(d["matched_rule"], "10.1.2.3")

    def test_cidr_target_overlap_and_containment(self):
        decisions = decide(
            self.service,
            ["10.0.0.0/8"],
            ["10.9.0.0/16"],
            ["10.9.1.0/24", "10.8.0.0/16", "192.168.0.0/16"],
        )
        self.assertEqual(decisions[0]["reason"], "deny_overlap")
        self.assertEqual(decisions[0]["matched_rule"], "10.9.0.0/16")
        self.assertFalse(decisions[0]["allowed"])
        self.assertTrue(decisions[1]["allowed"])
        self.assertEqual(decisions[2]["reason"], "no_allow_match")

    def test_address_families_do_not_cross(self):
        (d,) = decide(self.service, ["::/0"], [], ["1.2.3.4"])
        self.assertFalse(d["allowed"])
        self.assertEqual(d["reason"], "no_allow_match")

    def test_empty_allow_denies_everything(self):
        (d,) = decide(self.service, [], [], ["example.com"])
        self.assertFalse(d["allowed"])
        self.assertEqual(d["reason"], "no_allow_match")

    def test_order_and_duplicates_preserved(self):
        targets = ["a.example.com", "b.example.com", "a.example.com"]
        decisions = decide(self.service, ["*.example.com"], [], targets)
        self.assertEqual(
            [d["original"] for d in decisions], targets
        )

    def test_first_deciding_rule_reported(self):
        (d,) = decide(
            self.service,
            ["10.0.0.0/8", "10.1.0.0/16"],
            [],
            ["10.1.2.3"],
        )
        self.assertEqual(d["matched_rule"], "10.0.0.0/8")

    def test_validation_errors(self):
        bad_payloads = [
            None,
            [],
            {},
            {"deny": [], "targets": ["a"]},
            {"allow": [], "deny": [], "targets": []},
            {"allow": [], "deny": [], "targets": "a"},
            {"allow": {}, "deny": [], "targets": ["a"]},
            {"allow": [""], "deny": [], "targets": ["a"]},
            {"allow": [None], "deny": [], "targets": ["a"]},
            {"allow": [123], "deny": [], "targets": ["a"]},
            {"allow": ["not a host!!"], "deny": [], "targets": ["a"]},
            {"allow": ["10.0.0.0/33"], "deny": [], "targets": ["a"]},
            {"allow": [], "deny": [], "targets": ["*.example.com"]},
            {"allow": [], "deny": [], "targets": ["bad_host"]},
            {"allow": [], "deny": [], "targets": ["a"] * 1001},
            {"allow": ["a"] * 1001, "deny": [], "targets": ["a"]},
        ]
        for payload in bad_payloads:
            with self.subTest(payload=repr(payload)[:60]):
                with self.assertRaises(ValueError):
                    self.service.evaluate_scope(payload)


class ScopeHttpTest(unittest.TestCase):
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
        req = urllib.request.Request(url, method=method, data=body, headers=headers or {})
        try:
            with urllib.request.urlopen(req) as resp:
                return resp.status, json.loads(resp.read())
        except urllib.error.HTTPError as exc:
            status, payload = exc.code, json.loads(exc.read())
            exc.close()
            return status, payload

    def test_evaluate_ok(self):
        status, payload = self.request(
            "POST",
            "/v1/scope/evaluate",
            json.dumps(
                {
                    "allow": ["*.example.com", "10.0.0.0/8"],
                    "deny": ["evil.example.com"],
                    "targets": ["ok.example.com", "evil.example.com", "1.2.3.4"],
                }
            ).encode(),
            {"Content-Type": "application/json"},
        )
        self.assertEqual(status, 200)
        decisions = payload["decisions"]
        self.assertEqual(len(decisions), 3)
        self.assertTrue(decisions[0]["allowed"])
        self.assertEqual(decisions[1]["reason"], "deny_match")
        self.assertEqual(decisions[2]["reason"], "no_allow_match")

    def test_unauthorized_target_still_200(self):
        status, payload = self.request(
            "POST",
            "/v1/scope/evaluate",
            json.dumps({"allow": [], "deny": [], "targets": ["example.com"]}).encode(),
        )
        self.assertEqual(status, 200)
        self.assertFalse(payload["decisions"][0]["allowed"])

    def test_invalid_request_400(self):
        status, payload = self.request(
            "POST", "/v1/scope/evaluate", b'{"allow": []}'
        )
        self.assertEqual(status, 400)
        self.assertEqual(payload["error"]["code"], "invalid_request")

    def test_malformed_json_400(self):
        status, payload = self.request("POST", "/v1/scope/evaluate", b"{nope")
        self.assertEqual(status, 400)
        self.assertEqual(payload["error"]["code"], "invalid_request")

    def test_oversized_body_413(self):
        # The server rejects on Content-Length alone and closes the
        # connection without draining the body, so send headers first and
        # read the response before transmitting the (oversized) body.
        import http.client

        conn = http.client.HTTPConnection("127.0.0.1", self.port)
        conn.putrequest("POST", "/v1/scope/evaluate")
        conn.putheader("Content-Length", str(1024 * 1024 + 1))
        conn.endheaders()
        resp = conn.getresponse()
        payload = json.loads(resp.read())
        conn.close()
        self.assertEqual(resp.status, 413)
        self.assertEqual(payload["error"]["code"], "request_too_large")

    def test_method_not_allowed_405(self):
        for method in ("GET", "PUT", "DELETE"):
            with self.subTest(method=method):
                status, payload = self.request(method, "/v1/scope/evaluate")
                self.assertEqual(status, 405)
                self.assertEqual(payload["error"]["code"], "method_not_allowed")

    def test_healthz_and_404_unchanged(self):
        status, payload = self.request("GET", "/healthz")
        self.assertEqual(status, 200)
        self.assertEqual(payload["status"], "ok")
        status, payload = self.request("GET", "/nope")
        self.assertEqual(status, 404)
        self.assertEqual(payload["error"]["code"], "not_found")
        status, payload = self.request("POST", "/nope", b"{}")
        self.assertEqual(status, 404)
        self.assertEqual(payload["error"]["code"], "not_found")


if __name__ == "__main__":
    unittest.main()
