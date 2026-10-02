import http.client
import json
import threading
import unittest

from redforge.server import Handler
from redforge.server import ThreadingHTTPServer
from redforge.service import Service


def decide(service, payload):
    return service.evaluate_scope(payload)["decisions"]


class ScopeServiceTest(unittest.TestCase):
    def setUp(self):
        self.service = Service()

    def test_exact_host_allowed(self):
        [d] = decide(self.service, {"allow": ["Example.COM."], "deny": [], "targets": ["example.com"]})
        self.assertTrue(d["allowed"])
        self.assertEqual(d["reason"], "allowed")
        self.assertEqual(d["matched_rule"], "example.com")
        self.assertEqual(d["normalized"], "example.com")
        self.assertEqual(d["original"], "example.com")

    def test_wildcard_matches_subdomain_not_root(self):
        payload = {
            "allow": ["*.example.com"],
            "deny": [],
            "targets": ["a.example.com", "a.b.example.com", "example.com"],
        }
        d1, d2, d3 = decide(self.service, payload)
        self.assertTrue(d1["allowed"])
        self.assertTrue(d2["allowed"])
        self.assertFalse(d3["allowed"])
        self.assertEqual(d3["reason"], "no_allow_match")
        self.assertIsNone(d3["matched_rule"])

    def test_deny_wins_over_allow(self):
        payload = {
            "allow": ["*.example.com"],
            "deny": ["bad.example.com"],
            "targets": ["bad.example.com", "good.example.com"],
        }
        d1, d2 = decide(self.service, payload)
        self.assertFalse(d1["allowed"])
        self.assertEqual(d1["reason"], "deny_match")
        self.assertEqual(d1["matched_rule"], "bad.example.com")
        self.assertTrue(d2["allowed"])

    def test_empty_allow_denies_everything(self):
        [d] = decide(self.service, {"allow": [], "deny": [], "targets": ["1.2.3.4"]})
        self.assertFalse(d["allowed"])
        self.assertEqual(d["reason"], "no_allow_match")

    def test_ip_and_cidr_normalization(self):
        payload = {
            "allow": ["10.0.0.9/8", "2001:0DB8:0:0::/32"],
            "deny": [],
            "targets": ["10.1.2.3", "2001:0DB8::1", "10.0.0.9/8"],
        }
        d1, d2, d3 = decide(self.service, payload)
        self.assertEqual(d1["normalized"], "10.1.2.3")
        self.assertTrue(d1["allowed"])
        self.assertEqual(d1["matched_rule"], "10.0.0.0/8")
        self.assertEqual(d2["normalized"], "2001:db8::1")
        self.assertTrue(d2["allowed"])
        self.assertEqual(d3["normalized"], "10.0.0.0/8")
        self.assertTrue(d3["allowed"])

    def test_address_families_do_not_cross(self):
        payload = {"allow": ["10.0.0.0/8"], "deny": [], "targets": ["::ffff:10.1.2.3", "fe80::1"]}
        d1, d2 = decide(self.service, payload)
        self.assertFalse(d1["allowed"])
        self.assertFalse(d2["allowed"])

    def test_net_target_requires_containment(self):
        payload = {
            "allow": ["10.0.0.0/8"],
            "deny": [],
            "targets": ["10.1.0.0/16", "10.0.0.0/8", "11.0.0.0/8", "0.0.0.0/0"],
        }
        d1, d2, d3, d4 = decide(self.service, payload)
        self.assertTrue(d1["allowed"])
        self.assertTrue(d2["allowed"])
        self.assertFalse(d3["allowed"])
        self.assertEqual(d3["reason"], "no_allow_match")
        self.assertFalse(d4["allowed"])

    def test_net_target_deny_overlap(self):
        payload = {
            "allow": ["10.0.0.0/8"],
            "deny": ["10.1.2.0/24"],
            "targets": ["10.1.0.0/16", "10.2.0.0/16"],
        }
        d1, d2 = decide(self.service, payload)
        self.assertFalse(d1["allowed"])
        self.assertEqual(d1["reason"], "deny_overlap")
        self.assertEqual(d1["matched_rule"], "10.1.2.0/24")
        self.assertTrue(d2["allowed"])

    def test_deny_ip_rule_does_not_block_net_target(self):
        payload = {"allow": ["10.0.0.0/8"], "deny": ["10.1.2.3"], "targets": ["10.1.0.0/16"]}
        [d] = decide(self.service, payload)
        self.assertTrue(d["allowed"])

    def test_idna_and_trailing_dot(self):
        payload = {"allow": ["münchen.de"], "deny": [], "targets": ["MÜNCHEN.de."]}
        [d] = decide(self.service, payload)
        self.assertTrue(d["allowed"])
        self.assertEqual(d["normalized"], "xn--mnchen-3ya.de")
        self.assertEqual(d["matched_rule"], "xn--mnchen-3ya.de")

    def test_order_and_duplicates_preserved(self):
        payload = {
            "allow": ["a.example.com"],
            "deny": [],
            "targets": ["b.example.com", "a.example.com", "b.example.com"],
        }
        decisions = decide(self.service, payload)
        self.assertEqual([d["original"] for d in decisions], ["b.example.com", "a.example.com", "b.example.com"])
        self.assertEqual([d["allowed"] for d in decisions], [False, True, False])

    def test_first_deciding_rule_reported(self):
        payload = {
            "allow": ["10.0.0.0/8", "10.1.0.0/16"],
            "deny": ["1.1.1.1", "2.2.2.2"],
            "targets": ["10.1.2.3", "2.2.2.2"],
        }
        d1, d2 = decide(self.service, payload)
        self.assertEqual(d1["matched_rule"], "10.0.0.0/8")
        self.assertEqual(d2["matched_rule"], "2.2.2.2")

    def test_validation_errors(self):
        bad_payloads = [
            None,
            [],
            "x",
            {},
            {"deny": [], "targets": ["a.com"]},
            {"allow": [], "deny": [], "targets": []},
            {"allow": {}, "deny": [], "targets": ["a.com"]},
            {"allow": [], "deny": "x", "targets": ["a.com"]},
            {"allow": [""], "deny": [], "targets": ["a.com"]},
            {"allow": [None], "deny": [], "targets": ["a.com"]},
            {"allow": [123], "deny": [], "targets": ["a.com"]},
            {"allow": [], "deny": [], "targets": ["not a host!"]},
            {"allow": [], "deny": [], "targets": ["1.2.3.4/33"]},
            {"allow": [], "deny": [], "targets": ["*.example.com"]},
            {"allow": ["*"], "deny": [], "targets": ["a.com"]},
            {"allow": [], "deny": [], "targets": ["a..com"]},
            {"allow": [], "deny": [], "targets": ["under_score.com"]},
            {"allow": ["x"] * 1001, "deny": [], "targets": ["a.com"]},
            {"allow": [], "deny": [], "targets": ["a.com"] * 1001},
        ]
        for payload in bad_payloads:
            with self.assertRaises(ValueError, msg=f"payload {payload!r} should fail"):
                self.service.evaluate_scope(payload)

    def test_extra_fields_ignored(self):
        [d] = decide(
            self.service,
            {"allow": ["a.com"], "deny": [], "targets": ["a.com"], "note": "ok"},
        )
        self.assertTrue(d["allowed"])


class ScopeHttpTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()
        cls.port = cls.httpd.server_address[1]

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()
        cls.thread.join(timeout=5)

    def _request(self, method, path, body=None, headers=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        try:
            conn.request(method, path, body=body, headers=headers or {})
        except (BrokenPipeError, ConnectionResetError):
            # The server may reject an oversized body before reading it all.
            pass
        resp = conn.getresponse()
        data = resp.read()
        conn.close()
        return resp.status, json.loads(data) if data else None

    def test_evaluate_ok(self):
        status, payload = self._request(
            "POST",
            "/v1/scope/evaluate",
            body=json.dumps({"allow": ["*.example.com"], "deny": [], "targets": ["a.example.com", "b.com"]}),
        )
        self.assertEqual(status, 200)
        self.assertEqual([d["allowed"] for d in payload["decisions"]], [True, False])

    def test_unauthorized_target_still_200(self):
        status, payload = self._request(
            "POST",
            "/v1/scope/evaluate",
            body=json.dumps({"allow": [], "deny": [], "targets": ["a.example.com"]}),
        )
        self.assertEqual(status, 200)
        self.assertEqual(payload["decisions"][0]["reason"], "no_allow_match")

    def test_invalid_request_400(self):
        status, payload = self._request("POST", "/v1/scope/evaluate", body=json.dumps({"allow": []}))
        self.assertEqual(status, 400)
        self.assertEqual(payload["error"]["code"], "invalid_request")

    def test_malformed_json_400(self):
        status, payload = self._request("POST", "/v1/scope/evaluate", body="{not json")
        self.assertEqual(status, 400)
        self.assertEqual(payload["error"]["code"], "invalid_request")

    def test_oversized_body_413(self):
        status, payload = self._request("POST", "/v1/scope/evaluate", body=b"x" * (1024 * 1024 + 1))
        self.assertEqual(status, 413)
        self.assertEqual(payload["error"]["code"], "request_too_large")

    def test_non_post_405(self):
        for method in ("GET", "PUT", "DELETE"):
            status, payload = self._request(method, "/v1/scope/evaluate")
            self.assertEqual(status, 405, method)
            self.assertEqual(payload["error"]["code"], "method_not_allowed")

    def test_healthz_unchanged(self):
        status, payload = self._request("GET", "/healthz")
        self.assertEqual(status, 200)
        self.assertEqual(payload["status"], "ok")
        self.assertEqual(payload["service"], "redforge")

    def test_unknown_path_404(self):
        status, payload = self._request("GET", "/nope")
        self.assertEqual(status, 404)
        self.assertEqual(payload["error"]["code"], "not_found")
        self.assertEqual(payload["error"]["message"], "no route for /nope")


if __name__ == "__main__":
    unittest.main()
