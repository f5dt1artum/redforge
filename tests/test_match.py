import json
import threading
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

from redforge.server import Handler
from redforge.service import ScopeViolationError, Service


def make_template(**overrides):
    template = {
        "id": "tpl-1",
        "name": "Demo template",
        "severity": "high",
        "logic": "all",
        "matchers": [{"values": [200]}],
    }
    template.update(overrides)
    return template


def make_observation(**overrides):
    observation = {
        "id": "obs-1",
        "target": "app.example.com",
        "status": 200,
        "headers": {"Server": "nginx"},
        "body": "hello world",
    }
    observation.update(overrides)
    return observation


def match_payload(**overrides):
    payload = {
        "allow": ["*.example.com"],
        "deny": [],
        "templates": [make_template()],
        "observations": [make_observation()],
    }
    payload.update(overrides)
    return payload


class MatchServiceTest(unittest.TestCase):
    def setUp(self):
        self.service = Service()

    def match(self, **overrides):
        return self.service.match_vulnerabilities(match_payload(**overrides))[
            "findings"
        ]

    def test_status_matcher_hit(self):
        findings = self.match()
        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding["observation_id"], "obs-1")
        self.assertEqual(finding["target"], "app.example.com")
        self.assertEqual(finding["template_id"], "tpl-1")
        self.assertEqual(finding["name"], "Demo template")
        self.assertEqual(finding["severity"], "high")
        self.assertEqual(finding["evidence"], [0])

    def test_target_normalized_in_finding(self):
        findings = self.match(
            observations=[make_observation(target="APP.Example.COM.")]
        )
        self.assertEqual(findings[0]["target"], "app.example.com")

    def test_all_logic_requires_every_matcher(self):
        template = make_template(
            logic="all",
            matchers=[{"values": [200]}, {"operator": "contains", "value": "nope"}],
        )
        self.assertEqual(self.match(templates=[template]), [])

    def test_any_logic_reports_only_hit_indices(self):
        template = make_template(
            logic="any",
            matchers=[
                {"values": [500]},
                {"operator": "contains", "value": "world"},
                {"name": "Server", "operator": "equals", "value": "apache"},
            ],
        )
        findings = self.match(templates=[template])
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["evidence"], [1])

    def test_header_lookup_is_case_insensitive(self):
        template = make_template(
            matchers=[{"name": "sErVeR", "operator": "equals", "value": "nginx"}]
        )
        self.assertEqual(len(self.match(templates=[template])), 1)

    def test_missing_header_never_hits(self):
        template = make_template(
            logic="any",
            matchers=[{"name": "X-Absent", "operator": "contains", "value": "x"}],
        )
        self.assertEqual(self.match(templates=[template]), [])

    def test_operators_are_case_sensitive(self):
        equals = make_template(
            matchers=[{"operator": "equals", "value": "Hello world"}]
        )
        contains = make_template(
            matchers=[{"operator": "contains", "value": "WORLD"}]
        )
        self.assertEqual(self.match(templates=[equals]), [])
        self.assertEqual(self.match(templates=[contains]), [])

    def test_equals_requires_full_match(self):
        template = make_template(
            matchers=[{"operator": "equals", "value": "hello"}]
        )
        self.assertEqual(self.match(templates=[template]), [])

    def test_regex_search_semantics(self):
        hit = make_template(
            matchers=[{"operator": "regex", "value": r"h.llo\s+w\w+"}]
        )
        miss = make_template(
            matchers=[{"operator": "regex", "value": r"^world"}]
        )
        self.assertEqual(len(self.match(templates=[hit])), 1)
        self.assertEqual(self.match(templates=[miss]), [])

    def test_regex_unicode_by_default(self):
        template = make_template(
            matchers=[{"operator": "regex", "value": r"caf\w"}]
        )
        observations = [make_observation(body="café")]
        self.assertEqual(len(self.match(templates=[template], observations=observations)), 1)

    def test_ordering_by_observation_then_template(self):
        templates = [
            make_template(id="t-a", name="A"),
            make_template(id="t-b", name="B"),
        ]
        observations = [
            make_observation(id="o-1"),
            make_observation(id="o-2", status=404),
        ]
        findings = self.match(templates=templates, observations=observations)
        self.assertEqual(
            [(f["observation_id"], f["template_id"]) for f in findings],
            [("o-1", "t-a"), ("o-1", "t-b")],
        )

    def test_scope_violation_raises(self):
        with self.assertRaises(ScopeViolationError):
            self.match(observations=[make_observation(target="other.net")])
        with self.assertRaises(ScopeViolationError):
            self.match(deny=["app.example.com"])

    def test_empty_allow_denies_everything(self):
        with self.assertRaises(ScopeViolationError):
            self.match(allow=[])

    def test_validation_errors(self):
        bad_payloads = [
            None,
            [],
            {},
            {"allow": [], "deny": [], "templates": [make_template()]},
            match_payload(extra=1),
            match_payload(allow="*.example.com"),
            match_payload(templates=[]),
            match_payload(observations=[]),
            match_payload(templates="x"),
            # templates
            match_payload(templates=[{"id": "t"}]),
            match_payload(templates=[make_template(comment="hi")]),
            match_payload(templates=[make_template(id="")]),
            match_payload(templates=[make_template(id=1)]),
            match_payload(templates=[make_template(name=3)]),
            match_payload(templates=[make_template(severity="fatal")]),
            match_payload(templates=[make_template(logic="some")]),
            match_payload(templates=[make_template(matchers=[])]),
            match_payload(templates=[make_template(matchers="x")]),
            match_payload(
                templates=[make_template(), make_template()]
            ),
            # matchers
            match_payload(templates=[make_template(matchers=[{}])]),
            match_payload(templates=[make_template(matchers=[{"values": []}])]),
            match_payload(templates=[make_template(matchers=[{"values": "200"}])]),
            match_payload(templates=[make_template(matchers=[{"values": ["200"]}])]),
            match_payload(templates=[make_template(matchers=[{"values": [True]}])]),
            match_payload(
                templates=[
                    make_template(matchers=[{"operator": "contains", "value": "a", "x": 1}])
                ]
            ),
            match_payload(
                templates=[
                    make_template(matchers=[{"name": "A", "operator": "contains"}])
                ]
            ),
            match_payload(
                templates=[
                    make_template(matchers=[{"name": 1, "operator": "contains", "value": "a"}])
                ]
            ),
            match_payload(
                templates=[
                    make_template(matchers=[{"operator": "starts", "value": "a"}])
                ]
            ),
            match_payload(
                templates=[make_template(matchers=[{"operator": "equals", "value": ""}])]
            ),
            match_payload(
                templates=[make_template(matchers=[{"operator": "equals", "value": 1}])]
            ),
            match_payload(
                templates=[make_template(matchers=[{"operator": "regex", "value": "("}])]
            ),
            # observations
            match_payload(observations=[{"id": "o"}]),
            match_payload(observations=[make_observation(extra=1)]),
            match_payload(observations=[make_observation(id="")]),
            match_payload(observations=[make_observation(target="*.example.com")]),
            match_payload(observations=[make_observation(target="bad_host")]),
            match_payload(observations=[make_observation(status=99)]),
            match_payload(observations=[make_observation(status=600)]),
            match_payload(observations=[make_observation(status="200")]),
            match_payload(observations=[make_observation(status=True)]),
            match_payload(observations=[make_observation(headers=[])]),
            match_payload(observations=[make_observation(headers={"A": 1})]),
            match_payload(observations=[make_observation(body=None)]),
            match_payload(
                observations=[make_observation(), make_observation()]
            ),
        ]
        for payload in bad_payloads:
            with self.subTest(payload=repr(payload)[:80]):
                with self.assertRaises(ValueError):
                    self.service.match_vulnerabilities(payload)


class MatchHttpTest(unittest.TestCase):
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

    def post_match(self, payload):
        return self.request(
            "POST", "/v1/vulnerabilities/match", json.dumps(payload).encode()
        )

    def test_match_ok(self):
        status, payload = self.post_match(
            match_payload(
                templates=[
                    make_template(
                        id="t1",
                        logic="any",
                        matchers=[
                            {"values": [200, 302]},
                            {"name": "server", "operator": "regex", "value": r"^ng\w+"},
                            {"operator": "contains", "value": "absent"},
                        ],
                    )
                ]
            )
        )
        self.assertEqual(status, 200)
        self.assertEqual(list(payload), ["findings"])
        (finding,) = payload["findings"]
        self.assertEqual(finding["observation_id"], "obs-1")
        self.assertEqual(finding["target"], "app.example.com")
        self.assertEqual(finding["template_id"], "t1")
        self.assertEqual(finding["severity"], "high")
        self.assertEqual(finding["evidence"], [0, 1])

    def test_scope_violation_403(self):
        status, payload = self.post_match(
            match_payload(observations=[make_observation(target="evil.net")])
        )
        self.assertEqual(status, 403)
        self.assertEqual(payload["error"]["code"], "scope_violation")
        self.assertNotIn("findings", payload)

    def test_invalid_request_400(self):
        status, payload = self.post_match({"allow": [], "deny": []})
        self.assertEqual(status, 400)
        self.assertEqual(payload["error"]["code"], "invalid_request")

    def test_malformed_json_400(self):
        status, payload = self.request(
            "POST", "/v1/vulnerabilities/match", b"{nope"
        )
        self.assertEqual(status, 400)
        self.assertEqual(payload["error"]["code"], "invalid_request")

    def test_oversized_body_413(self):
        import http.client

        conn = http.client.HTTPConnection("127.0.0.1", self.port)
        conn.putrequest("POST", "/v1/vulnerabilities/match")
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
                status, payload = self.request(method, "/v1/vulnerabilities/match")
                self.assertEqual(status, 405)
                self.assertEqual(payload["error"]["code"], "method_not_allowed")


if __name__ == "__main__":
    unittest.main()
