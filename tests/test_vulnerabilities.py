import json
import threading
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

from redforge.server import Handler
from redforge.service import ScopeViolation, Service

ALLOW = ["*.example.com", "10.0.0.0/8"]
DENY = ["evil.example.com"]


def match(service, templates, observations, allow=None, deny=None):
    return service.match_vulnerabilities(
        {
            "allow": ALLOW if allow is None else allow,
            "deny": DENY if deny is None else deny,
            "templates": templates,
            "observations": observations,
        }
    )["findings"]


def obs(
    obs_id="o1",
    target="app.example.com",
    status=200,
    headers=None,
    body="",
):
    return {
        "id": obs_id,
        "target": target,
        "status": status,
        "headers": {"Content-Type": "text/html"} if headers is None else headers,
        "body": body,
    }


def tpl(template_id, logic, *matchers, name=None, severity="high"):
    return {
        "id": template_id,
        "name": name or f"Template {template_id}",
        "severity": severity,
        "logic": logic,
        "matchers": list(matchers),
    }


def status_m(values):
    return {"type": "status", "values": values}


def header_m(name, operator, value):
    return {"type": "header", "name": name, "operator": operator, "value": value}


def body_m(operator, value):
    return {"type": "body", "operator": operator, "value": value}


class VulnerabilityMatchTest(unittest.TestCase):
    def setUp(self):
        self.service = Service()

    def test_status_matcher_hits_and_ordering_by_observation_then_template(self):
        observations = [obs("o1", status=200), obs("o2", status=404)]
        templates = [
            tpl("t1", "any", status_m([200, 204])),
            tpl("t2", "any", status_m([404]), severity="low"),
        ]
        findings = match(self.service, templates, observations)
        self.assertEqual(
            [(f["observation_id"], f["template_id"]) for f in findings],
            [("o1", "t1"), ("o2", "t2")],
        )
        first = findings[0]
        self.assertEqual(first["target"], "app.example.com")
        self.assertEqual(first["name"], "Template t1")
        self.assertEqual(first["severity"], "high")
        self.assertEqual(first["evidence"], [0])

    def test_findings_ordered_with_multiple_templates_per_observation(self):
        findings = match(
            self.service,
            [
                tpl("t1", "any", status_m([200])),
                tpl("t2", "any", body_m("contains", "secret")),
                tpl("t3", "any", status_m([500])),
            ],
            [obs("o1", body="here is secret data"), obs("o2", status=500)],
        )
        self.assertEqual(
            [(f["observation_id"], f["template_id"]) for f in findings],
            [("o1", "t1"), ("o1", "t2"), ("o2", "t3")],
        )

    def test_all_logic_requires_every_matcher_and_collects_all_indices(self):
        template = tpl(
            "t1",
            "all",
            status_m([200]),
            header_m("X-Powered-By", "equals", "PHP/8.1"),
            body_m("regex", r"vulnerable\s+app"),
        )
        hit = obs(
            "o1",
            headers={
                "X-Powered-By": "PHP/8.1",
                "Content-Type": "text/html",
            },
            body="<p>vulnerable app</p>",
        )
        miss = obs("o2", headers={"X-Powered-By": "Python/3.12"}, body="nope")
        findings = match(self.service, [template], [hit, miss])
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["evidence"], [0, 1, 2])

    def test_any_logic_needs_one_hit_and_reports_only_hits(self):
        template = tpl(
            "t1",
            "any",
            status_m([401]),
            body_m("contains", "admin"),
        )
        observations = [
            obs("o1", status=200, body="login as admin here"),
            obs("o2", status=200, body="nothing here"),
        ]
        findings = match(self.service, [template], observations)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["observation_id"], "o1")
        # Only the body matcher (index 1) hit; the status miss is not listed.
        self.assertEqual(findings[0]["evidence"], [1])

    def test_header_name_lookup_is_case_insensitive(self):
        template = tpl("t1", "any", header_m("CONTENT-TYPE", "equals", "text/html"))
        findings = match(
            self.service,
            [template],
            [obs(headers={"cOnTeNt-TYPE": "text/html"})],
        )
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["evidence"], [0])

    def test_header_missing_means_no_hit(self):
        template = tpl("t1", "any", header_m("X-Missing", "equals", "x"))
        findings = match(self.service, [template], [obs(headers={})])
        self.assertEqual(findings, [])

    def test_equals_and_contains_are_case_sensitive(self):
        template = tpl(
            "t1",
            "any",
            body_m("equals", "Secret"),
            body_m("contains", "Key"),
            body_m("contains", "secRet"),
        )
        findings = match(
            self.service,
            [template],
            [obs(body="this has a Key inside")],
        )
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["evidence"], [1])

    def test_equals_requires_full_string(self):
        template = tpl("t1", "all", body_m("equals", "exact"))
        findings = match(
            self.service,
            [template],
            [obs("o1", body="exact"), obs("o2", body="exactly")],
        )
        self.assertEqual([f["observation_id"] for f in findings], ["o1"])

    def test_regex_uses_unicode_search_semantics(self):
        template = tpl("t1", "any", body_m("regex", r"版本[：:]\s*\d+"))
        findings = match(
            self.service,
            [template],
            [obs(body="当前版本： 42 已发布")],
        )
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["evidence"], [0])

    def test_regex_searches_not_fullmatch(self):
        template = tpl("t1", "any", body_m("regex", r"adm.n"))
        findings = match(
            self.service, [template], [obs(body="--admen--")]
        )
        self.assertEqual(len(findings), 1)

    def test_target_normalization_in_findings(self):
        findings = match(
            self.service,
            [tpl("t1", "any", status_m([200]))],
            [obs("o1", target="App.Example.COM.")],
        )
        self.assertEqual(findings[0]["target"], "app.example.com")

    def test_scope_denied_target_aborts_with_scope_violation(self):
        with self.assertRaises(ScopeViolation):
            match(
                self.service,
                [tpl("t1", "any", status_m([200]))],
                [
                    obs("o1", target="ok.example.com"),
                    obs("o2", target="evil.example.com", status=200),
                ],
            )

    def test_out_of_allow_scope_aborts(self):
        with self.assertRaises(ScopeViolation):
            match(
                self.service,
                [tpl("t1", "any", status_m([200]))],
                [obs("o1", target="stranger.test")],
            )

    def test_no_partial_findings_when_later_target_denied(self):
        # o1 would match, but o2 being denied must suppress o1's finding too.
        try:
            match(
                self.service,
                [tpl("t1", "any", status_m([200]))],
                [
                    obs("o1", target="ok.example.com"),
                    obs("o2", target="evil.example.com"),
                ],
            )
        except ScopeViolation:
            pass
        else:
            self.fail("ScopeViolation not raised")

    def test_ip_targets_go_through_same_scope_rules(self):
        findings = match(
            self.service,
            [tpl("t1", "any", status_m([200]))],
            [obs("o1", target="10.2.3.4")],
        )
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["target"], "10.2.3.4")

    def test_all_severities_accepted(self):
        templates = [
            tpl(f"s-{severity}", "any", status_m([200]), severity=severity)
            for severity in ("info", "low", "medium", "high", "critical")
        ]
        findings = match(self.service, templates, [obs()])
        self.assertEqual(
            [f["severity"] for f in findings],
            ["info", "low", "medium", "high", "critical"],
        )

    def test_template_name_and_header_name_may_be_empty_strings(self):
        # Spec only requires non-empty ids / matcher values; a present name
        # only needs to be a string.
        template = {
            "id": "t1",
            "name": "",
            "severity": "info",
            "logic": "any",
            "matchers": [
                {"type": "header", "name": "", "operator": "equals", "value": "x"}
            ],
        }
        findings = match(
            self.service,
            [template],
            [obs(headers={"": "x"})],
        )
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["name"], "")
        self.assertEqual(findings[0]["evidence"], [0])

    # --- validation -----------------------------------------------------

    def assert_invalid(self, payload):
        with self.assertRaises(ValueError):
            self.service.match_vulnerabilities(payload)

    def base_payload(self, **overrides):
        payload = {
            "allow": ALLOW,
            "deny": DENY,
            "templates": [tpl("t1", "any", status_m([200]))],
            "observations": [obs()],
        }
        payload.update(overrides)
        return payload

    def test_validation_bad_top_level(self):
        self.assert_invalid(None)
        self.assert_invalid([])
        self.assert_invalid("x")
        self.assert_invalid({})
        self.assert_invalid(
            {"allow": [], "deny": [], "templates": [], "observations": []}
        )

    def test_validation_undefined_fields_rejected_everywhere(self):
        bad = self.base_payload()
        bad["extra"] = 1
        self.assert_invalid(bad)

        bad = self.base_payload()
        bad["templates"] = [
            {
                "id": "t1",
                "name": "n",
                "severity": "high",
                "logic": "any",
                "matchers": [{"type": "status", "values": [200]}],
                "bogus": True,
            }
        ]
        self.assert_invalid(bad)

        bad = self.base_payload()
        bad["observations"] = [
            {
                "id": "o1",
                "target": "app.example.com",
                "status": 200,
                "headers": {},
                "body": "",
                "bogus": 1,
            }
        ]
        self.assert_invalid(bad)

        bad = self.base_payload()
        bad["templates"] = [
            tpl("t1", "any", {"type": "body", "operator": "equals",
                              "value": "x", "extra": 1})
        ]
        self.assert_invalid(bad)

    def test_validation_missing_required_fields(self):
        for field in ("allow", "deny", "templates", "observations"):
            payload = self.base_payload()
            del payload[field]
            self.assert_invalid(payload)

    def test_validation_empty_arrays_and_wrong_types(self):
        self.assert_invalid(self.base_payload(templates=[]))
        self.assert_invalid(self.base_payload(observations=[]))
        self.assert_invalid(self.base_payload(allow="10.0.0.0/8"))
        self.assert_invalid(self.base_payload(templates={}))
        self.assert_invalid(self.base_payload(observations="o"))

    def test_validation_duplicate_ids(self):
        bad = self.base_payload(
            observations=[obs("same"), obs("same", status=404)]
        )
        self.assert_invalid(bad)
        bad = self.base_payload(
            templates=[
                tpl("dup", "any", status_m([200])),
                tpl("dup", "any", status_m([404])),
            ]
        )
        self.assert_invalid(bad)

    def test_validation_empty_id(self):
        bad = self.base_payload(observations=[obs("")])
        self.assert_invalid(bad)
        bad = self.base_payload(
            templates=[
                {
                    "id": "",
                    "name": "n",
                    "severity": "high",
                    "logic": "any",
                    "matchers": [status_m([200])],
                }
            ]
        )
        self.assert_invalid(bad)

    def test_validation_status_range_and_type(self):
        for bad_status in (99, 600, "200", 200.0, True, None):
            self.assert_invalid(self.base_payload(observations=[obs(status=bad_status)]))

    def test_validation_headers_must_be_string_map(self):
        self.assert_invalid(
            self.base_payload(observations=[obs(headers=[])])
        )
        self.assert_invalid(
            self.base_payload(
                observations=[obs(headers={"X-Test": 1})]
            )
        )
        self.assert_invalid(
            self.base_payload(observations=[obs(headers={1: "x"})])
        )

    def test_validation_body_must_be_string(self):
        self.assert_invalid(self.base_payload(observations=[obs(body=b"x")]))
        self.assert_invalid(self.base_payload(observations=[obs(body=None)]))

    def test_validation_target(self):
        self.assert_invalid(self.base_payload(observations=[obs(target="")]))
        self.assert_invalid(
            self.base_payload(observations=[obs(target="not a host!!")])
        )
        self.assert_invalid(
            self.base_payload(observations=[obs(target="*.example.com")])
        )

    def test_validation_severity_enum(self):
        self.assert_invalid(
            self.base_payload(
                templates=[tpl("t1", "any", status_m([200]), severity="urgent")]
            )
        )

    def test_validation_logic_enum(self):
        self.assert_invalid(
            self.base_payload(
                templates=[tpl("t1", "maybe", status_m([200]))]
            )
        )

    def test_validation_matchers(self):
        base = {
            "id": "t1",
            "name": "n",
            "severity": "high",
            "logic": "any",
        }
        self.assert_invalid(
            self.base_payload(templates=[{**base, "matchers": []}])
        )
        self.assert_invalid(
            self.base_payload(templates=[{**base, "matchers": None}])
        )
        self.assert_invalid(
            self.base_payload(
                templates=[{**base, "matchers": [{"type": "nope", "value": "x"}]}]
            )
        )
        self.assert_invalid(
            self.base_payload(
                templates=[{**base, "matchers": [{"type": "status"}]}]
            )
        )
        self.assert_invalid(
            self.base_payload(
                templates=[
                    {**base, "matchers": [{"type": "status", "values": []}]}
                ]
            )
        )
        self.assert_invalid(
            self.base_payload(
                templates=[
                    {**base, "matchers": [{"type": "status", "values": ["200"]}]}
                ]
            )
        )
        self.assert_invalid(
            self.base_payload(
                templates=[
                    {**base,
                     "matchers": [{"type": "header", "operator": "equals",
                                   "value": "x"}]}
                ]
            )
        )
        self.assert_invalid(
            self.base_payload(
                templates=[
                    {**base,
                     "matchers": [{"type": "header", "name": "X",
                                   "operator": "weird", "value": "x"}]}
                ]
            )
        )
        self.assert_invalid(
            self.base_payload(
                templates=[
                    {**base,
                     "matchers": [{"type": "header", "name": "X",
                                   "operator": "contains", "value": ""}]}
                ]
            )
        )
        self.assert_invalid(
            self.base_payload(
                templates=[
                    {**base,
                     "matchers": [{"type": "body", "operator": "regex",
                                   "value": "("}]}
                ]
            )
        )

    def test_validation_malformed_scope_rules(self):
        self.assert_invalid(self.base_payload(allow=["bad host!!"]))
        self.assert_invalid(self.base_payload(deny=[123]))

    def test_structural_error_takes_precedence_over_scope(self):
        # Invalid status on a denied target: validation happens before the
        # scope gate, so this is invalid_request, not scope_violation.
        payload = self.base_payload(
            observations=[obs(target="evil.example.com", status="nope")]
        )
        with self.assertRaises(ValueError):
            self.service.match_vulnerabilities(payload)


class VulnerabilityMatchHttpTest(unittest.TestCase):
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

    MATCH_PATH = "/v1/vulnerabilities/match"

    def payload_bytes(self, **overrides):
        payload = {
            "allow": ["*.example.com"],
            "deny": [],
            "templates": [
                {
                    "id": "t1",
                    "name": "Exposed admin",
                    "severity": "medium",
                    "logic": "all",
                    "matchers": [
                        {"type": "status", "values": [200]},
                        {"type": "body", "operator": "contains", "value": "admin"},
                    ],
                }
            ],
            "observations": [
                {
                    "id": "o1",
                    "target": "app.example.com",
                    "status": 200,
                    "headers": {},
                    "body": "admin panel",
                }
            ],
        }
        payload.update(overrides)
        return json.dumps(payload).encode()

    def test_match_ok(self):
        status, payload = self.request(
            "POST", self.MATCH_PATH, self.payload_bytes()
        )
        self.assertEqual(status, 200)
        self.assertEqual(set(payload.keys()), {"findings"})
        findings = payload["findings"]
        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(
            set(finding.keys()),
            {
                "observation_id",
                "target",
                "template_id",
                "name",
                "severity",
                "evidence",
            },
        )
        self.assertEqual(finding["observation_id"], "o1")
        self.assertEqual(finding["target"], "app.example.com")
        self.assertEqual(finding["template_id"], "t1")
        self.assertEqual(finding["name"], "Exposed admin")
        self.assertEqual(finding["severity"], "medium")
        self.assertEqual(finding["evidence"], [0, 1])

    def test_no_matches_returns_empty_findings(self):
        status, payload = self.request(
            "POST",
            self.MATCH_PATH,
            self.payload_bytes(
                observations=[
                    {
                        "id": "o1",
                        "target": "app.example.com",
                        "status": 404,
                        "headers": {},
                        "body": "nothing",
                    }
                ]
            ),
        )
        self.assertEqual(status, 200)
        self.assertEqual(payload, {"findings": []})

    def test_scope_violation_returns_403(self):
        status, payload = self.request(
            "POST",
            self.MATCH_PATH,
            self.payload_bytes(
                observations=[
                    {
                        "id": "o1",
                        "target": "offscope.test",
                        "status": 200,
                        "headers": {},
                        "body": "admin",
                    }
                ]
            ),
        )
        self.assertEqual(status, 403)
        self.assertEqual(payload["error"]["code"], "scope_violation")

    def test_invalid_request_returns_400(self):
        status, payload = self.request(
            "POST", self.MATCH_PATH, b'{"allow": []}'
        )
        self.assertEqual(status, 400)
        self.assertEqual(payload["error"]["code"], "invalid_request")

    def test_malformed_json_400(self):
        status, payload = self.request("POST", self.MATCH_PATH, b"{nope")
        self.assertEqual(status, 400)
        self.assertEqual(payload["error"]["code"], "invalid_request")

    def test_oversized_body_413(self):
        import http.client

        conn = http.client.HTTPConnection("127.0.0.1", self.port)
        conn.putrequest("POST", self.MATCH_PATH)
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
                status, payload = self.request(method, self.MATCH_PATH)
                self.assertEqual(status, 405)
                self.assertEqual(payload["error"]["code"], "method_not_allowed")

    def test_unknown_route_404_and_existing_routes_intact(self):
        status, payload = self.request("POST", "/v1/nope", b"{}")
        self.assertEqual(status, 404)
        self.assertEqual(payload["error"]["code"], "not_found")
        status, payload = self.request("GET", "/healthz")
        self.assertEqual(status, 200)
        self.assertEqual(payload["status"], "ok")


if __name__ == "__main__":
    unittest.main()
