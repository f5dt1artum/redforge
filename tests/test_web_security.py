import json
import threading
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

from redforge.server import Handler
from redforge.service import ScopeViolationError, Service


def make_observation(**overrides):
    observation = {
        "id": "obs-1",
        "target": "app.example.com",
        "scheme": "https",
        "headers": {},
    }
    observation.update(overrides)
    return observation


def build_payload(observations=None, checks=None, **overrides):
    payload = {
        "allow": ["*.example.com", "10.0.0.0/8"],
        "deny": [],
        "checks": ["cors", "cookie"] if checks is None else checks,
        "observations": [make_observation()] if observations is None else observations,
    }
    payload.update(overrides)
    return payload


class WebSecurityServiceTest(unittest.TestCase):
    def setUp(self):
        self.service = Service()

    def analyze(self, **overrides):
        return self.service.analyze_web_security(build_payload(**overrides))

    def test_cors_wildcard_with_credentials(self):
        result = self.analyze(
            observations=[
                make_observation(
                    headers={
                        "Access-Control-Allow-Origin": ["*"],
                        "access-control-allow-credentials": ["TRUE"],
                    }
                )
            ]
        )
        self.assertEqual(list(result), ["findings"])
        self.assertEqual(
            result["findings"],
            [
                {
                    "observation_id": "obs-1",
                    "target": "app.example.com",
                    "category": "cors_wildcard_credentials",
                    "severity": "high",
                    "cookie_name": None,
                }
            ],
        )

    def test_cors_requires_both_conditions(self):
        only_origin = self.analyze(
            observations=[
                make_observation(
                    headers={"Access-Control-Allow-Origin": ["*"]}
                )
            ]
        )
        self.assertEqual(only_origin["findings"], [])
        only_credentials = self.analyze(
            observations=[
                make_observation(
                    headers={"Access-Control-Allow-Credentials": ["true"]}
                )
            ]
        )
        self.assertEqual(only_credentials["findings"], [])
        specific_origin = self.analyze(
            observations=[
                make_observation(
                    headers={
                        "Access-Control-Allow-Origin": ["https://a.example.com"],
                        "Access-Control-Allow-Credentials": ["true"],
                    }
                )
            ]
        )
        self.assertEqual(specific_origin["findings"], [])

    def test_cors_not_analyzed_when_not_checked(self):
        result = self.analyze(
            checks=["cookie"],
            observations=[
                make_observation(
                    headers={
                        "Access-Control-Allow-Origin": ["*"],
                        "Access-Control-Allow-Credentials": ["true"],
                    }
                )
            ],
        )
        self.assertEqual(result["findings"], [])

    def test_cookie_missing_both_attributes_yields_two_findings(self):
        result = self.analyze(
            observations=[
                make_observation(headers={"Set-Cookie": ["session=abc; Path=/"]})
            ]
        )
        self.assertEqual(
            result["findings"],
            [
                {
                    "observation_id": "obs-1",
                    "target": "app.example.com",
                    "category": "cookie_missing_secure",
                    "severity": "medium",
                    "cookie_name": "session",
                },
                {
                    "observation_id": "obs-1",
                    "target": "app.example.com",
                    "category": "cookie_missing_httponly",
                    "severity": "medium",
                    "cookie_name": "session",
                },
            ],
        )

    def test_cookie_attributes_case_insensitive(self):
        result = self.analyze(
            observations=[
                make_observation(
                    headers={"Set-Cookie": ["s=1; SECURE; Httponly"]}
                )
            ]
        )
        self.assertEqual(result["findings"], [])

    def test_cookie_attribute_with_value(self):
        result = self.analyze(
            observations=[
                make_observation(
                    headers={"Set-Cookie": ["s=1; Secure=true; HttpOnly=yes"]}
                )
            ]
        )
        self.assertEqual(result["findings"], [])

    def test_http_skips_secure_but_checks_httponly(self):
        result = self.analyze(
            observations=[
                make_observation(
                    scheme="http",
                    headers={"Set-Cookie": ["s=1; Path=/"]},
                )
            ]
        )
        self.assertEqual(
            [finding["category"] for finding in result["findings"]],
            ["cookie_missing_httponly"],
        )

    def test_http_fully_flagged_cookie_is_clean(self):
        result = self.analyze(
            observations=[
                make_observation(
                    scheme="http",
                    headers={"Set-Cookie": ["s=1; HttpOnly"]},
                )
            ]
        )
        self.assertEqual(result["findings"], [])

    def test_cookie_name_is_text_before_first_equals(self):
        result = self.analyze(
            observations=[
                make_observation(
                    headers={"Set-Cookie": ["a=b=c; Secure; HttpOnly", "x"]}
                )
            ]
        )
        names = [finding["cookie_name"] for finding in result["findings"]]
        self.assertEqual(names, ["x", "x"])

    def test_cookie_value_never_echoed(self):
        result = self.analyze(
            observations=[
                make_observation(
                    headers={"Set-Cookie": ["session=topsecretvalue; Path=/"]}
                )
            ]
        )
        self.assertNotIn("topsecretvalue", json.dumps(result))

    def test_multiple_set_cookie_values_keep_order(self):
        result = self.analyze(
            observations=[
                make_observation(
                    headers={
                        "Set-Cookie": [
                            "a=1; Secure; HttpOnly",
                            "b=2",
                            "c=3; Secure",
                        ]
                    }
                )
            ]
        )
        self.assertEqual(
            [
                (finding["cookie_name"], finding["category"])
                for finding in result["findings"]
            ],
            [
                ("b", "cookie_missing_secure"),
                ("b", "cookie_missing_httponly"),
                ("c", "cookie_missing_httponly"),
            ],
        )

    def test_findings_ordered_by_observations_then_checks(self):
        result = self.analyze(
            checks=["cookie", "cors"],
            observations=[
                make_observation(
                    id="obs-1",
                    headers={
                        "Access-Control-Allow-Origin": ["*"],
                        "Access-Control-Allow-Credentials": ["true"],
                        "Set-Cookie": ["s=1"],
                    },
                ),
                make_observation(
                    id="obs-2",
                    headers={"Set-Cookie": ["t=2"]},
                ),
            ],
        )
        self.assertEqual(
            [
                (finding["observation_id"], finding["category"])
                for finding in result["findings"]
            ],
            [
                ("obs-1", "cookie_missing_secure"),
                ("obs-1", "cookie_missing_httponly"),
                ("obs-1", "cors_wildcard_credentials"),
                ("obs-2", "cookie_missing_secure"),
                ("obs-2", "cookie_missing_httponly"),
            ],
        )

    def test_header_names_case_insensitive_and_merged(self):
        result = self.analyze(
            observations=[
                make_observation(
                    headers={
                        "set-cookie": ["a=1"],
                        "SET-COOKIE": ["b=2; Secure; HttpOnly"],
                    }
                )
            ]
        )
        self.assertEqual(
            [finding["cookie_name"] for finding in result["findings"]],
            ["a", "a"],
        )

    def test_empty_observations(self):
        self.assertEqual(self.analyze(observations=[]), {"findings": []})

    def test_no_hits_returns_empty_findings(self):
        result = self.analyze(
            observations=[
                make_observation(
                    headers={
                        "Set-Cookie": ["s=1; Secure; HttpOnly"],
                        "Access-Control-Allow-Origin": ["https://a.example.com"],
                    }
                )
            ]
        )
        self.assertEqual(result["findings"], [])

    def test_target_normalized_in_findings(self):
        result = self.analyze(
            observations=[
                make_observation(
                    target="APP.Example.COM.",
                    headers={"Set-Cookie": ["s=1"]},
                )
            ]
        )
        self.assertTrue(
            all(
                finding["target"] == "app.example.com"
                for finding in result["findings"]
            )
        )

    def test_deterministic(self):
        payload = build_payload(
            observations=[
                make_observation(
                    headers={
                        "Access-Control-Allow-Origin": ["*"],
                        "Access-Control-Allow-Credentials": ["true"],
                        "Set-Cookie": ["s=1"],
                    }
                )
            ]
        )
        self.assertEqual(
            self.service.analyze_web_security(payload),
            self.service.analyze_web_security(payload),
        )

    def test_structure_errors(self):
        bad_payloads = [
            {},
            {"allow": [], "deny": [], "checks": ["cors"]},
            build_payload(extra=1),
            build_payload(allow={}),
            build_payload(allow="nope"),
            build_payload(checks=[]),
            build_payload(checks="cors"),
            build_payload(checks=["xss"]),
            build_payload(checks=["cors", "cors"]),
            build_payload(checks=["cors", 1]),
            build_payload(observations={}),
            build_payload(observations=[{}]),
            build_payload(observations=[make_observation(extra=1)]),
            build_payload(observations=[make_observation(id="")]),
            build_payload(observations=[make_observation(id=4)]),
            build_payload(observations=[make_observation(target="*.example.com")]),
            build_payload(observations=[make_observation(target="bad host")]),
            build_payload(observations=[make_observation(scheme="HTTPS")]),
            build_payload(observations=[make_observation(scheme="ftp")]),
            build_payload(observations=[make_observation(scheme=1)]),
            build_payload(observations=[make_observation(headers=[])]),
            build_payload(observations=[make_observation(headers={"X": []})]),
            build_payload(observations=[make_observation(headers={"X": [""]})]),
            build_payload(observations=[make_observation(headers={"X": [1]})]),
            build_payload(observations=[make_observation(headers={"X": "v"})]),
            build_payload(
                observations=[make_observation(id="d"), make_observation(id="d")]
            ),
        ]
        for payload in bad_payloads:
            with self.subTest(payload=repr(payload)[:90]):
                with self.assertRaises(ValueError):
                    self.service.analyze_web_security(payload)

    def test_structure_error_precedes_scope(self):
        # Out-of-scope target plus a duplicate id: the structural error wins.
        with self.assertRaises(ValueError):
            self.analyze(
                observations=[
                    make_observation(id="x", target="evil.net"),
                    make_observation(id="x", target="evil.net"),
                ]
            )
        # A bad check with an out-of-scope target is also a 400.
        with self.assertRaises(ValueError):
            self.analyze(
                checks=["nope"],
                observations=[make_observation(target="evil.net")],
            )

    def test_out_of_scope_is_403(self):
        with self.assertRaises(ScopeViolationError):
            self.analyze(observations=[make_observation(target="evil.net")])
        # deny wins over allow.
        with self.assertRaises(ScopeViolationError):
            self.analyze(
                deny=["app.example.com"],
                observations=[make_observation(target="app.example.com")],
            )

    def test_empty_observations_still_validates_scope_rules(self):
        with self.assertRaises(ValueError):
            self.analyze(observations=[], allow=["bad host"])


class WebSecurityHttpTest(unittest.TestCase):
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

    def post(self, path, payload):
        return self.request("POST", path, json.dumps(payload).encode())

    def test_analyze_ok(self):
        status, payload = self.post(
            "/v1/web/security-analyze",
            build_payload(
                observations=[
                    make_observation(
                        headers={
                            "Access-Control-Allow-Origin": ["*"],
                            "Access-Control-Allow-Credentials": ["true"],
                            "Set-Cookie": ["s=1"],
                        }
                    )
                ]
            ),
        )
        self.assertEqual(status, 200)
        self.assertEqual(list(payload), ["findings"])
        self.assertEqual(
            [finding["category"] for finding in payload["findings"]],
            [
                "cors_wildcard_credentials",
                "cookie_missing_secure",
                "cookie_missing_httponly",
            ],
        )

    def test_analyze_empty_findings(self):
        status, payload = self.post(
            "/v1/web/security-analyze", build_payload(observations=[])
        )
        self.assertEqual(status, 200)
        self.assertEqual(payload, {"findings": []})

    def test_invalid_request_400(self):
        status, payload = self.post(
            "/v1/web/security-analyze",
            {"allow": [], "deny": [], "checks": ["cors"]},
        )
        self.assertEqual(status, 400)
        self.assertEqual(payload["error"]["code"], "invalid_request")

    def test_duplicate_check_400(self):
        status, payload = self.post(
            "/v1/web/security-analyze",
            build_payload(checks=["cors", "cors"], observations=[]),
        )
        self.assertEqual(status, 400)
        self.assertEqual(payload["error"]["code"], "invalid_request")

    def test_scope_violation_403(self):
        status, payload = self.post(
            "/v1/web/security-analyze",
            build_payload(observations=[make_observation(target="evil.net")]),
        )
        self.assertEqual(status, 403)
        self.assertEqual(payload["error"]["code"], "scope_violation")
        self.assertNotIn("findings", payload)

    def test_malformed_json_400(self):
        status, payload = self.request(
            "POST", "/v1/web/security-analyze", b"{nope"
        )
        self.assertEqual(status, 400)
        self.assertEqual(payload["error"]["code"], "invalid_request")

    def test_method_not_allowed_405(self):
        for method in ("GET", "PUT", "DELETE", "PATCH"):
            with self.subTest(method=method):
                status, payload = self.request(
                    method, "/v1/web/security-analyze"
                )
                self.assertEqual(status, 405)
                self.assertEqual(payload["error"]["code"], "method_not_allowed")

    def test_unknown_route_404(self):
        status, payload = self.request("POST", "/v1/web/nope", b"{}")
        self.assertEqual(status, 404)
        self.assertEqual(payload["error"]["code"], "not_found")


if __name__ == "__main__":
    unittest.main()
