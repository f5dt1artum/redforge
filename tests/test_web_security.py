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


def analyze_payload(**overrides):
    payload = {
        "allow": ["*.example.com", "10.0.0.0/8"],
        "deny": [],
        "checks": ["cors", "cookie"],
        "observations": [make_observation()],
    }
    payload.update(overrides)
    return payload


def cors_headers():
    return {
        "Access-Control-Allow-Origin": ["*"],
        "Access-Control-Allow-Credentials": ["true"],
    }


class WebSecurityServiceTest(unittest.TestCase):
    def setUp(self):
        self.service = Service()

    def analyze(self, **overrides):
        return self.service.analyze_web_security(analyze_payload(**overrides))[
            "findings"
        ]

    def test_empty_observations(self):
        self.assertEqual(self.analyze(observations=[]), [])

    # --- cors -----------------------------------------------------------

    def test_cors_wildcard_credentials_finding(self):
        (finding,) = self.analyze(
            checks=["cors"],
            observations=[make_observation(headers=cors_headers())],
        )
        self.assertEqual(
            set(finding),
            {"observation_id", "target", "category", "severity", "cookie_name"},
        )
        self.assertEqual(finding["observation_id"], "obs-1")
        self.assertEqual(finding["target"], "app.example.com")
        self.assertEqual(finding["category"], "cors_wildcard_credentials")
        self.assertEqual(finding["severity"], "high")
        self.assertIsNone(finding["cookie_name"])

    def test_cors_header_names_and_true_are_case_insensitive(self):
        (finding,) = self.analyze(
            checks=["cors"],
            observations=[
                make_observation(
                    headers={
                        "ACCESS-CONTROL-ALLOW-ORIGIN": ["*"],
                        "Access-Control-Allow-Credentials": ["True"],
                    }
                )
            ],
        )
        self.assertEqual(finding["category"], "cors_wildcard_credentials")
        # "true" may appear alongside surrounding content; the check is
        # containment on the lowercased value.
        (finding2,) = self.analyze(
            checks=["cors"],
            observations=[
                make_observation(
                    headers={
                        "Access-Control-Allow-Origin": ["https://example.com *"],
                        "Access-Control-Allow-Credentials": [" TRUE "],
                    }
                )
            ],
        )
        self.assertEqual(finding2["category"], "cors_wildcard_credentials")

    def test_cors_requires_both_conditions(self):
        # Wildcard origin without credentials: nothing.
        self.assertEqual(
            self.analyze(
                checks=["cors"],
                observations=[
                    make_observation(
                        headers={"Access-Control-Allow-Origin": ["*"]}
                    )
                ],
            ),
            [],
        )
        # Credentials without a wildcard origin: nothing.
        self.assertEqual(
            self.analyze(
                checks=["cors"],
                observations=[
                    make_observation(
                        headers={
                            "Access-Control-Allow-Origin": ["https://app.example.com"],
                            "Access-Control-Allow-Credentials": ["true"],
                        }
                    )
                ],
            ),
            [],
        )
        # Credentials value other than true: nothing.
        self.assertEqual(
            self.analyze(
                checks=["cors"],
                observations=[
                    make_observation(
                        headers={
                            "Access-Control-Allow-Origin": ["*"],
                            "Access-Control-Allow-Credentials": ["false"],
                        }
                    )
                ],
            ),
            [],
        )

    def test_cors_multiple_header_instances_any_match(self):
        (finding,) = self.analyze(
            checks=["cors"],
            observations=[
                make_observation(
                    headers={
                        "Access-Control-Allow-Origin": [
                            "https://app.example.com",
                            "*",
                        ],
                        "Access-Control-Allow-Credentials": ["true"],
                    }
                )
            ],
        )
        self.assertEqual(finding["category"], "cors_wildcard_credentials")
        # Multiple header values where only one enables credentials.
        (finding2,) = self.analyze(
            checks=["cors"],
            observations=[
                make_observation(
                    headers={
                        "Access-Control-Allow-Origin": ["*"],
                        "Access-Control-Allow-Credentials": ["false", "true"],
                    }
                )
            ],
        )
        self.assertEqual(finding2["category"], "cors_wildcard_credentials")

    # --- cookie ---------------------------------------------------------

    def test_https_cookie_missing_both_yields_two_ordered_findings(self):
        findings = self.analyze(
            checks=["cookie"],
            observations=[
                make_observation(headers={"Set-Cookie": ["session=abc123"]})
            ],
        )
        self.assertEqual(
            [f["category"] for f in findings],
            ["cookie_missing_secure", "cookie_missing_httponly"],
        )
        for finding in findings:
            self.assertEqual(
                set(finding),
                {"observation_id", "target", "category", "severity", "cookie_name"},
            )
            self.assertEqual(finding["severity"], "medium")
            self.assertEqual(finding["target"], "app.example.com")
            self.assertEqual(finding["cookie_name"], "session")

    def test_http_cookie_skips_secure_but_checks_httponly(self):
        findings = self.analyze(
            checks=["cookie"],
            observations=[
                make_observation(
                    scheme="http",
                    headers={"Set-Cookie": ["session=abc123"]},
                )
            ],
        )
        self.assertEqual(
            [f["category"] for f in findings], ["cookie_missing_httponly"]
        )

    def test_cookie_attributes_are_case_insensitive(self):
        self.assertEqual(
            self.analyze(
                checks=["cookie"],
                observations=[
                    make_observation(
                        headers={"set-cookie": ["session=abc; SECURE; HTTPONLY"]}
                    )
                ],
            ),
            [],
        )
        # Secure present but HttpOnly missing: only the HttpOnly finding.
        (finding,) = self.analyze(
            checks=["cookie"],
            observations=[
                make_observation(headers={"Set-Cookie": ["session=abc; Secure"]})
            ],
        )
        self.assertEqual(finding["category"], "cookie_missing_httponly")
        # HttpOnly present (https) but Secure missing: only the Secure finding.
        (finding2,) = self.analyze(
            checks=["cookie"],
            observations=[
                make_observation(headers={"Set-Cookie": ["session=abc; HttpOnly"]})
            ],
        )
        self.assertEqual(finding2["category"], "cookie_missing_secure")

    def test_cookie_attribute_lookalike_in_value_is_not_attribute(self):
        # The text before the first semicolon is the cookie pair; tokens in
        # it must never be parsed as attributes.
        findings = self.analyze(
            checks=["cookie"],
            observations=[
                make_observation(
                    headers={"Set-Cookie": ["securesite=HttpOnlyValue"]}
                )
            ],
        )
        self.assertEqual(
            [f["category"] for f in findings],
            ["cookie_missing_secure", "cookie_missing_httponly"],
        )

    def test_cookie_name_is_text_before_first_equals_only(self):
        findings = self.analyze(
            checks=["cookie"],
            observations=[
                make_observation(headers={"Set-Cookie": ["SID=abc=def; Path=/"]})
            ],
        )
        self.assertTrue(findings)
        self.assertTrue(all(f["cookie_name"] == "SID" for f in findings))
        # The full cookie value must never appear in a finding.
        self.assertNotIn("abc=def", json.dumps(findings))

    def test_multiple_set_cookie_values_keep_header_order(self):
        findings = self.analyze(
            checks=["cookie"],
            observations=[
                make_observation(
                    headers={
                        "Set-Cookie": ["first=1"],
                        "set-cookie": ["second=2"],
                    }
                )
            ],
        )
        # Two values, each missing both attributes, in value order with
        # Secure before HttpOnly per value.
        self.assertEqual(
            [(f["cookie_name"], f["category"]) for f in findings],
            [
                ("first", "cookie_missing_secure"),
                ("first", "cookie_missing_httponly"),
                ("second", "cookie_missing_secure"),
                ("second", "cookie_missing_httponly"),
            ],
        )

    def test_secure_cookie_on_http_still_flags_httponly_only(self):
        # A Secure attribute on an http response is unusual but must not
        # suppress the HttpOnly check; Secure is never evaluated for http.
        (finding,) = self.analyze(
            checks=["cookie"],
            observations=[
                make_observation(
                    scheme="http",
                    headers={"Set-Cookie": ["session=abc; Secure"]},
                )
            ],
        )
        self.assertEqual(finding["category"], "cookie_missing_httponly")

    # --- security_headers: HSTS -----------------------------------------

    def test_hsts_https_missing_yields_all_four_in_order(self):
        findings = self.analyze(
            checks=["security_headers"],
            observations=[make_observation(headers={})],
        )
        self.assertEqual(
            [(f["category"], f["severity"]) for f in findings],
            [
                ("hsts_missing_or_invalid", "high"),
                ("csp_missing", "medium"),
                ("clickjacking_unprotected", "medium"),
                ("nosniff_missing", "low"),
            ],
        )
        for finding in findings:
            self.assertEqual(
                set(finding),
                {"observation_id", "target", "category", "severity", "cookie_name"},
            )
            self.assertEqual(finding["observation_id"], "obs-1")
            self.assertEqual(finding["target"], "app.example.com")
            self.assertIsNone(finding["cookie_name"])

    def test_hsts_http_scheme_is_not_checked(self):
        findings = self.analyze(
            checks=["security_headers"],
            observations=[make_observation(scheme="http", headers={})],
        )
        self.assertEqual(
            [f["category"] for f in findings],
            ["csp_missing", "clickjacking_unprotected", "nosniff_missing"],
        )

    def test_hsts_valid_max_age_suppresses_finding(self):
        for value in (
            "max-age=31536000",
            "  max-age=1; includeSubDomains",
            "MAX-AGE=63072000",
            "includeSubDomains; max-age=99",
        ):
            with self.subTest(value=value):
                findings = self.analyze(
                    checks=["security_headers"],
                    observations=[
                        make_observation(
                            headers={"Strict-Transport-Security": [value]}
                        )
                    ],
                )
                self.assertNotIn("hsts_missing_or_invalid", [f["category"] for f in findings])

    def test_hsts_invalid_values_are_flagged_not_fatal(self):
        for value in (
            "max-age=0",
            "max-age=-1",
            "max-age= 63072000",
            "max-age=63072000 ",
            "max-age=12.0",
            "max-age=12a",
            "max-age=",
            "max-age",
            "includeSubDomains",
            "max-age=１２",
        ):
            with self.subTest(value=value):
                findings = self.analyze(
                    checks=["security_headers"],
                    observations=[
                        make_observation(
                            headers={"Strict-Transport-Security": [value]}
                        )
                    ],
                )
                self.assertIn("hsts_missing_or_invalid", [f["category"] for f in findings])

    def test_hsts_any_valid_value_or_directive_wins(self):
        findings = self.analyze(
            checks=["security_headers"],
            observations=[
                make_observation(
                    headers={
                        "Strict-Transport-Security": [
                            "max-age=0",
                            "garbage; max-age=1; preload",
                        ]
                    }
                )
            ],
        )
        self.assertNotIn("hsts_missing_or_invalid", [f["category"] for f in findings])

    # --- security_headers: CSP ------------------------------------------

    def test_csp_missing_or_blank_is_flagged(self):
        for value in (None, ["   "], ["\t\n"]):
            with self.subTest(value=value):
                headers = {} if value is None else {"Content-Security-Policy": value}
                findings = self.analyze(
                    checks=["security_headers"],
                    observations=[make_observation(scheme="http", headers=headers)],
                )
                self.assertIn("csp_missing", [f["category"] for f in findings])

    def test_csp_present_suppresses_csp_finding(self):
        findings = self.analyze(
            checks=["security_headers"],
            observations=[
                make_observation(
                    scheme="http",
                    headers={"Content-Security-Policy": ["default-src 'self'"]},
                )
            ],
        )
        self.assertNotIn("csp_missing", [f["category"] for f in findings])

    # --- security_headers: clickjacking ---------------------------------

    def test_xfo_deny_or_sameorigin_protects(self):
        for value in ("DENY", " deny ", "SameOrigin", "SAMEORIGIN"):
            with self.subTest(value=value):
                findings = self.analyze(
                    checks=["security_headers"],
                    observations=[
                        make_observation(
                            scheme="http",
                            headers={"X-Frame-Options": [value]},
                        )
                    ],
                )
                self.assertNotIn(
                    "clickjacking_unprotected", [f["category"] for f in findings]
                )

    def test_xfo_other_value_does_not_protect(self):
        findings = self.analyze(
            checks=["security_headers"],
            observations=[
                make_observation(
                    scheme="http",
                    headers={"X-Frame-Options": ["ALLOW-FROM https://x.example"]},
                )
            ],
        )
        self.assertIn(
            "clickjacking_unprotected", [f["category"] for f in findings]
        )

    def test_frame_ancestors_with_argument_protects(self):
        findings = self.analyze(
            checks=["security_headers"],
            observations=[
                make_observation(
                    scheme="http",
                    headers={
                        "Content-Security-Policy": [
                            "default-src 'self'; FRAME-ANCESTORS 'none'"
                        ]
                    },
                )
            ],
        )
        self.assertNotIn(
            "clickjacking_unprotected", [f["category"] for f in findings]
        )
        self.assertNotIn("csp_missing", [f["category"] for f in findings])

    def test_frame_ancestors_without_argument_does_not_protect(self):
        for value in ("frame-ancestors", "frame-ancestors;", "  frame-ancestors  "):
            with self.subTest(value=value):
                findings = self.analyze(
                    checks=["security_headers"],
                    observations=[
                        make_observation(
                            scheme="http",
                            headers={"Content-Security-Policy": [value]},
                        )
                    ],
                )
                self.assertIn(
                    "clickjacking_unprotected", [f["category"] for f in findings]
                )

    # --- security_headers: nosniff --------------------------------------

    def test_nosniff_present_only_when_exact(self):
        ok = self.analyze(
            checks=["security_headers"],
            observations=[
                make_observation(
                    scheme="http", headers={"X-Content-Type-Options": [" NoSniff "]}
                )
            ],
        )
        self.assertNotIn("nosniff_missing", [f["category"] for f in ok])
        bad = self.analyze(
            checks=["security_headers"],
            observations=[
                make_observation(
                    scheme="http",
                    headers={"X-Content-Type-Options": ["nosniff; always"]},
                )
            ],
        )
        self.assertIn("nosniff_missing", [f["category"] for f in bad])

    def test_security_headers_all_protected_is_empty(self):
        findings = self.analyze(
            checks=["security_headers"],
            observations=[
                make_observation(
                    headers={
                        "Strict-Transport-Security": ["max-age=31536000"],
                        "Content-Security-Policy": [
                            "default-src 'self'; frame-ancestors 'none'"
                        ],
                        "X-Frame-Options": ["DENY"],
                        "X-Content-Type-Options": ["nosniff"],
                    }
                )
            ],
        )
        self.assertEqual(findings, [])

    def test_security_headers_repeated_values_all_participate(self):
        findings = self.analyze(
            checks=["security_headers"],
            observations=[
                make_observation(
                    headers={
                        "Strict-Transport-Security": ["garbage", "max-age=1"],
                        "Content-Security-Policy": ["   ", "default-src 'self'"],
                        "X-Frame-Options": ["ALLOW-FROM x", "SAMEORIGIN"],
                        "X-Content-Type-Options": ["other", "nosniff"],
                    }
                )
            ],
        )
        self.assertEqual(findings, [])

    # --- check selection / ordering ------------------------------------

    def test_only_requested_categories_run(self):
        observation = make_observation(
            headers={
                "Set-Cookie": ["session=abc"],
                **cors_headers(),
            }
        )
        self.assertEqual(
            [f["category"] for f in self.analyze(checks=["cors"], observations=[observation])],
            ["cors_wildcard_credentials"],
        )
        cookie_only = self.analyze(checks=["cookie"], observations=[observation])
        self.assertEqual(
            [f["category"] for f in cookie_only],
            ["cookie_missing_secure", "cookie_missing_httponly"],
        )

    def test_security_headers_orders_within_and_across_observations(self):
        findings = self.analyze(
            checks=["security_headers"],
            observations=[
                make_observation(id="a", scheme="https", headers={}),
                make_observation(
                    id="b", target="api.example.com", scheme="http", headers={}
                ),
            ],
        )
        self.assertEqual(
            [(f["observation_id"], f["category"]) for f in findings],
            [
                ("a", "hsts_missing_or_invalid"),
                ("a", "csp_missing"),
                ("a", "clickjacking_unprotected"),
                ("a", "nosniff_missing"),
                ("b", "csp_missing"),
                ("b", "clickjacking_unprotected"),
                ("b", "nosniff_missing"),
            ],
        )

    def test_security_headers_respects_check_order(self):
        headers = {
            "Set-Cookie": ["session=abc"],
            "Strict-Transport-Security": ["max-age=0"],
        }
        first = self.analyze(
            checks=["security_headers", "cookie"],
            observations=[make_observation(headers=headers)],
        )
        self.assertEqual(
            [f["category"] for f in first],
            [
                "hsts_missing_or_invalid",
                "csp_missing",
                "clickjacking_unprotected",
                "nosniff_missing",
                "cookie_missing_secure",
                "cookie_missing_httponly",
            ],
        )
        second = self.analyze(
            checks=["cookie", "security_headers"],
            observations=[make_observation(headers=headers)],
        )
        self.assertEqual(
            [f["category"] for f in second],
            [
                "cookie_missing_secure",
                "cookie_missing_httponly",
                "hsts_missing_or_invalid",
                "csp_missing",
                "clickjacking_unprotected",
                "nosniff_missing",
            ],
        )

    def test_findings_follow_observation_then_check_order(self):
        bad = {
            "Set-Cookie": ["session=abc"],
            **cors_headers(),
        }
        observations = [
            make_observation(id="a", headers=bad),
            make_observation(id="b", target="api.example.com", headers=bad),
        ]
        # cors before cookie: per observation the cors finding comes first.
        findings_cors_first = self.analyze(checks=["cors", "cookie"], observations=observations)
        self.assertEqual(
            [f["observation_id"] for f in findings_cors_first[:3]],
            ["a", "a", "a"],
        )
        self.assertEqual(
            [f["category"] for f in findings_cors_first[:3]],
            [
                "cors_wildcard_credentials",
                "cookie_missing_secure",
                "cookie_missing_httponly",
            ],
        )
        self.assertEqual(
            [f["observation_id"] for f in findings_cors_first[3:]],
            ["b", "b", "b"],
        )
        # cookie before cors reverses the per-observation category order.
        findings_cookie_first = self.analyze(
            checks=["cookie", "cors"], observations=observations
        )
        self.assertEqual(
            [f["category"] for f in findings_cookie_first[:3]],
            [
                "cookie_missing_secure",
                "cookie_missing_httponly",
                "cors_wildcard_credentials",
            ],
        )

    def test_normalized_target(self):
        (finding,) = self.analyze(
            checks=["cors"],
            observations=[
                make_observation(
                    target="APP.Example.COM.",
                    headers=cors_headers(),
                )
            ],
        )
        self.assertEqual(finding["target"], "app.example.com")

    def test_results_are_stable(self):
        payload = analyze_payload(
            checks=["cookie", "cors"],
            observations=[
                make_observation(
                    id="a",
                    headers={"Set-Cookie": ["x=1"], **cors_headers()},
                ),
                make_observation(id="b", headers={"Set-Cookie": ["y=2; Secure"]}),
            ],
        )
        self.assertEqual(
            self.service.analyze_web_security(payload),
            self.service.analyze_web_security(payload),
        )

    def test_response_never_contains_full_cookie(self):
        marker = "UNIQUE-COOKIE-VALUE-xyz"
        result = self.service.analyze_web_security(
            analyze_payload(
                checks=["cookie"],
                observations=[
                    make_observation(headers={"Set-Cookie": [f"session={marker}"]})
                ],
            )
        )
        self.assertNotIn(marker, json.dumps(result))

    # --- scope / validation --------------------------------------------

    def test_scope_violation_raises_after_structure_ok(self):
        with self.assertRaises(ScopeViolationError):
            self.analyze(
                observations=[
                    make_observation(target="evil.net", headers=cors_headers())
                ]
            )
        with self.assertRaises(ScopeViolationError):
            self.analyze(
                deny=["app.example.com"],
                observations=[
                    make_observation(headers=cors_headers())
                ],
            )
        with self.assertRaises(ScopeViolationError):
            self.analyze(
                allow=["10.0.0.0/8"],
                observations=[
                    make_observation(headers=cors_headers())
                ],
            )

    def test_empty_observations_still_gate_scope_rules(self):
        # With no observations there is nothing to authorize, but malformed
        # scope rules still make the request invalid.
        with self.assertRaises(ValueError):
            self.analyze(allow=["bad_host"], observations=[])

    def test_structure_error_takes_precedence_over_scope(self):
        with self.assertRaises(ValueError):
            self.analyze(
                observations=[
                    make_observation(id="x", target="evil.net", scheme="ftp"),
                    make_observation(id="x", target="evil.net"),
                ]
            )

    def test_scope_violation_message_has_no_cookie_value(self):
        marker = "SCOPE-COOKIE-MARKER"
        try:
            self.service.analyze_web_security(
                analyze_payload(
                    checks=["cookie"],
                    observations=[
                        make_observation(
                            target="evil.net",
                            headers={"Set-Cookie": [f"session={marker}"]},
                        )
                    ],
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
            {"allow": [], "deny": []},
            analyze_payload(extra=1),
            analyze_payload(allow="*.example.com"),
            analyze_payload(deny=["bad_host"]),
            analyze_payload(allow=["10.0.0.0/33"]),
            # checks
            analyze_payload(checks=[]),
            analyze_payload(checks="cors"),
            analyze_payload(checks={}),
            analyze_payload(checks=["x"]),
            analyze_payload(checks=["CORS"]),
            analyze_payload(checks=[1]),
            analyze_payload(checks=[None]),
            analyze_payload(checks=["cors", "cors"]),
            # observations
            analyze_payload(observations={}),
            analyze_payload(observations="nope"),
            analyze_payload(observations=[[]]),
            analyze_payload(observations=[{"id": "a"}]),
            analyze_payload(observations=[make_observation(extra=1)]),
            analyze_payload(observations=[make_observation(id="")]),
            analyze_payload(observations=[make_observation(id=1)]),
            analyze_payload(observations=[make_observation(target="")]),
            analyze_payload(observations=[make_observation(target="*.example.com")]),
            analyze_payload(observations=[make_observation(target="bad_host")]),
            analyze_payload(observations=[make_observation(scheme="ftp")]),
            analyze_payload(observations=[make_observation(scheme="HTTPS")]),
            analyze_payload(observations=[make_observation(scheme=1)]),
            analyze_payload(observations=[make_observation(headers=[])]),
            analyze_payload(observations=[make_observation(headers="")]),
            analyze_payload(
                observations=[make_observation(headers={"": ["x"]})]
            ),
            analyze_payload(
                observations=[make_observation(headers={1: ["x"]})]
            ),
            analyze_payload(
                observations=[make_observation(headers={"Set-Cookie": ""})]
            ),
            analyze_payload(
                observations=[make_observation(headers={"Set-Cookie": []})]
            ),
            analyze_payload(
                observations=[make_observation(headers={"Set-Cookie": [1]})]
            ),
            analyze_payload(
                observations=[make_observation(headers={"Set-Cookie": [""]})]
            ),
            analyze_payload(
                observations=[
                    make_observation(id="dup"),
                    make_observation(id="dup"),
                ]
            ),
        ]
        for payload in bad_payloads:
            with self.subTest(payload=repr(payload)[:80]):
                with self.assertRaises(ValueError):
                    self.service.analyze_web_security(payload)


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

    def post_analyze(self, payload):
        return self.request(
            "POST",
            "/v1/web/security-analyze",
            json.dumps(payload).encode(),
        )

    def test_analyze_ok(self):
        status, payload = self.post_analyze(
            analyze_payload(
                checks=["cors", "cookie"],
                observations=[
                    make_observation(
                        headers={
                            "Set-Cookie": ["session=abc"],
                            **cors_headers(),
                        }
                    )
                ],
            )
        )
        self.assertEqual(status, 200)
        self.assertEqual(list(payload), ["findings"])
        self.assertEqual(
            [f["category"] for f in payload["findings"]],
            [
                "cors_wildcard_credentials",
                "cookie_missing_secure",
                "cookie_missing_httponly",
            ],
        )
        self.assertIsNone(payload["findings"][0]["cookie_name"])

    def test_empty_observations_ok(self):
        status, payload = self.post_analyze(analyze_payload(observations=[]))
        self.assertEqual(status, 200)
        self.assertEqual(payload, {"findings": []})

    def test_no_findings_ok(self):
        status, payload = self.post_analyze(
            analyze_payload(
                observations=[
                    make_observation(
                        headers={"Set-Cookie": ["session=abc; Secure; HttpOnly"]}
                    )
                ]
            )
        )
        self.assertEqual(status, 200)
        self.assertEqual(payload, {"findings": []})

    def test_cookie_value_absent_from_http_response(self):
        marker = "HTTP-COOKIE-MARKER"
        status, payload = self.post_analyze(
            analyze_payload(
                checks=["cookie"],
                observations=[
                    make_observation(headers={"Set-Cookie": [f"session={marker}"]})
                ],
            )
        )
        self.assertEqual(status, 200)
        self.assertNotIn(marker, json.dumps(payload))

    def test_scope_violation_403(self):
        status, payload = self.post_analyze(
            analyze_payload(
                observations=[
                    make_observation(target="evil.net", headers=cors_headers())
                ]
            )
        )
        self.assertEqual(status, 403)
        self.assertEqual(payload["error"]["code"], "scope_violation")
        self.assertNotIn("findings", payload)

    def test_invalid_request_400(self):
        status, payload = self.post_analyze({"allow": [], "deny": []})
        self.assertEqual(status, 400)
        self.assertEqual(payload["error"]["code"], "invalid_request")

    def test_duplicate_check_400(self):
        status, payload = self.post_analyze(analyze_payload(checks=["cors", "cors"]))
        self.assertEqual(status, 400)
        self.assertEqual(payload["error"]["code"], "invalid_request")

    def test_security_headers_ok(self):
        status, payload = self.post_analyze(
            analyze_payload(
                checks=["security_headers"],
                observations=[
                    make_observation(
                        headers={
                            "Strict-Transport-Security": ["max-age=31536000"],
                            "Content-Security-Policy": [
                                "frame-ancestors 'none'"
                            ],
                            "X-Frame-Options": ["DENY"],
                            "X-Content-Type-Options": ["nosniff"],
                        }
                    )
                ],
            )
        )
        self.assertEqual(status, 200)
        self.assertEqual(payload, {"findings": []})

    def test_security_headers_findings_ok(self):
        status, payload = self.post_analyze(
            analyze_payload(
                checks=["security_headers"],
                observations=[make_observation(scheme="http", headers={})],
            )
        )
        self.assertEqual(status, 200)
        self.assertEqual(
            [f["category"] for f in payload["findings"]],
            ["csp_missing", "clickjacking_unprotected", "nosniff_missing"],
        )
        self.assertTrue(all(f["cookie_name"] is None for f in payload["findings"]))

    def test_unknown_check_400(self):
        status, payload = self.post_analyze(
            analyze_payload(checks=["security-headers"])
        )
        self.assertEqual(status, 400)
        self.assertEqual(payload["error"]["code"], "invalid_request")

    def test_malformed_json_400(self):
        status, payload = self.request(
            "POST", "/v1/web/security-analyze", b"{nope"
        )
        self.assertEqual(status, 400)
        self.assertEqual(payload["error"]["code"], "invalid_request")

    def test_oversized_body_413(self):
        import http.client

        conn = http.client.HTTPConnection("127.0.0.1", self.port)
        conn.putrequest("POST", "/v1/web/security-analyze")
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
                status, payload = self.request(method, "/v1/web/security-analyze")
                self.assertEqual(status, 405)
                self.assertEqual(payload["error"]["code"], "method_not_allowed")


if __name__ == "__main__":
    unittest.main()
