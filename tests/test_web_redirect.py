import json
import threading
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

from redforge.server import Handler
from redforge.service import ScopeViolationError, Service

CANARY = "https://canary.attacker.example/go"


def make_observation(**overrides):
    observation = {
        "id": "obs-1",
        "target": "app.example.com",
        "scheme": "https",
        "request_path": "/redirect?url=xxx",
        "status": 302,
        "location": CANARY,
        "canary_url": CANARY,
    }
    observation.update(overrides)
    return observation


def analyze_payload(**overrides):
    payload = {
        "allow": ["*.example.com", "10.0.0.0/8"],
        "deny": [],
        "observations": [make_observation()],
    }
    payload.update(overrides)
    return payload


class RedirectServiceTest(unittest.TestCase):
    def setUp(self):
        self.service = Service()

    def analyze(self, **overrides):
        return self.service.analyze_web_redirect(analyze_payload(**overrides))[
            "findings"
        ]

    # --- basic detection ------------------------------------------------

    def test_empty_observations(self):
        self.assertEqual(self.analyze(observations=[]), [])

    def test_open_redirect_finding(self):
        (finding,) = self.analyze()
        self.assertEqual(
            set(finding),
            {"observation_id", "target", "category", "severity", "destination"},
        )
        self.assertEqual(finding["observation_id"], "obs-1")
        self.assertEqual(finding["target"], "app.example.com")
        self.assertEqual(finding["category"], "open_redirect")
        self.assertEqual(finding["severity"], "high")
        self.assertEqual(finding["destination"], CANARY)

    def test_results_follow_observation_order(self):
        findings = self.analyze(
            observations=[
                make_observation(id="a"),
                make_observation(id="b", location=None),
                make_observation(id="c", location="/same-origin"),
                make_observation(id="d", canary_url="https://other.example/x"),
                make_observation(id="e"),
            ]
        )
        self.assertEqual([f["observation_id"] for f in findings], ["a", "e"])

    def test_normalized_target_in_finding(self):
        (finding,) = self.analyze(
            observations=[
                make_observation(target="APP.Example.COM.", location=CANARY)
            ]
        )
        self.assertEqual(finding["target"], "app.example.com")

    def test_results_are_stable(self):
        payload = analyze_payload()
        self.assertEqual(
            self.service.analyze_web_redirect(payload),
            self.service.analyze_web_redirect(payload),
        )

    # --- status gating --------------------------------------------------

    def test_only_redirect_statuses_trigger(self):
        for status in (100, 200, 204, 300, 304, 305, 306, 404, 500):
            with self.subTest(status=status):
                self.assertEqual(
                    self.analyze(observations=[make_observation(status=status)]),
                    [],
                )
        for status in (301, 302, 303, 307, 308):
            with self.subTest(status=status):
                (finding,) = self.analyze(
                    observations=[make_observation(status=status)]
                )
                self.assertEqual(finding["category"], "open_redirect")

    def test_location_null_or_empty_never_triggers(self):
        for location in (None, ""):
            with self.subTest(location=location):
                self.assertEqual(
                    self.analyze(observations=[make_observation(location=location)]),
                    [],
                )

    # --- URL resolution / matching -------------------------------------

    def test_protocol_relative_location_inherits_scheme(self):
        (finding,) = self.analyze(
            observations=[
                make_observation(
                    location="//canary.attacker.example/go",
                    canary_url=CANARY,
                )
            ]
        )
        self.assertEqual(finding["destination"], CANARY)

    def test_absolute_location_normalizes_dot_segments(self):
        (finding,) = self.analyze(
            observations=[
                make_observation(
                    location="https://canary.attacker.example/a/../t/./go",
                    canary_url="https://canary.attacker.example/t/go",
                )
            ]
        )
        self.assertEqual(
            finding["destination"], "https://canary.attacker.example/t/go"
        )

    def test_relative_locations_stay_on_request_host_so_no_cross_origin_hit(self):
        # Root-relative and path-relative locations resolve to the request
        # host; matching a canary on that host is same-origin, not a hit.
        for location, canary in [
            ("/landing", "https://app.example.com/landing"),
            ("../t/./go", "https://app.example.com/t/go"),
        ]:
            with self.subTest(location=location):
                self.assertEqual(
                    self.analyze(
                        observations=[
                            make_observation(
                                request_path="/a/b/redirect?url=x",
                                location=location,
                                canary_url=canary,
                            )
                        ]
                    ),
                    [],
                )

    def test_request_query_is_stripped_before_relative_merge(self):
        # A path-relative reference merges against '/redirect', not against
        # '/redirect?next=1'; either way it stays same-origin and misses.
        self.assertEqual(
            self.analyze(
                observations=[
                    make_observation(
                        request_path="/redirect?next=1",
                        location="landing",
                        canary_url="https://app.example.com/landing",
                    )
                ]
            ),
            [],
        )

    def test_default_port_equivalence_and_case_insensitive_origin(self):
        for location in (
            "https://canary.attacker.example/go",
            "https://canary.attacker.example:443/go",
            "HTTPS://CANARY.ATTACKER.EXAMPLE:443/go",
        ):
            with self.subTest(location=location):
                (finding,) = self.analyze(
                    observations=[make_observation(location=location)]
                )
                # Destination is the normalized form without the default port.
                self.assertEqual(
                    finding["destination"],
                    "https://canary.attacker.example/go",
                )

    def test_non_default_ports_participate_in_origin(self):
        (finding,) = self.analyze(
            observations=[
                make_observation(
                    location="https://canary.attacker.example:8443/go",
                    canary_url="https://canary.attacker.example:8443/go",
                )
            ]
        )
        self.assertEqual(
            finding["destination"], "https://canary.attacker.example:8443/go"
        )
        # Omitted vs explicit non-default port differs.
        self.assertEqual(
            self.analyze(
                observations=[
                    make_observation(
                        location="https://canary.attacker.example/go",
                        canary_url="https://canary.attacker.example:8443/go",
                    )
                ]
            ),
            [],
        )

    def test_scheme_and_host_must_match_for_origin(self):
        # Different scheme (http vs https) is a different origin: a hit when
        # the canary names the resolved http URL; a miss when it does not.
        (finding,) = self.analyze(
            observations=[
                make_observation(
                    scheme="https",
                    location="http://canary.attacker.example/go",
                    canary_url="http://canary.attacker.example/go",
                )
            ]
        )
        self.assertEqual(finding["destination"], "http://canary.attacker.example/go")
        self.assertEqual(
            self.analyze(
                observations=[
                    make_observation(
                        location="http://canary.attacker.example/go",
                        canary_url=CANARY,
                    )
                ]
            ),
            [],
        )

    def test_path_and_query_are_case_sensitive(self):
        for location, canary in [
            ("https://canary.attacker.example/GO", CANARY),
            ("https://canary.attacker.example/go", "https://canary.attacker.example/GO"),
            (
                "https://canary.attacker.example/go?X=1",
                "https://canary.attacker.example/go?x=1",
            ),
        ]:
            with self.subTest(location=location):
                self.assertEqual(
                    self.analyze(
                        observations=[
                            make_observation(location=location, canary_url=canary)
                        ]
                    ),
                    [],
                )

    def test_query_presence_and_value_must_match(self):
        self.assertEqual(
            self.analyze(
                observations=[
                    make_observation(
                        location="https://canary.attacker.example/go?x=1",
                        canary_url="https://canary.attacker.example/go",
                    )
                ]
            ),
            [],
        )
        (finding,) = self.analyze(
            observations=[
                make_observation(
                    location="https://canary.attacker.example/go?x=1",
                    canary_url="https://canary.attacker.example/go?x=1",
                )
            ]
        )
        self.assertEqual(
            finding["destination"], "https://canary.attacker.example/go?x=1"
        )

    def test_percent_encoded_slash_does_not_split_path(self):
        # %2F is data, not a separator: it must survive normalization and
        # must not enable dot-segment traversal.
        (finding,) = self.analyze(
            observations=[
                make_observation(
                    location="https://canary.attacker.example/x%2F..%2Fgo",
                    canary_url="https://canary.attacker.example/x%2F..%2Fgo",
                )
            ]
        )
        self.assertEqual(
            finding["destination"],
            "https://canary.attacker.example/x%2F..%2Fgo",
        )

    def test_malformed_or_disallowed_locations_just_miss(self):
        for location in [
            "javascript:alert(1)",
            "data:text/html,hi",
            "ftp://canary.attacker.example/go",
            "//user@canary.attacker.example/go",
            "https://canary.attacker.example/go#frag",
            "https://canary.attacker.example:99999/go",
            "https://[::1/",
            "  https://canary.attacker.example/go",
            "https://canary.attacker.example/g\to",
            "\t",
            "",
        ]:
            with self.subTest(location=location):
                self.assertEqual(
                    self.analyze(
                        observations=[make_observation(location=location)]
                    ),
                    [],
                )

    def test_malformed_location_does_not_fail_request(self):
        findings = self.analyze(
            observations=[
                make_observation(id="bad", location="javascript:alert(1)"),
                make_observation(id="good"),
            ]
        )
        self.assertEqual([f["observation_id"] for f in findings], ["good"])

    def test_ipv4_and_ipv6_targets_and_canaries(self):
        (finding,) = self.analyze(
            allow=["10.0.0.0/8"],
            observations=[
                make_observation(
                    target="10.1.2.3",
                    scheme="http",
                    request_path="/r",
                    location="https://[2001:db8::1]/x",
                    canary_url="https://[2001:db8::1]/x",
                )
            ],
        )
        self.assertEqual(finding["target"], "10.1.2.3")
        self.assertEqual(finding["destination"], "https://[2001:db8::1]/x")

    # --- scope / validation --------------------------------------------

    def test_scope_violation_raises_after_structure_ok(self):
        with self.assertRaises(ScopeViolationError):
            self.analyze(observations=[make_observation(target="evil.net")])
        with self.assertRaises(ScopeViolationError):
            self.analyze(
                deny=["app.example.com"],
                observations=[make_observation()],
            )

    def test_empty_observations_still_gate_scope_rules(self):
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

    def test_scope_error_message_does_not_leak_location(self):
        marker = "SECRET-MARKER"
        try:
            self.service.analyze_web_redirect(
                analyze_payload(
                    observations=[
                        make_observation(
                            target="evil.net", location=f"https://evil.test/{marker}"
                        )
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
            {"allow": [], "deny": []},
            analyze_payload(extra=1),
            analyze_payload(allow="*.example.com"),
            analyze_payload(deny=["bad_host"]),
            analyze_payload(allow=["10.0.0.0/33"]),
            # observations container
            analyze_payload(observations={}),
            analyze_payload(observations="nope"),
            analyze_payload(observations=[[]]),
            analyze_payload(observations=[{"id": "a"}]),
            # observation fields
            analyze_payload(observations=[make_observation(extra=1)]),
            analyze_payload(observations=[make_observation(id="")]),
            analyze_payload(observations=[make_observation(id=1)]),
            analyze_payload(observations=[make_observation(target="")]),
            analyze_payload(observations=[make_observation(target="*.example.com")]),
            analyze_payload(observations=[make_observation(target="bad_host")]),
            analyze_payload(observations=[make_observation(scheme="ftp")]),
            analyze_payload(observations=[make_observation(scheme="HTTPS")]),
            analyze_payload(observations=[make_observation(scheme=1)]),
            analyze_payload(observations=[make_observation(request_path="")]),
            analyze_payload(observations=[make_observation(request_path="rel/x")]),
            analyze_payload(observations=[make_observation(request_path="/x#frag")]),
            analyze_payload(observations=[make_observation(request_path=1)]),
            analyze_payload(observations=[make_observation(status=True)]),
            analyze_payload(observations=[make_observation(status=99)]),
            analyze_payload(observations=[make_observation(status=600)]),
            analyze_payload(observations=[make_observation(status="302")]),
            analyze_payload(observations=[make_observation(location=1)]),
            analyze_payload(observations=[make_observation(canary_url="")]),
            analyze_payload(observations=[make_observation(canary_url=None)]),
            analyze_payload(observations=[make_observation(canary_url="not a url")]),
            analyze_payload(observations=[make_observation(canary_url="ftp://x/")]),
            analyze_payload(observations=[make_observation(canary_url="http://u:p@x/")]),
            analyze_payload(observations=[make_observation(canary_url="http://x/#f")]),
            analyze_payload(observations=[make_observation(canary_url="http://x:99999/")]),
            # duplicate ids
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
                    self.service.analyze_web_redirect(payload)


class RedirectHttpTest(unittest.TestCase):
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
            "/v1/web/redirect-analyze",
            json.dumps(payload).encode(),
        )

    def test_ok_open_redirect(self):
        status, payload = self.post_analyze(analyze_payload())
        self.assertEqual(status, 200)
        self.assertEqual(list(payload), ["findings"])
        self.assertEqual(
            [f["category"] for f in payload["findings"]], ["open_redirect"]
        )

    def test_empty_observations_ok(self):
        status, payload = self.post_analyze(analyze_payload(observations=[]))
        self.assertEqual(status, 200)
        self.assertEqual(payload, {"findings": []})

    def test_no_findings_ok(self):
        status, payload = self.post_analyze(
            analyze_payload(
                observations=[
                    make_observation(location="/home", canary_url="https://x.test/h")
                ]
            )
        )
        self.assertEqual(status, 200)
        self.assertEqual(payload, {"findings": []})

    def test_scope_violation_403(self):
        status, payload = self.post_analyze(
            analyze_payload(observations=[make_observation(target="evil.net")])
        )
        self.assertEqual(status, 403)
        self.assertEqual(payload["error"]["code"], "scope_violation")
        self.assertNotIn("findings", payload)

    def test_invalid_request_400(self):
        status, payload = self.post_analyze({"allow": [], "deny": []})
        self.assertEqual(status, 400)
        self.assertEqual(payload["error"]["code"], "invalid_request")

    def test_invalid_canary_400(self):
        status, payload = self.post_analyze(
            analyze_payload(
                observations=[make_observation(canary_url="javascript:0")]
            )
        )
        self.assertEqual(status, 400)
        self.assertEqual(payload["error"]["code"], "invalid_request")

    def test_malformed_location_still_200(self):
        status, payload = self.post_analyze(
            analyze_payload(
                observations=[
                    make_observation(id="bad", location="ftp://x/"),
                    make_observation(id="good"),
                ]
            )
        )
        self.assertEqual(status, 200)
        self.assertEqual(
            [f["observation_id"] for f in payload["findings"]], ["good"]
        )

    def test_malformed_json_400(self):
        status, payload = self.request("POST", "/v1/web/redirect-analyze", b"{nope")
        self.assertEqual(status, 400)
        self.assertEqual(payload["error"]["code"], "invalid_request")

    def test_method_not_allowed_405(self):
        for method in ("GET", "PUT", "DELETE", "PATCH"):
            with self.subTest(method=method):
                status, payload = self.request(
                    method, "/v1/web/redirect-analyze"
                )
                self.assertEqual(status, 405)
                self.assertEqual(payload["error"]["code"], "method_not_allowed")
