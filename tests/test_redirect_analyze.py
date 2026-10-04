import json
import threading
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

from redforge.server import Handler
from redforge.service import ScopeViolationError, Service

CANARY = "https://evil.example.com/cb?next=1"


def make_observation(**overrides):
    observation = {
        "id": "obs-1",
        "target": "app.example.com",
        "scheme": "https",
        "request_path": "/login",
        "status": 302,
        "location": CANARY,
        "canary_url": CANARY,
    }
    observation.update(overrides)
    return observation


def analyze_payload(**overrides):
    payload = {
        "allow": ["*.example.com", "10.0.0.0/8", "2001:db8::/32"],
        "deny": [],
        "observations": [make_observation()],
    }
    payload.update(overrides)
    return payload


class RedirectAnalyzeServiceTest(unittest.TestCase):
    def setUp(self):
        self.service = Service()

    def analyze(self, **overrides):
        return self.service.analyze_redirects(analyze_payload(**overrides))[
            "findings"
        ]

    def test_empty_observations(self):
        self.assertEqual(self.analyze(observations=[]), [])

    def test_absolute_location_hit(self):
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

    def test_all_redirect_statuses_hit(self):
        for status in (301, 302, 303, 307, 308):
            with self.subTest(status=status):
                (finding,) = self.analyze(
                    observations=[make_observation(status=status)]
                )
                self.assertEqual(finding["category"], "open_redirect")

    def test_non_redirect_statuses_do_not_hit(self):
        for status in (200, 300, 304, 400, 500):
            with self.subTest(status=status):
                self.assertEqual(
                    self.analyze(
                        observations=[make_observation(status=status)]
                    ),
                    [],
                )

    def test_null_and_empty_location_do_not_hit(self):
        self.assertEqual(
            self.analyze(observations=[make_observation(location=None)]), []
        )
        self.assertEqual(
            self.analyze(observations=[make_observation(location="")]), []
        )

    def test_scheme_relative_location_hit(self):
        (finding,) = self.analyze(
            observations=[make_observation(location="//evil.example.com/cb?next=1")]
        )
        self.assertEqual(finding["destination"], CANARY)

    def test_scheme_relative_uses_request_scheme(self):
        # //host inherits the request scheme; an https canary does not match
        # an http resolution.
        self.assertEqual(
            self.analyze(
                observations=[
                    make_observation(
                        scheme="http", location="//evil.example.com/cb?next=1"
                    )
                ]
            ),
            [],
        )
        (finding,) = self.analyze(
            observations=[
                make_observation(
                    scheme="http",
                    location="//evil.example.com/cb?next=1",
                    canary_url="http://evil.example.com/cb?next=1",
                )
            ]
        )
        self.assertEqual(finding["destination"], "http://evil.example.com/cb?next=1")

    def test_scheme_and_host_are_case_insensitive(self):
        (finding,) = self.analyze(
            observations=[
                make_observation(location="HTTPS://EVIL.Example.COM./cb?next=1")
            ]
        )
        self.assertEqual(finding["destination"], CANARY)

    def test_default_ports_are_equivalent(self):
        (finding,) = self.analyze(
            observations=[
                make_observation(location="https://evil.example.com:443/cb?next=1")
            ]
        )
        self.assertEqual(finding["destination"], CANARY)
        (finding2,) = self.analyze(
            observations=[
                make_observation(
                    scheme="http",
                    location="http://evil.example.com:80/cb?next=1",
                    canary_url="http://evil.example.com/cb?next=1",
                )
            ]
        )
        self.assertEqual(finding2["destination"], "http://evil.example.com/cb?next=1")

    def test_non_default_port_must_match_and_is_kept(self):
        self.assertEqual(
            self.analyze(
                observations=[
                    make_observation(location="https://evil.example.com:8443/cb?next=1")
                ]
            ),
            [],
        )
        (finding,) = self.analyze(
            observations=[
                make_observation(
                    location="https://evil.example.com:8443/cb?next=1",
                    canary_url="https://evil.example.com:8443/cb?next=1",
                )
            ]
        )
        self.assertEqual(
            finding["destination"], "https://evil.example.com:8443/cb?next=1"
        )

    def test_path_and_query_are_case_sensitive(self):
        self.assertEqual(
            self.analyze(
                observations=[
                    make_observation(location="https://evil.example.com/CB?next=1")
                ]
            ),
            [],
        )
        self.assertEqual(
            self.analyze(
                observations=[
                    make_observation(location="https://evil.example.com/cb?NEXT=1")
                ]
            ),
            [],
        )

    def test_empty_path_normalizes_to_slash(self):
        (finding,) = self.analyze(
            observations=[
                make_observation(
                    location="https://evil.example.com",
                    canary_url="https://evil.example.com/",
                )
            ]
        )
        self.assertEqual(finding["destination"], "https://evil.example.com/")

    def test_fragment_in_location_is_not_part_of_destination(self):
        (finding,) = self.analyze(
            observations=[make_observation(location=CANARY + "#section")]
        )
        self.assertEqual(finding["destination"], CANARY)

    def test_same_origin_destination_does_not_hit(self):
        # Absolute URL back to the request origin.
        self.assertEqual(
            self.analyze(
                observations=[
                    make_observation(
                        location="https://app.example.com/cb?next=1",
                        canary_url="https://app.example.com/cb?next=1",
                    )
                ]
            ),
            [],
        )
        # Relative location resolving onto the request origin.
        self.assertEqual(
            self.analyze(
                observations=[
                    make_observation(
                        location="/cb?next=1",
                        canary_url="https://app.example.com/cb?next=1",
                    )
                ]
            ),
            [],
        )
        # Default-port equivalence also applies to the origin comparison.
        self.assertEqual(
            self.analyze(
                observations=[
                    make_observation(
                        location="https://app.example.com:443/cb?next=1",
                        canary_url="https://app.example.com/cb?next=1",
                    )
                ]
            ),
            [],
        )

    def test_scheme_change_is_cross_origin(self):
        (finding,) = self.analyze(
            observations=[
                make_observation(
                    scheme="http",
                    location="https://app.example.com/cb?next=1",
                    canary_url="https://app.example.com/cb?next=1",
                )
            ]
        )
        self.assertEqual(finding["destination"], "https://app.example.com/cb?next=1")

    def test_relative_location_never_leaves_origin(self):
        # A relative reference that merely looks like a host stays relative.
        self.assertEqual(
            self.analyze(
                observations=[
                    make_observation(
                        request_path="/a/b",
                        location="evil.example.com/cb?next=1",
                    )
                ]
            ),
            [],
        )

    def test_malformed_percent_escape_does_not_hit_but_passes(self):
        for location in (
            "https://evil.example.com/cb%zz",
            "https://evil.example.com/cb%1",
            "https://evil.example.com/cb%",
        ):
            with self.subTest(location=location):
                self.assertEqual(
                    self.analyze(
                        observations=[make_observation(location=location)]
                    ),
                    [],
                )

    def test_non_http_location_scheme_does_not_hit(self):
        for location in (
            "javascript:alert(1)",
            "ftp://evil.example.com/cb?next=1",
            "data:text/html,<p>x</p>",
        ):
            with self.subTest(location=location):
                self.assertEqual(
                    self.analyze(
                        observations=[make_observation(location=location)]
                    ),
                    [],
                )

    def test_unresolvable_location_does_not_hit_but_passes(self):
        for location in (
            "http://[::1",
            "https://evil.example.com:99999/cb",
            "https://evil.example.com:abc/cb",
            "https://exa mple.com/cb",
            "https://user@evil.example.com/cb?next=1",
        ):
            with self.subTest(location=location):
                self.assertEqual(
                    self.analyze(
                        observations=[make_observation(location=location)]
                    ),
                    [],
                )

    def test_ip_target(self):
        (finding,) = self.analyze(
            observations=[
                make_observation(
                    target="10.0.0.9",
                    scheme="http",
                    location="//evil.example.com/cb?next=1",
                    canary_url="http://evil.example.com/cb?next=1",
                )
            ]
        )
        self.assertEqual(finding["target"], "10.0.0.9")
        # Same IP and scheme is the same origin: no finding.
        self.assertEqual(
            self.analyze(
                observations=[
                    make_observation(
                        target="10.0.0.9",
                        scheme="http",
                        location="http://10.0.0.9/cb?next=1",
                        canary_url="http://10.0.0.9/cb?next=1",
                    )
                ]
            ),
            [],
        )

    def test_ipv6_target_and_destination(self):
        (finding,) = self.analyze(
            observations=[
                make_observation(
                    target="2001:db8::1",
                    scheme="http",
                    location="//[2001:DB8::99]/cb?next=1",
                    canary_url="http://[2001:db8::99]/cb?next=1",
                )
            ]
        )
        self.assertEqual(finding["target"], "2001:db8::1")
        self.assertEqual(
            finding["destination"], "http://[2001:db8::99]/cb?next=1"
        )
        # Same IPv6 origin: no finding.
        self.assertEqual(
            self.analyze(
                observations=[
                    make_observation(
                        target="2001:db8::1",
                        scheme="http",
                        location="//[2001:db8::1]/cb?next=1",
                        canary_url="http://[2001:db8::1]/cb?next=1",
                    )
                ]
            ),
            [],
        )

    def test_findings_follow_observation_order(self):
        observations = [
            make_observation(id="a", location="/local"),
            make_observation(id="b"),
            make_observation(id="c", status=200),
            make_observation(id="d", location="//evil.example.com/cb?next=1"),
        ]
        findings = self.analyze(observations=observations)
        self.assertEqual([f["observation_id"] for f in findings], ["b", "d"])

    def test_normalized_target(self):
        (finding,) = self.analyze(
            observations=[make_observation(target="APP.Example.COM.")]
        )
        self.assertEqual(finding["target"], "app.example.com")

    def test_results_are_stable(self):
        payload = analyze_payload(
            observations=[make_observation(id="a"), make_observation(id="b")]
        )
        self.assertEqual(
            self.service.analyze_redirects(payload),
            self.service.analyze_redirects(payload),
        )

    # --- scope / validation --------------------------------------------

    def test_scope_violation_raises_after_structure_ok(self):
        with self.assertRaises(ScopeViolationError):
            self.analyze(observations=[make_observation(target="evil.net")])
        with self.assertRaises(ScopeViolationError):
            self.analyze(deny=["app.example.com"])
        with self.assertRaises(ScopeViolationError):
            self.analyze(allow=["10.0.0.0/8"])

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

    def test_validation_errors(self):
        bad_observations = [
            [],
            {"id": "a"},
            make_observation(extra=1),
            make_observation(id=""),
            make_observation(id=1),
            make_observation(target=""),
            make_observation(target="*.example.com"),
            make_observation(target="bad_host"),
            make_observation(scheme="ftp"),
            make_observation(scheme="HTTPS"),
            make_observation(scheme=1),
            make_observation(request_path=""),
            make_observation(request_path="login"),
            make_observation(request_path=1),
            make_observation(request_path="/login#frag"),
            make_observation(status=True),
            make_observation(status=99),
            make_observation(status=600),
            make_observation(status="302"),
            make_observation(location=1),
            make_observation(canary_url=""),
            make_observation(canary_url=1),
            make_observation(canary_url=None),
            make_observation(canary_url="evil.example.com/cb"),
            make_observation(canary_url="/cb?next=1"),
            make_observation(canary_url="ftp://evil.example.com/cb"),
            make_observation(canary_url="https://user@evil.example.com/cb"),
            make_observation(canary_url="https://evil.example.com/cb#frag"),
            make_observation(canary_url="https://evil example.com/cb"),
            make_observation(canary_url="http://[::1"),
            make_observation(canary_url="https://evil.example.com:99999/cb"),
        ]
        bad_payloads = [
            None,
            [],
            {},
            {"allow": [], "deny": []},
            analyze_payload(extra=1),
            analyze_payload(allow="*.example.com"),
            analyze_payload(deny=["bad_host"]),
            analyze_payload(allow=["10.0.0.0/33"]),
            analyze_payload(observations={}),
            analyze_payload(observations="nope"),
            analyze_payload(
                observations=[make_observation(id="dup"), make_observation(id="dup")]
            ),
        ] + [analyze_payload(observations=[obs]) for obs in bad_observations]
        for payload in bad_payloads:
            with self.subTest(payload=repr(payload)[:80]):
                with self.assertRaises(ValueError):
                    self.service.analyze_redirects(payload)


class RedirectAnalyzeHttpTest(unittest.TestCase):
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

    def test_analyze_ok(self):
        status, payload = self.post_analyze(analyze_payload())
        self.assertEqual(status, 200)
        self.assertEqual(list(payload), ["findings"])
        (finding,) = payload["findings"]
        self.assertEqual(finding["category"], "open_redirect")
        self.assertEqual(finding["severity"], "high")
        self.assertEqual(finding["destination"], CANARY)

    def test_empty_observations_ok(self):
        status, payload = self.post_analyze(analyze_payload(observations=[]))
        self.assertEqual(status, 200)
        self.assertEqual(payload, {"findings": []})

    def test_no_findings_ok(self):
        status, payload = self.post_analyze(
            analyze_payload(observations=[make_observation(status=200)])
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

    def test_bad_canary_400(self):
        status, payload = self.post_analyze(
            analyze_payload(
                observations=[
                    make_observation(canary_url="https://user@evil.example.com/")
                ]
            )
        )
        self.assertEqual(status, 400)
        self.assertEqual(payload["error"]["code"], "invalid_request")

    def test_malformed_json_400(self):
        status, payload = self.request(
            "POST", "/v1/web/redirect-analyze", b"{nope"
        )
        self.assertEqual(status, 400)
        self.assertEqual(payload["error"]["code"], "invalid_request")

    def test_method_not_allowed_405(self):
        for method in ("GET", "PUT", "DELETE", "PATCH"):
            with self.subTest(method=method):
                status, payload = self.request(method, "/v1/web/redirect-analyze")
                self.assertEqual(status, 405)
                self.assertEqual(payload["error"]["code"], "method_not_allowed")


if __name__ == "__main__":
    unittest.main()
