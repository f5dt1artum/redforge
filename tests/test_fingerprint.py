import json
import threading
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

from redforge.server import Handler
from redforge.service import ScopeViolationError, Service


def make_fingerprint(**overrides):
    fingerprint = {
        "id": "fp-1",
        "name": "Demo service",
        "service": "demo",
        "priority": 10,
        "logic": "all",
        "matchers": [{"ports": [80]}],
    }
    fingerprint.update(overrides)
    return fingerprint


def make_port_observation(**overrides):
    observation = {
        "id": "po-1",
        "target": "app.example.com",
        "port": 80,
        "transport": "tcp",
        "banner": "hello world",
    }
    observation.update(overrides)
    return observation


def fingerprint_payload(**overrides):
    payload = {
        "allow": ["*.example.com"],
        "deny": [],
        "fingerprints": [make_fingerprint()],
        "observations": [make_port_observation()],
    }
    payload.update(overrides)
    return payload


class FingerprintServiceTest(unittest.TestCase):
    def setUp(self):
        self.service = Service()

    def assets(self, **overrides):
        return self.service.fingerprint_assets(fingerprint_payload(**overrides))[
            "assets"
        ]

    def test_ports_matcher_hit(self):
        assets = self.assets()
        self.assertEqual(len(assets), 1)
        asset = assets[0]
        self.assertEqual(asset["target"], "app.example.com")
        (service,) = asset["services"]
        self.assertEqual(service["observation_id"], "po-1")
        self.assertEqual(service["port"], 80)
        self.assertEqual(service["transport"], "tcp")
        self.assertEqual(service["service"], "demo")
        self.assertEqual(service["fingerprint_id"], "fp-1")
        self.assertEqual(service["name"], "Demo service")
        self.assertEqual(service["evidence"], [0])

    def test_target_normalized_in_asset(self):
        assets = self.assets(
            observations=[make_port_observation(target="APP.Example.COM.")]
        )
        self.assertEqual(assets[0]["target"], "app.example.com")

    def test_unknown_service_shape(self):
        assets = self.assets(
            fingerprints=[make_fingerprint(matchers=[{"ports": [81]}])]
        )
        (service,) = assets[0]["services"]
        self.assertEqual(service["service"], "unknown")
        self.assertIsNone(service["fingerprint_id"])
        self.assertIsNone(service["name"])
        self.assertEqual(service["evidence"], [])
        self.assertEqual(service["port"], 80)

    def test_transport_matcher(self):
        tcp_hit = make_fingerprint(
            id="tcp", matchers=[{"transport": "tcp"}]
        )
        udp_hit = make_fingerprint(
            id="udp", service="udp-demo", matchers=[{"transport": "udp"}]
        )
        assets = self.assets(fingerprints=[tcp_hit, udp_hit])
        self.assertEqual(assets[0]["services"][0]["fingerprint_id"], "tcp")

    def test_banner_operators(self):
        equals = make_fingerprint(
            matchers=[{"operator": "equals", "value": "hello world"}]
        )
        contains = make_fingerprint(
            id="fp-c",
            service="contains",
            matchers=[{"operator": "contains", "value": "world"}],
        )
        regex = make_fingerprint(
            id="fp-r",
            service="regex",
            matchers=[{"operator": "regex", "value": r"h.llo\s+w\w+"}],
        )
        assets = self.assets(fingerprints=[equals, contains, regex])
        services = assets[0]["services"]
        self.assertEqual(len(services), 1)
        self.assertEqual(services[0]["service"], "demo")

    def test_banner_comparison_is_case_sensitive(self):
        for operator, value in (
            ("equals", "Hello World"),
            ("contains", "WORLD"),
        ):
            with self.subTest(operator=operator):
                assets = self.assets(
                    fingerprints=[
                        make_fingerprint(
                            matchers=[{"operator": operator, "value": value}]
                        )
                    ]
                )
                self.assertEqual(
                    assets[0]["services"][0]["service"], "unknown"
                )

    def test_regex_search_semantics(self):
        hit = make_fingerprint(
            matchers=[{"operator": "regex", "value": r"world"}]
        )
        miss = make_fingerprint(
            id="miss",
            service="nope",
            matchers=[{"operator": "regex", "value": r"^world"}],
        )
        services = self.assets(fingerprints=[hit, miss])[0]["services"]
        self.assertEqual(services[0]["fingerprint_id"], "fp-1")

    def test_all_logic_requires_every_matcher(self):
        fingerprint = make_fingerprint(
            logic="all",
            matchers=[{"ports": [80]}, {"transport": "udp"}],
        )
        self.assertEqual(
            self.assets(fingerprints=[fingerprint])[0]["services"][0]["service"],
            "unknown",
        )

    def test_any_logic_evidence_indices_ascending(self):
        fingerprint = make_fingerprint(
            logic="any",
            matchers=[
                {"ports": [81]},
                {"transport": "tcp"},
                {"operator": "contains", "value": "world"},
            ],
        )
        service = self.assets(fingerprints=[fingerprint])[0]["services"][0]
        self.assertEqual(service["evidence"], [1, 2])

    def test_priority_picks_max(self):
        low = make_fingerprint(
            id="low", service="low-svc", priority=1, matchers=[{"ports": [80]}]
        )
        high = make_fingerprint(
            id="high", service="high-svc", priority=100, matchers=[{"ports": [80]}]
        )
        service = self.assets(fingerprints=[low, high])[0]["services"][0]
        self.assertEqual(service["fingerprint_id"], "high")
        self.assertEqual(service["service"], "high-svc")

    def test_priority_tie_keeps_input_order(self):
        first = make_fingerprint(
            id="first", service="first-svc", priority=5, matchers=[{"ports": [80]}]
        )
        second = make_fingerprint(
            id="second", service="second-svc", priority=5, matchers=[{"ports": [80]}]
        )
        service = self.assets(fingerprints=[first, second])[0]["services"][0]
        self.assertEqual(service["fingerprint_id"], "first")
        service_rev = self.assets(fingerprints=[second, first])[0]["services"][0]
        self.assertEqual(service_rev["fingerprint_id"], "second")

    def test_grouping_by_first_occurrence_and_service_order(self):
        observations = [
            make_port_observation(id="a", target="a.example.com", port=80),
            make_port_observation(
                id="b", target="b.example.com", port=22, banner="ssh"
            ),
            make_port_observation(
                id="a2", target="a.example.com", port=443
            ),
        ]
        assets = self.assets(observations=observations)
        self.assertEqual([asset["target"] for asset in assets], [
            "a.example.com",
            "b.example.com",
        ])
        self.assertEqual(
            [s["observation_id"] for s in assets[0]["services"]],
            ["a", "a2"],
        )
        self.assertEqual(
            [s["port"] for s in assets[0]["services"]],
            [80, 443],
        )

    def test_empty_observations_returns_empty_assets(self):
        self.assertEqual(self.assets(observations=[]), [])

    def test_empty_fingerprints_marks_unknown(self):
        assets = self.assets(fingerprints=[])
        self.assertEqual(assets[0]["services"][0]["service"], "unknown")

    def test_udp_observation(self):
        fingerprint = make_fingerprint(matchers=[{"transport": "udp"}])
        assets = self.assets(
            fingerprints=[fingerprint],
            observations=[make_port_observation(transport="udp", port=53)],
        )
        service = assets[0]["services"][0]
        self.assertEqual(service["fingerprint_id"], "fp-1")
        self.assertEqual(service["transport"], "udp")
        self.assertEqual(service["port"], 53)

    def test_evidence_tied_to_chosen_fingerprint(self):
        # Lower priority matches all three matchers; chosen high-priority
        # fingerprint only hits matcher index 2.
        low = make_fingerprint(
            id="low",
            service="low-svc",
            priority=1,
            matchers=[{"ports": [80]}, {"transport": "tcp"}],
        )
        high = make_fingerprint(
            id="high",
            service="high-svc",
            priority=9,
            matchers=[{"operator": "contains", "value": "world"}],
        )
        service = self.assets(fingerprints=[low, high])[0]["services"][0]
        self.assertEqual(service["fingerprint_id"], "high")
        self.assertEqual(service["evidence"], [0])

    def test_scope_violation_raises(self):
        with self.assertRaises(ScopeViolationError):
            self.assets(
                observations=[make_port_observation(target="evil.net")]
            )
        with self.assertRaises(ScopeViolationError):
            self.assets(deny=["app.example.com"])

    def test_empty_allow_denies_everything(self):
        with self.assertRaises(ScopeViolationError):
            self.assets(allow=[])

    def test_structure_errors_before_scope_gate(self):
        # Out-of-scope target but also malformed fingerprint: 400 wins.
        bad_payloads = [
            None,
            [],
            {},
            {"allow": [], "deny": [], "fingerprints": []},
            fingerprint_payload(extra=1),
            fingerprint_payload(allow="*.example.com"),
            fingerprint_payload(fingerprints="x"),
            fingerprint_payload(observations="x"),
            # fingerprints
            fingerprint_payload(fingerprints=[{"id": "f"}]),
            fingerprint_payload(fingerprints=[make_fingerprint(extra=1)]),
            fingerprint_payload(fingerprints=[make_fingerprint(id="")]),
            fingerprint_payload(fingerprints=[make_fingerprint(id=1)]),
            fingerprint_payload(fingerprints=[make_fingerprint(name="")]),
            fingerprint_payload(fingerprints=[make_fingerprint(name=3)]),
            fingerprint_payload(fingerprints=[make_fingerprint(service="")]),
            fingerprint_payload(fingerprints=[make_fingerprint(service=3)]),
            fingerprint_payload(fingerprints=[make_fingerprint(priority="1")]),
            fingerprint_payload(fingerprints=[make_fingerprint(priority=True)]),
            fingerprint_payload(fingerprints=[make_fingerprint(logic="some")]),
            fingerprint_payload(fingerprints=[make_fingerprint(matchers=[])]),
            fingerprint_payload(fingerprints=[make_fingerprint(matchers="x")]),
            fingerprint_payload(fingerprints=[make_fingerprint(), make_fingerprint()]),
            # matchers
            fingerprint_payload(fingerprints=[make_fingerprint(matchers=[{}])]),
            fingerprint_payload(
                fingerprints=[make_fingerprint(matchers=[{"ports": []}])]
            ),
            fingerprint_payload(
                fingerprints=[make_fingerprint(matchers=[{"ports": "80"}])]
            ),
            fingerprint_payload(
                fingerprints=[make_fingerprint(matchers=[{"ports": ["80"]}])]
            ),
            fingerprint_payload(
                fingerprints=[make_fingerprint(matchers=[{"ports": [0]}])]
            ),
            fingerprint_payload(
                fingerprints=[make_fingerprint(matchers=[{"ports": [65536]}])]
            ),
            fingerprint_payload(
                fingerprints=[make_fingerprint(matchers=[{"ports": [True]}])]
            ),
            fingerprint_payload(
                fingerprints=[make_fingerprint(matchers=[{"ports": [80, 80]}])]
            ),
            fingerprint_payload(
                fingerprints=[make_fingerprint(matchers=[{"transport": "icmp"}])]
            ),
            fingerprint_payload(
                fingerprints=[
                    make_fingerprint(
                        matchers=[{"ports": [80], "transport": "tcp"}]
                    )
                ]
            ),
            fingerprint_payload(
                fingerprints=[
                    make_fingerprint(
                        matchers=[{"operator": "starts", "value": "a"}]
                    )
                ]
            ),
            fingerprint_payload(
                fingerprints=[
                    make_fingerprint(
                        matchers=[{"operator": "equals", "value": ""}]
                    )
                ]
            ),
            fingerprint_payload(
                fingerprints=[
                    make_fingerprint(
                        matchers=[{"operator": "equals", "value": 1}]
                    )
                ]
            ),
            fingerprint_payload(
                fingerprints=[
                    make_fingerprint(matchers=[{"operator": "contains"}])
                ]
            ),
            fingerprint_payload(
                fingerprints=[
                    make_fingerprint(
                        matchers=[{"operator": "regex", "value": "("}]
                    )
                ]
            ),
            # observations
            fingerprint_payload(observations=[{"id": "o"}]),
            fingerprint_payload(observations=[make_port_observation(extra=1)]),
            fingerprint_payload(observations=[make_port_observation(id="")]),
            fingerprint_payload(
                observations=[make_port_observation(id=1)]
            ),
            fingerprint_payload(
                observations=[make_port_observation(target="*.example.com")]
            ),
            fingerprint_payload(
                observations=[make_port_observation(target="bad_host")]
            ),
            fingerprint_payload(observations=[make_port_observation(port=0)]),
            fingerprint_payload(
                observations=[make_port_observation(port=65536)]
            ),
            fingerprint_payload(
                observations=[make_port_observation(port="80")]
            ),
            fingerprint_payload(
                observations=[make_port_observation(port=True)]
            ),
            fingerprint_payload(
                observations=[make_port_observation(transport="icmp")]
            ),
            fingerprint_payload(
                observations=[make_port_observation(transport=None)]
            ),
            fingerprint_payload(
                observations=[make_port_observation(banner=None)]
            ),
            fingerprint_payload(
                observations=[
                    make_port_observation(),
                    make_port_observation(),
                ]
            ),
            # Same endpoint, different observation id: still a duplicate.
            fingerprint_payload(
                observations=[
                    make_port_observation(id="x"),
                    make_port_observation(id="y", banner="different"),
                ]
            ),
            # Duplicate endpoint after target normalization.
            fingerprint_payload(
                observations=[
                    make_port_observation(target="APP.Example.COM"),
                    make_port_observation(target="app.example.com."),
                ]
            ),
            # Malformed fingerprint plus an out-of-scope observation: 400.
            {
                "allow": ["*.example.com"],
                "deny": [],
                "fingerprints": [make_fingerprint(matchers=[{"ports": [0]}])],
                "observations": [
                    make_port_observation(target="evil.net")
                ],
            },
        ]
        for payload in bad_payloads:
            with self.subTest(payload=repr(payload)[:100]):
                with self.assertRaises(ValueError):
                    self.service.fingerprint_assets(payload)

    def test_same_endpoint_on_different_transport_is_distinct(self):
        observations = [
            make_port_observation(id="t", transport="tcp", port=53),
            make_port_observation(id="u", transport="udp", port=53),
        ]
        assets = self.assets(observations=observations)
        self.assertEqual(len(assets[0]["services"]), 2)

    def test_same_endpoint_on_different_target_is_distinct(self):
        observations = [
            make_port_observation(id="a", target="a.example.com"),
            make_port_observation(id="b", target="b.example.com"),
        ]
        assets = self.assets(observations=observations)
        self.assertEqual(len(assets), 2)


class FingerprintHttpTest(unittest.TestCase):
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

    def post_fingerprint(self, payload):
        return self.request(
            "POST",
            "/v1/assets/fingerprint",
            json.dumps(payload).encode(),
        )

    def test_fingerprint_ok(self):
        status, payload = self.post_fingerprint(
            fingerprint_payload(
                fingerprints=[
                    make_fingerprint(
                        id="web",
                        service="http",
                        priority=5,
                        logic="any",
                        matchers=[
                            {"ports": [80, 8080]},
                            {"transport": "udp"},
                            {"operator": "contains", "value": "world"},
                        ],
                    )
                ]
            )
        )
        self.assertEqual(status, 200)
        self.assertEqual(list(payload), ["assets"])
        (asset,) = payload["assets"]
        self.assertEqual(asset["target"], "app.example.com")
        (service,) = asset["services"]
        self.assertEqual(service["observation_id"], "po-1")
        self.assertEqual(service["port"], 80)
        self.assertEqual(service["transport"], "tcp")
        self.assertEqual(service["service"], "http")
        self.assertEqual(service["fingerprint_id"], "web")
        self.assertEqual(service["name"], "Demo service")
        self.assertEqual(service["evidence"], [0, 2])

    def test_empty_observations_ok(self):
        status, payload = self.post_fingerprint(
            fingerprint_payload(observations=[])
        )
        self.assertEqual(status, 200)
        self.assertEqual(payload, {"assets": []})

    def test_scope_violation_403(self):
        status, payload = self.post_fingerprint(
            fingerprint_payload(
                observations=[make_port_observation(target="evil.net")]
            )
        )
        self.assertEqual(status, 403)
        self.assertEqual(payload["error"]["code"], "scope_violation")
        self.assertNotIn("assets", payload)

    def test_invalid_request_400(self):
        status, payload = self.post_fingerprint({"allow": [], "deny": []})
        self.assertEqual(status, 400)
        self.assertEqual(payload["error"]["code"], "invalid_request")

    def test_duplicate_endpoint_400(self):
        status, payload = self.post_fingerprint(
            fingerprint_payload(
                observations=[
                    make_port_observation(id="x"),
                    make_port_observation(id="y", banner="other"),
                ]
            )
        )
        self.assertEqual(status, 400)
        self.assertEqual(payload["error"]["code"], "invalid_request")

    def test_bad_regex_400(self):
        status, payload = self.post_fingerprint(
            fingerprint_payload(
                fingerprints=[
                    make_fingerprint(
                        matchers=[{"operator": "regex", "value": "("}]
                    )
                ]
            )
        )
        self.assertEqual(status, 400)
        self.assertEqual(payload["error"]["code"], "invalid_request")

    def test_malformed_json_400(self):
        status, payload = self.request(
            "POST", "/v1/assets/fingerprint", b"{nope"
        )
        self.assertEqual(status, 400)
        self.assertEqual(payload["error"]["code"], "invalid_request")

    def test_method_not_allowed_405(self):
        for method in ("GET", "PUT", "DELETE"):
            with self.subTest(method=method):
                status, payload = self.request(
                    method, "/v1/assets/fingerprint"
                )
                self.assertEqual(status, 405)
                self.assertEqual(payload["error"]["code"], "method_not_allowed")

    def test_unknown_route_404(self):
        status, payload = self.post_fingerprint(
            fingerprint_payload()
        )
        self.assertEqual(status, 200)
        # Sanity: an unrelated unknown path still 404s.
        not_found = self.request(
            "POST", "/v1/assets/unknown", b"{}"
        )
        self.assertEqual(not_found[0], 404)


if __name__ == "__main__":
    unittest.main()
