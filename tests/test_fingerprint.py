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
        "id": "fp-ssh",
        "name": "OpenSSH",
        "service": "ssh",
        "priority": 10,
        "logic": "all",
        "matchers": [
            {"ports": [22]},
            {"operator": "contains", "value": "OpenSSH"},
        ],
    }
    fingerprint.update(overrides)
    return fingerprint


def make_observation(**overrides):
    observation = {
        "id": "obs-1",
        "target": "app.example.com",
        "port": 22,
        "transport": "tcp",
        "banner": "SSH-2.0-OpenSSH_8.9p1",
    }
    observation.update(overrides)
    return observation


def fingerprint_payload(**overrides):
    payload = {
        "allow": ["*.example.com"],
        "deny": [],
        "fingerprints": [make_fingerprint()],
        "observations": [make_observation()],
    }
    payload.update(overrides)
    return payload


class FingerprintServiceTest(unittest.TestCase):
    def setUp(self):
        self.service = Service()

    def fingerprint(self, **overrides):
        return self.service.fingerprint_assets(fingerprint_payload(**overrides))[
            "assets"
        ]

    def test_basic_hit(self):
        assets = self.fingerprint()
        self.assertEqual(len(assets), 1)
        asset = assets[0]
        self.assertEqual(asset["target"], "app.example.com")
        self.assertEqual(len(asset["services"]), 1)
        service = asset["services"][0]
        self.assertEqual(service["observation_id"], "obs-1")
        self.assertEqual(service["port"], 22)
        self.assertEqual(service["transport"], "tcp")
        self.assertEqual(service["service"], "ssh")
        self.assertEqual(service["fingerprint_id"], "fp-ssh")
        self.assertEqual(service["name"], "OpenSSH")
        self.assertEqual(service["evidence"], [0, 1])

    def test_target_normalized(self):
        assets = self.fingerprint(
            observations=[make_observation(target="APP.Example.COM.")]
        )
        self.assertEqual(assets[0]["target"], "app.example.com")

    def test_no_match_reports_unknown(self):
        assets = self.fingerprint(
            observations=[make_observation(port=80, banner="nginx")]
        )
        service = assets[0]["services"][0]
        self.assertEqual(service["service"], "unknown")
        self.assertIsNone(service["fingerprint_id"])
        self.assertIsNone(service["name"])
        self.assertEqual(service["evidence"], [])

    def test_empty_observations_returns_empty_assets(self):
        self.assertEqual(self.fingerprint(observations=[]), [])

    def test_empty_fingerprints_all_unknown(self):
        assets = self.fingerprint(fingerprints=[])
        service = assets[0]["services"][0]
        self.assertEqual(service["service"], "unknown")
        self.assertIsNone(service["fingerprint_id"])

    def test_all_logic_requires_every_matcher(self):
        fingerprint = make_fingerprint(
            logic="all",
            matchers=[{"ports": [22]}, {"operator": "contains", "value": "nope"}],
        )
        assets = self.fingerprint(fingerprints=[fingerprint])
        self.assertEqual(assets[0]["services"][0]["service"], "unknown")

    def test_any_logic_reports_only_hit_indices(self):
        fingerprint = make_fingerprint(
            logic="any",
            matchers=[
                {"ports": [80]},
                {"transport": "tcp"},
                {"operator": "contains", "value": "OpenSSH"},
            ],
        )
        assets = self.fingerprint(fingerprints=[fingerprint])
        service = assets[0]["services"][0]
        self.assertEqual(service["service"], "ssh")
        self.assertEqual(service["evidence"], [1, 2])

    def test_transport_matcher(self):
        fingerprint = make_fingerprint(matchers=[{"transport": "udp"}])
        hit = self.fingerprint(
            fingerprints=[fingerprint],
            observations=[make_observation(transport="udp")],
        )
        self.assertEqual(hit[0]["services"][0]["service"], "ssh")
        miss = self.fingerprint(fingerprints=[fingerprint])
        self.assertEqual(miss[0]["services"][0]["service"], "unknown")

    def test_ports_matcher(self):
        fingerprint = make_fingerprint(matchers=[{"ports": [22, 2222]}])
        self.assertEqual(
            self.fingerprint(fingerprints=[fingerprint])[0]["services"][0]["service"],
            "ssh",
        )
        miss = self.fingerprint(
            fingerprints=[fingerprint],
            observations=[make_observation(port=2221)],
        )
        self.assertEqual(miss[0]["services"][0]["service"], "unknown")

    def test_banner_operators_case_sensitive(self):
        equals = make_fingerprint(
            matchers=[{"operator": "equals", "value": "ssh-2.0-openssh_8.9p1"}]
        )
        contains = make_fingerprint(
            matchers=[{"operator": "contains", "value": "openssh"}]
        )
        self.assertEqual(
            self.fingerprint(fingerprints=[equals])[0]["services"][0]["service"],
            "unknown",
        )
        self.assertEqual(
            self.fingerprint(fingerprints=[contains])[0]["services"][0]["service"],
            "unknown",
        )

    def test_regex_search_semantics(self):
        hit = make_fingerprint(
            matchers=[{"operator": "regex", "value": r"OpenSSH_\d+\.\d+"}]
        )
        miss = make_fingerprint(
            matchers=[{"operator": "regex", "value": r"^OpenSSH"}]
        )
        self.assertEqual(
            self.fingerprint(fingerprints=[hit])[0]["services"][0]["service"], "ssh"
        )
        self.assertEqual(
            self.fingerprint(fingerprints=[miss])[0]["services"][0]["service"],
            "unknown",
        )

    def test_highest_priority_wins(self):
        low = make_fingerprint(id="fp-low", priority=1, service="ssh-low")
        high = make_fingerprint(id="fp-high", priority=99, service="ssh-high")
        assets = self.fingerprint(fingerprints=[low, high])
        service = assets[0]["services"][0]
        self.assertEqual(service["fingerprint_id"], "fp-high")
        self.assertEqual(service["service"], "ssh-high")

    def test_priority_tie_prefers_earlier_input(self):
        first = make_fingerprint(id="fp-a", priority=10, service="ssh-a")
        second = make_fingerprint(id="fp-b", priority=10, service="ssh-b")
        assets = self.fingerprint(fingerprints=[first, second])
        self.assertEqual(assets[0]["services"][0]["fingerprint_id"], "fp-a")

    def test_negative_priority_accepted(self):
        fingerprint = make_fingerprint(priority=-5)
        assets = self.fingerprint(fingerprints=[fingerprint])
        self.assertEqual(assets[0]["services"][0]["service"], "ssh")

    def test_grouping_by_target_first_occurrence(self):
        observations = [
            make_observation(id="o-1", target="b.example.com", port=22),
            make_observation(id="o-2", target="a.example.com", port=22),
            make_observation(id="o-3", target="b.example.com", port=23),
        ]
        assets = self.fingerprint(observations=observations)
        self.assertEqual([a["target"] for a in assets], ["b.example.com", "a.example.com"])
        self.assertEqual(
            [s["observation_id"] for s in assets[0]["services"]], ["o-1", "o-3"]
        )
        self.assertEqual(
            [s["observation_id"] for s in assets[1]["services"]], ["o-2"]
        )

    def test_scope_violation_raises(self):
        with self.assertRaises(ScopeViolationError):
            self.fingerprint(observations=[make_observation(target="other.net")])
        with self.assertRaises(ScopeViolationError):
            self.fingerprint(deny=["app.example.com"])

    def test_structure_validated_before_scope(self):
        # A duplicate endpoint is a 400 even when a target is out of scope.
        payload = fingerprint_payload(
            observations=[
                make_observation(id="o-1", target="other.net"),
                make_observation(id="o-2", target="other.net"),
            ]
        )
        with self.assertRaises(ValueError):
            self.service.fingerprint_assets(payload)

    def test_duplicate_endpoint_rejected(self):
        observations = [
            make_observation(id="o-1", target="APP.example.com"),
            make_observation(id="o-2", target="app.EXAMPLE.com."),
        ]
        with self.assertRaises(ValueError):
            self.fingerprint(observations=observations)
        # Same port on a different transport is a different endpoint.
        observations = [
            make_observation(id="o-1"),
            make_observation(id="o-2", transport="udp"),
        ]
        self.assertEqual(len(self.fingerprint(observations=observations)), 1)

    def test_validation_errors(self):
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
            fingerprint_payload(fingerprints=[make_fingerprint(comment="hi")]),
            fingerprint_payload(fingerprints=[make_fingerprint(id="")]),
            fingerprint_payload(fingerprints=[make_fingerprint(id=1)]),
            fingerprint_payload(fingerprints=[make_fingerprint(name="")]),
            fingerprint_payload(fingerprints=[make_fingerprint(name=3)]),
            fingerprint_payload(fingerprints=[make_fingerprint(service="")]),
            fingerprint_payload(fingerprints=[make_fingerprint(service=None)]),
            fingerprint_payload(fingerprints=[make_fingerprint(priority="1")]),
            fingerprint_payload(fingerprints=[make_fingerprint(priority=True)]),
            fingerprint_payload(fingerprints=[make_fingerprint(priority=1.5)]),
            fingerprint_payload(fingerprints=[make_fingerprint(logic="some")]),
            fingerprint_payload(fingerprints=[make_fingerprint(matchers=[])]),
            fingerprint_payload(fingerprints=[make_fingerprint(matchers="x")]),
            fingerprint_payload(
                fingerprints=[make_fingerprint(), make_fingerprint()]
            ),
            # matchers
            fingerprint_payload(fingerprints=[make_fingerprint(matchers=[{}])]),
            fingerprint_payload(
                fingerprints=[make_fingerprint(matchers=[{"ports": []}])]
            ),
            fingerprint_payload(
                fingerprints=[make_fingerprint(matchers=[{"ports": "22"}])]
            ),
            fingerprint_payload(
                fingerprints=[make_fingerprint(matchers=[{"ports": ["22"]}])]
            ),
            fingerprint_payload(
                fingerprints=[make_fingerprint(matchers=[{"ports": [True]}])]
            ),
            fingerprint_payload(
                fingerprints=[make_fingerprint(matchers=[{"ports": [0]}])]
            ),
            fingerprint_payload(
                fingerprints=[make_fingerprint(matchers=[{"ports": [65536]}])]
            ),
            fingerprint_payload(
                fingerprints=[make_fingerprint(matchers=[{"ports": [22, 22]}])]
            ),
            fingerprint_payload(
                fingerprints=[make_fingerprint(matchers=[{"transport": "sctp"}])]
            ),
            fingerprint_payload(
                fingerprints=[make_fingerprint(matchers=[{"transport": 1}])]
            ),
            fingerprint_payload(
                fingerprints=[
                    make_fingerprint(matchers=[{"operator": "starts", "value": "a"}])
                ]
            ),
            fingerprint_payload(
                fingerprints=[
                    make_fingerprint(matchers=[{"operator": "equals", "value": ""}])
                ]
            ),
            fingerprint_payload(
                fingerprints=[
                    make_fingerprint(matchers=[{"operator": "equals", "value": 1}])
                ]
            ),
            fingerprint_payload(
                fingerprints=[
                    make_fingerprint(matchers=[{"operator": "regex", "value": "("}])
                ]
            ),
            fingerprint_payload(
                fingerprints=[
                    make_fingerprint(matchers=[{"ports": [22], "transport": "tcp"}])
                ]
            ),
            # observations
            fingerprint_payload(observations=[{"id": "o"}]),
            fingerprint_payload(observations=[make_observation(extra=1)]),
            fingerprint_payload(observations=[make_observation(id="")]),
            fingerprint_payload(observations=[make_observation(target="*.example.com")]),
            fingerprint_payload(observations=[make_observation(target="bad_host")]),
            fingerprint_payload(observations=[make_observation(port=0)]),
            fingerprint_payload(observations=[make_observation(port=65536)]),
            fingerprint_payload(observations=[make_observation(port="22")]),
            fingerprint_payload(observations=[make_observation(port=True)]),
            fingerprint_payload(observations=[make_observation(transport="sctp")]),
            fingerprint_payload(observations=[make_observation(banner=None)]),
            fingerprint_payload(observations=[make_observation(banner=1)]),
            fingerprint_payload(
                observations=[make_observation(), make_observation()]
            ),
        ]
        for payload in bad_payloads:
            with self.subTest(payload=repr(payload)[:80]):
                with self.assertRaises(ValueError):
                    self.service.fingerprint_assets(payload)


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
        req = urllib.request.Request(url, method=method, data=body, headers=headers or {})
        try:
            with urllib.request.urlopen(req) as resp:
                return resp.status, json.loads(resp.read())
        except urllib.error.HTTPError as exc:
            status, payload = exc.code, json.loads(exc.read())
            exc.close()
            return status, payload

    def post_fingerprint(self, payload):
        return self.request(
            "POST", "/v1/assets/fingerprint", json.dumps(payload).encode()
        )

    def test_fingerprint_ok(self):
        status, payload = self.post_fingerprint(fingerprint_payload())
        self.assertEqual(status, 200)
        self.assertEqual(list(payload), ["assets"])
        (asset,) = payload["assets"]
        self.assertEqual(asset["target"], "app.example.com")
        (service,) = asset["services"]
        self.assertEqual(service["observation_id"], "obs-1")
        self.assertEqual(service["service"], "ssh")
        self.assertEqual(service["fingerprint_id"], "fp-ssh")
        self.assertEqual(service["evidence"], [0, 1])

    def test_scope_violation_403(self):
        status, payload = self.post_fingerprint(
            fingerprint_payload(observations=[make_observation(target="evil.net")])
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
                observations=[make_observation(), make_observation(id="o-2")]
            )
        )
        self.assertEqual(status, 400)
        self.assertEqual(payload["error"]["code"], "invalid_request")

    def test_method_not_allowed_405(self):
        for method in ("GET", "PUT", "DELETE"):
            with self.subTest(method=method):
                status, payload = self.request(method, "/v1/assets/fingerprint")
                self.assertEqual(status, 405)
                self.assertEqual(payload["error"]["code"], "method_not_allowed")


if __name__ == "__main__":
    unittest.main()
