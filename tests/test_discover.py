import json
import threading
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

from redforge.server import Handler
from redforge.service import ScopeViolationError, Service


def make_record(**overrides):
    record = {
        "id": "r-1",
        "name": "app.example.com",
        "type": "A",
        "value": "192.0.2.10",
    }
    record.update(overrides)
    return record


def discover_payload(**overrides):
    payload = {
        "allow": ["*.example.com", "192.0.2.0/24", "2001:db8::/32"],
        "deny": [],
        "seeds": ["app.example.com"],
        "records": [make_record()],
        "max_depth": 2,
    }
    payload.update(overrides)
    return payload


class DiscoverServiceTest(unittest.TestCase):
    def setUp(self):
        self.service = Service()

    def assets(self, **overrides):
        return self.service.discover_assets(discover_payload(**overrides))[
            "assets"
        ]

    def test_seed_only_when_no_records_match(self):
        assets = self.assets(records=[])
        self.assertEqual(
            assets,
            [
                {
                    "target": "app.example.com",
                    "kind": "hostname",
                    "depth": 0,
                    "source": None,
                    "record_id": None,
                }
            ],
        )

    def test_a_record_expands_to_ip(self):
        assets = self.assets()
        self.assertEqual([a["target"] for a in assets], [
            "app.example.com",
            "192.0.2.10",
        ])
        ip_asset = assets[1]
        self.assertEqual(ip_asset["kind"], "ip")
        self.assertEqual(ip_asset["depth"], 1)
        self.assertEqual(ip_asset["source"], "app.example.com")
        self.assertEqual(ip_asset["record_id"], "r-1")

    def test_seed_normalized(self):
        assets = self.assets(seeds=["APP.Example.COM."], records=[])
        self.assertEqual(assets[0]["target"], "app.example.com")

    def test_ip_seed_not_expanded(self):
        assets = self.assets(
            seeds=["192.0.2.10"],
            records=[make_record(name="192.0.2.10")],
        )
        self.assertEqual(len(assets), 1)
        self.assertEqual(assets[0]["kind"], "ip")

    def test_max_depth_zero_returns_only_seeds(self):
        assets = self.assets(max_depth=0)
        self.assertEqual([a["target"] for a in assets], ["app.example.com"])

    def test_max_depth_bounds_expansion(self):
        records = [
            make_record(id="r1", type="CNAME", value="alias.example.com"),
            make_record(
                id="r2",
                name="alias.example.com",
                type="CNAME",
                value="deep.example.com",
            ),
            make_record(
                id="r3", name="deep.example.com", type="A", value="192.0.2.20"
            ),
        ]
        assets = self.assets(records=records, max_depth=1)
        self.assertEqual(
            [a["target"] for a in assets],
            ["app.example.com", "alias.example.com"],
        )
        assets = self.assets(records=records, max_depth=3)
        self.assertEqual(
            [a["target"] for a in assets],
            [
                "app.example.com",
                "alias.example.com",
                "deep.example.com",
                "192.0.2.20",
            ],
        )
        self.assertEqual([a["depth"] for a in assets], [0, 1, 2, 3])

    def test_cname_chain_and_record_name_normalization(self):
        records = [
            make_record(
                id="r1", name="APP.Example.COM.", type="CNAME", value="Alias.Example.com."
            ),
            make_record(
                id="r2", name="alias.example.com", type="AAAA", value="2001:db8::1"
            ),
        ]
        assets = self.assets(records=records)
        self.assertEqual(
            [a["target"] for a in assets],
            ["app.example.com", "alias.example.com", "2001:db8::1"],
        )
        self.assertEqual(assets[1]["record_id"], "r1")
        self.assertEqual(assets[2]["record_id"], "r2")
        self.assertEqual(assets[2]["source"], "alias.example.com")

    def test_records_expanded_in_record_order(self):
        records = [
            make_record(id="r-b", type="A", value="192.0.2.20"),
            make_record(id="r-a", type="A", value="192.0.2.10"),
        ]
        assets = self.assets(records=records)
        self.assertEqual(
            [a["target"] for a in assets],
            ["app.example.com", "192.0.2.20", "192.0.2.10"],
        )

    def test_breadth_first_order_across_seeds(self):
        records = [
            make_record(id="r1", name="a.example.com", type="A", value="192.0.2.1"),
            make_record(id="r2", name="b.example.com", type="A", value="192.0.2.2"),
            make_record(
                id="r3", name="a.example.com", type="CNAME", value="c.example.com"
            ),
        ]
        assets = self.assets(
            seeds=["a.example.com", "b.example.com"], records=records
        )
        self.assertEqual(
            [a["target"] for a in assets],
            [
                "a.example.com",
                "b.example.com",
                "192.0.2.1",
                "c.example.com",
                "192.0.2.2",
            ],
        )

    def test_cycle_not_repeated(self):
        records = [
            make_record(id="r1", type="CNAME", value="loop.example.com"),
            make_record(
                id="r2",
                name="loop.example.com",
                type="CNAME",
                value="app.example.com",
            ),
        ]
        assets = self.assets(records=records, max_depth=32)
        self.assertEqual(
            [a["target"] for a in assets],
            ["app.example.com", "loop.example.com"],
        )

    def test_first_shortest_path_wins(self):
        # target.example.com is reachable directly from the seed (depth 1)
        # and via the alias (depth 2); the direct record wins.
        records = [
            make_record(id="r-alias", type="CNAME", value="alias.example.com"),
            make_record(id="r-direct", type="CNAME", value="target.example.com"),
            make_record(
                id="r-indirect",
                name="alias.example.com",
                type="CNAME",
                value="target.example.com",
            ),
        ]
        assets = self.assets(records=records)
        by_target = {a["target"]: a for a in assets}
        self.assertEqual(by_target["target.example.com"]["depth"], 1)
        self.assertEqual(by_target["target.example.com"]["record_id"], "r-direct")

    def test_equal_length_first_discovered_wins(self):
        records = [
            make_record(id="r-first", type="CNAME", value="shared.example.com"),
            make_record(
                id="r-second",
                name="other.example.com",
                type="CNAME",
                value="shared.example.com",
            ),
        ]
        assets = self.assets(
            seeds=["app.example.com", "other.example.com"], records=records
        )
        by_target = {a["target"]: a for a in assets}
        self.assertEqual(
            by_target["shared.example.com"]["source"], "app.example.com"
        )
        self.assertEqual(by_target["shared.example.com"]["record_id"], "r-first")

    def test_seed_value_collision_dedupes(self):
        # A record pointing at an existing seed adds nothing.
        assets = self.assets(
            seeds=["app.example.com", "192.0.2.10"],
        )
        self.assertEqual(
            [a["target"] for a in assets],
            ["app.example.com", "192.0.2.10"],
        )

    def test_empty_seeds_returns_empty_assets(self):
        self.assertEqual(self.assets(seeds=[]), [])

    def test_empty_seeds_still_validates(self):
        with self.assertRaises(ValueError):
            self.assets(seeds=[], max_depth=True)
        with self.assertRaises(ValueError):
            self.assets(seeds=[], records=[make_record(type="TXT")])

    def test_scope_violation_raises(self):
        with self.assertRaises(ScopeViolationError):
            self.assets(seeds=["evil.net"], records=[])
        with self.assertRaises(ScopeViolationError):
            self.assets(deny=["app.example.com"])
        # Discovered targets are checked too.
        with self.assertRaises(ScopeViolationError):
            self.assets(records=[make_record(value="10.0.0.1")])

    def test_unreached_record_values_not_scope_checked(self):
        # 10.0.0.9 is outside the allow rules, but the record name does not
        # match any reached hostname, so it is never evaluated.
        records = [
            make_record(id="r1"),
            make_record(id="r2", name="other.example.com", value="10.0.0.9"),
        ]
        assets = self.assets(records=records)
        self.assertEqual(
            [a["target"] for a in assets], ["app.example.com", "192.0.2.10"]
        )

    def test_depth_gate_keeps_deep_values_out_of_scope_check(self):
        # deep.example.com resolves to an out-of-scope address, but
        # max_depth stops the traversal before reaching it.
        records = [
            make_record(id="r1", type="CNAME", value="deep.example.com"),
            make_record(
                id="r2",
                name="deep.example.com",
                type="A",
                value="10.0.0.9",
            ),
        ]
        assets = self.assets(records=records, max_depth=1)
        self.assertEqual(
            [a["target"] for a in assets],
            ["app.example.com", "deep.example.com"],
        )

    def test_structure_errors_before_scope_gate(self):
        bad_payloads = [
            None,
            [],
            {},
            {"allow": [], "deny": [], "seeds": [], "records": []},
            discover_payload(extra=1),
            discover_payload(allow="*.example.com"),
            discover_payload(allow=["bad rule"]),
            discover_payload(seeds="app.example.com"),
            discover_payload(records="x"),
            # max_depth
            discover_payload(max_depth=True),
            discover_payload(max_depth="1"),
            discover_payload(max_depth=-1),
            discover_payload(max_depth=33),
            discover_payload(max_depth=1.5),
            # seeds
            discover_payload(seeds=[""]),
            discover_payload(seeds=[None]),
            discover_payload(seeds=["*.example.com"]),
            discover_payload(seeds=["10.0.0.0/8"]),
            discover_payload(seeds=["bad_host"]),
            discover_payload(seeds=["app.example.com", "APP.Example.COM."]),
            discover_payload(seeds=["192.0.2.10", "192.0.2.10"]),
            # records
            discover_payload(records=[{"id": "r"}]),
            discover_payload(records=[make_record(extra=1)]),
            discover_payload(records=["x"]),
            discover_payload(records=[make_record(id="")]),
            discover_payload(records=[make_record(id=1)]),
            discover_payload(records=[make_record(name="")]),
            discover_payload(records=[make_record(name=1)]),
            discover_payload(records=[make_record(name="bad_host")]),
            discover_payload(records=[make_record(type="TXT")]),
            discover_payload(records=[make_record(type="a")]),
            discover_payload(records=[make_record(value="")]),
            discover_payload(records=[make_record(value=1)]),
            discover_payload(records=[make_record(type="A", value="::1")]),
            discover_payload(records=[make_record(type="AAAA", value="1.2.3.4")]),
            discover_payload(records=[make_record(type="A", value="not-an-ip")]),
            discover_payload(
                records=[make_record(type="CNAME", value="1.2.3.4")]
            ),
            discover_payload(
                records=[make_record(type="CNAME", value="bad_host")]
            ),
            discover_payload(records=[make_record(), make_record()]),
            # Malformed record plus an out-of-scope seed: 400 wins.
            {
                "allow": ["*.example.com"],
                "deny": [],
                "seeds": ["evil.net"],
                "records": [make_record(type="TXT")],
                "max_depth": 1,
            },
        ]
        for payload in bad_payloads:
            with self.subTest(payload=repr(payload)[:100]):
                with self.assertRaises(ValueError):
                    self.service.discover_assets(payload)

    def test_valid_boundary_depths(self):
        self.assertEqual(len(self.assets(max_depth=0)), 1)
        self.assertEqual(len(self.assets(max_depth=32)), 2)

    def test_deterministic_output(self):
        first = self.service.discover_assets(discover_payload())
        second = self.service.discover_assets(discover_payload())
        self.assertEqual(first, second)


class DiscoverHttpTest(unittest.TestCase):
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

    def post_discover(self, payload):
        return self.request(
            "POST",
            "/v1/assets/discover",
            json.dumps(payload).encode(),
        )

    def test_discover_ok(self):
        status, payload = self.post_discover(discover_payload())
        self.assertEqual(status, 200)
        self.assertEqual(list(payload), ["assets"])
        self.assertEqual(
            [a["target"] for a in payload["assets"]],
            ["app.example.com", "192.0.2.10"],
        )

    def test_empty_seeds_ok(self):
        status, payload = self.post_discover(discover_payload(seeds=[]))
        self.assertEqual(status, 200)
        self.assertEqual(payload, {"assets": []})

    def test_scope_violation_403(self):
        status, payload = self.post_discover(
            discover_payload(seeds=["evil.net"], records=[])
        )
        self.assertEqual(status, 403)
        self.assertEqual(payload["error"]["code"], "scope_violation")
        self.assertNotIn("assets", payload)

    def test_invalid_request_400(self):
        status, payload = self.post_discover({"allow": [], "deny": []})
        self.assertEqual(status, 400)
        self.assertEqual(payload["error"]["code"], "invalid_request")

    def test_duplicate_seed_400(self):
        status, payload = self.post_discover(
            discover_payload(seeds=["app.example.com", "App.Example.com."])
        )
        self.assertEqual(status, 400)
        self.assertEqual(payload["error"]["code"], "invalid_request")

    def test_type_version_mismatch_400(self):
        status, payload = self.post_discover(
            discover_payload(records=[make_record(type="AAAA")])
        )
        self.assertEqual(status, 400)
        self.assertEqual(payload["error"]["code"], "invalid_request")

    def test_malformed_json_400(self):
        status, payload = self.request(
            "POST", "/v1/assets/discover", b"{nope"
        )
        self.assertEqual(status, 400)
        self.assertEqual(payload["error"]["code"], "invalid_request")

    def test_method_not_allowed_405(self):
        for method in ("GET", "PUT", "DELETE"):
            with self.subTest(method=method):
                status, payload = self.request(method, "/v1/assets/discover")
                self.assertEqual(status, 405)
                self.assertEqual(payload["error"]["code"], "method_not_allowed")


if __name__ == "__main__":
    unittest.main()
