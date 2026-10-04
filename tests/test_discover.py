import json
import threading
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

from redforge.server import Handler
from redforge.service import ScopeViolationError, Service


def make_record(rid, name, rtype, value):
    return {"id": rid, "name": name, "type": rtype, "value": value}


def discover_payload(**overrides):
    payload = {
        "allow": ["example.com", "*.example.com", "10.0.0.0/8", "2001:db8::/32"],
        "deny": [],
        "seeds": ["app.example.com"],
        "records": [],
        "max_depth": 3,
    }
    payload.update(overrides)
    return payload


class DiscoverServiceTest(unittest.TestCase):
    def setUp(self):
        self.service = Service()

    def assets(self, **overrides):
        return self.service.discover_assets(discover_payload(**overrides))["assets"]

    def test_seed_only_shape(self):
        (asset,) = self.assets()
        self.assertEqual(
            asset,
            {
                "target": "app.example.com",
                "kind": "hostname",
                "depth": 0,
                "source": None,
                "record_id": None,
            },
        )

    def test_seed_normalization(self):
        assets = self.assets(seeds=["APP.Example.COM."])
        self.assertEqual(assets[0]["target"], "app.example.com")

    def test_cname_and_a_chain_bfs(self):
        assets = self.assets(
            records=[
                make_record("r1", "app.example.com", "CNAME", "www.example.com"),
                make_record("r2", "www.example.com", "A", "10.1.2.3"),
            ],
            max_depth=2,
        )
        self.assertEqual(
            [(a["target"], a["kind"], a["depth"]) for a in assets],
            [
                ("app.example.com", "hostname", 0),
                ("www.example.com", "hostname", 1),
                ("10.1.2.3", "ip", 2),
            ],
        )
        self.assertEqual(assets[1]["source"], "app.example.com")
        self.assertEqual(assets[1]["record_id"], "r1")
        self.assertEqual(assets[2]["source"], "www.example.com")
        self.assertEqual(assets[2]["record_id"], "r2")

    def test_bfs_layer_order_uses_record_order(self):
        records = [
            make_record("ab", "root.example.com", "CNAME", "b.example.com"),
            make_record("ac", "root.example.com", "CNAME", "c.example.com"),
            make_record("b1", "b.example.com", "A", "10.0.0.1"),
            make_record("c1", "c.example.com", "A", "10.0.0.2"),
        ]
        assets = self.assets(seeds=["root.example.com"], records=records)
        self.assertEqual(
            [a["target"] for a in assets],
            ["root.example.com", "b.example.com", "c.example.com",
             "10.0.0.1", "10.0.0.2"],
        )
        self.assertEqual([a["depth"] for a in assets], [0, 1, 1, 2, 2])

    def test_aaaa_record(self):
        assets = self.assets(
            records=[make_record("v6", "app.example.com", "AAAA", "2001:db8::1")],
            max_depth=1,
        )
        self.assertEqual(assets[-1]["target"], "2001:db8::1")
        self.assertEqual(assets[-1]["kind"], "ip")
        self.assertEqual(assets[-1]["record_id"], "v6")

    def test_ip_seed_is_not_expanded(self):
        assets = self.assets(
            seeds=["10.0.0.9"],
            records=[make_record("r1", "app.example.com", "A", "10.0.0.9")],
        )
        self.assertEqual(len(assets), 1)
        self.assertEqual(assets[0]["kind"], "ip")
        self.assertEqual(assets[0]["source"], None)

    def test_max_depth_zero_returns_seeds_only(self):
        assets = self.assets(
            records=[
                make_record("r1", "app.example.com", "CNAME", "www.example.com"),
            ],
            max_depth=0,
        )
        self.assertEqual([a["target"] for a in assets], ["app.example.com"])

    def test_depth_limit_truncates_chain(self):
        assets = self.assets(
            records=[
                make_record("r1", "app.example.com", "CNAME", "a.example.com"),
                make_record("r2", "a.example.com", "CNAME", "b.example.com"),
            ],
            max_depth=1,
        )
        self.assertEqual(
            [a["target"] for a in assets], ["app.example.com", "a.example.com"]
        )

    def test_cycle_does_not_repeat(self):
        assets = self.assets(
            records=[
                make_record("ab", "app.example.com", "CNAME", "a.example.com"),
                make_record("ba", "a.example.com", "CNAME", "app.example.com"),
            ],
            max_depth=5,
        )
        self.assertEqual(
            [a["target"] for a in assets], ["app.example.com", "a.example.com"]
        )

    def test_diamond_keeps_shortest_path(self):
        records = [
            make_record("ab", "app.example.com", "CNAME", "b.example.com"),
            make_record("ac", "app.example.com", "CNAME", "c.example.com"),
            make_record("bc", "b.example.com", "CNAME", "c.example.com"),
        ]
        assets = self.assets(records=records)
        c = next(a for a in assets if a["target"] == "c.example.com")
        self.assertEqual(c["depth"], 1)
        self.assertEqual(c["source"], "app.example.com")
        self.assertEqual(c["record_id"], "ac")

    def test_equal_length_keeps_first_seed_then_record_path(self):
        records = [
            make_record("s1x", "s1.example.com", "CNAME", "x.example.com"),
            make_record("s2x", "s2.example.com", "CNAME", "x.example.com"),
        ]
        assets = self.assets(
            seeds=["s1.example.com", "s2.example.com"], records=records
        )
        x = next(a for a in assets if a["target"] == "x.example.com")
        self.assertEqual(x["depth"], 1)
        self.assertEqual(x["source"], "s1.example.com")
        self.assertEqual(x["record_id"], "s1x")
        self.assertEqual(
            [a["target"] for a in assets],
            ["s1.example.com", "s2.example.com", "x.example.com"],
        )

    def test_multiple_seeds_order_and_dedup(self):
        assets = self.assets(
            seeds=["a.example.com", "10.0.0.1"],
            allow=["a.example.com", "10.0.0.1"],
        )
        self.assertEqual(
            [(a["target"], a["kind"]) for a in assets],
            [("a.example.com", "hostname"), ("10.0.0.1", "ip")],
        )

    def test_empty_seeds_returns_empty_assets(self):
        self.assertEqual(self.assets(seeds=[]), [])

    def test_empty_seeds_still_validates_records(self):
        with self.assertRaises(ValueError):
            self.assets(seeds=[], records=[make_record("r", "bad host", "A", "10.0.0.1")])
        with self.assertRaises(ValueError):
            self.assets(seeds=[], max_depth=True)

    def test_scope_skips_unreached_record_values(self):
        # evil.example is only reachable beyond max_depth: no scope error.
        assets = self.assets(
            records=[
                make_record("ab", "app.example.com", "CNAME", "www.example.com"),
                make_record("be", "www.example.com", "CNAME", "evil.example"),
            ],
            max_depth=1,
        )
        self.assertEqual(
            [a["target"] for a in assets], ["app.example.com", "www.example.com"]
        )

    def test_reached_target_out_of_scope_raises(self):
        with self.assertRaises(ScopeViolationError):
            self.assets(
                records=[
                    make_record("ab", "app.example.com", "CNAME", "evil.example"),
                ],
                max_depth=1,
            )

    def test_seed_out_of_scope_raises(self):
        with self.assertRaises(ScopeViolationError):
            self.assets(seeds=["evil.example"])

    def test_deny_on_reached_target_raises(self):
        with self.assertRaises(ScopeViolationError):
            self.assets(
                deny=["10.1.2.3"],
                records=[make_record("r1", "app.example.com", "A", "10.1.2.3")],
                max_depth=1,
            )

    def test_deterministic_ordering(self):
        records = [
            make_record("ab", "app.example.com", "CNAME", "b.example.com"),
            make_record("ac", "app.example.com", "CNAME", "c.example.com"),
            make_record("b1", "b.example.com", "A", "10.0.0.1"),
            make_record("c1", "c.example.com", "A", "10.0.0.2"),
        ]
        first = self.assets(records=records)
        second = self.assets(records=records)
        self.assertEqual(first, second)

    def test_structure_errors(self):
        bad_payloads = [
            None,
            [],
            {},
            {"allow": [], "deny": [], "seeds": [], "records": []},
            discover_payload(extra=1),
            discover_payload(allow="x"),
            discover_payload(allow=["bad rule/99"]),
            discover_payload(seeds="x"),
            discover_payload(records="x"),
            discover_payload(seeds=["10.0.0.0/24"]),
            discover_payload(seeds=["*.example.com"]),
            discover_payload(seeds=[""]),
            discover_payload(seeds=[1]),
            discover_payload(seeds=["app.example.com", "APP.EXAMPLE.COM."]),
            discover_payload(max_depth=-1),
            discover_payload(max_depth=33),
            discover_payload(max_depth="1"),
            discover_payload(max_depth=True),
            # records
            discover_payload(records=[{"id": "r"}]),
            discover_payload(records=[{"id": "r", "name": "app.example.com",
                                       "type": "A", "value": "10.0.0.1",
                                       "extra": 1}]),
            discover_payload(records=[make_record("", "app.example.com", "A", "10.0.0.1")]),
            discover_payload(records=[make_record(1, "app.example.com", "A", "10.0.0.1")]),
            discover_payload(records=[make_record("r", "10.0.0.1", "A", "10.0.0.2")]),
            discover_payload(records=[make_record("r", "app.example.com", "MX", "x")]),
            discover_payload(records=[make_record("r", "app.example.com", "A", "2001:db8::1")]),
            discover_payload(records=[make_record("r", "app.example.com", "AAAA", "10.0.0.1")]),
            discover_payload(records=[make_record("r", "app.example.com", "A", "10.0.0.0/24")]),
            discover_payload(records=[make_record("r", "app.example.com", "CNAME", "10.0.0.1")]),
            discover_payload(records=[make_record("r", "bad host", "A", "10.0.0.1")]),
            discover_payload(
                records=[
                    make_record("dup", "app.example.com", "A", "10.0.0.1"),
                    make_record("dup", "app.example.com", "A", "10.0.0.2"),
                ]
            ),
        ]
        for payload in bad_payloads:
            with self.subTest(payload=repr(payload)[:100]):
                with self.assertRaises(ValueError):
                    self.service.discover_assets(payload)


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
            "POST", "/v1/assets/discover", json.dumps(payload).encode()
        )

    def test_discover_ok(self):
        status, payload = self.post_discover(
            discover_payload(
                records=[
                    make_record("r1", "app.example.com", "CNAME", "www.example.com"),
                    make_record("r2", "www.example.com", "A", "10.1.2.3"),
                ],
                max_depth=2,
            )
        )
        self.assertEqual(status, 200)
        self.assertEqual(list(payload), ["assets"])
        self.assertEqual(
            [a["target"] for a in payload["assets"]],
            ["app.example.com", "www.example.com", "10.1.2.3"],
        )

    def test_empty_seeds_ok(self):
        status, payload = self.post_discover(discover_payload(seeds=[]))
        self.assertEqual(status, 200)
        self.assertEqual(payload, {"assets": []})

    def test_scope_violation_403(self):
        status, payload = self.post_discover(
            discover_payload(seeds=["evil.example"])
        )
        self.assertEqual(status, 403)
        self.assertEqual(payload["error"]["code"], "scope_violation")
        self.assertNotIn("assets", payload)

    def test_invalid_request_400(self):
        status, payload = self.post_discover({"allow": [], "deny": []})
        self.assertEqual(status, 400)
        self.assertEqual(payload["error"]["code"], "invalid_request")

    def test_type_version_mismatch_400(self):
        status, payload = self.post_discover(
            discover_payload(
                records=[make_record("r", "app.example.com", "A", "2001:db8::1")]
            )
        )
        self.assertEqual(status, 400)
        self.assertEqual(payload["error"]["code"], "invalid_request")

    def test_malformed_json_400(self):
        status, payload = self.request("POST", "/v1/assets/discover", b"{nope")
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
