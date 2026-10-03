import json
import threading
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

from redforge.server import Handler
from redforge.service import Service


def make_variant(vid="v1", steps=None):
    return {"id": vid, "steps": [] if steps is None else steps}


def make_item(**overrides):
    item = {
        "id": "item-1",
        "template": "GET /${path}?q=${q}",
        "variables": {"path": "a b", "q": "x"},
        "variants": [make_variant()],
    }
    item.update(overrides)
    return item


def generate_payload(**overrides):
    payload = {
        "allow": ["*.example.com", "10.0.0.0/8"],
        "deny": [],
        "target": "app.example.com",
        "items": [make_item()],
    }
    payload.update(overrides)
    return payload


class PayloadGenerationServiceTest(unittest.TestCase):
    def setUp(self):
        self.service = Service()

    def generate(self, **overrides):
        return self.service.generate_payloads(generate_payload(**overrides))[
            "generated"
        ]

    def test_empty_items_still_authorizes_target(self):
        self.assertEqual(self.generate(items=[]), [])

    def test_empty_items_out_of_scope_is_403(self):
        from redforge.service import ScopeViolationError

        with self.assertRaises(ScopeViolationError):
            self.generate(items=[], target="other.example.org")

    def test_empty_steps_returns_rendered_text(self):
        (entry,) = self.generate()
        self.assertEqual(entry["value"], "GET /a b?q=x")
        self.assertEqual(entry["steps"], [])

    def test_entry_shape_and_order(self):
        items = [
            make_item(
                id="i1",
                variants=[
                    make_variant("z", ["hex"]),
                    make_variant("a", ["base64"]),
                ],
            ),
            make_item(id="i2", template="${v}", variables={"v": "y"}, variants=[]),
            make_item(
                id="i3",
                template="${v}",
                variables={"v": "z"},
                variants=[make_variant("m", ["url_percent", "base64", "hex"])],
            ),
        ]
        result = self.generate(items=items)
        self.assertEqual([(r["item_id"], r["variant_id"]) for r in result], [
            ("i1", "z"),
            ("i1", "a"),
            ("i3", "m"),
        ])
        for row in result:
            self.assertEqual(set(row), {"item_id", "variant_id", "target", "steps", "value"})
            self.assertEqual(row["target"], "app.example.com")
        # Item with no variants contributes nothing.

    def test_no_variants_anywhere_yields_empty(self):
        items = [make_item(variants=[]), make_item(id="i2", variants=[])]
        self.assertEqual(self.generate(items=items), [])

    def test_target_is_normalized(self):
        entries = self.generate(target="APP.Example.COM")
        self.assertEqual(entries[0]["target"], "app.example.com")

    def test_wildcard_target_is_invalid(self):
        with self.assertRaises(ValueError):
            self.generate(target="*.example.com")

    # --- encoding semantics -------------------------------------------------

    def test_url_percent_keeps_unreserved_and_uppercases_hex(self):
        items = [
            make_item(
                id="i",
                template="${v}",
                variables={"v": "Az0-._~ /é"},
                variants=[make_variant(steps=["url_percent"])],
            )
        ]
        (entry,) = self.generate(items=items)
        # space -> %20, slash -> %2F, é -> UTF-8 C3 A9 -> %C3%A9
        self.assertEqual(entry["value"], "Az0-._~%20%2F%C3%A9")

    def test_base64_standard_with_padding(self):
        items = [
            make_item(
                id="i",
                template="${v}",
                variables={"v": "ab"},
                variants=[make_variant(steps=["base64"])],
            )
        ]
        (entry,) = self.generate(items=items)
        self.assertEqual(entry["value"], "YWI=")

    def test_base64_encodes_utf8(self):
        items = [
            make_item(
                id="i",
                template="${v}",
                variables={"v": "é"},
                variants=[make_variant(steps=["base64"])],
            )
        ]
        (entry,) = self.generate(items=items)
        self.assertEqual(entry["value"], "w6k=")

    def test_hex_lowercase_no_prefix(self):
        items = [
            make_item(
                id="i",
                template="${v}",
                variables={"v": "Aé"},
                variants=[make_variant(steps=["hex"])],
            )
        ]
        (entry,) = self.generate(items=items)
        self.assertEqual(entry["value"], "41c3a9")

    def test_steps_apply_in_order_and_chain(self):
        items = [
            make_item(
                id="i",
                template="${v}",
                variables={"v": "a b"},
                variants=[
                    make_variant("b64-u", ["base64", "url_percent"]),
                    make_variant("u-b64", ["url_percent", "base64"]),
                ],
            )
        ]
        first, second = self.generate(items=items)
        # base64("a b") == "YSBi", then percent-encoding keeps that ascii.
        self.assertEqual(first["value"], "YSBi")
        # url_percent("a b") == "a%20b", then base64 of that ascii.
        self.assertEqual(second["value"], "YSUyMGI=")

    def test_steps_can_repeat(self):
        items = [
            make_item(
                id="i",
                template="${v}",
                variables={"v": " "},
                variants=[make_variant(steps=["hex", "hex"])],
            )
        ]
        (entry,) = self.generate(items=items)
        # hex(" ") == "20"; hex("20") == "3230"
        self.assertEqual(entry["value"], "3230")

    def test_each_variant_starts_independently_from_rendered_text(self):
        items = [
            make_item(
                id="i",
                template="${v}",
                variables={"v": " "},
                variants=[
                    make_variant("a", ["hex"]),
                    make_variant("b", ["base64"]),
                ],
            )
        ]
        a, b = self.generate(items=items)
        self.assertEqual(a["value"], "20")
        self.assertEqual(b["value"], "IA==")

    def test_same_value_distinct_ids_are_not_merged(self):
        items = [
            make_item(
                id="i",
                template="${v}",
                variables={"v": "a"},
                variants=[
                    make_variant("one", []),
                    make_variant("two", []),
                ],
            )
        ]
        result = self.generate(items=items)
        self.assertEqual(len(result), 2)
        self.assertEqual([r["variant_id"] for r in result], ["one", "two"])
        self.assertEqual([r["value"] for r in result], ["a", "a"])

    def test_deterministic_across_calls(self):
        payload = generate_payload()
        first = self.service.generate_payloads(payload)
        second = self.service.generate_payloads(payload)
        self.assertEqual(first, second)

    # --- template substitution ----------------------------------------------

    def test_substitution_is_single_pass(self):
        items = [
            make_item(
                id="i",
                template="${a}",
                variables={"a": "${b}"},
                variants=[make_variant()],
            )
        ]
        (entry,) = self.generate(items=items)
        self.assertEqual(entry["value"], "${b}")

    def test_dollar_without_brace_is_literal(self):
        items = [
            make_item(
                id="i",
                template="$x ${v} 5$",
                variables={"v": "z"},
                variants=[make_variant()],
            )
        ]
        (entry,) = self.generate(items=items)
        self.assertEqual(entry["value"], "$x z 5$")

    def test_missing_variable_reference_is_invalid(self):
        items = [make_item(template="${a}", variables={}, variants=[make_variant()])]
        with self.assertRaises(ValueError):
            self.generate(items=items)

    def test_extra_variable_is_invalid(self):
        items = [
            make_item(
                template="${a}",
                variables={"a": "1", "b": "2"},
                variants=[make_variant()],
            )
        ]
        with self.assertRaises(ValueError):
            self.generate(items=items)

    def test_malformed_placeholder_is_invalid(self):
        for template in ("${a", "${1a}", "${}", "${a-b}", "x ${"):
            with self.subTest(template=template):
                items = [
                    make_item(template=template, variables={"a": "1"}, variants=[])
                ]
                with self.assertRaises(ValueError):
                    self.generate(items=items)

    def test_empty_template_is_invalid(self):
        with self.assertRaises(ValueError):
            self.generate(items=[make_item(template="", variables={}, variants=[])])

    def test_variable_names_must_match_rule(self):
        for name in ("1a", "a-b", "a.b", ""):
            with self.subTest(name=name):
                with self.assertRaises(ValueError):
                    self.generate(
                        items=[
                            make_item(variables={name: "v"}, variants=[])
                        ]
                    )

    def test_variables_value_must_be_string(self):
        with self.assertRaises(ValueError):
            self.generate(items=[make_item(variables={"x": 1}, variants=[])])

    # --- structural validation ----------------------------------------------

    def test_duplicate_item_ids(self):
        with self.assertRaises(ValueError):
            self.generate(items=[make_item(id="dup"), make_item(id="dup")])

    def test_duplicate_variant_ids_within_item(self):
        items = [
            make_item(
                variants=[make_variant("dup"), make_variant("dup", ["hex"])]
            )
        ]
        with self.assertRaises(ValueError):
            self.generate(items=items)

    def test_variant_ids_may_repeat_across_items(self):
        result = self.generate(
            items=[
                make_item(id="a", variants=[make_variant("v", ["hex"])]),
                make_item(id="b", variants=[make_variant("v", ["hex"])]),
            ]
        )
        self.assertEqual([(r["item_id"], r["variant_id"]) for r in result], [
            ("a", "v"),
            ("b", "v"),
        ])

    def test_unknown_step_is_invalid(self):
        items = [make_item(variants=[make_variant(steps=["rot13"])])]
        with self.assertRaises(ValueError):
            self.generate(items=items)

    def test_bad_payloads(self):
        bad_payloads = [
            None,
            [],
            {},
            {"deny": [], "target": "app.example.com", "items": []},
            {"allow": [], "target": "app.example.com", "items": []},
            {"allow": [], "deny": [], "items": []},
            {"allow": [], "deny": [], "target": "app.example.com"},
            {"allow": [], "deny": [], "target": "app.example.com", "items": [], "x": 1},
            {"allow": [], "deny": [], "target": "app.example.com", "items": {}},
            {"allow": "notlist", "deny": [], "target": "app.example.com", "items": []},
            {"allow": [], "deny": [], "target": 9, "items": []},
            {"allow": [], "deny": [], "target": "not a host!!", "items": []},
            {"allow": [], "deny": [], "target": "app.example.com", "items": [{}]},
            {"allow": [], "deny": [], "target": "app.example.com",
             "items": [{"id": "", "template": "x", "variables": {}, "variants": []}]},
            {"allow": [], "deny": [], "target": "app.example.com",
             "items": [{"id": "i", "template": "x", "variables": [], "variants": []}]},
            {"allow": [], "deny": [], "target": "app.example.com",
             "items": [{"id": "i", "template": "x", "variables": {}, "variants": {}}]},
            {"allow": [], "deny": [], "target": "app.example.com",
             "items": [make_item(variants=[{"id": "v"}])]},
            {"allow": [], "deny": [], "target": "app.example.com",
             "items": [make_item(variants=[{"id": "v", "steps": None}])]},
            {"allow": [], "deny": [], "target": "app.example.com",
             "items": [make_item(variants=[{"id": "v", "steps": [1]}])]},
            {"allow": [], "deny": [], "target": "app.example.com",
             "items": [make_item(variants=[{"id": "v", "steps": [], "extra": 1}])]},
            {"allow": [], "deny": [], "target": "app.example.com",
             "items": [make_item(variants=[{"id": 1, "steps": []}])]},
        ]
        for payload in bad_payloads:
            with self.subTest(payload=repr(payload)[:80]):
                with self.assertRaises(ValueError):
                    self.service.generate_payloads(payload)

    def test_structural_error_takes_precedence_over_scope(self):
        # Malformed item -> 400 even though target is also out of scope.
        from redforge.service import ScopeViolationError

        payload = generate_payload(
            target="other.example.org",
            items=[make_item(template="${missing}", variables={})],
        )
        with self.assertRaises(ValueError):
            self.service.generate_payloads(payload)
        # Well-formed but unauthorized -> ScopeViolationError.
        with self.assertRaises(ScopeViolationError):
            self.service.generate_payloads(
                generate_payload(target="other.example.org")
            )

    def test_deny_wins_over_allow(self):
        from redforge.service import ScopeViolationError

        with self.assertRaises(ScopeViolationError):
            self.generate(
                allow=["*.example.com"],
                deny=["app.example.com"],
            )


class PayloadGenerationHttpTest(unittest.TestCase):
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

    def test_generate_ok(self):
        status, payload = self.request(
            "POST",
            "/v1/payloads/generate",
            json.dumps(generate_payload()).encode(),
            {"Content-Type": "application/json"},
        )
        self.assertEqual(status, 200)
        self.assertEqual(set(payload), {"generated"})
        (entry,) = payload["generated"]
        self.assertEqual(
            entry,
            {
                "item_id": "item-1",
                "variant_id": "v1",
                "target": "app.example.com",
                "steps": [],
                "value": "GET /a b?q=x",
            },
        )

    def test_empty_items_ok(self):
        status, payload = self.request(
            "POST",
            "/v1/payloads/generate",
            json.dumps(generate_payload(items=[])).encode(),
        )
        self.assertEqual(status, 200)
        self.assertEqual(payload, {"generated": []})

    def test_invalid_request_400(self):
        status, payload = self.request(
            "POST", "/v1/payloads/generate", b'{"allow": []}'
        )
        self.assertEqual(status, 400)
        self.assertEqual(payload["error"]["code"], "invalid_request")

    def test_malformed_json_400(self):
        status, payload = self.request(
            "POST", "/v1/payloads/generate", b"{nope"
        )
        self.assertEqual(status, 400)
        self.assertEqual(payload["error"]["code"], "invalid_request")

    def test_scope_violation_403(self):
        body = json.dumps(generate_payload(target="elsewhere.example.net")).encode()
        status, payload = self.request("POST", "/v1/payloads/generate", body)
        self.assertEqual(status, 403)
        self.assertEqual(payload["error"]["code"], "scope_violation")

    def test_oversized_body_413(self):
        import http.client

        conn = http.client.HTTPConnection("127.0.0.1", self.port)
        conn.putrequest("POST", "/v1/payloads/generate")
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
                status, payload = self.request(method, "/v1/payloads/generate")
                self.assertEqual(status, 405)
                self.assertEqual(payload["error"]["code"], "method_not_allowed")

    def test_healthz_unchanged(self):
        status, payload = self.request("GET", "/healthz")
        self.assertEqual(status, 200)
        self.assertEqual(payload["status"], "ok")


if __name__ == "__main__":
    unittest.main()
