import json
import threading
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

from redforge.server import Handler
from redforge.service import (
    ScopeViolationError,
    Service,
    _encode_base64,
    _encode_hex,
    _encode_url_percent,
)


def make_variant(vid="v1", steps=None):
    return {"id": vid, "steps": [] if steps is None else steps}


def make_item(iid="i1", template="${x}", variables=None, variants=None):
    item = {
        "id": iid,
        "template": template,
        "variables": {"x": "a"} if variables is None else variables,
        "variants": [make_variant()] if variants is None else variants,
    }
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


class EncoderTest(unittest.TestCase):
    def test_url_percent_keeps_unreserved(self):
        self.assertEqual(_encode_url_percent("Az09-._~"), "Az09-._~")

    def test_url_percent_escapes_ascii_special_uppercase(self):
        self.assertEqual(_encode_url_percent("a b/c"), "a%20b%2Fc")
        self.assertEqual(_encode_url_percent("${}"), "%24%7B%7D")

    def test_url_percent_encodes_utf8_bytes(self):
        # "é" is C3 A9 in UTF-8; "中" is E4 B8 AD.
        self.assertEqual(_encode_url_percent("é"), "%C3%A9")
        self.assertEqual(_encode_url_percent("中"), "%E4%B8%AD")

    def test_base64_standard_with_padding(self):
        self.assertEqual(_encode_base64(""), "")
        self.assertEqual(_encode_base64("f"), "Zg==")
        self.assertEqual(_encode_base64("fo"), "Zm8=")
        self.assertEqual(_encode_base64("foo"), "Zm9v")
        self.assertEqual(_encode_base64("é"), "w6k=")

    def test_hex_lowercase_no_prefix(self):
        self.assertEqual(_encode_hex(""), "")
        self.assertEqual(_encode_hex("a"), "61")
        self.assertEqual(_encode_hex("é"), "c3a9")
        self.assertEqual(_encode_hex("中"), "e4b8ad")


class PayloadGenerationServiceTest(unittest.TestCase):
    def setUp(self):
        self.service = Service()

    def generate(self, **overrides):
        return self.service.generate_payloads(generate_payload(**overrides))[
            "generated"
        ]

    def test_empty_steps_returns_rendered_text(self):
        (entry,) = self.generate(
            items=[make_item(template="${x}", variables={"x": "a b"})]
        )
        self.assertEqual(entry["value"], "a b")
        self.assertEqual(entry["steps"], [])

    def test_template_substitution_is_single_pass(self):
        # The value contains a placeholder that must not be expanded again;
        # a variable that would have been needed only by such nested text is
        # not required to exist.
        (entry,) = self.generate(
            items=[
                make_item(
                    template="p=${x}",
                    variables={"x": "${y}"},
                    variants=[make_variant(steps=[])],
                )
            ]
        )
        self.assertEqual(entry["value"], "p=${y}")

    def test_placeholder_inside_value_is_literal(self):
        (plain,) = self.generate(
            items=[
                make_item(
                    template="${x}",
                    variables={"x": "${y}"},
                    variants=[make_variant(steps=[])],
                )
            ]
        )
        self.assertEqual(plain["value"], "${y}")
        # Encoded form percent-encodes the literal placeholder characters.
        (encoded,) = self.generate(
            items=[
                make_item(
                    template="${x}",
                    variables={"x": "${y}"},
                    variants=[make_variant(steps=["url_percent"])],
                )
            ]
        )
        self.assertEqual(encoded["value"], "%24%7By%7D")

    def test_steps_chain_in_order(self):
        # url_percent then base64: base64 sees the percent-encoded text.
        (entry,) = self.generate(
            items=[
                make_item(
                    template="${x}",
                    variables={"x": "a b"},
                    variants=[make_variant(steps=["url_percent", "base64"])],
                )
            ]
        )
        self.assertEqual(entry["value"], _encode_base64("a%20b"))
        (entry_hex,) = self.generate(
            items=[
                make_item(
                    template="${x}",
                    variables={"x": "a b"},
                    variants=[
                        make_variant(steps=["url_percent", "hex"])
                    ],
                )
            ]
        )
        self.assertEqual(entry_hex["value"], _encode_hex("a%20b"))

    def test_steps_may_repeat(self):
        (entry,) = self.generate(
            items=[
                make_item(
                    template="x",
                    variables={},
                    variants=[make_variant(steps=["hex", "hex", "hex"])],
                )
            ]
        )
        once = _encode_hex("x")
        twice = _encode_hex(once)
        self.assertEqual(entry["value"], _encode_hex(twice))

    def test_empty_template_value(self):
        (entry,) = self.generate(
            items=[
                make_item(
                    template="${x}",
                    variables={"x": ""},
                    variants=[make_variant(steps=["base64"])],
                )
            ]
        )
        self.assertEqual(entry["value"], "")

    def test_template_without_placeholders_and_empty_variables(self):
        (entry,) = self.generate(
            items=[make_item(template="literal", variables={})]
        )
        self.assertEqual(entry["value"], "literal")

    def test_ordering_items_then_variants(self):
        generated = self.generate(
            items=[
                make_item(
                    iid="A",
                    variants=[make_variant("a1"), make_variant("a2")],
                ),
                make_item(
                    iid="B",
                    variants=[make_variant("b1")],
                ),
            ]
        )
        self.assertEqual(
            [(g["item_id"], g["variant_id"]) for g in generated],
            [("A", "a1"), ("A", "a2"), ("B", "b1")],
        )

    def test_empty_items_returns_empty_list(self):
        self.assertEqual(self.generate(items=[]), [])

    def test_item_without_variants_contributes_nothing(self):
        self.assertEqual(
            self.generate(items=[make_item(variants=[])]),
            [],
        )

    def test_equal_values_are_not_merged(self):
        generated = self.generate(
            items=[
                make_item(
                    iid="A",
                    variants=[make_variant("a1"), make_variant("a2")],
                ),
            ]
        )
        self.assertEqual(len(generated), 2)
        self.assertEqual(generated[0]["value"], generated[1]["value"])
        self.assertEqual(
            [g["variant_id"] for g in generated], ["a1", "a2"]
        )

    def test_result_shape_and_normalized_target(self):
        (entry,) = self.generate(
            target="APP.Example.COM.",
            items=[make_item(template="${x}", variables={"x": "z"})],
        )
        self.assertEqual(set(entry), {"item_id", "variant_id", "target", "steps", "value"})
        self.assertEqual(entry["item_id"], "i1")
        self.assertEqual(entry["variant_id"], "v1")
        self.assertEqual(entry["target"], "app.example.com")
        self.assertEqual(entry["steps"], [])
        self.assertEqual(entry["value"], "z")

    def test_deterministic(self):
        payload = generate_payload(
            items=[
                make_item(
                    iid="A",
                    variants=[
                        make_variant("a1", ["url_percent"]),
                        make_variant("a2", ["base64", "hex"]),
                    ],
                )
            ]
        )
        first = self.service.generate_payloads(payload)
        second = self.service.generate_payloads(payload)
        self.assertEqual(first, second)

    def test_ip_target_normalized(self):
        (entry,) = self.generate(
            target="10.1.2.3",
            items=[make_item(template="x", variables={})],
        )
        self.assertEqual(entry["target"], "10.1.2.3")

    def test_scope_violation_empty_items_still_checked(self):
        with self.assertRaises(ScopeViolationError):
            self.generate(target="evil.net", items=[])
        with self.assertRaises(ScopeViolationError):
            self.generate(deny=["app.example.com"], items=[])

    def test_scope_violation_denies_whole_request(self):
        with self.assertRaises(ScopeViolationError):
            self.generate(
                items=[
                    make_item(iid="ok"),
                    make_item(iid="bad"),
                ],
                target="evil.net",
            )

    def test_structure_error_takes_precedence_over_scope(self):
        # Out-of-scope target plus malformed structure: 400 wins, not 403.
        with self.assertRaises(ValueError):
            self.generate(
                target="evil.net",
                items=[{"id": "broken"}],
            )
        with self.assertRaises(ValueError):
            self.generate(
                target="evil.net",
                items=[make_item(template="${missing}")],
            )

    def test_wildcard_target_rejected(self):
        with self.assertRaises(ValueError):
            self.generate(target="*.example.com")

    def test_validation_errors(self):
        bad_payloads = [
            None,
            [],
            {},
            {"deny": [], "target": "a", "items": []},
            generate_payload(extra=1),
            generate_payload(allow="*.example.com"),
            generate_payload(allow=["bad_host"]),
            generate_payload(allow=["10.0.0.0/33"]),
            generate_payload(deny=["bad_host"]),
            generate_payload(target=123),
            generate_payload(target="bad_host"),
            generate_payload(target=""),
            generate_payload(items={}),
            # items entries
            generate_payload(items=[{}]),
            generate_payload(items=["nope"]),
            generate_payload(
                items=[{"id": "i", "template": "x",
                        "variables": {}, "variants": [], "extra": 1}]
            ),
            generate_payload(items=[{"id": "", "template": "x",
                                     "variables": {}, "variants": []}]),
            generate_payload(items=[{"id": 1, "template": "x",
                                     "variables": {}, "variants": []}]),
            generate_payload(items=[{"id": "i", "template": "",
                                     "variables": {}, "variants": []}]),
            generate_payload(items=[{"id": "i", "template": 1,
                                     "variables": {}, "variants": []}]),
            generate_payload(items=[{"id": "i", "template": "x",
                                     "variants": []}]),
            # variables
            generate_payload(items=[{"id": "i", "template": "x",
                                     "variables": [], "variants": []}]),
            generate_payload(items=[{"id": "i", "template": "x",
                                     "variables": {"1bad": "v"},
                                     "variants": []}]),
            generate_payload(items=[{"id": "i", "template": "x",
                                     "variables": {"has-dash": "v"},
                                     "variants": []}]),
            generate_payload(items=[{"id": "i", "template": "x",
                                     "variables": {"ok": 1},
                                     "variants": []}]),
            # placeholder errors
            generate_payload(items=[make_item(
                template="${x}", variables={})]),
            generate_payload(items=[make_item(
                template="${x}${y}", variables={"x": "1"})]),
            generate_payload(items=[make_item(
                template="${x", variables={"x": "1"})]),
            generate_payload(items=[make_item(
                template="${}", variables={"": "1"})]),
            generate_payload(items=[make_item(
                template="${1x}", variables={"1x": "1"})]),
            generate_payload(items=[make_item(
                template="${x-y}", variables={"x-y": "1"})]),
            generate_payload(items=[make_item(
                template="literal", variables={"x": "1"})]),
            # duplicate item ids
            generate_payload(items=[make_item(iid="d"), make_item(iid="d")]),
            # variants
            generate_payload(items=[{"id": "i", "template": "x",
                                     "variables": {}, "variants": {}}]),
            generate_payload(items=[{"id": "i", "template": "x",
                                     "variables": {}, "variants": [{}]}]),
            generate_payload(items=[{"id": "i", "template": "x",
                                     "variables": {},
                                     "variants": [{"id": "v"}]}]),
            generate_payload(items=[{"id": "i", "template": "x",
                                     "variables": {},
                                     "variants": [{"id": "", "steps": []}]}]),
            generate_payload(items=[{"id": "i", "template": "x",
                                     "variables": {},
                                     "variants": [{"id": "v", "steps": {}}]}]),
            generate_payload(items=[{"id": "i", "template": "x",
                                     "variables": {},
                                     "variants": [{"id": "v",
                                                   "steps": ["gzip"]}]}]),
            generate_payload(items=[{"id": "i", "template": "x",
                                     "variables": {},
                                     "variants": [{"id": "v",
                                                   "steps": ["hex", 1]}]}]),
            generate_payload(items=[{"id": "i", "template": "x",
                                     "variables": {},
                                     "variants": [
                                         {"id": "d", "steps": []},
                                         {"id": "d", "steps": []},
                                     ]}]),
        ]
        for payload in bad_payloads:
            with self.subTest(payload=repr(payload)[:90]):
                with self.assertRaises(ValueError):
                    self.service.generate_payloads(payload)

    def test_plain_dollar_without_brace_is_literal(self):
        (entry,) = self.generate(
            items=[
                make_item(
                    template="$x $ ${x}",
                    variables={"x": "v"},
                    variants=[make_variant(steps=[])],
                )
            ]
        )
        self.assertEqual(entry["value"], "$x $ v")


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

    def post_generate(self, payload):
        return self.request(
            "POST", "/v1/payloads/generate", json.dumps(payload).encode()
        )

    def test_generate_ok(self):
        status, payload = self.post_generate(
            generate_payload(
                items=[
                    make_item(
                        template="${who} ${n}",
                        variables={"who": "a b/c", "n": "é"},
                        variants=[
                            make_variant("plain", []),
                            make_variant("u", ["url_percent"]),
                            make_variant("b64", ["base64"]),
                            make_variant("h", ["hex"]),
                            make_variant("chain", ["url_percent", "hex"]),
                        ],
                    )
                ]
            )
        )
        self.assertEqual(status, 200)
        self.assertEqual(list(payload), ["generated"])
        entries = payload["generated"]
        self.assertEqual([e["variant_id"] for e in entries],
                         ["plain", "u", "b64", "h", "chain"])
        self.assertEqual(entries[0]["value"], "a b/c é")
        self.assertEqual(entries[1]["value"], "a%20b%2Fc%20%C3%A9")
        self.assertEqual(entries[2]["value"], _encode_base64("a b/c é"))
        self.assertEqual(entries[3]["value"], _encode_hex("a b/c é"))
        self.assertEqual(
            entries[4]["value"], _encode_hex("a%20b%2Fc%20%C3%A9")
        )
        for entry in entries:
            self.assertEqual(
                set(entry),
                {"item_id", "variant_id", "target", "steps", "value"},
            )
            self.assertEqual(entry["item_id"], "i1")
            self.assertEqual(entry["target"], "app.example.com")

    def test_empty_items_ok(self):
        status, payload = self.post_generate(generate_payload(items=[]))
        self.assertEqual(status, 200)
        self.assertEqual(payload, {"generated": []})

    def test_scope_violation_403(self):
        status, payload = self.post_generate(
            generate_payload(target="evil.net")
        )
        self.assertEqual(status, 403)
        self.assertEqual(payload["error"]["code"], "scope_violation")
        self.assertNotIn("generated", payload)

    def test_empty_items_scope_still_403(self):
        status, payload = self.post_generate(
            generate_payload(target="evil.net", items=[])
        )
        self.assertEqual(status, 403)
        self.assertEqual(payload["error"]["code"], "scope_violation")

    def test_invalid_request_400(self):
        status, payload = self.post_generate({"allow": [], "deny": []})
        self.assertEqual(status, 400)
        self.assertEqual(payload["error"]["code"], "invalid_request")

    def test_unknown_step_400(self):
        status, payload = self.post_generate(
            generate_payload(
                items=[make_item(
                    template="x", variables={},
                    variants=[make_variant(steps=["rot13"])])]
            )
        )
        self.assertEqual(status, 400)
        self.assertEqual(payload["error"]["code"], "invalid_request")

    def test_malformed_json_400(self):
        status, payload = self.request(
            "POST", "/v1/payloads/generate", b"{nope"
        )
        self.assertEqual(status, 400)
        self.assertEqual(payload["error"]["code"], "invalid_request")

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
        for method in ("GET", "PUT", "DELETE", "PATCH"):
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
