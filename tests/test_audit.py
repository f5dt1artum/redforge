import copy
import hashlib
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
    _audit_record_hash,
    _jcs_bytes,
)

ZERO_HASH = "0" * 64

HASH_EVT1 = "770e3a23eb3dbfd98917da791de8d32564c41b40c511712fdb0609f35a9921d8"
HASH_EVT2 = "f5e4dd99d766d45bebbf8ef70c74355d2a04b6c59ced1c8038ac99bc2e992404"


def make_event(**overrides):
    event = {
        "id": "evt-1",
        "target": "app.example.com",
        "kind": "discovery",
        "outcome": "done",
        "occurred_ms": 100,
    }
    event.update(overrides)
    return event


def build_payload(events=None, exercise_id="EX-42", **overrides):
    payload = {
        "allow": ["*.example.com", "10.0.0.0/8"],
        "deny": [],
        "exercise_id": exercise_id,
        "events": [make_event()] if events is None else events,
    }
    payload.update(overrides)
    return payload


def verify_payload(audit, **overrides):
    payload = {
        "allow": ["*.example.com", "10.0.0.0/8"],
        "deny": [],
        "audit": audit,
    }
    payload.update(overrides)
    return payload


def tamper(audit, index, **changes):
    """Return a deep copy of audit with fields of one record changed."""
    audit = copy.deepcopy(audit)
    audit["records"][index].update(changes)
    return audit


class JcsCanonicalizationTest(unittest.TestCase):
    def test_rfc8785_canonical_sample(self):
        sample = {
            "numbers": [333333333.3333333, 1e30, 4.5, 0.002, 1e-27],
            "literals": [None, True, False],
            "string": "€$\x0f\nA'B\"\\\\\"/",
        }
        expected = (
            b'{"literals":[null,true,false],'
            b'"numbers":[333333333.3333333,1e+30,4.5,0.002,1e-27],'
            b'"string":"\xe2\x82\xac$\\u000f\\nA\'B\\"\\\\\\\\\\"/"}'
        )
        self.assertEqual(_jcs_bytes(sample), expected)

    def test_number_serialization_boundaries(self):
        cases = {
            0: b"0",
            -0.0: b"0",
            5: b"5",
            5.0: b"5",
            0.000001: b"0.000001",
            1e-7: b"1e-7",
            100000000000000000000: b"100000000000000000000",
            1e21: b"1e+21",
            1e-27: b"1e-27",
            5e-324: b"5e-324",
        }
        for value, expected in cases.items():
            with self.subTest(value=value):
                self.assertEqual(_jcs_bytes(value), expected)

    def test_keys_sorted_by_utf16_code_units(self):
        obj = {"€": 1, "a": 2, "é": 3}
        self.assertEqual(_jcs_bytes(obj), b'{"a":2,"\xc3\xa9":3,"\xe2\x82\xac":1}')

    def test_record_hash_is_jcs_sha256_with_exercise_id(self):
        record = {
            "id": "evt-1",
            "target": "app.example.com",
            "kind": "discovery",
            "outcome": "done",
            "occurred_ms": 100,
            "sequence": 0,
            "previous_hash": ZERO_HASH,
        }
        canonical = (
            b'{"exercise_id":"EX-42","id":"evt-1","kind":"discovery",'
            b'"occurred_ms":100,"outcome":"done","previous_hash":"'
            + ZERO_HASH.encode()
            + b'","sequence":0,"target":"app.example.com"}'
        )
        expected = hashlib.sha256(canonical).hexdigest()
        self.assertEqual(_audit_record_hash(record, "EX-42"), expected)
        self.assertEqual(expected, HASH_EVT1)


class BuildAuditServiceTest(unittest.TestCase):
    def setUp(self):
        self.service = Service()

    def build(self, **overrides):
        return self.service.build_audit(build_payload(**overrides))

    def test_single_record_chain(self):
        result = self.build()
        self.assertEqual(list(result), ["audit"])
        audit = result["audit"]
        self.assertEqual(set(audit), {"exercise_id", "records", "head_hash"})
        self.assertEqual(audit["exercise_id"], "EX-42")
        (record,) = audit["records"]
        self.assertEqual(
            record,
            {
                "id": "evt-1",
                "target": "app.example.com",
                "kind": "discovery",
                "outcome": "done",
                "occurred_ms": 100,
                "sequence": 0,
                "previous_hash": ZERO_HASH,
                "hash": HASH_EVT1,
            },
        )
        self.assertEqual(audit["head_hash"], HASH_EVT1)

    def test_chain_links_and_head(self):
        events = [
            make_event(id="evt-1", occurred_ms=100),
            make_event(
                id="evt-2", target="10.0.0.5", kind="verification",
                outcome="found", occurred_ms=250,
            ),
        ]
        audit = self.build(events=events)["audit"]
        first, second = audit["records"]
        self.assertEqual(first["sequence"], 0)
        self.assertEqual(first["previous_hash"], ZERO_HASH)
        self.assertEqual(first["hash"], HASH_EVT1)
        self.assertEqual(second["sequence"], 1)
        self.assertEqual(second["previous_hash"], HASH_EVT1)
        self.assertEqual(second["hash"], HASH_EVT2)
        self.assertEqual(audit["head_hash"], HASH_EVT2)

    def test_records_keep_input_order_and_normalize_target(self):
        events = [
            make_event(id="b", target="APP.Example.COM.", occurred_ms=2),
            make_event(id="a", target="app.example.com", occurred_ms=2),
        ]
        records = self.build(events=events)["audit"]["records"]
        self.assertEqual([r["id"] for r in records], ["b", "a"])
        self.assertTrue(all(r["target"] == "app.example.com" for r in records))

    def test_equal_timestamps_are_allowed(self):
        events = [
            make_event(id="a", occurred_ms=5),
            make_event(id="b", occurred_ms=5),
        ]
        records = self.build(events=events)["audit"]["records"]
        self.assertEqual([r["sequence"] for r in records], [0, 1])

    def test_empty_chain_has_zero_head(self):
        audit = self.build(events=[])["audit"]
        self.assertEqual(audit["records"], [])
        self.assertEqual(audit["head_hash"], ZERO_HASH)

    def test_deterministic(self):
        payload = build_payload(
            events=[
                make_event(id="a", occurred_ms=1),
                make_event(id="b", target="10.0.0.5", occurred_ms=2),
            ]
        )
        self.assertEqual(
            self.service.build_audit(payload), self.service.build_audit(payload)
        )

    def test_structure_errors(self):
        bad_payloads = [
            {},
            {"allow": [], "deny": [], "events": []},
            build_payload(extra=1),
            build_payload(allow={}),
            build_payload(allow="nope"),
            build_payload(exercise_id=""),
            build_payload(exercise_id=5),
            build_payload(events={}),
            build_payload(events=[{}]),
            build_payload(events=[make_event(extra=1)]),
            build_payload(events=[make_event(id="")]),
            build_payload(events=[make_event(id=4)]),
            build_payload(events=[make_event(target="*.example.com")]),
            build_payload(events=[make_event(target="bad host")]),
            build_payload(events=[make_event(kind="")]),
            build_payload(events=[make_event(kind=3)]),
            build_payload(events=[make_event(outcome="")]),
            build_payload(events=[make_event(outcome=False)]),
            build_payload(events=[make_event(occurred_ms=-1)]),
            build_payload(events=[make_event(occurred_ms=True)]),
            build_payload(events=[make_event(occurred_ms=1.5)]),
            build_payload(events=[make_event(occurred_ms="0")]),
            build_payload(
                events=[make_event(id="dup"), make_event(id="dup")]
            ),
            build_payload(
                events=[
                    make_event(id="a", occurred_ms=9),
                    make_event(id="b", occurred_ms=8),
                ]
            ),
        ]
        for payload in bad_payloads:
            with self.subTest(payload=repr(payload)[:90]):
                with self.assertRaises(ValueError):
                    self.service.build_audit(payload)

    def test_structure_error_precedes_scope(self):
        # Out-of-scope target plus a duplicate id: the structural error wins.
        with self.assertRaises(ValueError):
            self.build(
                events=[
                    make_event(id="x", target="evil.net"),
                    make_event(id="x", target="evil.net"),
                ]
            )
        # A bad timestamp with an out-of-scope target is also a 400.
        with self.assertRaises(ValueError):
            self.build(events=[make_event(target="evil.net", occurred_ms=-1)])

    def test_out_of_scope_is_403(self):
        with self.assertRaises(ScopeViolationError):
            self.build(events=[make_event(target="evil.net")])
        # deny wins over allow.
        with self.assertRaises(ScopeViolationError):
            self.build(
                deny=["app.example.com"],
                events=[make_event(target="app.example.com")],
            )

    def test_empty_events_still_gates_scope_rules(self):
        # Malformed allow rules are a 400 even without events.
        with self.assertRaises(ValueError):
            self.build(events=[], allow=["bad host"])


class VerifyAuditServiceTest(unittest.TestCase):
    def setUp(self):
        self.service = Service()
        events = [
            make_event(id="evt-1", occurred_ms=100),
            make_event(
                id="evt-2", target="10.0.0.5", kind="verification",
                outcome="found", occurred_ms=250,
            ),
        ]
        self.audit = self.service.build_audit(
            build_payload(events=events)
        )["audit"]

    def verify(self, audit=None, **overrides):
        return self.service.verify_audit(
            verify_payload(self.audit if audit is None else audit, **overrides)
        )["verification"]

    def test_valid_chain(self):
        verification = self.verify()
        self.assertTrue(verification["valid"])
        self.assertEqual(verification["checked"], 2)
        self.assertEqual(verification["head_hash"], HASH_EVT2)
        self.assertIsNone(verification["failure"])

    def test_empty_chain_valid(self):
        empty = self.service.build_audit(
            build_payload(events=[], allow=[], deny=[])
        )["audit"]
        verification = self.service.verify_audit(
            {"allow": [], "deny": [], "audit": empty}
        )["verification"]
        self.assertEqual(
            verification,
            {
                "valid": True,
                "checked": 0,
                "head_hash": ZERO_HASH,
                "failure": None,
            },
        )

    def test_sequence_mismatch_stops_checking(self):
        verification = self.verify(tamper(self.audit, 1, sequence=9))
        self.assertFalse(verification["valid"])
        self.assertEqual(verification["checked"], 1)
        self.assertEqual(verification["head_hash"], HASH_EVT1)
        self.assertEqual(
            verification["failure"],
            {"index": 1, "reason": "sequence_mismatch"},
        )

    def test_previous_hash_mismatch(self):
        verification = self.verify(tamper(self.audit, 1, previous_hash="a" * 64))
        self.assertFalse(verification["valid"])
        self.assertEqual(verification["checked"], 1)
        self.assertEqual(
            verification["failure"],
            {"index": 1, "reason": "previous_hash_mismatch"},
        )

    def test_first_previous_hash_must_be_zero(self):
        verification = self.verify(tamper(self.audit, 0, previous_hash="a" * 64))
        self.assertEqual(
            verification["failure"],
            {"index": 0, "reason": "previous_hash_mismatch"},
        )
        self.assertEqual(verification["checked"], 0)

    def test_hash_mismatch_on_tampered_payload(self):
        # Changing a hashed field without recomputing the hash breaks record 0.
        verification = self.verify(tamper(self.audit, 0, outcome="tampered"))
        self.assertFalse(verification["valid"])
        self.assertEqual(verification["checked"], 0)
        self.assertEqual(verification["head_hash"], ZERO_HASH)
        self.assertEqual(
            verification["failure"], {"index": 0, "reason": "hash_mismatch"}
        )

    def test_sequence_checked_before_previous_and_hash(self):
        verification = self.verify(
            tamper(self.audit, 1, sequence=9, previous_hash="a" * 64, hash="b" * 64)
        )
        self.assertEqual(
            verification["failure"]["reason"], "sequence_mismatch"
        )

    def test_previous_hash_checked_before_record_hash(self):
        verification = self.verify(
            tamper(self.audit, 1, previous_hash="a" * 64, hash="b" * 64)
        )
        self.assertEqual(
            verification["failure"]["reason"], "previous_hash_mismatch"
        )

    def test_head_hash_mismatch_index_is_record_count(self):
        broken = copy.deepcopy(self.audit)
        broken["head_hash"] = "f" * 64
        verification = self.verify(broken)
        self.assertFalse(verification["valid"])
        self.assertEqual(verification["checked"], 2)
        self.assertEqual(verification["head_hash"], HASH_EVT2)
        self.assertEqual(
            verification["failure"],
            {"index": 2, "reason": "head_hash_mismatch"},
        )

    def test_record_hash_checked_before_head_hash(self):
        broken = tamper(self.audit, 1, outcome="tampered")
        broken["head_hash"] = "f" * 64
        verification = self.verify(broken)
        self.assertEqual(verification["failure"]["reason"], "hash_mismatch")

    def test_empty_chain_nonzero_head_is_head_mismatch(self):
        empty = self.service.build_audit(
            build_payload(events=[], allow=[], deny=[])
        )["audit"]
        empty["head_hash"] = "f" * 64
        verification = self.service.verify_audit(
            {"allow": [], "deny": [], "audit": empty}
        )["verification"]
        self.assertEqual(
            verification["failure"],
            {"index": 0, "reason": "head_hash_mismatch"},
        )

    def test_structural_errors(self):
        good = self.audit

        def with_audit(audit_obj):
            return {
                "allow": ["*.example.com", "10.0.0.0/8"],
                "deny": [],
                "audit": audit_obj,
            }

        bad_audits_and_payloads = [
            {},
            {"allow": [], "deny": []},
            verify_payload(good, extra=1),
            verify_payload(good, allow={}),
            with_audit([]),
            with_audit({"exercise_id": "x"}),
            with_audit({**good, "extra": 1}),
            with_audit({**good, "exercise_id": ""}),
            with_audit({**good, "exercise_id": 7}),
            with_audit({**good, "head_hash": "zzz"}),
            with_audit({**good, "head_hash": "A" * 64}),
            with_audit({**good, "records": {}}),
            with_audit(tamper(good, 0, extra=1)),
            with_audit(tamper(good, 0, id="")),
            with_audit(tamper(good, 0, target="*.example.com")),
            with_audit(tamper(good, 0, kind="")),
            with_audit(tamper(good, 0, outcome="")),
            with_audit(tamper(good, 0, occurred_ms=-1)),
            with_audit(tamper(good, 0, occurred_ms=True)),
            with_audit(tamper(good, 0, sequence=-1)),
            with_audit(tamper(good, 0, sequence=1.0)),
            with_audit(tamper(good, 0, previous_hash="z" * 64)),
            with_audit(tamper(good, 0, hash="0" * 63)),
            with_audit(tamper(good, 0, hash="G" * 64)),
        ]
        for payload in bad_audits_and_payloads:
            with self.subTest(payload=repr(payload)[:90]):
                with self.assertRaises(ValueError):
                    self.service.verify_audit(payload)

    def test_duplicate_event_ids_is_structural(self):
        dup = copy.deepcopy(self.audit)
        dup["records"][1]["id"] = dup["records"][0]["id"]
        with self.assertRaises(ValueError):
            self.verify(dup)

    def test_non_increasing_timestamps_is_structural(self):
        ordered = copy.deepcopy(self.audit)
        ordered["records"][0]["occurred_ms"] = 250
        ordered["records"][1]["occurred_ms"] = 100
        with self.assertRaises(ValueError):
            self.verify(ordered)

    def test_tampered_hash_then_restored_sequence_still_rejected(self):
        # A claimed sequence beyond the chain length is caught regardless.
        verification = self.verify(tamper(self.audit, 0, sequence=1))
        self.assertEqual(
            verification["failure"],
            {"index": 0, "reason": "sequence_mismatch"},
        )

    def test_scope_gate_runs_after_structure(self):
        with self.assertRaises(ScopeViolationError):
            self.verify(allow=["example.org"])

    def test_scope_gate_precedes_chain_consistency(self):
        # Even with a broken chain, an out-of-scope target yields 403.
        broken = tamper(self.audit, 1, sequence=9)
        with self.assertRaises(ScopeViolationError):
            self.service.verify_audit(
                {"allow": ["example.org"], "deny": [], "audit": broken}
            )

    def test_normalized_target_used_for_scope(self):
        # The carried target is normalized again before the gate.
        audit = self.service.build_audit(
            build_payload(events=[make_event(target="APP.Example.COM.")])
        )["audit"]
        verification = self.service.verify_audit(
            {"allow": ["*.example.com"], "deny": [], "audit": audit}
        )["verification"]
        self.assertTrue(verification["valid"])


class AuditHttpTest(unittest.TestCase):
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

    def test_build_ok(self):
        status, payload = self.post(
            "/v1/audit/build", build_payload(events=[make_event()])
        )
        self.assertEqual(status, 200)
        self.assertEqual(list(payload), ["audit"])
        record = payload["audit"]["records"][0]
        self.assertEqual(record["hash"], HASH_EVT1)
        self.assertEqual(payload["audit"]["head_hash"], HASH_EVT1)

    def test_verify_ok_round_trip(self):
        _, built = self.post("/v1/audit/build", build_payload())
        status, payload = self.post(
            "/v1/audit/verify", {"allow": build_payload()["allow"], "deny": [],
                                  "audit": built["audit"]}
        )
        self.assertEqual(status, 200)
        self.assertEqual(list(payload), ["verification"])
        self.assertTrue(payload["verification"]["valid"])

    def test_build_empty_chain(self):
        status, payload = self.post(
            "/v1/audit/build", build_payload(events=[])
        )
        self.assertEqual(status, 200)
        self.assertEqual(payload["audit"]["records"], [])
        self.assertEqual(payload["audit"]["head_hash"], ZERO_HASH)

    def test_build_invalid_request_400(self):
        status, payload = self.post(
            "/v1/audit/build", {"allow": [], "deny": [], "events": []}
        )
        self.assertEqual(status, 400)
        self.assertEqual(payload["error"]["code"], "invalid_request")

    def test_build_scope_violation_403(self):
        status, payload = self.post(
            "/v1/audit/build", build_payload(events=[make_event(target="evil.net")])
        )
        self.assertEqual(status, 403)
        self.assertEqual(payload["error"]["code"], "scope_violation")
        self.assertNotIn("audit", payload)

    def test_verify_invalid_request_400(self):
        status, payload = self.post("/v1/audit/verify", {"allow": [], "deny": []})
        self.assertEqual(status, 400)
        self.assertEqual(payload["error"]["code"], "invalid_request")

    def test_verify_hash_mismatch_200(self):
        _, built = self.post("/v1/audit/build", build_payload())
        audit = built["audit"]
        audit["records"][0]["outcome"] = "tampered"
        status, payload = self.post(
            "/v1/audit/verify",
            {"allow": build_payload()["allow"], "deny": [], "audit": audit},
        )
        self.assertEqual(status, 200)
        self.assertEqual(
            payload["verification"]["failure"],
            {"index": 0, "reason": "hash_mismatch"},
        )
        self.assertFalse(payload["verification"]["valid"])

    def test_verify_scope_violation_403(self):
        _, built = self.post("/v1/audit/build", build_payload())
        status, payload = self.post(
            "/v1/audit/verify",
            {"allow": ["example.org"], "deny": [], "audit": built["audit"]},
        )
        self.assertEqual(status, 403)
        self.assertEqual(payload["error"]["code"], "scope_violation")

    def test_malformed_json_400(self):
        for path in ("/v1/audit/build", "/v1/audit/verify"):
            with self.subTest(path=path):
                status, payload = self.request("POST", path, b"{nope")
                self.assertEqual(status, 400)
                self.assertEqual(payload["error"]["code"], "invalid_request")

    def test_method_not_allowed_405(self):
        for path in ("/v1/audit/build", "/v1/audit/verify"):
            for method in ("GET", "PUT", "DELETE", "PATCH"):
                with self.subTest(path=path, method=method):
                    status, payload = self.request(method, path)
                    self.assertEqual(status, 405)
                    self.assertEqual(
                        payload["error"]["code"], "method_not_allowed"
                    )

    def test_unknown_route_404(self):
        status, payload = self.request("POST", "/v1/audit/nope", b"{}")
        self.assertEqual(status, 404)
        self.assertEqual(payload["error"]["code"], "not_found")


if __name__ == "__main__":
    unittest.main()
