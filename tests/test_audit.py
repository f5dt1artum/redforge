import hashlib
import json
import threading
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

from redforge.server import Handler
from redforge.service import ZERO_HASH, ScopeViolationError, Service


def make_event(**overrides):
    event = {
        "id": "evt-1",
        "target": "app.example.com",
        "kind": "discovery",
        "outcome": "success",
        "occurred_ms": 0,
    }
    event.update(overrides)
    return event


def build_payload(**overrides):
    payload = {
        "allow": ["*.example.com", "10.0.0.0/8"],
        "deny": [],
        "exercise_id": "ex-1",
        "events": [make_event()],
    }
    payload.update(overrides)
    return payload


def canonical_record(exercise_id, record):
    """Independently canonicalize a record (minus hash) per RFC 8785."""
    obj = {key: value for key, value in record.items() if key != "hash"}
    obj["exercise_id"] = exercise_id
    parts = []
    for key in sorted(obj):
        parts.append(json.dumps(key) + ":" + json.dumps(obj[key]))
    return ("{" + ",".join(parts) + "}").encode("utf-8")


def expected_hash(exercise_id, record):
    return hashlib.sha256(canonical_record(exercise_id, record)).hexdigest()


def build_audit(service, **overrides):
    return service.build_audit(build_payload(**overrides))["audit"]


def verify_payload(audit, **overrides):
    payload = {
        "allow": ["*.example.com", "10.0.0.0/8"],
        "deny": [],
        "audit": audit,
    }
    payload.update(overrides)
    return payload


class AuditBuildServiceTest(unittest.TestCase):
    def setUp(self):
        self.service = Service()

    def build(self, **overrides):
        return build_audit(self.service, **overrides)

    def test_single_event_chain(self):
        audit = self.build(events=[make_event(occurred_ms=250)])
        self.assertEqual(list(audit), ["exercise_id", "records", "head_hash"])
        self.assertEqual(audit["exercise_id"], "ex-1")
        (record,) = audit["records"]
        self.assertEqual(
            list(record),
            [
                "id",
                "target",
                "kind",
                "outcome",
                "occurred_ms",
                "sequence",
                "previous_hash",
                "hash",
            ],
        )
        self.assertEqual(record["id"], "evt-1")
        self.assertEqual(record["target"], "app.example.com")
        self.assertEqual(record["kind"], "discovery")
        self.assertEqual(record["outcome"], "success")
        self.assertEqual(record["occurred_ms"], 250)
        self.assertEqual(record["sequence"], 0)
        self.assertEqual(record["previous_hash"], ZERO_HASH)
        self.assertEqual(record["hash"], expected_hash("ex-1", record))
        self.assertEqual(audit["head_hash"], record["hash"])

    def test_empty_events_returns_empty_chain_with_zero_head(self):
        audit = self.build(events=[])
        self.assertEqual(
            audit,
            {"exercise_id": "ex-1", "records": [], "head_hash": ZERO_HASH},
        )

    def test_records_keep_input_order_and_link_hashes(self):
        events = [
            make_event(id="a", occurred_ms=100),
            make_event(id="b", occurred_ms=100),
            make_event(id="c", occurred_ms=300),
        ]
        audit = self.build(events=events)
        records = audit["records"]
        self.assertEqual([r["id"] for r in records], ["a", "b", "c"])
        self.assertEqual([r["sequence"] for r in records], [0, 1, 2])
        self.assertEqual(records[0]["previous_hash"], ZERO_HASH)
        for previous, current in zip(records, records[1:]):
            self.assertEqual(current["previous_hash"], previous["hash"])
        self.assertEqual(audit["head_hash"], records[-1]["hash"])
        for record in records:
            self.assertEqual(
                record["hash"], expected_hash("ex-1", record)
            )

    def test_target_is_normalized_before_hashing(self):
        audit = self.build(events=[make_event(target="APP.Example.COM.")])
        (record,) = audit["records"]
        self.assertEqual(record["target"], "app.example.com")
        self.assertEqual(record["hash"], expected_hash("ex-1", record))

    def test_exercise_id_changes_hashes(self):
        events = [make_event()]
        first = self.build(events=[dict(e) for e in events])
        second = self.build(exercise_id="ex-2", events=[dict(e) for e in events])
        self.assertNotEqual(
            first["records"][0]["hash"], second["records"][0]["hash"]
        )

    def test_result_is_stable(self):
        events = [make_event(id=f"e{i}", occurred_ms=i * 100) for i in range(4)]
        first = self.build(events=[dict(e) for e in events])
        second = self.build(events=[dict(e) for e in events])
        self.assertEqual(first, second)

    def test_scope_violation_raises_after_structure_ok(self):
        with self.assertRaises(ScopeViolationError):
            self.build(events=[make_event(target="evil.net")])
        with self.assertRaises(ScopeViolationError):
            self.build(deny=["app.example.com"])
        with self.assertRaises(ScopeViolationError):
            self.build(allow=["10.0.0.0/8"])

    def test_empty_events_still_validates_scope_rules(self):
        with self.assertRaises(ValueError):
            self.build(events=[], allow=["bad_host"])

    def test_validation_errors(self):
        bad_payloads = [
            None,
            [],
            {},
            {"allow": [], "deny": [], "exercise_id": "x"},
            build_payload(extra=1),
            build_payload(allow="*.example.com"),
            build_payload(deny=["bad_host"]),
            build_payload(exercise_id=""),
            build_payload(exercise_id=1),
            build_payload(events={}),
            build_payload(events=[{"id": "a"}]),
            build_payload(events=[make_event(extra=1)]),
            build_payload(events=[make_event(id="")]),
            build_payload(events=[make_event(id=1)]),
            build_payload(events=[make_event(target="*.example.com")]),
            build_payload(events=[make_event(target="bad_host")]),
            build_payload(events=[make_event(kind="")]),
            build_payload(events=[make_event(kind=1)]),
            build_payload(events=[make_event(outcome="")]),
            build_payload(events=[make_event(outcome=None)]),
            build_payload(events=[make_event(occurred_ms=-1)]),
            build_payload(events=[make_event(occurred_ms=1.5)]),
            build_payload(events=[make_event(occurred_ms=True)]),
            build_payload(events=[make_event(occurred_ms="0")]),
            build_payload(
                events=[make_event(id="dup"), make_event(id="dup")]
            ),
            # occurred_ms must not decrease along the input order.
            build_payload(
                events=[
                    make_event(id="a", occurred_ms=200),
                    make_event(id="b", occurred_ms=100),
                ]
            ),
        ]
        for payload in bad_payloads:
            with self.subTest(payload=repr(payload)[:80]):
                with self.assertRaises(ValueError):
                    self.service.build_audit(payload)

    def test_structure_error_takes_precedence_over_scope(self):
        with self.assertRaises(ValueError):
            self.build(
                events=[
                    make_event(id="x", target="evil.net"),
                    make_event(id="x", target="evil.net"),
                ]
            )
        with self.assertRaises(ValueError):
            self.build(events=[make_event(target="evil.net", kind="")])


class AuditVerifyServiceTest(unittest.TestCase):
    def setUp(self):
        self.service = Service()

    def built(self, **overrides):
        return build_audit(self.service, **overrides)

    def verify(self, audit, **overrides):
        return self.service.verify_audit(verify_payload(audit, **overrides))[
            "verification"
        ]

    def test_round_trip_valid(self):
        audit = self.built(
            events=[
                make_event(id="a", occurred_ms=100),
                make_event(id="b", occurred_ms=200),
                make_event(id="c", occurred_ms=300),
            ]
        )
        result = self.verify(audit)
        self.assertEqual(
            result,
            {
                "valid": True,
                "checked": 3,
                "head_hash": audit["head_hash"],
                "failure": None,
            },
        )

    def test_empty_chain_valid(self):
        audit = self.built(events=[])
        result = self.verify(audit)
        self.assertEqual(
            result,
            {
                "valid": True,
                "checked": 0,
                "head_hash": ZERO_HASH,
                "failure": None,
            },
        )

    def test_sequence_mismatch(self):
        audit = self.built(
            events=[make_event(id="a"), make_event(id="b", occurred_ms=1)]
        )
        audit["records"][1]["sequence"] = 5
        result = self.verify(audit)
        self.assertFalse(result["valid"])
        self.assertEqual(result["checked"], 1)
        self.assertEqual(result["head_hash"], audit["records"][0]["hash"])
        self.assertEqual(
            result["failure"], {"index": 1, "reason": "sequence_mismatch"}
        )

    def test_previous_hash_mismatch(self):
        audit = self.built(
            events=[make_event(id="a"), make_event(id="b", occurred_ms=1)]
        )
        audit["records"][1]["previous_hash"] = ZERO_HASH
        result = self.verify(audit)
        self.assertFalse(result["valid"])
        self.assertEqual(result["checked"], 1)
        self.assertEqual(
            result["failure"],
            {"index": 1, "reason": "previous_hash_mismatch"},
        )

    def test_first_record_previous_hash_must_be_zero(self):
        audit = self.built(events=[make_event()])
        audit["records"][0]["previous_hash"] = "f" * 64
        result = self.verify(audit)
        self.assertEqual(result["checked"], 0)
        self.assertEqual(result["head_hash"], ZERO_HASH)
        self.assertEqual(
            result["failure"],
            {"index": 0, "reason": "previous_hash_mismatch"},
        )

    def test_hash_mismatch(self):
        audit = self.built(
            events=[make_event(id="a"), make_event(id="b", occurred_ms=1)]
        )
        audit["records"][0]["hash"] = "0" * 63 + "1"
        result = self.verify(audit)
        self.assertFalse(result["valid"])
        self.assertEqual(result["checked"], 0)
        self.assertEqual(result["head_hash"], ZERO_HASH)
        self.assertEqual(
            result["failure"], {"index": 0, "reason": "hash_mismatch"}
        )

    def test_tampered_content_breaks_hash(self):
        audit = self.built(events=[make_event()])
        audit["records"][0]["outcome"] = "failure"
        result = self.verify(audit)
        self.assertEqual(
            result["failure"], {"index": 0, "reason": "hash_mismatch"}
        )

    def test_head_hash_mismatch(self):
        audit = self.built(
            events=[make_event(id="a"), make_event(id="b", occurred_ms=1)]
        )
        audit["head_hash"] = "0" * 63 + "1"
        result = self.verify(audit)
        self.assertFalse(result["valid"])
        self.assertEqual(result["checked"], 2)
        self.assertEqual(result["head_hash"], audit["records"][1]["hash"])
        self.assertEqual(
            result["failure"], {"index": 2, "reason": "head_hash_mismatch"}
        )

    def test_empty_chain_with_nonzero_head_hash(self):
        audit = self.built(events=[])
        audit["head_hash"] = "f" * 64
        result = self.verify(audit)
        self.assertFalse(result["valid"])
        self.assertEqual(result["checked"], 0)
        self.assertEqual(result["head_hash"], ZERO_HASH)
        self.assertEqual(
            result["failure"], {"index": 0, "reason": "head_hash_mismatch"}
        )

    def test_first_failure_wins(self):
        audit = self.built(
            events=[make_event(id="a"), make_event(id="b", occurred_ms=1)]
        )
        # Both records are broken; only the first failure is reported.
        audit["records"][0]["sequence"] = 9
        audit["records"][1]["hash"] = "f" * 64
        result = self.verify(audit)
        self.assertEqual(
            result["failure"], {"index": 0, "reason": "sequence_mismatch"}
        )
        self.assertEqual(result["checked"], 0)

    def test_scope_violation_raises(self):
        audit = self.built(events=[make_event()])
        with self.assertRaises(ScopeViolationError):
            self.verify(audit, deny=["app.example.com"])
        evil = self.built(events=[make_event(target="evil.example.com")])
        with self.assertRaises(ScopeViolationError):
            self.verify(evil, allow=["app.example.com"])

    def test_validation_errors(self):
        good = self.built(events=[make_event()])

        def record_audit(**record_overrides):
            record = dict(good["records"][0])
            record.update(record_overrides)
            return {
                "exercise_id": "ex-1",
                "records": [record],
                "head_hash": good["head_hash"],
            }

        bad_audits = [
            None,
            [],
            {},
            {"exercise_id": "ex-1", "records": []},
            {"exercise_id": "ex-1", "records": [], "head_hash": ZERO_HASH, "x": 1},
            {"exercise_id": "", "records": [], "head_hash": ZERO_HASH},
            {"exercise_id": "ex-1", "records": {}, "head_hash": ZERO_HASH},
            {"exercise_id": "ex-1", "records": [], "head_hash": ""},
            {"exercise_id": "ex-1", "records": [], "head_hash": "F" * 64},
            {"exercise_id": "ex-1", "records": [], "head_hash": "0" * 63},
            {"exercise_id": "ex-1", "records": [], "head_hash": 0},
            record_audit(hash="F" * 64),
            record_audit(hash="0" * 65),
            record_audit(previous_hash="zz"),
            record_audit(sequence=-1),
            record_audit(sequence=True),
            record_audit(sequence="0"),
            record_audit(occurred_ms=-1),
            record_audit(kind=""),
            record_audit(outcome=""),
            record_audit(extra=1),
        ]
        for audit in bad_audits:
            with self.subTest(audit=repr(audit)[:80]):
                with self.assertRaises(ValueError):
                    self.verify(audit)

        # Duplicate event ids and decreasing occurred_ms are structural.
        two = self.built(
            events=[make_event(id="a"), make_event(id="b", occurred_ms=1)]
        )
        dup = dict(two)
        dup["records"] = [dict(two["records"][0]), dict(two["records"][0])]
        with self.assertRaises(ValueError):
            self.verify(dup)
        reordered = dict(two)
        reordered["records"] = [
            dict(two["records"][1]),
            dict(two["records"][0]),
        ]
        with self.assertRaises(ValueError):
            self.verify(reordered)

        # Bad payload envelope.
        for payload in (None, [], {}, {"allow": [], "deny": []}):
            with self.assertRaises(ValueError):
                self.service.verify_audit(payload)
        with self.assertRaises(ValueError):
            self.service.verify_audit(verify_payload(good, extra=1))
        with self.assertRaises(ValueError):
            self.service.verify_audit(verify_payload(good, allow="x"))

    def test_structure_error_takes_precedence_over_scope(self):
        audit = self.built(events=[make_event()])
        audit["records"][0]["hash"] = "not-a-hash"
        with self.assertRaises(ValueError):
            self.verify(audit, deny=["app.example.com"])


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

    def post_build(self, payload):
        return self.request(
            "POST", "/v1/audit/build", json.dumps(payload).encode()
        )

    def post_verify(self, payload):
        return self.request(
            "POST", "/v1/audit/verify", json.dumps(payload).encode()
        )

    def test_build_ok(self):
        status, payload = self.post_build(
            build_payload(
                events=[
                    make_event(id="a", occurred_ms=100),
                    make_event(id="b", occurred_ms=200),
                ]
            )
        )
        self.assertEqual(status, 200)
        self.assertEqual(list(payload), ["audit"])
        audit = payload["audit"]
        self.assertEqual(audit["exercise_id"], "ex-1")
        self.assertEqual(len(audit["records"]), 2)
        self.assertEqual(audit["records"][0]["previous_hash"], ZERO_HASH)
        self.assertEqual(
            audit["records"][1]["previous_hash"],
            audit["records"][0]["hash"],
        )
        self.assertEqual(audit["head_hash"], audit["records"][1]["hash"])

    def test_build_empty_events_ok(self):
        status, payload = self.post_build(build_payload(events=[]))
        self.assertEqual(status, 200)
        self.assertEqual(
            payload,
            {
                "audit": {
                    "exercise_id": "ex-1",
                    "records": [],
                    "head_hash": ZERO_HASH,
                }
            },
        )

    def test_verify_round_trip_ok(self):
        _, built = self.post_build(
            build_payload(
                events=[
                    make_event(id="a", occurred_ms=100),
                    make_event(id="b", occurred_ms=200),
                ]
            )
        )
        status, payload = self.post_verify(verify_payload(built["audit"]))
        self.assertEqual(status, 200)
        self.assertEqual(list(payload), ["verification"])
        self.assertEqual(
            payload["verification"],
            {
                "valid": True,
                "checked": 2,
                "head_hash": built["audit"]["head_hash"],
                "failure": None,
            },
        )

    def test_verify_detects_tampering(self):
        _, built = self.post_build(build_payload(events=[make_event()]))
        built["audit"]["records"][0]["kind"] = "exploitation"
        status, payload = self.post_verify(verify_payload(built["audit"]))
        self.assertEqual(status, 200)
        verification = payload["verification"]
        self.assertFalse(verification["valid"])
        self.assertEqual(verification["checked"], 0)
        self.assertEqual(
            verification["failure"], {"index": 0, "reason": "hash_mismatch"}
        )

    def test_scope_violation_403(self):
        status, payload = self.post_build(
            build_payload(events=[make_event(target="evil.net")])
        )
        self.assertEqual(status, 403)
        self.assertEqual(payload["error"]["code"], "scope_violation")
        self.assertNotIn("audit", payload)

        _, built = self.post_build(build_payload(events=[make_event()]))
        status, payload = self.post_verify(
            verify_payload(built["audit"], deny=["app.example.com"])
        )
        self.assertEqual(status, 403)
        self.assertEqual(payload["error"]["code"], "scope_violation")
        self.assertNotIn("verification", payload)

    def test_invalid_request_400(self):
        status, payload = self.post_build({"allow": [], "deny": []})
        self.assertEqual(status, 400)
        self.assertEqual(payload["error"]["code"], "invalid_request")
        status, payload = self.post_verify({"allow": [], "deny": []})
        self.assertEqual(status, 400)
        self.assertEqual(payload["error"]["code"], "invalid_request")

    def test_malformed_json_400(self):
        status, payload = self.request("POST", "/v1/audit/build", b"{nope")
        self.assertEqual(status, 400)
        self.assertEqual(payload["error"]["code"], "invalid_request")

    def test_oversized_body_413(self):
        import http.client

        conn = http.client.HTTPConnection("127.0.0.1", self.port)
        conn.putrequest("POST", "/v1/audit/build")
        conn.putheader("Content-Length", str(1024 * 1024 + 1))
        conn.endheaders()
        resp = conn.getresponse()
        payload = json.loads(resp.read())
        conn.close()
        self.assertEqual(resp.status, 413)
        self.assertEqual(payload["error"]["code"], "request_too_large")

    def test_method_not_allowed_405(self):
        for path in ("/v1/audit/build", "/v1/audit/verify"):
            for method in ("GET", "PUT", "DELETE", "PATCH"):
                with self.subTest(method=method, path=path):
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
