import json
import threading
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

from redforge.server import Handler
from redforge.service import ScopeViolationError, Service


def make_finding(**overrides):
    finding = {
        "observation_id": "obs-1",
        "target": "app.example.com",
        "template_id": "tpl-1",
        "name": "Demo template",
        "severity": "high",
        "evidence": [0],
    }
    finding.update(overrides)
    return finding


def make_run(**overrides):
    run = {"id": "run-1", "reliability": 50, "findings": [make_finding()]}
    run.update(overrides)
    return run


def consolidated_item(**overrides):
    item = {
        "target": "app.example.com",
        "template_id": "tpl-1",
        "name": "Demo template",
        "severity": "high",
        "observation_ids": ["obs-1"],
        "sources": ["run-1"],
        "evidence": [0],
        "confidence": 50,
    }
    item.update(overrides)
    return item


def retest_payload(**overrides):
    payload = {
        "allow": ["*.example.com"],
        "deny": [],
        "baseline": [consolidated_item()],
        "retest_runs": [make_run()],
    }
    payload.update(overrides)
    return payload


class RetestServiceTest(unittest.TestCase):
    def setUp(self):
        self.service = Service()

    def retest(self, **overrides):
        return self.service.retest_findings(retest_payload(**overrides))

    def test_persistent_keeps_baseline_order_and_name(self):
        result = self.retest()
        self.assertEqual(list(result), ["comparisons", "summary"])
        (cmp_,) = result["comparisons"]
        self.assertEqual(
            list(cmp_),
            ["target", "template_id", "name", "status", "before", "after"],
        )
        self.assertEqual(cmp_["target"], "app.example.com")
        self.assertEqual(cmp_["template_id"], "tpl-1")
        self.assertEqual(cmp_["name"], "Demo template")
        self.assertEqual(cmp_["status"], "persistent")
        self.assertEqual(cmp_["before"]["target"], "app.example.com")
        self.assertEqual(cmp_["before"]["confidence"], 50)
        self.assertEqual(cmp_["after"]["sources"], ["run-1"])
        self.assertEqual(cmp_["after"]["confidence"], 50)
        self.assertEqual(
            result["summary"],
            {
                "total_before": 1,
                "total_after": 1,
                "persistent": 1,
                "resolved": 0,
                "new": 0,
            },
        )

    def test_resolved_when_missing_from_retest(self):
        result = self.retest(retest_runs=[make_run(findings=[])])
        (cmp_,) = result["comparisons"]
        self.assertEqual(cmp_["status"], "resolved")
        self.assertIsNotNone(cmp_["before"])
        self.assertIsNone(cmp_["after"])
        self.assertEqual(
            result["summary"],
            {
                "total_before": 1,
                "total_after": 0,
                "persistent": 0,
                "resolved": 1,
                "new": 0,
            },
        )

    def test_new_with_empty_baseline(self):
        result = self.retest(baseline=[])
        (cmp_,) = result["comparisons"]
        self.assertEqual(cmp_["status"], "new")
        self.assertIsNone(cmp_["before"])
        self.assertIsNotNone(cmp_["after"])
        self.assertEqual(cmp_["name"], "Demo template")
        self.assertEqual(
            result["summary"],
            {
                "total_before": 0,
                "total_after": 1,
                "persistent": 0,
                "resolved": 0,
                "new": 1,
            },
        )

    def test_empty_everything(self):
        result = self.retest(baseline=[], retest_runs=[make_run(findings=[])])
        self.assertEqual(result["comparisons"], [])
        self.assertEqual(
            result["summary"],
            {
                "total_before": 0,
                "total_after": 0,
                "persistent": 0,
                "resolved": 0,
                "new": 0,
            },
        )

    def test_comparison_order_baseline_first_then_new(self):
        baseline = [
            consolidated_item(target="b.example.com", template_id="x"),
            consolidated_item(target="a.example.com", template_id="y"),
        ]
        retest_runs = [
            make_run(
                id="r2",
                findings=[
            make_finding(target="a.example.com", template_id="y"),
            make_finding(target="c.example.com", template_id="z"),
                ],
            )
        ]
        result = self.retest(baseline=baseline, retest_runs=retest_runs)
        self.assertEqual(
            [
                (c["target"], c["template_id"], c["status"])
                for c in result["comparisons"]
            ],
            [
                ("b.example.com", "x", "resolved"),
                ("a.example.com", "y", "persistent"),
                ("c.example.com", "z", "new"),
            ],
        )
        self.assertEqual(
            result["summary"],
            {
                "total_before": 2,
                "total_after": 2,
                "persistent": 1,
                "resolved": 1,
                "new": 1,
            },
        )

    def test_normalized_target_is_the_comparison_key(self):
        result = self.retest(
            baseline=[consolidated_item(target="APP.Example.COM.")]
        )
        (cmp_,) = result["comparisons"]
        self.assertEqual(cmp_["status"], "persistent")
        self.assertEqual(cmp_["target"], "app.example.com")
        self.assertEqual(cmp_["before"]["target"], "app.example.com")

    def test_template_id_is_case_sensitive(self):
        result = self.retest(
            baseline=[consolidated_item(template_id="TPL", name="A")],
            retest_runs=[make_run(findings=[make_finding(template_id="tpl")])],
        )
        statuses = [(c["template_id"], c["status"]) for c in result["comparisons"]]
        self.assertEqual(statuses, [("TPL", "resolved"), ("tpl", "new")])

    def test_name_prefers_baseline_and_field_changes_keep_persistent(self):
        result = self.retest(
            retest_runs=[
                make_run(
                    reliability=90,
                    findings=[
                        make_finding(
                            name="Brand new name",
                            severity="critical",
                            observation_id="obs-9",
                            evidence=[3, 4],
                        )
                    ],
                )
            ]
        )
        (cmp_,) = result["comparisons"]
        self.assertEqual(cmp_["status"], "persistent")
        self.assertEqual(cmp_["name"], "Demo template")
        self.assertEqual(cmp_["after"]["name"], "Brand new name")
        self.assertEqual(cmp_["after"]["severity"], "critical")

    def test_after_item_has_full_consolidation_semantics(self):
        result = self.retest(
            baseline=[],
            retest_runs=[
                make_run(id="r1", reliability=50, findings=[make_finding(evidence=[2, 0])]),
                make_run(
                    id="r2",
                    reliability=80,
                    findings=[make_finding(observation_id="obs-2", evidence=[1])],
                ),
            ],
        )
        (cmp_,) = result["comparisons"]
        after = cmp_["after"]
        self.assertEqual(after["observation_ids"], ["obs-1", "obs-2"])
        self.assertEqual(after["sources"], ["r1", "r2"])
        self.assertEqual(after["evidence"], [0, 1, 2])
        self.assertEqual(after["confidence"], 90)

    def test_baseline_shape_matches_consolidate_output(self):
        # A baseline taken verbatim from a consolidate response must compare.
        first = self.service.consolidate_findings(
            {
                "allow": ["*.example.com"],
                "deny": [],
                "runs": [
                    make_run(
                        id="r1",
                        reliability=70,
                        findings=[make_finding(evidence=[0, 1])],
                    )
                ],
            }
        )["consolidated"]
        result = self.service.retest_findings(
            {
                "allow": ["*.example.com"],
                "deny": [],
                "baseline": first,
                "retest_runs": [make_run(id="r2", reliability=40)],
            }
        )
        (cmp_,) = result["comparisons"]
        self.assertEqual(cmp_["status"], "persistent")
        self.assertEqual(cmp_["before"]["evidence"], [0, 1])
        self.assertEqual(cmp_["before"]["confidence"], 70)

    def test_duplicate_baseline_key_is_invalid(self):
        with self.assertRaises(ValueError):
            self.retest(
                baseline=[
                    consolidated_item(),
                    consolidated_item(name="Other"),
                ]
            )
        # The same key reached through different target spellings counts too.
        with self.assertRaises(ValueError):
            self.retest(
                baseline=[
                    consolidated_item(),
                    consolidated_item(target="APP.Example.COM."),
                ]
            )

    def test_scope_violation_in_either_side_raises(self):
        with self.assertRaises(ScopeViolationError):
            self.retest(
                baseline=[consolidated_item(target="evil.net")]
            )
        with self.assertRaises(ScopeViolationError):
            self.retest(
                retest_runs=[make_run(findings=[make_finding(target="evil.net")])]
            )
        with self.assertRaises(ScopeViolationError):
            self.retest(deny=["app.example.com"])

    def test_structure_validated_before_scope_gate(self):
        # A malformed baseline is a 400 even though the retest also carries
        # an out-of-scope target.
        with self.assertRaises(ValueError):
            self.retest(
                baseline=[consolidated_item(confidence=200)],
                retest_runs=[make_run(findings=[make_finding(target="evil.net")])],
            )

    def test_validation_errors(self):
        bad_payloads = [
            None,
            [],
            {},
            {"allow": [], "deny": []},
            {"allow": [], "deny": [], "baseline": []},
            retest_payload(extra=1),
            retest_payload(allow="*.example.com"),
            retest_payload(deny=1),
            retest_payload(allow=["not a host!!"]),
            retest_payload(baseline={}),
            retest_payload(baseline="x"),
            retest_payload(baseline=[None]),
            retest_payload(baseline=["x"]),
            retest_payload(baseline=[{"target": "app.example.com"}]),
            retest_payload(baseline=[consolidated_item(extra=1)]),
            retest_payload(baseline=[consolidated_item(target="bad_host")]),
            retest_payload(baseline=[consolidated_item(target="*.example.com")]),
            retest_payload(baseline=[consolidated_item(template_id="")]),
            retest_payload(baseline=[consolidated_item(template_id=3)]),
            retest_payload(baseline=[consolidated_item(name="")]),
            retest_payload(baseline=[consolidated_item(name=4)]),
            retest_payload(baseline=[consolidated_item(severity="fatal")]),
            retest_payload(baseline=[consolidated_item(observation_ids="x")]),
            retest_payload(baseline=[consolidated_item(observation_ids=[1])]),
            retest_payload(baseline=[consolidated_item(observation_ids=[""])]),
            retest_payload(baseline=[consolidated_item(sources={})]),
            retest_payload(baseline=[consolidated_item(sources=[1])]),
            retest_payload(baseline=[consolidated_item(sources=[""])]),
            retest_payload(baseline=[consolidated_item(evidence={})]),
            retest_payload(baseline=[consolidated_item(evidence="0")]),
            retest_payload(baseline=[consolidated_item(evidence=[-1])]),
            retest_payload(baseline=[consolidated_item(evidence=[True])]),
            retest_payload(baseline=[consolidated_item(evidence=[1.5])]),
            retest_payload(baseline=[consolidated_item(evidence=[1, "2"])]),
            retest_payload(baseline=[consolidated_item(confidence=-1)]),
            retest_payload(baseline=[consolidated_item(confidence=101)]),
            retest_payload(baseline=[consolidated_item(confidence="50")]),
            retest_payload(baseline=[consolidated_item(confidence=True)]),
            retest_payload(baseline=[consolidated_item(confidence=1.5)]),
            # retest_runs inherit the runs constraints
            retest_payload(retest_runs=[]),
            retest_payload(retest_runs={}),
            retest_payload(retest_runs="x"),
            retest_payload(retest_runs=[None]),
            retest_payload(retest_runs=[{"id": "r1", "reliability": 0}]),
            retest_payload(retest_runs=[make_run(extra=1)]),
            retest_payload(retest_runs=[make_run(id="")]),
            retest_payload(retest_runs=[make_run(reliability=-1)]),
            retest_payload(retest_runs=[make_run(reliability=101)]),
            retest_payload(retest_runs=[make_run(reliability=True)]),
            retest_payload(retest_runs=[make_run(), make_run(id="run-1")]),
            retest_payload(
                retest_runs=[make_run(findings=[make_finding(severity="nope")])]
            ),
            retest_payload(
                retest_runs=[make_run(findings=[make_finding(evidence=[-1])])]
            ),
        ]
        for payload in bad_payloads:
            with self.subTest(payload=repr(payload)[:90]):
                with self.assertRaises(ValueError):
                    self.service.retest_findings(payload)

    def test_empty_baseline_evidence_is_allowed(self):
        # The consolidated shape only requires evidence to be non-negative
        # integers; an empty array stays a valid baseline item.
        result = self.retest(baseline=[consolidated_item(evidence=[])])
        (cmp_,) = result["comparisons"]
        self.assertEqual(cmp_["before"]["evidence"], [])

    def test_order_is_stable_for_same_input(self):
        payload = retest_payload(
            baseline=[
                consolidated_item(target="b.example.com", template_id="x"),
                consolidated_item(target="a.example.com", template_id="y"),
            ],
            retest_runs=[
                make_run(
                    id="r2",
                    findings=[
                        make_finding(target="c.example.com", template_id="z"),
                        make_finding(target="a.example.com", template_id="y"),
                    ],
                )
            ],
        )
        first = self.service.retest_findings(payload)
        second = self.service.retest_findings(payload)
        self.assertEqual(first, second)


class RetestHttpTest(unittest.TestCase):
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

    def post(self, payload):
        return self.request(
            "POST", "/v1/findings/retest", json.dumps(payload).encode()
        )

    def test_retest_ok(self):
        status, payload = self.post(
            retest_payload(
                baseline=[
                    consolidated_item(target="a.example.com", template_id="p"),
                    consolidated_item(target="b.example.com", template_id="q"),
                ],
                retest_runs=[
                    make_run(
                        id="r2",
                        findings=[
                            make_finding(target="a.example.com", template_id="p"),
                            make_finding(target="c.example.com", template_id="r"),
                        ],
                    )
                ],
            )
        )
        self.assertEqual(status, 200)
        self.assertEqual(list(payload), ["comparisons", "summary"])
        self.assertEqual(
            [(c["template_id"], c["status"]) for c in payload["comparisons"]],
            [("p", "persistent"), ("q", "resolved"), ("r", "new")],
        )
        for cmp_ in payload["comparisons"]:
            self.assertEqual(
                set(cmp_),
                {"target", "template_id", "name", "status", "before", "after"},
            )
        self.assertEqual(
            payload["summary"],
            {
                "total_before": 2,
                "total_after": 2,
                "persistent": 1,
                "resolved": 1,
                "new": 1,
            },
        )

    def test_empty_retest_findings_all_resolved(self):
        status, payload = self.post(
            retest_payload(retest_runs=[make_run(findings=[])])
        )
        self.assertEqual(status, 200)
        self.assertEqual(payload["comparisons"][0]["status"], "resolved")
        self.assertIsNone(payload["comparisons"][0]["after"])

    def test_scope_violation_403(self):
        status, payload = self.post(
            retest_payload(baseline=[consolidated_item(target="evil.net")])
        )
        self.assertEqual(status, 403)
        self.assertEqual(payload["error"]["code"], "scope_violation")
        self.assertNotIn("comparisons", payload)

    def test_invalid_request_400(self):
        status, payload = self.post(retest_payload(baseline=[{}]))
        self.assertEqual(status, 400)
        self.assertEqual(payload["error"]["code"], "invalid_request")

    def test_duplicate_baseline_key_400(self):
        status, payload = self.post(
            retest_payload(
                baseline=[consolidated_item(), consolidated_item(name="X")]
            )
        )
        self.assertEqual(status, 400)
        self.assertEqual(payload["error"]["code"], "invalid_request")

    def test_malformed_json_400(self):
        status, payload = self.request("POST", "/v1/findings/retest", b"{nope")
        self.assertEqual(status, 400)
        self.assertEqual(payload["error"]["code"], "invalid_request")

    def test_oversized_body_413(self):
        import http.client

        conn = http.client.HTTPConnection("127.0.0.1", self.port)
        conn.putrequest("POST", "/v1/findings/retest")
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
                status, payload = self.request(method, "/v1/findings/retest")
                self.assertEqual(status, 405)
                self.assertEqual(payload["error"]["code"], "method_not_allowed")

    def test_existing_routes_unchanged(self):
        status, payload = self.request("GET", "/healthz")
        self.assertEqual(status, 200)
        self.assertEqual(payload["status"], "ok")
        status, payload = self.post({"allow": [], "deny": [], "runs": []})
        self.assertEqual(status, 400)
        status, payload = self.request(
            "POST",
            "/v1/findings/consolidate",
            json.dumps(
                {
                    "allow": ["*.example.com"],
                    "deny": [],
                    "runs": [make_run(findings=[])],
                }
            ).encode(),
        )
        self.assertEqual(status, 200)
        self.assertEqual(payload, {"consolidated": []})


if __name__ == "__main__":
    unittest.main()
