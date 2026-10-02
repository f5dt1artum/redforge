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

    def test_persistent_basic(self):
        result = self.retest()
        self.assertEqual(list(result), ["comparisons", "summary"])
        (comparison,) = result["comparisons"]
        self.assertEqual(
            set(comparison),
            {"target", "template_id", "name", "status", "before", "after"},
        )
        self.assertEqual(comparison["target"], "app.example.com")
        self.assertEqual(comparison["template_id"], "tpl-1")
        self.assertEqual(comparison["name"], "Demo template")
        self.assertEqual(comparison["status"], "persistent")
        self.assertEqual(comparison["before"], consolidated_item())
        self.assertEqual(
            comparison["after"],
            consolidated_item(confidence=50),
        )
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

    def test_resolved_when_missing_in_retest(self):
        result = self.retest(retest_runs=[make_run(findings=[])])
        (comparison,) = result["comparisons"]
        self.assertEqual(comparison["status"], "resolved")
        self.assertEqual(comparison["before"], consolidated_item())
        self.assertIsNone(comparison["after"])
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
        (comparison,) = result["comparisons"]
        self.assertEqual(comparison["status"], "new")
        self.assertIsNone(comparison["before"])
        self.assertEqual(comparison["after"]["target"], "app.example.com")
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

    def test_all_resolved_when_retest_has_no_findings(self):
        baseline = [
            consolidated_item(target="a.example.com", template_id="x"),
            consolidated_item(target="b.example.com", template_id="y"),
        ]
        result = self.retest(
            baseline=baseline,
            retest_runs=[
                make_run(id="r1", findings=[]),
                make_run(id="r2", findings=[]),
            ],
        )
        self.assertEqual(
            [c["status"] for c in result["comparisons"]],
            ["resolved", "resolved"],
        )
        self.assertEqual(result["summary"]["resolved"], 2)
        self.assertEqual(result["summary"]["total_after"], 0)

    def test_ordering_baseline_first_then_new_first_seen(self):
        baseline = [
            consolidated_item(target="b.example.com", template_id="x"),
            consolidated_item(target="gone.example.com", template_id="g"),
            consolidated_item(target="a.example.com", template_id="y"),
        ]
        retest_runs = [
            make_run(
                id="r1",
                reliability=10,
                findings=[
                    make_finding(target="new1.example.com", template_id="n1"),
                    make_finding(target="a.example.com", template_id="y"),
                    make_finding(target="b.example.com", template_id="x"),
                    make_finding(target="new2.example.com", template_id="n2"),
                ],
            ),
        ]
        result = self.retest(baseline=baseline, retest_runs=retest_runs)
        comparisons = result["comparisons"]
        self.assertEqual(
            [(c["target"], c["template_id"], c["status"]) for c in comparisons],
            [
                ("b.example.com", "x", "persistent"),
                ("gone.example.com", "g", "resolved"),
                ("a.example.com", "y", "persistent"),
                ("new1.example.com", "n1", "new"),
                ("new2.example.com", "n2", "new"),
            ],
        )
        self.assertEqual(
            result["summary"],
            {
                "total_before": 3,
                "total_after": 4,
                "persistent": 2,
                "resolved": 1,
                "new": 2,
            },
        )

    def test_comparison_key_normalizes_target(self):
        result = self.retest(
            baseline=[consolidated_item(target="APP.Example.COM.")],
            retest_runs=[make_run(findings=[make_finding(target="app.example.com")])],
        )
        (comparison,) = result["comparisons"]
        self.assertEqual(comparison["status"], "persistent")
        self.assertEqual(comparison["target"], "app.example.com")

    def test_comparison_key_template_id_is_case_sensitive(self):
        result = self.retest(
            baseline=[consolidated_item(template_id="TPL")],
            retest_runs=[make_run(findings=[make_finding(template_id="tpl")])],
        )
        statuses = {(c["template_id"], c["status"]) for c in result["comparisons"]}
        self.assertEqual(statuses, {("TPL", "resolved"), ("tpl", "new")})

    def test_baseline_name_wins_for_persistent(self):
        result = self.retest(
            baseline=[consolidated_item(name="Baseline name")],
            retest_runs=[
                make_run(findings=[make_finding(name="Retest name")])
            ],
        )
        (comparison,) = result["comparisons"]
        self.assertEqual(comparison["status"], "persistent")
        self.assertEqual(comparison["name"], "Baseline name")
        self.assertEqual(comparison["before"]["name"], "Baseline name")
        self.assertEqual(comparison["after"]["name"], "Retest name")

    def test_new_name_comes_from_retest(self):
        result = self.retest(
            baseline=[],
            retest_runs=[make_run(findings=[make_finding(name="Fresh")])],
        )
        self.assertEqual(result["comparisons"][0]["name"], "Fresh")

    def test_field_changes_keep_persistent(self):
        result = self.retest(
            baseline=[
                consolidated_item(
                    severity="low", confidence=10, evidence=[0],
                    observation_ids=["old-obs"], sources=["old-run"],
                )
            ],
            retest_runs=[
                make_run(
                    id="new-run",
                    reliability=90,
                    findings=[
                        make_finding(
                            observation_id="new-obs",
                            severity="critical",
                            evidence=[3, 1],
                        )
                    ],
                )
            ],
        )
        comparison = result["comparisons"][0]
        self.assertEqual(comparison["status"], "persistent")
        self.assertEqual(comparison["after"]["severity"], "critical")
        self.assertEqual(comparison["after"]["evidence"], [1, 3])
        self.assertEqual(comparison["after"]["confidence"], 90)
        self.assertEqual(comparison["before"]["severity"], "low")

    def test_before_is_echoed_verbatim(self):
        baseline_item = consolidated_item(evidence=[2, 0, 2], confidence=42)
        result = self.retest(baseline=[baseline_item])
        self.assertEqual(result["comparisons"][0]["before"], baseline_item)

    def test_after_uses_consolidation_semantics(self):
        retest_runs = [
            make_run(id="r1", reliability=50, findings=[make_finding(evidence=[0])]),
            make_run(
                id="r2",
                reliability=80,
                findings=[make_finding(observation_id="obs-2", evidence=[2, 1])],
            ),
        ]
        result = self.retest(baseline=[], retest_runs=retest_runs)
        after = result["comparisons"][0]["after"]
        self.assertEqual(after["observation_ids"], ["obs-1", "obs-2"])
        self.assertEqual(after["sources"], ["r1", "r2"])
        self.assertEqual(after["evidence"], [0, 1, 2])
        self.assertEqual(after["confidence"], 90)

    def test_empty_baseline_and_empty_retest_findings(self):
        result = self.retest(
            baseline=[], retest_runs=[make_run(findings=[])]
        )
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

    def test_stable_order_for_same_input(self):
        baseline = [
            consolidated_item(target="a.example.com", template_id="x"),
            consolidated_item(target="b.example.com", template_id="y"),
        ]
        retest_runs = [
            make_run(
                findings=[
                    make_finding(target="b.example.com", template_id="y"),
                    make_finding(target="c.example.com", template_id="z"),
                ]
            )
        ]
        first = self.retest(baseline=baseline, retest_runs=retest_runs)
        second = self.retest(baseline=baseline, retest_runs=retest_runs)
        self.assertEqual(first, second)

    # ---- scope ---------------------------------------------------------

    def test_scope_violation_in_baseline_target(self):
        with self.assertRaises(ScopeViolationError):
            self.retest(
                baseline=[consolidated_item(target="evil.net")],
                retest_runs=[make_run(findings=[])],
            )

    def test_scope_violation_in_retest_target(self):
        with self.assertRaises(ScopeViolationError):
            self.retest(
                baseline=[],
                retest_runs=[make_run(findings=[make_finding(target="evil.net")])],
            )

    def test_deny_rule_triggers_scope_violation(self):
        with self.assertRaises(ScopeViolationError):
            self.retest(
                deny=["app.example.com"],
                retest_runs=[make_run()],
            )

    def test_scope_gate_covers_ip_targets(self):
        result = self.retest(
            allow=["10.0.0.0/8"],
            baseline=[consolidated_item(target="10.1.2.3")],
            retest_runs=[
                make_run(findings=[make_finding(target="10.4.5.6")])
            ],
        )
        self.assertEqual(result["comparisons"][0]["status"], "resolved")
        self.assertEqual(result["comparisons"][1]["status"], "new")

    def test_malformed_structure_takes_precedence_over_scope(self):
        # Structural failure (duplicate baseline key) wins even though a
        # baseline target is also out of scope.
        with self.assertRaises(ValueError):
            self.retest(
                baseline=[
                    consolidated_item(target="evil.net", template_id="x"),
                    consolidated_item(target="evil.net", template_id="x"),
                ],
                retest_runs=[make_run(findings=[])],
            )

    def test_scope_takes_precedence_over_name_conflict(self):
        # The retest name conflict only surfaces during consolidation, which
        # runs after the scope gate.
        with self.assertRaises(ScopeViolationError):
            self.retest(
                retest_runs=[
                    make_run(
                        id="r1",
                        findings=[make_finding(target="evil.net", name="A")],
                    ),
                    make_run(
                        id="r2",
                        reliability=1,
                        findings=[make_finding(target="evil.net", name="B")],
                    ),
                ]
            )

    # ---- validation ----------------------------------------------------

    def test_validation_errors(self):
        bad_item = consolidated_item
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
            retest_payload(retest_runs=[]),
            retest_payload(retest_runs={}),
            # baseline item shape
            retest_payload(baseline=[None]),
            retest_payload(baseline=[[]]),
            retest_payload(baseline=[{"target": "app.example.com"}]),
            retest_payload(baseline=[bad_item(extra=1)]),
            retest_payload(baseline=[bad_item(target="bad_host")]),
            retest_payload(baseline=[bad_item(target="*.example.com")]),
            retest_payload(baseline=[bad_item(target="")]),
            retest_payload(baseline=[bad_item(target=5)]),
            retest_payload(baseline=[bad_item(template_id="")]),
            retest_payload(baseline=[bad_item(template_id=4)]),
            retest_payload(baseline=[bad_item(name="")]),
            retest_payload(baseline=[bad_item(name=4)]),
            retest_payload(baseline=[bad_item(severity="fatal")]),
            retest_payload(baseline=[bad_item(observation_ids=[])]),
            retest_payload(baseline=[bad_item(observation_ids="x")]),
            retest_payload(baseline=[bad_item(observation_ids=[""])]),
            retest_payload(baseline=[bad_item(observation_ids=[1])]),
            retest_payload(baseline=[bad_item(sources=[])]),
            retest_payload(baseline=[bad_item(sources={})]),
            retest_payload(baseline=[bad_item(sources=[""])]),
            retest_payload(baseline=[bad_item(evidence=[])]),
            retest_payload(baseline=[bad_item(evidence="0")]),
            retest_payload(baseline=[bad_item(evidence=[-1])]),
            retest_payload(baseline=[bad_item(evidence=[True])]),
            retest_payload(baseline=[bad_item(evidence=[1.5])]),
            retest_payload(baseline=[bad_item(evidence=[1, "2"])]),
            retest_payload(baseline=[bad_item(confidence=-1)]),
            retest_payload(baseline=[bad_item(confidence=101)]),
            retest_payload(baseline=[bad_item(confidence="50")]),
            retest_payload(baseline=[bad_item(confidence=True)]),
            retest_payload(baseline=[bad_item(confidence=1.5)]),
            # duplicate baseline keys
            retest_payload(
                baseline=[
                    consolidated_item(template_id="x"),
                    consolidated_item(template_id="x"),
                ]
            ),
            retest_payload(
                baseline=[
                    consolidated_item(target="app.example.com"),
                    consolidated_item(target="APP.Example.COM."),
                ]
            ),
            # retest runs
            retest_payload(retest_runs=[None]),
            retest_payload(retest_runs=[{"id": "r1"}]),
            retest_payload(retest_runs=[make_run(extra=1)]),
            retest_payload(retest_runs=[make_run(id="")]),
            retest_payload(retest_runs=[make_run(reliability=-1)]),
            retest_payload(retest_runs=[make_run(reliability=101)]),
            retest_payload(retest_runs=[make_run(reliability="50")]),
            retest_payload(retest_runs=[make_run(reliability=True)]),
            retest_payload(retest_runs=[make_run(findings={})]),
            retest_payload(
                retest_runs=[make_run(id="run-1"), make_run(id="run-1")]
            ),
            retest_payload(
                retest_runs=[
                    make_run(id="r1", findings=[make_finding(severity="nope")])
                ]
            ),
            retest_payload(
                retest_runs=[
                    make_run(id="r1", findings=[make_finding(evidence=[-1])])
                ]
            ),
        ]
        for payload in bad_payloads:
            with self.subTest(payload=repr(payload)[:90]):
                with self.assertRaises(ValueError):
                    self.service.retest_findings(payload)

    def test_same_key_name_conflict_within_retest_is_invalid(self):
        with self.assertRaises(ValueError):
            self.retest(
                baseline=[],
                retest_runs=[
                    make_run(id="r1", findings=[make_finding(name="A")]),
                    make_run(
                        id="r2",
                        reliability=1,
                        findings=[make_finding(name="B")],
                    ),
                ],
            )


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
        status, payload = self.post(retest_payload())
        self.assertEqual(status, 200)
        self.assertEqual(list(payload), ["comparisons", "summary"])
        (comparison,) = payload["comparisons"]
        self.assertEqual(comparison["status"], "persistent")
        self.assertEqual(comparison["before"]["target"], "app.example.com")
        self.assertEqual(comparison["after"]["confidence"], 50)
        self.assertEqual(payload["summary"]["persistent"], 1)

    def test_empty_baseline_200(self):
        status, payload = self.post(retest_payload(baseline=[]))
        self.assertEqual(status, 200)
        self.assertEqual(payload["comparisons"][0]["status"], "new")

    def test_scope_violation_403(self):
        status, payload = self.post(
            retest_payload(
                retest_runs=[make_run(findings=[make_finding(target="evil.net")])]
            )
        )
        self.assertEqual(status, 403)
        self.assertEqual(payload["error"]["code"], "scope_violation")
        self.assertNotIn("comparisons", payload)

    def test_baseline_scope_violation_403(self):
        status, payload = self.post(
            retest_payload(baseline=[consolidated_item(target="evil.net")])
        )
        self.assertEqual(status, 403)
        self.assertEqual(payload["error"]["code"], "scope_violation")

    def test_invalid_request_400(self):
        status, payload = self.post({"allow": [], "deny": [], "baseline": []})
        self.assertEqual(status, 400)
        self.assertEqual(payload["error"]["code"], "invalid_request")

    def test_duplicate_baseline_key_400(self):
        status, payload = self.post(
            retest_payload(
                baseline=[
                    consolidated_item(template_id="x"),
                    consolidated_item(template_id="x"),
                ]
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

    def test_unknown_route_404(self):
        status, payload = self.request("POST", "/v1/findings/nope", b"{}")
        self.assertEqual(status, 404)
        self.assertEqual(payload["error"]["code"], "not_found")

    def test_existing_consolidate_route_still_works(self):
        status, payload = self.request(
            "POST",
            "/v1/findings/consolidate",
            json.dumps(
                {
                    "allow": ["*.example.com"],
                    "deny": [],
                    "runs": [make_run()],
                }
            ).encode(),
        )
        self.assertEqual(status, 200)
        self.assertEqual(list(payload), ["consolidated"])


if __name__ == "__main__":
    unittest.main()
