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
        "target": "app.example.com",
        "template_id": "tpl-1",
        "name": "Demo template",
        "severity": "high",
        "observation_ids": ["obs-1"],
        "sources": ["run-1"],
        "evidence": [0],
        "confidence": 80,
    }
    finding.update(overrides)
    return finding


def make_comparison(**overrides):
    comparison = {
        "target": "app.example.com",
        "template_id": "tpl-1",
        "name": "Demo template",
        "status": "persistent",
        "before": make_finding(confidence=50),
        "after": make_finding(),
    }
    comparison.update(overrides)
    return comparison


def make_stage_result(**overrides):
    stage = {
        "id": "stage-1",
        "name": "Initial access",
        "status": "ready",
        "reason": None,
    }
    stage.update(overrides)
    return stage


def make_plan(**overrides):
    plan = {
        "target": "app.example.com",
        "stages": [make_stage_result()],
    }
    plan.update(overrides)
    return plan


def export_payload(**overrides):
    payload = {
        "allow": ["*.example.com"],
        "deny": [],
        "title": "Quarterly evidence",
        "findings": [make_finding()],
        "comparisons": [make_comparison()],
        "plans": [make_plan()],
    }
    payload.update(overrides)
    return payload


ZERO_SUMMARY = {
    "targets": 0,
    "current_findings": 0,
    "persistent": 0,
    "resolved": 0,
    "new": 0,
    "ready_stages": 0,
    "skipped_stages": 0,
}


class ExportServiceTest(unittest.TestCase):
    def setUp(self):
        self.service = Service()

    def export(self, **overrides):
        return self.service.export_report(export_payload(**overrides))

    def test_export_ok(self):
        result = self.export()
        self.assertEqual(list(result), ["report"])
        report = result["report"]
        self.assertEqual(
            list(report), ["schema_version", "title", "summary", "targets"]
        )
        self.assertEqual(report["schema_version"], "1.0")
        self.assertEqual(report["title"], "Quarterly evidence")
        self.assertEqual(
            report["summary"],
            {
                "targets": 1,
                "current_findings": 1,
                "persistent": 1,
                "resolved": 0,
                "new": 0,
                "ready_stages": 1,
                "skipped_stages": 0,
            },
        )
        (target,) = report["targets"]
        self.assertEqual(list(target), ["target", "findings", "comparisons", "stages"])
        self.assertEqual(target["target"], "app.example.com")
        self.assertEqual(target["findings"], [make_finding()])
        self.assertEqual(target["comparisons"], [make_comparison()])
        self.assertEqual(target["stages"], [make_stage_result()])

    def test_empty_input_returns_zero_summary(self):
        result = self.export(findings=[], comparisons=[], plans=[])
        report = result["report"]
        self.assertEqual(report["summary"], ZERO_SUMMARY)
        self.assertEqual(report["targets"], [])
        self.assertEqual(report["schema_version"], "1.0")
        self.assertEqual(report["title"], "Quarterly evidence")

    def test_targets_ordered_by_findings_then_comparisons_only(self):
        result = self.export(
            findings=[
                make_finding(target="b.example.com", template_id="x"),
                make_finding(target="a.example.com", template_id="y"),
            ],
            comparisons=[
                make_comparison(
                    target="b.example.com",
                    template_id="x",
                    before=make_finding(target="b.example.com", template_id="x"),
                    after=make_finding(target="b.example.com", template_id="x"),
                ),
                make_comparison(
                    target="a.example.com",
                    template_id="y",
                    before=make_finding(target="a.example.com", template_id="y"),
                    after=make_finding(target="a.example.com", template_id="y"),
                ),
                make_comparison(
                    target="c.example.com",
                    template_id="z",
                    name="Gone",
                    status="resolved",
                    before=make_finding(
                        target="c.example.com", template_id="z", name="Gone"
                    ),
                    after=None,
                ),
            ],
            plans=[],
        )
        report = result["report"]
        self.assertEqual(
            [t["target"] for t in report["targets"]],
            ["b.example.com", "a.example.com", "c.example.com"],
        )
        self.assertEqual(report["targets"][2]["findings"], [])
        self.assertEqual(report["targets"][2]["stages"], [])
        self.assertEqual(len(report["targets"][2]["comparisons"]), 1)
        self.assertEqual(
            report["summary"],
            {
                "targets": 3,
                "current_findings": 2,
                "persistent": 2,
                "resolved": 1,
                "new": 0,
                "ready_stages": 0,
                "skipped_stages": 0,
            },
        )

    def test_targets_are_normalized(self):
        result = self.export(
            findings=[make_finding(target="APP.Example.COM.")],
            comparisons=[
                make_comparison(
                    target="app.example.com",
                    before=make_finding(target="App.Example.com"),
                )
            ],
            plans=[make_plan(target="app.EXAMPLE.com")],
        )
        (target,) = result["report"]["targets"]
        self.assertEqual(target["target"], "app.example.com")
        self.assertEqual(target["findings"][0]["target"], "app.example.com")
        self.assertEqual(target["comparisons"][0]["target"], "app.example.com")

    def test_skipped_stage_combinations_count(self):
        result = self.export(
            plans=[
                make_plan(
                    stages=[
                        make_stage_result(
                            id="s1", status="skipped", reason="missing_requirements"
                        ),
                        make_stage_result(
                            id="s2", status="skipped", reason="dependency_blocked"
                        ),
                        make_stage_result(id="s3"),
                    ]
                )
            ]
        )
        summary = result["report"]["summary"]
        self.assertEqual(summary["ready_stages"], 1)
        self.assertEqual(summary["skipped_stages"], 2)

    def test_findings_without_comparisons_are_allowed_when_no_comparisons(self):
        result = self.export(comparisons=[], plans=[])
        report = result["report"]
        self.assertEqual(report["summary"]["current_findings"], 1)
        (target,) = report["targets"]
        self.assertEqual(target["comparisons"], [])

    def test_same_input_same_output(self):
        payload = export_payload(
            findings=[
                make_finding(target="b.example.com", template_id="x"),
                make_finding(target="a.example.com", template_id="y"),
            ],
            comparisons=[],
            plans=[],
        )
        self.assertEqual(
            self.service.export_report(payload),
            self.service.export_report(payload),
        )

    def test_duplicate_keys_are_invalid(self):
        with self.assertRaises(ValueError):
            self.export(
                findings=[make_finding(), make_finding(name="Other")],
                comparisons=[],
                plans=[],
            )
        with self.assertRaises(ValueError):
            self.export(
                comparisons=[make_comparison(), make_comparison()],
            )
        # The same key reached through different target spellings counts too.
        with self.assertRaises(ValueError):
            self.export(
                findings=[make_finding(), make_finding(target="APP.Example.COM.")],
                comparisons=[],
                plans=[],
            )

    def test_comparison_status_and_null_placement(self):
        bad = [
            make_comparison(status="persistent", before=None),
            make_comparison(status="persistent", after=None),
            make_comparison(status="resolved", after=make_finding()),
            make_comparison(status="resolved", before=None),
            make_comparison(status="new", before=make_finding()),
            make_comparison(status="new", after=None),
            make_comparison(status="unknown"),
        ]
        for comparison in bad:
            with self.subTest(comparison=comparison):
                with self.assertRaises(ValueError):
                    self.export(comparisons=[comparison])

    def test_comparison_side_key_must_match_outer_key(self):
        with self.assertRaises(ValueError):
            self.export(
                comparisons=[
                    make_comparison(after=make_finding(template_id="tpl-2"))
                ]
            )
        with self.assertRaises(ValueError):
            self.export(
                comparisons=[
                    make_comparison(before=make_finding(target="other.example.com"))
                ]
            )

    def test_after_must_match_current_finding(self):
        with self.assertRaises(ValueError):
            self.export(
                comparisons=[
                    make_comparison(after=make_finding(confidence=10))
                ]
            )
        # No finding at all for the key.
        with self.assertRaises(ValueError):
            self.export(
                findings=[],
                comparisons=[make_comparison()],
                plans=[],
            )

    def test_findings_must_be_covered_when_comparisons_present(self):
        with self.assertRaises(ValueError):
            self.export(
                findings=[make_finding(), make_finding(template_id="tpl-2")],
                plans=[],
            )
        # A resolved comparison does not count as covering a current finding.
        with self.assertRaises(ValueError):
            self.export(
                comparisons=[
                    make_comparison(status="resolved", after=None),
                ]
            )

    def test_conflicting_names_are_invalid(self):
        with self.assertRaises(ValueError):
            self.export(
                comparisons=[make_comparison(name="Different name")]
            )
        with self.assertRaises(ValueError):
            self.export(
                comparisons=[
                    make_comparison(before=make_finding(name="Old name"))
                ]
            )

    def test_plan_target_must_be_unique_and_known(self):
        with self.assertRaises(ValueError):
            self.export(plans=[make_plan(), make_plan()])
        with self.assertRaises(ValueError):
            self.export(plans=[make_plan(target="other.example.com")])
        with self.assertRaises(ValueError):
            self.export(findings=[], comparisons=[], plans=[make_plan()])

    def test_plan_stage_ids_unique_per_plan(self):
        with self.assertRaises(ValueError):
            self.export(
                plans=[
                    make_plan(
                        stages=[make_stage_result(), make_stage_result()]
                    )
                ]
            )
        # The same id in different plans is fine.
        result = self.export(
            findings=[
                make_finding(),
                make_finding(target="other.example.com"),
            ],
            comparisons=[],
            plans=[make_plan(), make_plan(target="other.example.com")],
        )
        self.assertEqual(result["report"]["summary"]["ready_stages"], 2)

    def test_stage_status_reason_combinations(self):
        bad = [
            make_stage_result(status="ready", reason="missing_requirements"),
            make_stage_result(status="skipped", reason=None),
            make_stage_result(status="skipped", reason="other"),
            make_stage_result(status="done", reason=None),
            make_stage_result(status="ready", reason=5),
        ]
        for stage in bad:
            with self.subTest(stage=stage):
                with self.assertRaises(ValueError):
                    self.export(plans=[make_plan(stages=[stage])])

    def test_scope_violation_raises(self):
        with self.assertRaises(ScopeViolationError):
            self.export(
                findings=[make_finding(target="evil.net")],
                comparisons=[],
                plans=[],
            )
        with self.assertRaises(ScopeViolationError):
            self.export(
                findings=[],
                comparisons=[
                    make_comparison(
                        target="evil.net",
                        status="resolved",
                        before=make_finding(target="evil.net"),
                        after=None,
                    )
                ],
                plans=[],
            )
        with self.assertRaises(ScopeViolationError):
            self.export(deny=["app.example.com"])

    def test_structure_validated_before_scope_gate(self):
        # A duplicate key is a 400 even though a target is out of scope.
        with self.assertRaises(ValueError):
            self.export(
                findings=[
                    make_finding(target="evil.net"),
                    make_finding(target="EVIL.net."),
                ],
                comparisons=[],
                plans=[],
            )

    def test_validation_errors(self):
        bad_payloads = [
            None,
            [],
            {},
            {"allow": [], "deny": [], "title": "t"},
            export_payload(extra=1),
            export_payload(allow="*.example.com"),
            export_payload(deny=1),
            export_payload(title=""),
            export_payload(title=3),
            export_payload(title=None),
            export_payload(findings={}),
            export_payload(findings="x"),
            export_payload(findings=None),
            export_payload(findings=[None]),
            export_payload(findings=[make_finding(extra=1)]),
            export_payload(findings=[make_finding(severity="fatal")]),
            export_payload(findings=[make_finding(confidence=True)]),
            export_payload(comparisons={}),
            export_payload(comparisons=None),
            export_payload(comparisons=[None]),
            export_payload(comparisons=[make_comparison(extra=1)]),
            export_payload(comparisons=[make_comparison(target="*.example.com")]),
            export_payload(comparisons=[make_comparison(template_id="")]),
            export_payload(comparisons=[make_comparison(name="")]),
            export_payload(comparisons=[make_comparison(status="PERSISTENT")]),
            export_payload(comparisons=[make_comparison(before="x")]),
            export_payload(
                comparisons=[make_comparison(after=make_finding(evidence=[-1]))]
            ),
            export_payload(plans={}),
            export_payload(plans=None),
            export_payload(plans=[None]),
            export_payload(plans=[make_plan(extra=1)]),
            export_payload(plans=[make_plan(stages={})]),
            export_payload(plans=[make_plan(stages=[None])]),
            export_payload(plans=[make_plan(stages=[make_stage_result(extra=1)])]),
            export_payload(plans=[make_plan(stages=[make_stage_result(id="")])]),
            export_payload(plans=[make_plan(stages=[make_stage_result(name="")])]),
        ]
        for payload in bad_payloads:
            with self.subTest(payload=repr(payload)[:90]):
                with self.assertRaises(ValueError):
                    self.service.export_report(payload)


class ExportHttpTest(unittest.TestCase):
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
            "POST", "/v1/reports/export", json.dumps(payload).encode()
        )

    def test_export_ok(self):
        status, payload = self.post(export_payload())
        self.assertEqual(status, 200)
        self.assertEqual(list(payload), ["report"])
        report = payload["report"]
        self.assertEqual(report["schema_version"], "1.0")
        self.assertEqual(report["title"], "Quarterly evidence")
        self.assertEqual(
            set(report["summary"]),
            {
                "targets",
                "current_findings",
                "persistent",
                "resolved",
                "new",
                "ready_stages",
                "skipped_stages",
            },
        )
        (target,) = report["targets"]
        self.assertEqual(
            set(target), {"target", "findings", "comparisons", "stages"}
        )

    def test_empty_export_ok(self):
        status, payload = self.post(
            export_payload(findings=[], comparisons=[], plans=[])
        )
        self.assertEqual(status, 200)
        self.assertEqual(payload["report"]["summary"], ZERO_SUMMARY)
        self.assertEqual(payload["report"]["targets"], [])

    def test_scope_violation_403(self):
        status, payload = self.post(
            export_payload(
                findings=[make_finding(target="evil.net")],
                comparisons=[],
                plans=[],
            )
        )
        self.assertEqual(status, 403)
        self.assertEqual(payload["error"]["code"], "scope_violation")
        self.assertNotIn("report", payload)

    def test_invalid_request_400(self):
        status, payload = self.post(export_payload(title=""))
        self.assertEqual(status, 400)
        self.assertEqual(payload["error"]["code"], "invalid_request")

    def test_inconsistent_report_400(self):
        status, payload = self.post(
            export_payload(comparisons=[make_comparison(name="Other")])
        )
        self.assertEqual(status, 400)
        self.assertEqual(payload["error"]["code"], "invalid_request")

    def test_malformed_json_400(self):
        status, payload = self.request("POST", "/v1/reports/export", b"{nope")
        self.assertEqual(status, 400)
        self.assertEqual(payload["error"]["code"], "invalid_request")

    def test_method_not_allowed_405(self):
        for method in ("GET", "PUT", "DELETE", "PATCH"):
            with self.subTest(method=method):
                status, payload = self.request(method, "/v1/reports/export")
                self.assertEqual(status, 405)
                self.assertEqual(payload["error"]["code"], "method_not_allowed")

    def test_existing_routes_unchanged(self):
        status, payload = self.request("GET", "/healthz")
        self.assertEqual(status, 200)
        self.assertEqual(payload["status"], "ok")
        status, payload = self.request(
            "POST",
            "/v1/attack-chains/plan",
            json.dumps(
                {
                    "allow": ["*.example.com"],
                    "deny": [],
                    "findings": [],
                    "stages": [
                        {
                            "id": "s1",
                            "name": "A",
                            "logic": "all",
                            "requires": [
                                {
                                    "template_id": "tpl-1",
                                    "min_severity": "low",
                                    "min_confidence": 0,
                                }
                            ],
                            "depends_on": [],
                        }
                    ],
                }
            ).encode(),
        )
        self.assertEqual(status, 200)
        self.assertEqual(payload, {"plans": []})


if __name__ == "__main__":
    unittest.main()
