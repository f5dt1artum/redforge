import copy
import json
import threading
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

from redforge.server import Handler
from redforge.service import ScopeViolationError, Service


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


def comparison(**overrides):
    target = overrides.get("target", "app.example.com")
    template_id = overrides.get("template_id", "tpl-1")
    name = overrides.get("name", "Demo template")
    item = consolidated_item(
        target=target, template_id=template_id, name=name
    )
    cmp_ = {
        "target": target,
        "template_id": template_id,
        "name": name,
        "status": "persistent",
        "before": item,
        "after": dict(item),
    }
    cmp_.update(overrides)
    return cmp_


def plan(**overrides):
    plan_ = {
        "target": "app.example.com",
        "stages": [
            {"id": "s1", "name": "Initial access", "status": "ready", "reason": None}
        ],
    }
    plan_.update(overrides)
    return plan_


def export_payload(**overrides):
    payload = {
        "allow": ["*.example.com"],
        "deny": [],
        "title": "Weekly report",
        "findings": [consolidated_item()],
        "comparisons": [comparison()],
        "plans": [plan()],
    }
    payload.update(overrides)
    return payload


class ReportServiceTest(unittest.TestCase):
    def setUp(self):
        self.service = Service()

    def export(self, **overrides):
        return self.service.export_report(export_payload(**overrides))

    def test_report_shape(self):
        result = self.export()
        self.assertEqual(list(result), ["report"])
        report = result["report"]
        self.assertEqual(
            list(report), ["schema_version", "title", "summary", "targets"]
        )
        self.assertEqual(report["schema_version"], "1.0")
        self.assertEqual(report["title"], "Weekly report")
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
        self.assertEqual(len(target["findings"]), 1)
        self.assertEqual(len(target["comparisons"]), 1)
        self.assertEqual(target["stages"][0]["id"], "s1")

    def test_empty_inputs_return_zero_summary(self):
        for empty in ([], None):
            with self.subTest(empty=empty):
                result = self.export(
                    findings=empty, comparisons=empty, plans=empty
                )
                report = result["report"]
                self.assertEqual(report["targets"], [])
                self.assertEqual(
                    report["summary"],
                    {
                        "targets": 0,
                        "current_findings": 0,
                        "persistent": 0,
                        "resolved": 0,
                        "new": 0,
                        "ready_stages": 0,
                        "skipped_stages": 0,
                    },
                )

    def test_title_is_kept_verbatim(self):
        result = self.export(title="  spaced 标题  ")
        self.assertEqual(result["report"]["title"], "  spaced 标题  ")

    def test_target_order_findings_first_then_comparison_only(self):
        result = self.export(
            findings=[
                consolidated_item(target="b.example.com", template_id="x"),
                consolidated_item(target="a.example.com", template_id="y"),
            ],
            comparisons=[
                comparison(target="b.example.com", template_id="x"),
                comparison(target="a.example.com", template_id="y"),
                # A target seen only in a resolved comparison is appended
                # after every target introduced by findings.
                comparison(
                    target="c.example.com",
                    template_id="z",
                    name="C only",
                    status="resolved",
                    before=consolidated_item(
                        target="c.example.com", template_id="z", name="C only"
                    ),
                    after=None,
                ),
            ],
            plans=[],
        )
        self.assertEqual(
            [t["target"] for t in result["report"]["targets"]],
            ["b.example.com", "a.example.com", "c.example.com"],
        )
        self.assertEqual(result["report"]["summary"]["targets"], 3)

    def test_groups_collect_per_target_arrays(self):
        result = self.export(
            findings=[
                consolidated_item(target="a.example.com", template_id="x"),
                consolidated_item(target="b.example.com", template_id="y"),
                consolidated_item(target="a.example.com", template_id="z"),
            ],
            comparisons=[
                comparison(target="a.example.com", template_id="x"),
                comparison(target="a.example.com", template_id="z"),
                comparison(target="b.example.com", template_id="y"),
            ],
            plans=[
                plan(target="a.example.com"),
                plan(target="b.example.com"),
            ],
        )
        groups = {t["target"]: t for t in result["report"]["targets"]}
        self.assertEqual(
            [item["template_id"] for item in groups["a.example.com"]["findings"]],
            ["x", "z"],
        )
        self.assertEqual(
            [item["template_id"] for item in groups["a.example.com"]["comparisons"]],
            ["x", "z"],
        )
        self.assertEqual(len(groups["a.example.com"]["stages"]), 1)
        self.assertEqual(groups["b.example.com"]["findings"][0]["template_id"], "y")

    def test_status_counts(self):
        keep = consolidated_item(target="a.example.com", template_id="keep")
        fresh = consolidated_item(target="a.example.com", template_id="fresh")
        gone = consolidated_item(target="a.example.com", template_id="gone")
        result = self.export(
            findings=[keep, fresh],
            comparisons=[
                comparison(
                    target="a.example.com",
                    template_id="keep",
                    before=dict(keep),
                    after=dict(keep),
                ),
                comparison(
                    target="a.example.com",
                    template_id="gone",
                    name="Demo template",
                    status="resolved",
                    before=dict(gone),
                    after=None,
                ),
                comparison(
                    target="a.example.com",
                    template_id="fresh",
                    name="Demo template",
                    status="new",
                    before=None,
                    after=dict(fresh),
                ),
            ],
            plans=[
                plan(
                    target="a.example.com",
                    stages=[
                        {"id": "r", "name": "R", "status": "ready", "reason": None},
                        {
                            "id": "m",
                            "name": "M",
                            "status": "skipped",
                            "reason": "missing_requirements",
                        },
                        {
                            "id": "d",
                            "name": "D",
                            "status": "skipped",
                            "reason": "dependency_blocked",
                        },
                    ],
                )
            ],
        )
        self.assertEqual(
            result["report"]["summary"],
            {
                "targets": 1,
                "current_findings": 2,
                "persistent": 1,
                "resolved": 1,
                "new": 1,
                "ready_stages": 1,
                "skipped_stages": 2,
            },
        )

    def test_normalized_target_groups(self):
        result = self.export(
            findings=[consolidated_item(target="APP.Example.COM.")],
            comparisons=[
                comparison(
                    target="APP.Example.COM.",
                    before=consolidated_item(target="APP.Example.COM."),
                    after=consolidated_item(target="APP.Example.COM."),
                )
            ],
            plans=[plan(target="APP.Example.COM.")],
        )
        self.assertEqual(
            [t["target"] for t in result["report"]["targets"]],
            ["app.example.com"],
        )

    def test_template_id_is_case_sensitive(self):
        # TPL vs tpl are distinct keys: findings carry only tpl, so the
        # persistent TPL comparison is inconsistent.
        payload = export_payload(
            comparisons=[
                comparison(
                    template_id="TPL",
                    before=consolidated_item(template_id="TPL"),
                    after=consolidated_item(template_id="TPL"),
                )
            ],
            plans=[],
        )
        with self.assertRaises(ValueError):
            self.service.export_report(payload)

    def test_persistent_before_name_may_differ_from_finding(self):
        # Retest keeps field changes persistent; only after must equal the
        # current finding. The outer name follows the baseline side.
        result = self.export(
            comparisons=[
                comparison(
                    name="Old name",
                    before=consolidated_item(name="Old name"),
                    after=consolidated_item(name="Demo template"),
                )
            ]
        )
        (cmp_,) = result["report"]["targets"][0]["comparisons"]
        self.assertEqual(cmp_["name"], "Old name")
        self.assertEqual(cmp_["before"]["name"], "Old name")

    def test_duplicate_keys_are_invalid(self):
        with self.assertRaises(ValueError):
            self.export(findings=[consolidated_item(), consolidated_item()])
        with self.assertRaises(ValueError):
            self.export(comparisons=[comparison(), comparison()])
        with self.assertRaises(ValueError):
            self.export(plans=[plan(), plan()])
        # Same key reached through different target spellings counts too.
        with self.assertRaises(ValueError):
            self.export(
                findings=[
                    consolidated_item(),
                    consolidated_item(target="APP.Example.COM."),
                ]
            )

    def test_comparison_null_positions_follow_status(self):
        bad = [
            comparison(status="persistent", before=None),
            comparison(status="persistent", after=None),
            comparison(status="resolved", before=None, after=None),
            comparison(status="resolved"),
            comparison(status="new", before=None, after=None),
            comparison(status="new"),
            comparison(status="weird"),
        ]
        for cmp_ in bad:
            with self.subTest(cmp_=json.dumps(cmp_)[:80]):
                with self.assertRaises(ValueError):
                    self.export(comparisons=[cmp_])

    def test_comparison_side_must_match_outer_key(self):
        with self.assertRaises(ValueError):
            self.export(
                comparisons=[
                    comparison(
                        before=consolidated_item(target="other.example.com"),
                        after=consolidated_item(target="other.example.com"),
                    )
                ]
            )
        with self.assertRaises(ValueError):
            self.export(
                comparisons=[
                    comparison(
                        before=consolidated_item(template_id="other"),
                        after=consolidated_item(template_id="other"),
                    )
                ]
            )

    def test_comparison_name_must_follow_named_side(self):
        with self.assertRaises(ValueError):
            self.export(
                comparisons=[
                    comparison(
                        name="Brand new name",
                    )
                ]
            )

    def test_after_set_must_match_findings_when_comparisons_present(self):
        # An extra current finding with no comparison is invalid.
        with self.assertRaises(ValueError):
            self.export(
                findings=[
                    consolidated_item(),
                    consolidated_item(target="a.example.com", template_id="x"),
                ]
            )
        # A persistent comparison without the matching finding is invalid.
        with self.assertRaises(ValueError):
            self.export(findings=[])
        # A mismatch in the after body is invalid.
        with self.assertRaises(ValueError):
            self.export(
                comparisons=[
                    comparison(
                        after=consolidated_item(confidence=99),
                    )
                ]
            )

    def test_resolved_and_new_need_no_plan_and_specific_sides(self):
        result = self.export(
            findings=[consolidated_item(target="a.example.com", template_id="new")],
            comparisons=[
                comparison(
                    target="a.example.com",
                    template_id="gone",
                    name="Gone",
                    status="resolved",
                    before=consolidated_item(
                        target="a.example.com", template_id="gone", name="Gone"
                    ),
                    after=None,
                ),
                comparison(
                    target="a.example.com",
                    template_id="new",
                    name="Demo template",
                    status="new",
                    before=None,
                ),
            ],
            plans=[plan(target="a.example.com")],
        )
        summary = result["report"]["summary"]
        self.assertEqual(summary["persistent"], 0)
        self.assertEqual(summary["resolved"], 1)
        self.assertEqual(summary["new"], 1)
        self.assertEqual(summary["current_findings"], 1)
        self.assertEqual(summary["targets"], 1)

    def test_plan_target_must_have_current_finding(self):
        with self.assertRaises(ValueError):
            self.export(plans=[plan(target="other.example.com")])
        # A resolved-only target has no current finding.
        with self.assertRaises(ValueError):
            self.export(
                findings=[],
                comparisons=[
                    comparison(
                        status="resolved",
                        after=None,
                    )
                ],
                plans=[plan()],
            )

    def test_plan_stage_ids_unique_within_plan_and_status_reason_pairs(self):
        with self.assertRaises(ValueError):
            self.export(
                plans=[
                    plan(
                        stages=[
                            {"id": "s1", "name": "A", "status": "ready", "reason": None},
                            {"id": "s1", "name": "B", "status": "ready", "reason": None},
                        ]
                    )
                ]
            )
        bad_stages = [
            {"id": "s1", "name": "A", "status": "ready", "reason": "blocked"},
            {"id": "s1", "name": "A", "status": "skipped", "reason": None},
            {"id": "s1", "name": "A", "status": "skipped", "reason": "nope"},
            {"id": "s1", "name": "A", "status": "done", "reason": None},
        ]
        for stage in bad_stages:
            with self.subTest(stage=stage):
                with self.assertRaises(ValueError):
                    self.export(plans=[plan(stages=[stage])])

    def test_scope_violation_raises(self):
        with self.assertRaises(ScopeViolationError):
            self.export(
                findings=[consolidated_item(target="evil.net")],
                comparisons=[],
                plans=[],
            )
        evil = consolidated_item(target="evil.net")
        with self.assertRaises(ScopeViolationError):
            self.export(
                findings=[evil],
                comparisons=[
                    comparison(
                        target="evil.net",
                        before=dict(evil),
                        after=dict(evil),
                    )
                ],
                plans=[],
            )
        with self.assertRaises(ScopeViolationError):
            self.export(
                findings=[evil],
                comparisons=[],
                plans=[plan(target="evil.net")],
            )
        with self.assertRaises(ScopeViolationError):
            self.export(deny=["app.example.com"])

    def test_structure_validated_before_scope_gate(self):
        # Malformed structure is a 400 even though a target is out of scope.
        with self.assertRaises(ValueError):
            self.export(
                findings=[
                    consolidated_item(target="evil.net"),
                    consolidated_item(target="evil.net"),
                ]
            )
        with self.assertRaises(ValueError):
            self.export(
                plans=[plan(target="evil.net"), plan(target="evil.net")]
            )

    def test_validation_errors(self):
        bad_payloads = [
            None,
            [],
            {},
            {"allow": [], "deny": [], "title": "T"},
            export_payload(extra=1),
            export_payload(allow="*.example.com"),
            export_payload(deny=1),
            export_payload(allow=["not a host!!"]),
            export_payload(title=""),
            export_payload(title=4),
            export_payload(title=None),
            export_payload(findings={}),
            export_payload(findings="x"),
            export_payload(findings=[None]),
            export_payload(findings=[{"target": "app.example.com"}]),
            export_payload(findings=[consolidated_item(extra=1)]),
            export_payload(findings=[consolidated_item(severity="fatal")]),
            export_payload(findings=[consolidated_item(confidence=101)]),
            export_payload(comparisons={}),
            export_payload(comparisons="x"),
            export_payload(comparisons=[None]),
            export_payload(comparisons=[{"target": "app.example.com"}]),
            export_payload(comparisons=[comparison(extra=1)]),
            export_payload(comparisons=[comparison(target="bad_host")]),
            export_payload(comparisons=[comparison(template_id="")]),
            export_payload(comparisons=[comparison(name="")]),
            export_payload(comparisons=[comparison(status=4)]),
            export_payload(comparisons=[comparison(before="x")]),
            export_payload(comparisons=[comparison(after={})]),
            export_payload(plans={}),
            export_payload(plans="x"),
            export_payload(plans=[None]),
            export_payload(plans=[{"target": "app.example.com"}]),
            export_payload(plans=[plan(extra=1)]),
            export_payload(plans=[plan(target="bad_host")]),
            export_payload(plans=[plan(stages={})]),
            export_payload(plans=[plan(stages=None)]),
            export_payload(plans=[plan(stages=[None])]),
            export_payload(plans=[plan(stages=[{}])]),
            export_payload(plans=[plan(stages=[{"id": "s1"}])]),
            export_payload(plans=[plan(stages=[{"id": "s1", "name": "A",
                                               "status": "ready", "reason": None,
                                               "extra": 1}])]),
        ]
        for payload in bad_payloads:
            with self.subTest(payload=repr(payload)[:90]):
                with self.assertRaises(ValueError):
                    self.service.export_report(payload)

    def test_same_input_is_stable(self):
        payload = export_payload(
            findings=[
                consolidated_item(target="b.example.com", template_id="x"),
                consolidated_item(target="a.example.com", template_id="y"),
            ],
            comparisons=[],
            plans=[plan(target="b.example.com"), plan(target="a.example.com")],
        )
        first = self.service.export_report(copy.deepcopy(payload))
        second = self.service.export_report(copy.deepcopy(payload))
        self.assertEqual(first, second)
        self.assertEqual(
            json.dumps(first, sort_keys=True),
            json.dumps(second, sort_keys=True),
        )


class ReportHttpTest(unittest.TestCase):
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
        self.assertEqual(report["title"], "Weekly report")
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

    def test_empty_export_ok(self):
        status, payload = self.post(
            {
                "allow": [],
                "deny": [],
                "title": "Empty",
                "findings": [],
                "comparisons": None,
                "plans": None,
            }
        )
        self.assertEqual(status, 200)
        self.assertEqual(payload["report"]["targets"], [])
        self.assertEqual(payload["report"]["summary"]["targets"], 0)

    def test_scope_violation_403(self):
        status, payload = self.post(
            export_payload(
                findings=[consolidated_item(target="evil.net")],
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

    def test_inconsistent_comparison_400(self):
        status, payload = self.post(export_payload(findings=[]))
        self.assertEqual(status, 400)
        self.assertEqual(payload["error"]["code"], "invalid_request")

    def test_unknown_target_404(self):
        status, payload = self.request(
            "POST", "/v1/reports/", b"{}"
        )
        self.assertEqual(status, 404)
        self.assertEqual(payload["error"]["code"], "not_found")

    def test_malformed_json_400(self):
        status, payload = self.request("POST", "/v1/reports/export", b"{nope")
        self.assertEqual(status, 400)
        self.assertEqual(payload["error"]["code"], "invalid_request")

    def test_oversized_body_413(self):
        import http.client

        conn = http.client.HTTPConnection("127.0.0.1", self.port)
        conn.putrequest("POST", "/v1/reports/export")
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
                                    "template_id": "t",
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
        self.assertEqual(payload["plans"], [])


if __name__ == "__main__":
    unittest.main()
