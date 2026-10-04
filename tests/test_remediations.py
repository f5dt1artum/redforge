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


def make_remediation(**overrides):
    remediation = {
        "id": "rem-1",
        "title": "Patch the thing",
        "guidance": "Upgrade to a fixed release.",
        "priority": 50,
        "template_ids": ["tpl-1"],
        "depends_on": [],
    }
    remediation.update(overrides)
    return remediation


def remediations_payload(**overrides):
    payload = {
        "allow": ["*.example.com"],
        "deny": [],
        "findings": [make_finding()],
        "remediations": [make_remediation()],
    }
    payload.update(overrides)
    return payload


class RemediationPlanServiceTest(unittest.TestCase):
    def setUp(self):
        self.service = Service()

    def plan(self, **overrides):
        return self.service.plan_remediations(remediations_payload(**overrides))

    def test_ready_action_shape(self):
        result = self.plan()
        self.assertEqual(list(result), ["plans", "summary"])
        (plan,) = result["plans"]
        self.assertEqual(list(plan), ["target", "actions", "uncovered_template_ids"])
        self.assertEqual(plan["target"], "app.example.com")
        self.assertEqual(plan["uncovered_template_ids"], [])
        (action,) = plan["actions"]
        self.assertEqual(
            list(action),
            [
                "remediation_id",
                "title",
                "guidance",
                "status",
                "reason",
                "matched_template_ids",
            ],
        )
        self.assertEqual(
            action,
            {
                "remediation_id": "rem-1",
                "title": "Patch the thing",
                "guidance": "Upgrade to a fixed release.",
                "status": "ready",
                "reason": None,
                "matched_template_ids": ["tpl-1"],
            },
        )
        self.assertEqual(
            result["summary"],
            {
                "targets": 1,
                "actions": 1,
                "ready": 1,
                "blocked": 0,
                "uncovered_findings": 0,
            },
        )

    def test_empty_findings_returns_empty_plans_zero_summary(self):
        result = self.plan(findings=[])
        self.assertEqual(result, {"plans": [], "summary": {
            "targets": 0,
            "actions": 0,
            "ready": 0,
            "blocked": 0,
            "uncovered_findings": 0,
        }})

    def test_empty_remediations_leaves_findings_uncovered(self):
        result = self.plan(
            findings=[
                make_finding(template_id="tpl-1"),
                make_finding(template_id="tpl-2"),
            ],
            remediations=[],
        )
        (plan,) = result["plans"]
        self.assertEqual(plan["actions"], [])
        self.assertEqual(plan["uncovered_template_ids"], ["tpl-1", "tpl-2"])
        self.assertEqual(result["summary"]["uncovered_findings"], 2)

    def test_remediation_only_enters_matching_target(self):
        result = self.plan(
            findings=[
                make_finding(target="a.example.com", template_id="tpl-1"),
                make_finding(target="b.example.com", template_id="tpl-2"),
            ],
        )
        plans = result["plans"]
        self.assertEqual([plan["target"] for plan in plans],
                         ["a.example.com", "b.example.com"])
        # The single remediation covers tpl-1, so it only enters target a.
        self.assertEqual([a["remediation_id"] for a in plans[0]["actions"]],
                         ["rem-1"])
        self.assertEqual(plans[0]["uncovered_template_ids"], [])
        self.assertEqual(plans[1]["actions"], [])
        self.assertEqual(plans[1]["uncovered_template_ids"], ["tpl-2"])

    def test_template_id_match_is_case_sensitive(self):
        result = self.plan(findings=[make_finding(template_id="TPL-1")])
        (plan,) = result["plans"]
        self.assertEqual(plan["actions"], [])
        self.assertEqual(plan["uncovered_template_ids"], ["TPL-1"])

    def test_direct_dependency_not_entered_is_blocked_not_applicable(self):
        # rem-2 depends on rem-1, but rem-1 matches a template that no
        # finding in this target carries, so rem-1 never enters; rem-2
        # enters on its own match and is blocked/dependency_not_applicable.
        remediations = [
            make_remediation(id="rem-1", template_ids=["absent"]),
            make_remediation(id="rem-2", template_ids=["tpl-1"],
                             depends_on=["rem-1"]),
        ]
        result = self.plan(remediations=remediations)
        (plan,) = result["plans"]
        self.assertEqual(
            [(a["remediation_id"], a["status"], a["reason"])
             for a in plan["actions"]],
            [("rem-2", "blocked", "dependency_not_applicable")],
        )
        self.assertEqual(result["summary"]["blocked"], 1)
        self.assertEqual(result["summary"]["ready"], 0)

    def test_entered_blocked_dependency_propagates(self):
        # rem-1 enters but is blocked because its dependency rem-0 did not
        # enter; rem-2 depends on rem-1 -> dependency_blocked; rem-3 on
        # rem-2 stays dependency_blocked transitively.
        remediations = [
            make_remediation(id="rem-0", template_ids=["absent"]),
            make_remediation(id="rem-1", template_ids=["tpl-1"],
                             depends_on=["rem-0"]),
            make_remediation(id="rem-2", template_ids=["tpl-1"],
                             depends_on=["rem-1"]),
            make_remediation(id="rem-3", template_ids=["tpl-1"],
                             depends_on=["rem-2"]),
        ]
        result = self.plan(remediations=remediations)
        (plan,) = result["plans"]
        self.assertEqual(
            [(a["remediation_id"], a["status"], a["reason"])
             for a in plan["actions"]],
            [
                ("rem-1", "blocked", "dependency_not_applicable"),
                ("rem-2", "blocked", "dependency_blocked"),
                ("rem-3", "blocked", "dependency_blocked"),
            ],
        )

    def test_ready_dependency_keeps_dependent_ready(self):
        remediations = [
            make_remediation(id="rem-2", template_ids=["tpl-2"],
                             depends_on=["rem-1"]),
            make_remediation(id="rem-1", template_ids=["tpl-1"]),
        ]
        result = self.plan(
            findings=[
                make_finding(template_id="tpl-1"),
                make_finding(template_id="tpl-2"),
            ],
            remediations=remediations,
        )
        (plan,) = result["plans"]
        # Topological order puts the dependency rem-1 first.
        self.assertEqual(
            [(a["remediation_id"], a["status"]) for a in plan["actions"]],
            [("rem-1", "ready"), ("rem-2", "ready")],
        )

    def test_not_applicable_dep_does_not_block_ready_chain(self):
        # rem-1 is ready; rem-2 depends on rem-1 (ready) and rem-x (never
        # enters) -> dependency_not_applicable; rem-3 depends only on rem-1
        # and stays ready.
        remediations = [
            make_remediation(id="rem-1", template_ids=["tpl-1"]),
            make_remediation(id="rem-x", template_ids=["absent"]),
            make_remediation(id="rem-2", template_ids=["tpl-1"],
                             depends_on=["rem-1", "rem-x"]),
            make_remediation(id="rem-3", template_ids=["tpl-1"],
                             depends_on=["rem-1"]),
        ]
        result = self.plan(remediations=remediations)
        (plan,) = result["plans"]
        statuses = {a["remediation_id"]: (a["status"], a["reason"])
                    for a in plan["actions"]}
        self.assertNotIn("rem-x", statuses)
        self.assertEqual(statuses["rem-1"], ("ready", None))
        self.assertEqual(statuses["rem-2"],
                         ("blocked", "dependency_not_applicable"))
        self.assertEqual(statuses["rem-3"], ("ready", None))

    def test_actions_ordered_by_topology_then_priority_then_input(self):
        # s3 depends on s1/s2; s1 and s2 are the same level and priority
        # decides (s2 priority 90 before s1 priority 10); s3 last.
        remediations = [
            make_remediation(id="s3", title="C", priority=100,
                             template_ids=["tpl-1"], depends_on=["s1", "s2"]),
            make_remediation(id="s1", title="A", priority=10,
                             template_ids=["tpl-1"]),
            make_remediation(id="s2", title="B", priority=90,
                             template_ids=["tpl-1"]),
        ]
        result = self.plan(remediations=remediations)
        (plan,) = result["plans"]
        self.assertEqual(
            [a["remediation_id"] for a in plan["actions"]],
            ["s2", "s1", "s3"],
        )

    def test_input_order_breaks_priority_tie(self):
        remediations = [
            make_remediation(id="low-first", priority=50,
                             template_ids=["tpl-1"]),
            make_remediation(id="low-second", priority=50,
                             template_ids=["tpl-1"]),
        ]
        result = self.plan(remediations=remediations)
        (plan,) = result["plans"]
        self.assertEqual(
            [a["remediation_id"] for a in plan["actions"]],
            ["low-first", "low-second"],
        )

    def test_matched_template_ids_follow_finding_first_occurrence(self):
        # Catalog lists tpl-2 before tpl-1, but finding order is tpl-1 then
        # tpl-2, so matched order follows findings.
        remediation = make_remediation(template_ids=["tpl-2", "tpl-1"])
        result = self.plan(
            findings=[
                make_finding(template_id="tpl-1"),
                make_finding(template_id="tpl-2"),
            ],
            remediations=[remediation],
        )
        (plan,) = result["plans"]
        self.assertEqual(plan["actions"][0]["matched_template_ids"],
                         ["tpl-1", "tpl-2"])

    def test_matched_template_ids_deduplicated(self):
        # Findings cannot repeat the same (target, template_id) key, but
        # matched ids must still be unique per action.
        remediation = make_remediation(template_ids=["tpl-1", "tpl-1"])
        with self.assertRaises(ValueError):
            self.plan(remediations=[remediation])

    def test_uncovered_template_ids_follow_finding_order(self):
        remediations = [make_remediation(template_ids=["tpl-2"])]
        result = self.plan(
            findings=[
                make_finding(template_id="tpl-3"),
                make_finding(template_id="tpl-1"),
                make_finding(template_id="tpl-2"),
            ],
            remediations=remediations,
        )
        (plan,) = result["plans"]
        self.assertEqual(plan["uncovered_template_ids"], ["tpl-3", "tpl-1"])

    def test_targets_keep_first_occurrence_order(self):
        result = self.plan(
            findings=[
                make_finding(target="b.example.com", template_id="tpl-1"),
                make_finding(target="a.example.com", template_id="tpl-1"),
                make_finding(target="b.example.com", template_id="tpl-2"),
            ]
        )
        self.assertEqual(
            [plan["target"] for plan in result["plans"]],
            ["b.example.com", "a.example.com"],
        )

    def test_normalized_target_groups_findings(self):
        result = self.plan(
            findings=[
                make_finding(target="APP.Example.COM.", template_id="tpl-1"),
                make_finding(target="app.example.com", template_id="tpl-2"),
            ],
            remediations=[
                make_remediation(id="r1", template_ids=["tpl-1", "tpl-2"]),
            ],
        )
        self.assertEqual(len(result["plans"]), 1)
        self.assertEqual(result["plans"][0]["target"], "app.example.com")
        self.assertEqual(
            result["plans"][0]["actions"][0]["matched_template_ids"],
            ["tpl-1", "tpl-2"],
        )

    def test_summary_counts_across_targets(self):
        result = self.plan(
            findings=[
                make_finding(target="a.example.com", template_id="tpl-1"),
                make_finding(target="b.example.com", template_id="zzz"),
            ],
            remediations=[make_remediation()],
        )
        self.assertEqual(
            result["summary"],
            {
                "targets": 2,
                "actions": 1,
                "ready": 1,
                "blocked": 0,
                "uncovered_findings": 1,
            },
        )

    def test_duplicate_finding_key_is_invalid(self):
        with self.assertRaises(ValueError):
            self.plan(findings=[make_finding(), make_finding(name="Other")])
        with self.assertRaises(ValueError):
            self.plan(
                findings=[
                    make_finding(),
                    make_finding(target="APP.Example.COM."),
                ]
            )

    def test_scope_violation_raises(self):
        with self.assertRaises(ScopeViolationError):
            self.plan(findings=[make_finding(target="evil.net")])
        with self.assertRaises(ScopeViolationError):
            self.plan(deny=["app.example.com"])

    def test_empty_findings_still_checks_catalog_and_scope(self):
        # A broken catalog is a 400 even with no findings.
        with self.assertRaises(ValueError):
            self.service.plan_remediations(
                remediations_payload(
                    findings=[],
                    remediations=[
                        make_remediation(depends_on=["ghost"]),
                    ],
                )
            )
        # Bad scope rules are a 400 too with no findings.
        with self.assertRaises(ValueError):
            self.service.plan_remediations(
                {"allow": ["not a host!"], "deny": [],
                 "findings": [], "remediations": []}
            )

    def test_structure_validated_before_scope_gate(self):
        with self.assertRaises(ValueError):
            self.plan(
                findings=[
                    make_finding(target="evil.net"),
                    make_finding(target="evil.net"),
                ]
            )
        with self.assertRaises(ValueError):
            self.plan(
                findings=[make_finding(target="evil.net")],
                remediations=[make_remediation(depends_on=["nope"])],
            )

    def test_remediation_dependency_validation(self):
        bad_remediations = [
            [make_remediation(id="a", depends_on=["a"])],  # self reference
            [make_remediation(depends_on=["ghost"])],  # unknown id
            [
                make_remediation(id="a", depends_on=["b", "b"]),
            ],  # duplicate dependency
            [
                make_remediation(id="dup"),
                make_remediation(id="dup"),
            ],  # duplicate id
            [
                make_remediation(id="a", depends_on=["b"]),
                make_remediation(id="b", depends_on=["a"]),
            ],  # cycle
            [
                make_remediation(id="a", depends_on=["c"]),
                make_remediation(id="b", depends_on=["a"]),
                make_remediation(id="c", depends_on=["b"]),
            ],  # longer cycle
        ]
        for remediations in bad_remediations:
            with self.subTest(remediations=remediations):
                with self.assertRaises(ValueError):
                    self.plan(remediations=remediations)

    def test_validation_errors(self):
        bad_payloads = [
            None,
            [],
            {},
            {"allow": [], "deny": [], "findings": []},
            remediations_payload(extra=1),
            remediations_payload(allow="*.example.com"),
            remediations_payload(deny=1),
            remediations_payload(findings={}),
            remediations_payload(findings="x"),
            remediations_payload(findings=[None]),
            remediations_payload(findings=[{"target": "app.example.com"}]),
            remediations_payload(findings=[make_finding(extra=1)]),
            remediations_payload(findings=[make_finding(severity="fatal")]),
            remediations_payload(findings=[make_finding(confidence=101)]),
            remediations_payload(findings=[make_finding(confidence=True)]),
            remediations_payload(remediations={}),
            remediations_payload(remediations="x"),
            remediations_payload(remediations=[None]),
            remediations_payload(remediations=[{"id": "r1"}]),
            remediations_payload(remediations=[make_remediation(extra=1)]),
            remediations_payload(remediations=[make_remediation(id="")]),
            remediations_payload(remediations=[make_remediation(id=3)]),
            remediations_payload(remediations=[make_remediation(title="")]),
            remediations_payload(remediations=[make_remediation(title=1)]),
            remediations_payload(remediations=[make_remediation(guidance="")]),
            remediations_payload(remediations=[make_remediation(guidance=1)]),
            remediations_payload(remediations=[make_remediation(priority=0)]),
            remediations_payload(remediations=[make_remediation(priority=101)]),
            remediations_payload(remediations=[make_remediation(priority=True)]),
            remediations_payload(remediations=[make_remediation(priority=1.5)]),
            remediations_payload(remediations=[make_remediation(template_ids=[])]),
            remediations_payload(remediations=[make_remediation(template_ids="x")]),
            remediations_payload(
                remediations=[make_remediation(template_ids=[""])]
            ),
            remediations_payload(
                remediations=[make_remediation(template_ids=[1])]
            ),
            remediations_payload(
                remediations=[make_remediation(depends_on="r1")]
            ),
            remediations_payload(remediations=[make_remediation(depends_on=[1])]),
            remediations_payload(remediations=[make_remediation(depends_on=[""])]),
        ]
        for payload in bad_payloads:
            with self.subTest(payload=repr(payload)[:90]):
                with self.assertRaises(ValueError):
                    self.service.plan_remediations(payload)

    def test_order_is_stable_for_same_input(self):
        payload = remediations_payload(
            findings=[
                make_finding(target="b.example.com", template_id="tpl-1"),
                make_finding(target="a.example.com", template_id="tpl-1"),
            ],
            remediations=[
                make_remediation(id="r2", priority=5, depends_on=["r1"]),
                make_remediation(id="r1", priority=5),
                make_remediation(id="r3", priority=90),
            ],
        )
        first = self.service.plan_remediations(payload)
        second = self.service.plan_remediations(payload)
        self.assertEqual(first, second)


class RemediationPlanHttpTest(unittest.TestCase):
    PATH = "/v1/remediations/plan"

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
            "POST", self.PATH, json.dumps(payload).encode()
        )

    def test_plan_ok(self):
        status, payload = self.post(
            remediations_payload(
                findings=[
                    make_finding(target="a.example.com", template_id="tpl-1"),
                    make_finding(target="b.example.com", template_id="tpl-1"),
                ],
                remediations=[
                    make_remediation(id="r1"),
                    make_remediation(id="r2", depends_on=["r1"]),
                ],
            )
        )
        self.assertEqual(status, 200)
        self.assertEqual(list(payload), ["plans", "summary"])
        self.assertEqual(
            [plan["target"] for plan in payload["plans"]],
            ["a.example.com", "b.example.com"],
        )
        for plan in payload["plans"]:
            self.assertEqual(
                [(a["remediation_id"], a["status"], a["reason"])
                 for a in plan["actions"]],
                [("r1", "ready", None), ("r2", "ready", None)],
            )

    def test_empty_findings_ok(self):
        status, payload = self.post(remediations_payload(findings=[]))
        self.assertEqual(status, 200)
        self.assertEqual(payload["plans"], [])
        self.assertEqual(
            payload["summary"],
            {
                "targets": 0,
                "actions": 0,
                "ready": 0,
                "blocked": 0,
                "uncovered_findings": 0,
            },
        )

    def test_scope_violation_403(self):
        status, payload = self.post(
            remediations_payload(findings=[make_finding(target="evil.net")])
        )
        self.assertEqual(status, 403)
        self.assertEqual(payload["error"]["code"], "scope_violation")
        self.assertNotIn("plans", payload)

    def test_invalid_request_400(self):
        status, payload = self.post(
            remediations_payload(remediations=[make_remediation(priority=0)])
        )
        self.assertEqual(status, 400)
        self.assertEqual(payload["error"]["code"], "invalid_request")

    def test_duplicate_finding_key_400(self):
        status, payload = self.post(
            remediations_payload(findings=[make_finding(), make_finding()])
        )
        self.assertEqual(status, 400)
        self.assertEqual(payload["error"]["code"], "invalid_request")

    def test_duplicate_remediation_id_400(self):
        status, payload = self.post(
            remediations_payload(
                remediations=[make_remediation(id="dup"),
                              make_remediation(id="dup")]
            )
        )
        self.assertEqual(status, 400)
        self.assertEqual(payload["error"]["code"], "invalid_request")

    def test_cycle_400(self):
        status, payload = self.post(
            remediations_payload(
                remediations=[
                    make_remediation(id="a", depends_on=["b"]),
                    make_remediation(id="b", depends_on=["a"]),
                ]
            )
        )
        self.assertEqual(status, 400)
        self.assertEqual(payload["error"]["code"], "invalid_request")

    def test_malformed_json_400(self):
        status, payload = self.request("POST", self.PATH, b"{nope")
        self.assertEqual(status, 400)
        self.assertEqual(payload["error"]["code"], "invalid_request")

    def test_method_not_allowed_405(self):
        for method in ("GET", "PUT", "DELETE", "PATCH"):
            with self.subTest(method=method):
                status, payload = self.request(method, self.PATH)
                self.assertEqual(status, 405)
                self.assertEqual(payload["error"]["code"], "method_not_allowed")

    def test_existing_routes_unchanged(self):
        status, payload = self.request("GET", "/healthz")
        self.assertEqual(status, 200)
        self.assertEqual(payload["status"], "ok")
        status, payload = self.post(
            remediations_payload(findings=[], remediations=[])
        )
        self.assertEqual(status, 200)
        self.assertEqual(payload["plans"], [])


if __name__ == "__main__":
    unittest.main()
