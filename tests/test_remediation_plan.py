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
        "guidance": "Apply vendor patch and retest.",
        "priority": 50,
        "template_ids": ["tpl-1"],
        "depends_on": [],
    }
    remediation.update(overrides)
    return remediation


def plan_payload(**overrides):
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
        return self.service.plan_remediations(plan_payload(**overrides))

    def test_ready_action(self):
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
                "guidance": "Apply vendor patch and retest.",
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

    def test_empty_findings_returns_empty_plans_and_zero_summary(self):
        result = self.plan(
            findings=[],
            remediations=[make_remediation(), make_remediation(id="rem-2")],
        )
        self.assertEqual(result, {"plans": [], "summary": {
            "targets": 0,
            "actions": 0,
            "ready": 0,
            "blocked": 0,
            "uncovered_findings": 0,
        }})

    def test_empty_remediations_leaves_every_finding_uncovered(self):
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

    def test_template_id_match_is_case_sensitive(self):
        result = self.plan(
            findings=[make_finding(template_id="TPL-1")],
        )
        (plan,) = result["plans"]
        self.assertEqual(plan["actions"], [])
        self.assertEqual(plan["uncovered_template_ids"], ["TPL-1"])

    def test_matched_template_ids_follow_finding_order(self):
        remediation = make_remediation(template_ids=["tpl-3", "tpl-1", "tpl-2"])
        result = self.plan(
            findings=[
                make_finding(template_id="tpl-2"),
                make_finding(template_id="tpl-1"),
                make_finding(template_id="tpl-3"),
            ],
            remediations=[remediation],
        )
        (action,) = result["plans"][0]["actions"]
        # Catalog order does not matter; finding first-occurrence order wins.
        self.assertEqual(action["matched_template_ids"], ["tpl-2", "tpl-1", "tpl-3"])

    def test_uncovered_templates_keep_finding_order(self):
        result = self.plan(
            findings=[
                make_finding(template_id="tpl-2"),
                make_finding(template_id="tpl-1"),
                make_finding(template_id="tpl-9"),
            ],
            remediations=[make_remediation(template_ids=["tpl-1"])],
        )
        (plan,) = result["plans"]
        self.assertEqual(plan["uncovered_template_ids"], ["tpl-2", "tpl-9"])

    def test_dependency_not_applicable(self):
        # rem-1 matches no template on this target, so rem-2's direct
        # dependency never enters the plan; no missing dependency is invented.
        result = self.plan(
            remediations=[
                make_remediation(id="rem-1", template_ids=["absent"]),
                make_remediation(id="rem-2", template_ids=["tpl-1"],
                                 depends_on=["rem-1"]),
            ]
        )
        (plan,) = result["plans"]
        self.assertEqual([a["remediation_id"] for a in plan["actions"]], ["rem-2"])
        action = plan["actions"][0]
        self.assertEqual(action["status"], "blocked")
        self.assertEqual(action["reason"], "dependency_not_applicable")

    def test_dependency_blocked_propagates(self):
        result = self.plan(
            remediations=[
                make_remediation(id="rem-1", template_ids=["absent"]),
                make_remediation(id="rem-2", template_ids=["tpl-1"],
                                 depends_on=["rem-1"]),
                make_remediation(id="rem-3", template_ids=["tpl-1"],
                                 depends_on=["rem-2"]),
            ]
        )
        actions = result["plans"][0]["actions"]
        self.assertEqual(
            [(a["remediation_id"], a["status"], a["reason"]) for a in actions],
            [
                ("rem-2", "blocked", "dependency_not_applicable"),
                ("rem-3", "blocked", "dependency_blocked"),
            ],
        )
        self.assertEqual(result["summary"]["blocked"], 2)
        self.assertEqual(result["summary"]["ready"], 0)

    def test_ready_dependency_chain(self):
        result = self.plan(
            findings=[
                make_finding(template_id="tpl-1"),
                make_finding(template_id="tpl-2"),
            ],
            remediations=[
                make_remediation(id="rem-2", template_ids=["tpl-2"],
                                 depends_on=["rem-1"]),
                make_remediation(id="rem-1", template_ids=["tpl-1"]),
            ],
        )
        actions = result["plans"][0]["actions"]
        self.assertEqual(
            [(a["remediation_id"], a["status"]) for a in actions],
            [("rem-1", "ready"), ("rem-2", "ready")],
        )

    def test_not_applicable_takes_precedence_over_blocked_dependency(self):
        # rem-2 has one blocked entered dependency and one dependency that
        # never enters; the spec names dependency_not_applicable first.
        result = self.plan(
            remediations=[
                make_remediation(id="rem-1", template_ids=["absent"]),
                make_remediation(id="rem-3", template_ids=["absent"]),
                make_remediation(id="rem-2", template_ids=["tpl-1"],
                                 depends_on=["rem-1", "rem-3"]),
            ]
        )
        action = result["plans"][0]["actions"][0]
        self.assertEqual(action["status"], "blocked")
        self.assertEqual(action["reason"], "dependency_not_applicable")

    def test_actions_follow_topological_layers(self):
        # Layer 0: a, b (both roots); layer 1: c depends on a and b.
        result = self.plan(
            findings=[make_finding(template_id="tpl-1")],
            remediations=[
                make_remediation(id="c", depends_on=["a", "b"]),
                make_remediation(id="a"),
                make_remediation(id="b"),
            ],
        )
        ids = [a["remediation_id"] for a in result["plans"][0]["actions"]]
        self.assertEqual(ids, ["a", "b", "c"])

    def test_same_layer_priority_descends_then_input_order(self):
        result = self.plan(
            findings=[make_finding(template_id="tpl-1")],
            remediations=[
                make_remediation(id="low", priority=10),
                make_remediation(id="high", priority=90),
                make_remediation(id="mid", priority=50),
                make_remediation(id="high2", priority=90),
            ],
        )
        ids = [a["remediation_id"] for a in result["plans"][0]["actions"]]
        self.assertEqual(ids, ["high", "high2", "mid", "low"])

    def test_priority_only_breaks_ties_within_layer(self):
        # A lower-priority root still precedes a higher-priority child.
        result = self.plan(
            findings=[make_finding(template_id="tpl-1")],
            remediations=[
                make_remediation(id="child", priority=100, depends_on=["root"]),
                make_remediation(id="root", priority=1),
            ],
        )
        ids = [a["remediation_id"] for a in result["plans"][0]["actions"]]
        self.assertEqual(ids, ["root", "child"])

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
            ]
        )
        (plan,) = result["plans"]
        self.assertEqual(plan["target"], "app.example.com")
        self.assertEqual(
            [a["remediation_id"] for a in plan["actions"]], ["rem-1"]
        )
        self.assertEqual(plan["uncovered_template_ids"], ["tpl-2"])

    def test_per_target_entry_is_independent(self):
        # Dependency enters on the first target but not the second; each
        # target's statuses are computed independently.
        result = self.plan(
            findings=[
                make_finding(target="a.example.com", template_id="tpl-1"),
                make_finding(target="a.example.com", template_id="tpl-2"),
                make_finding(target="b.example.com", template_id="tpl-2"),
            ],
            remediations=[
                make_remediation(id="base", template_ids=["tpl-1"]),
                make_remediation(id="follow", template_ids=["tpl-2"],
                                 depends_on=["base"]),
            ],
        )
        plans = {plan["target"]: plan for plan in result["plans"]}
        self.assertEqual(
            [a["remediation_id"] for a in plans["a.example.com"]["actions"]],
            ["base", "follow"],
        )
        self.assertTrue(
            all(a["status"] == "ready" for a in plans["a.example.com"]["actions"])
        )
        (follow_b,) = plans["b.example.com"]["actions"]
        self.assertEqual(follow_b["remediation_id"], "follow")
        self.assertEqual(follow_b["status"], "blocked")
        self.assertEqual(follow_b["reason"], "dependency_not_applicable")
        self.assertEqual(
            result["summary"],
            {
                "targets": 2,
                "actions": 3,
                "ready": 2,
                "blocked": 1,
                "uncovered_findings": 0,
            },
        )

    def test_duplicate_finding_key_is_invalid(self):
        with self.assertRaises(ValueError):
            self.plan(findings=[make_finding(), make_finding()])
        # The same key reached through different target spellings counts too.
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

    def test_empty_findings_still_checks_catalog_and_scope_rules(self):
        # A cyclic catalog is a 400 even with no findings.
        with self.assertRaises(ValueError):
            self.service.plan_remediations(
                {
                    "allow": ["*.example.com"],
                    "deny": [],
                    "findings": [],
                    "remediations": [
                        make_remediation(id="a", depends_on=["b"]),
                        make_remediation(id="b", depends_on=["a"]),
                    ],
                }
            )
        # Invalid scope rules are a 400 too.
        with self.assertRaises(ValueError):
            self.service.plan_remediations(
                {
                    "allow": ["not a hostname!"],
                    "deny": [],
                    "findings": [],
                    "remediations": [],
                }
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
                remediations=[make_remediation(depends_on=["ghost"])],
            )

    def test_remediation_dependency_validation(self):
        bad_catalogs = [
            [make_remediation(depends_on=["rem-1"])],  # self reference
            [make_remediation(depends_on=["ghost"])],  # unknown id
            [make_remediation(depends_on=["a", "a"])],  # duplicate entry
            [make_remediation(id="a"), make_remediation(id="a")],  # dup id
            [
                make_remediation(id="a", depends_on=["b"]),
                make_remediation(id="b", depends_on=["a"]),
            ],  # cycle
        ]
        for remediations in bad_catalogs:
            with self.subTest(remediations=remediations):
                with self.assertRaises(ValueError):
                    self.plan(remediations=remediations)

    def test_validation_errors(self):
        bad_payloads = [
            None,
            [],
            {},
            {"allow": [], "deny": [], "findings": []},
            plan_payload(extra=1),
            plan_payload(allow="*.example.com"),
            plan_payload(deny=1),
            plan_payload(findings={}),
            plan_payload(findings="x"),
            plan_payload(findings=[None]),
            plan_payload(findings=[{"target": "app.example.com"}]),
            plan_payload(findings=[make_finding(extra=1)]),
            plan_payload(findings=[make_finding(severity="fatal")]),
            plan_payload(findings=[make_finding(confidence=101)]),
            plan_payload(findings=[make_finding(confidence=True)]),
            plan_payload(remediations={}),
            plan_payload(remediations="x"),
            plan_payload(remediations=[None]),
            plan_payload(remediations=[{"id": "r1"}]),
            plan_payload(remediations=[make_remediation(extra=1)]),
            plan_payload(remediations=[make_remediation(id="")]),
            plan_payload(remediations=[make_remediation(id=3)]),
            plan_payload(remediations=[make_remediation(title="")]),
            plan_payload(remediations=[make_remediation(title=1)]),
            plan_payload(remediations=[make_remediation(guidance="")]),
            plan_payload(remediations=[make_remediation(guidance=1)]),
            plan_payload(remediations=[make_remediation(priority=0)]),
            plan_payload(remediations=[make_remediation(priority=101)]),
            plan_payload(remediations=[make_remediation(priority=True)]),
            plan_payload(remediations=[make_remediation(priority=1.5)]),
            plan_payload(remediations=[make_remediation(template_ids=[])]),
            plan_payload(remediations=[make_remediation(template_ids="x")]),
            plan_payload(remediations=[make_remediation(template_ids=[""])]),
            plan_payload(remediations=[make_remediation(template_ids=[1])]),
            plan_payload(
                remediations=[make_remediation(template_ids=["tpl-1", "tpl-1"])]
            ),
            plan_payload(remediations=[make_remediation(depends_on="r1")]),
            plan_payload(remediations=[make_remediation(depends_on=[1])]),
            plan_payload(remediations=[make_remediation(depends_on=[""])]),
        ]
        for payload in bad_payloads:
            with self.subTest(payload=repr(payload)[:90]):
                with self.assertRaises(ValueError):
                    self.service.plan_remediations(payload)

    def test_order_is_stable_for_same_input(self):
        payload = plan_payload(
            findings=[
                make_finding(target="b.example.com", template_id="tpl-2"),
                make_finding(target="a.example.com", template_id="tpl-1"),
            ],
            remediations=[
                make_remediation(id="r2", priority=10, template_ids=["tpl-2"]),
                make_remediation(id="r1", priority=90, template_ids=["tpl-1"]),
            ],
        )
        first = self.service.plan_remediations(payload)
        second = self.service.plan_remediations(payload)
        self.assertEqual(first, second)


class RemediationPlanHttpTest(unittest.TestCase):
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
            "POST", "/v1/remediations/plan", json.dumps(payload).encode()
        )

    def test_plan_ok(self):
        status, payload = self.post(
            plan_payload(
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
        self.assertEqual(
            payload["summary"],
            {
                "targets": 2,
                "actions": 4,
                "ready": 4,
                "blocked": 0,
                "uncovered_findings": 0,
            },
        )

    def test_empty_findings_ok(self):
        status, payload = self.post(plan_payload(findings=[]))
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
            plan_payload(findings=[make_finding(target="evil.net")])
        )
        self.assertEqual(status, 403)
        self.assertEqual(payload["error"]["code"], "scope_violation")
        self.assertNotIn("plans", payload)

    def test_invalid_request_400(self):
        status, payload = self.post(
            plan_payload(remediations=[make_remediation(priority=0)])
        )
        self.assertEqual(status, 400)
        self.assertEqual(payload["error"]["code"], "invalid_request")

    def test_duplicate_remediation_id_400(self):
        status, payload = self.post(
            plan_payload(
                remediations=[make_remediation(id="r1"), make_remediation(id="r1")]
            )
        )
        self.assertEqual(status, 400)
        self.assertEqual(payload["error"]["code"], "invalid_request")

    def test_cycle_400(self):
        status, payload = self.post(
            plan_payload(
                remediations=[
                    make_remediation(id="a", depends_on=["b"]),
                    make_remediation(id="b", depends_on=["a"]),
                ]
            )
        )
        self.assertEqual(status, 400)
        self.assertEqual(payload["error"]["code"], "invalid_request")

    def test_malformed_json_400(self):
        status, payload = self.request("POST", "/v1/remediations/plan", b"{nope")
        self.assertEqual(status, 400)
        self.assertEqual(payload["error"]["code"], "invalid_request")

    def test_oversized_body_413(self):
        import http.client

        conn = http.client.HTTPConnection("127.0.0.1", self.port)
        conn.putrequest("POST", "/v1/remediations/plan")
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
                status, payload = self.request(method, "/v1/remediations/plan")
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
                    "findings": [make_finding()],
                    "stages": [
                        {
                            "id": "stage-1",
                            "name": "Initial access",
                            "logic": "all",
                            "requires": [
                                {
                                    "template_id": "tpl-1",
                                    "min_severity": "medium",
                                    "min_confidence": 50,
                                }
                            ],
                            "depends_on": [],
                        }
                    ],
                }
            ).encode(),
        )
        self.assertEqual(status, 200)
        self.assertEqual(list(payload), ["plans"])


if __name__ == "__main__":
    unittest.main()
