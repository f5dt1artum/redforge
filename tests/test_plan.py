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


def make_requirement(**overrides):
    requirement = {
        "template_id": "tpl-1",
        "min_severity": "medium",
        "min_confidence": 50,
    }
    requirement.update(overrides)
    return requirement


def make_stage(**overrides):
    stage = {
        "id": "stage-1",
        "name": "Initial access",
        "logic": "all",
        "requires": [make_requirement()],
        "depends_on": [],
    }
    stage.update(overrides)
    return stage


def plan_payload(**overrides):
    payload = {
        "allow": ["*.example.com"],
        "deny": [],
        "findings": [make_finding()],
        "stages": [make_stage()],
    }
    payload.update(overrides)
    return payload


class PlanServiceTest(unittest.TestCase):
    def setUp(self):
        self.service = Service()

    def plan(self, **overrides):
        return self.service.plan_attack_chains(plan_payload(**overrides))

    def test_ready_stage(self):
        result = self.plan()
        self.assertEqual(list(result), ["plans"])
        (plan,) = result["plans"]
        self.assertEqual(list(plan), ["target", "stages"])
        self.assertEqual(plan["target"], "app.example.com")
        (stage,) = plan["stages"]
        self.assertEqual(list(stage), ["id", "name", "status", "reason"])
        self.assertEqual(
            stage,
            {
                "id": "stage-1",
                "name": "Initial access",
                "status": "ready",
                "reason": None,
            },
        )

    def test_empty_findings_returns_empty_plans(self):
        result = self.plan(findings=[])
        self.assertEqual(result, {"plans": []})

    def test_missing_requirements_when_thresholds_not_met(self):
        result = self.plan(findings=[make_finding(severity="low")])
        (stage,) = result["plans"][0]["stages"]
        self.assertEqual(stage["status"], "skipped")
        self.assertEqual(stage["reason"], "missing_requirements")
        result = self.plan(findings=[make_finding(confidence=10)])
        (stage,) = result["plans"][0]["stages"]
        self.assertEqual(stage["status"], "skipped")
        self.assertEqual(stage["reason"], "missing_requirements")

    def test_template_id_match_is_case_sensitive(self):
        result = self.plan(findings=[make_finding(template_id="TPL-1")])
        (stage,) = result["plans"][0]["stages"]
        self.assertEqual(stage["status"], "skipped")
        self.assertEqual(stage["reason"], "missing_requirements")

    def test_requirements_only_match_same_target(self):
        result = self.plan(
            findings=[make_finding(target="other.example.com")],
            stages=[
                make_stage(id="s1", name="A"),
                make_stage(id="s2", name="B", depends_on=["s1"]),
            ],
        )
        (plan,) = result["plans"]
        self.assertEqual(plan["target"], "other.example.com")
        self.assertEqual(
            [(s["status"], s["reason"]) for s in plan["stages"]],
            [("ready", None), ("ready", None)],
        )

    def test_dependency_blocked(self):
        stages = [
            make_stage(
                id="s1",
                name="A",
                requires=[make_requirement(template_id="absent")],
            ),
            make_stage(id="s2", name="B", depends_on=["s1"]),
        ]
        result = self.plan(stages=stages)
        (plan,) = result["plans"]
        self.assertEqual(
            [(s["status"], s["reason"]) for s in plan["stages"]],
            [("skipped", "missing_requirements"), ("skipped", "dependency_blocked")],
        )

    def test_blocked_dependency_propagates_transitively(self):
        stages = [
            make_stage(
                id="s1",
                name="A",
                requires=[make_requirement(template_id="absent")],
            ),
            make_stage(id="s2", name="B", depends_on=["s1"]),
            make_stage(id="s3", name="C", depends_on=["s2"]),
        ]
        result = self.plan(stages=stages)
        (plan,) = result["plans"]
        self.assertEqual(
            [s["reason"] for s in plan["stages"]],
            ["missing_requirements", "dependency_blocked", "dependency_blocked"],
        )

    def test_logic_any_matches_one_requirement(self):
        stage = make_stage(
            logic="any",
            requires=[
                make_requirement(template_id="absent"),
                make_requirement(template_id="tpl-1"),
            ],
        )
        result = self.plan(stages=[stage])
        (stage_result,) = result["plans"][0]["stages"]
        self.assertEqual(stage_result["status"], "ready")

    def test_logic_all_requires_every_requirement(self):
        stage = make_stage(
            logic="all",
            requires=[
                make_requirement(template_id="tpl-1"),
                make_requirement(template_id="absent"),
            ],
        )
        result = self.plan(stages=[stage])
        (stage_result,) = result["plans"][0]["stages"]
        self.assertEqual(stage_result["status"], "skipped")
        self.assertEqual(stage_result["reason"], "missing_requirements")

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

    def test_same_level_stages_keep_input_order(self):
        stages = [
            make_stage(id="s3", name="C", depends_on=["s1", "s2"]),
            make_stage(id="s1", name="A"),
            make_stage(id="s2", name="B"),
        ]
        result = self.plan(stages=stages)
        (plan,) = result["plans"]
        self.assertEqual([s["id"] for s in plan["stages"]], ["s1", "s2", "s3"])

    def test_duplicate_finding_key_is_invalid(self):
        with self.assertRaises(ValueError):
            self.plan(
                findings=[make_finding(), make_finding(name="Other name")]
            )
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

    def test_structure_validated_before_scope_gate(self):
        # A duplicate finding key is a 400 even though a target is out of
        # scope.
        with self.assertRaises(ValueError):
            self.plan(
                findings=[make_finding(target="evil.net"), make_finding(target="evil.net")]
            )
        # A broken dependency graph is a 400 too.
        with self.assertRaises(ValueError):
            self.plan(
                findings=[make_finding(target="evil.net")],
                stages=[make_stage(depends_on=["nope"])],
            )

    def test_stage_dependency_validation(self):
        bad_stages = [
            [make_stage(depends_on=["stage-1"])],  # self reference
            [make_stage(depends_on=["ghost"])],  # unknown id
            [make_stage(depends_on=["a", "a"])],  # duplicate entry
            [make_stage(id="a"), make_stage(id="a")],  # duplicate stage id
            [
                make_stage(id="a", depends_on=["b"]),
                make_stage(id="b", depends_on=["a"]),
            ],  # cycle
            [
                make_stage(id="a", depends_on=["c"]),
                make_stage(id="b", depends_on=["a"]),
                make_stage(id="c", depends_on=["b"]),
            ],  # longer cycle
        ]
        for stages in bad_stages:
            with self.subTest(stages=stages):
                with self.assertRaises(ValueError):
                    self.plan(stages=stages)

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
            plan_payload(stages=[]),
            plan_payload(stages={}),
            plan_payload(stages="x"),
            plan_payload(stages=[None]),
            plan_payload(stages=[{"id": "s1"}]),
            plan_payload(stages=[make_stage(extra=1)]),
            plan_payload(stages=[make_stage(id="")]),
            plan_payload(stages=[make_stage(id=3)]),
            plan_payload(stages=[make_stage(name="")]),
            plan_payload(stages=[make_stage(name=1)]),
            plan_payload(stages=[make_stage(logic="all!")]),
            plan_payload(stages=[make_stage(logic="ALL")]),
            plan_payload(stages=[make_stage(requires=[])]),
            plan_payload(stages=[make_stage(requires="x")]),
            plan_payload(stages=[make_stage(requires=[{}])]),
            plan_payload(stages=[make_stage(requires=[make_requirement(extra=1)])]),
            plan_payload(
                stages=[make_stage(requires=[make_requirement(template_id="")])]
            ),
            plan_payload(
                stages=[make_stage(requires=[make_requirement(min_severity="fatal")])]
            ),
            plan_payload(
                stages=[make_stage(requires=[make_requirement(min_confidence=-1)])]
            ),
            plan_payload(
                stages=[make_stage(requires=[make_requirement(min_confidence=101)])]
            ),
            plan_payload(
                stages=[make_stage(requires=[make_requirement(min_confidence=True)])]
            ),
            plan_payload(
                stages=[make_stage(requires=[make_requirement(min_confidence=1.5)])]
            ),
            plan_payload(stages=[make_stage(depends_on="s1")]),
            plan_payload(stages=[make_stage(depends_on=[1])]),
            plan_payload(stages=[make_stage(depends_on=[""])]),
        ]
        for payload in bad_payloads:
            with self.subTest(payload=repr(payload)[:90]):
                with self.assertRaises(ValueError):
                    self.service.plan_attack_chains(payload)

    def test_order_is_stable_for_same_input(self):
        payload = plan_payload(
            findings=[
                make_finding(target="b.example.com", template_id="tpl-1"),
                make_finding(target="a.example.com", template_id="tpl-1"),
            ],
            stages=[
                make_stage(id="s2", name="B", depends_on=["s1"]),
                make_stage(id="s1", name="A"),
            ],
        )
        first = self.service.plan_attack_chains(payload)
        second = self.service.plan_attack_chains(payload)
        self.assertEqual(first, second)


class PlanHttpTest(unittest.TestCase):
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
            "POST", "/v1/attack-chains/plan", json.dumps(payload).encode()
        )

    def test_plan_ok(self):
        status, payload = self.post(
            plan_payload(
                findings=[
                    make_finding(target="a.example.com", template_id="tpl-1"),
                    make_finding(target="b.example.com", template_id="tpl-1"),
                ],
                stages=[
                    make_stage(id="s1", name="A"),
                    make_stage(id="s2", name="B", depends_on=["s1"]),
                ],
            )
        )
        self.assertEqual(status, 200)
        self.assertEqual(list(payload), ["plans"])
        self.assertEqual(
            [plan["target"] for plan in payload["plans"]],
            ["a.example.com", "b.example.com"],
        )
        for plan in payload["plans"]:
            self.assertEqual(
                [(s["id"], s["status"], s["reason"]) for s in plan["stages"]],
                [("s1", "ready", None), ("s2", "ready", None)],
            )

    def test_empty_findings_ok(self):
        status, payload = self.post(plan_payload(findings=[]))
        self.assertEqual(status, 200)
        self.assertEqual(payload, {"plans": []})

    def test_scope_violation_403(self):
        status, payload = self.post(
            plan_payload(findings=[make_finding(target="evil.net")])
        )
        self.assertEqual(status, 403)
        self.assertEqual(payload["error"]["code"], "scope_violation")
        self.assertNotIn("plans", payload)

    def test_invalid_request_400(self):
        status, payload = self.post(plan_payload(stages=[make_stage(logic="bad")]))
        self.assertEqual(status, 400)
        self.assertEqual(payload["error"]["code"], "invalid_request")

    def test_duplicate_finding_key_400(self):
        status, payload = self.post(
            plan_payload(findings=[make_finding(), make_finding()])
        )
        self.assertEqual(status, 400)
        self.assertEqual(payload["error"]["code"], "invalid_request")

    def test_cycle_400(self):
        status, payload = self.post(
            plan_payload(
                stages=[
                    make_stage(id="a", depends_on=["b"]),
                    make_stage(id="b", depends_on=["a"]),
                ]
            )
        )
        self.assertEqual(status, 400)
        self.assertEqual(payload["error"]["code"], "invalid_request")

    def test_malformed_json_400(self):
        status, payload = self.request("POST", "/v1/attack-chains/plan", b"{nope")
        self.assertEqual(status, 400)
        self.assertEqual(payload["error"]["code"], "invalid_request")

    def test_oversized_body_413(self):
        import http.client

        conn = http.client.HTTPConnection("127.0.0.1", self.port)
        conn.putrequest("POST", "/v1/attack-chains/plan")
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
                status, payload = self.request(method, "/v1/attack-chains/plan")
                self.assertEqual(status, 405)
                self.assertEqual(payload["error"]["code"], "method_not_allowed")

    def test_existing_routes_unchanged(self):
        status, payload = self.request("GET", "/healthz")
        self.assertEqual(status, 200)
        self.assertEqual(payload["status"], "ok")
        status, payload = self.request(
            "POST",
            "/v1/findings/retest",
            json.dumps(
                {
                    "allow": ["*.example.com"],
                    "deny": [],
                    "baseline": [],
                    "retest_runs": [
                        {"id": "r1", "reliability": 50, "findings": []}
                    ],
                }
            ).encode(),
        )
        self.assertEqual(status, 200)
        self.assertEqual(
            payload["summary"],
            {
                "total_before": 0,
                "total_after": 0,
                "persistent": 0,
                "resolved": 0,
                "new": 0,
            },
        )


if __name__ == "__main__":
    unittest.main()
