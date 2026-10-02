import json
import threading
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

from redforge.server import Handler
from redforge.service import ScopeViolationError, Service


def finding(**overrides):
    item = {
        "target": "app.example.com",
        "template_id": "tpl-1",
        "name": "Demo template",
        "severity": "high",
        "observation_ids": ["obs-1"],
        "sources": ["run-1"],
        "evidence": [0],
        "confidence": 80,
    }
    item.update(overrides)
    return item


def requirement(**overrides):
    item = {
        "template_id": "tpl-1",
        "min_severity": "low",
        "min_confidence": 50,
    }
    item.update(overrides)
    return item


def stage(**overrides):
    item = {
        "id": "s1",
        "name": "Stage one",
        "logic": "all",
        "requires": [requirement()],
        "depends_on": [],
    }
    item.update(overrides)
    return item


def plan_payload(**overrides):
    payload = {
        "allow": ["*.example.com"],
        "deny": [],
        "findings": [finding()],
        "stages": [stage()],
    }
    payload.update(overrides)
    return payload


class AttackChainServiceTest(unittest.TestCase):
    def setUp(self):
        self.service = Service()

    def plan(self, **overrides):
        return self.service.plan_attack_chains(plan_payload(**overrides))

    def test_ready_stage_shape(self):
        result = self.plan()
        self.assertEqual(list(result), ["plans"])
        (plan,) = result["plans"]
        self.assertEqual(list(plan), ["target", "stages"])
        self.assertEqual(plan["target"], "app.example.com")
        (s,) = plan["stages"]
        self.assertEqual(s, {"id": "s1", "name": "Stage one",
                             "status": "ready", "reason": None})

    def test_empty_findings_returns_empty_plans(self):
        result = self.plan(findings=[])
        self.assertEqual(result, {"plans": []})

    def test_target_grouping_keeps_first_occurrence_order(self):
        result = self.plan(
            findings=[
                finding(target="b.example.com", template_id="x"),
                finding(target="a.example.com", template_id="y"),
                finding(target="b.example.com", template_id="z"),
            ],
            stages=[stage(id="g")],
        )
        self.assertEqual([p["target"] for p in result["plans"]],
                         ["b.example.com", "a.example.com"])
        # Normalized spelling is used for grouping and output.
        result = self.plan(
            findings=[
                finding(target="APP.Example.COM."),
                finding(target="app.example.com", template_id="tpl-2"),
            ],
            stages=[stage(id="g", requires=[requirement(template_id="tpl-2")])],
        )
        self.assertEqual(len(result["plans"]), 1)
        self.assertEqual(result["plans"][0]["target"], "app.example.com")

    def test_missing_requirements_skips_stage(self):
        result = self.plan(
            findings=[finding(target="other.example.com")],
            stages=[stage(id="g", requires=[requirement(template_id="nope")])],
        )
        (plan,) = result["plans"]
        self.assertEqual(plan["target"], "other.example.com")
        self.assertEqual(plan["stages"][0]["status"], "skipped")
        self.assertEqual(plan["stages"][0]["reason"], "missing_requirements")

    def test_severity_and_confidence_thresholds(self):
        def status_for(**overrides):
            result = self.plan(
                findings=[finding(**overrides)],
                stages=[
                    stage(
                        id="g",
                        requires=[
                            requirement(min_severity="high", min_confidence=80)
                        ],
                    )
                ],
            )
            return result["plans"][0]["stages"][0]["status"]

        self.assertEqual(status_for(severity="high", confidence=80), "ready")
        self.assertEqual(status_for(severity="medium", confidence=80), "skipped")
        self.assertEqual(status_for(severity="critical", confidence=79), "skipped")
        self.assertEqual(status_for(severity="low", confidence=100), "skipped")

    def test_template_id_is_case_sensitive_and_target_scoped(self):
        result = self.plan(
            findings=[
                finding(target="app.example.com", template_id="TPL-1"),
                finding(target="other.example.com", template_id="tpl-1"),
            ],
        )
        by_target = {p["target"]: p["stages"][0]["status"]
                     for p in result["plans"]}
        self.assertEqual(by_target["app.example.com"], "skipped")
        self.assertEqual(by_target["other.example.com"], "ready")

    def test_all_and_any_logic(self):
        reqs = [
            requirement(template_id="a", min_severity="info",
                        min_confidence=0),
            requirement(template_id="b", min_severity="info",
                        min_confidence=0),
        ]
        findings = [
            finding(template_id="a", severity="info", confidence=0),
        ]
        result = self.plan(
            findings=findings,
            stages=[stage(id="g", logic="all", requires=reqs)],
        )
        self.assertEqual(result["plans"][0]["stages"][0]["status"], "skipped")
        result = self.plan(
            findings=findings,
            stages=[stage(id="g", logic="any", requires=reqs)],
        )
        self.assertEqual(result["plans"][0]["stages"][0]["status"], "ready")

    def test_dependency_chain_topological_evaluation(self):
        stages = [
            stage(id="c", name="C", requires=[requirement(template_id="hit")],
                  depends_on=["a", "b"]),
            stage(id="a", name="A",
                  requires=[requirement(template_id="hit")], depends_on=[]),
            stage(id="b", name="B",
                  requires=[requirement(template_id="miss")], depends_on=[]),
        ]
        result = self.plan(
            findings=[finding(template_id="hit")],
            stages=stages,
        )
        statuses = {s["id"]: (s["status"], s["reason"])
                    for s in result["plans"][0]["stages"]}
        self.assertEqual(statuses["a"], ("ready", None))
        self.assertEqual(statuses["b"], ("skipped", "missing_requirements"))
        # c satisfies its own requirements but b is not ready.
        self.assertEqual(statuses["c"], ("skipped", "dependency_blocked"))
        # Output keeps input order and covers all stages.
        self.assertEqual([s["id"] for s in result["plans"][0]["stages"]],
                         ["c", "a", "b"])

    def test_missing_requirements_precedence_over_blocked_dependency(self):
        result = self.plan(
            findings=[finding(template_id="hit")],
            stages=[
                stage(id="a", requires=[requirement(template_id="gone")]),
                stage(id="b", requires=[requirement(template_id="hit")],
                      depends_on=["a"]),
            ],
        )
        statuses = {s["id"]: s["status"]
                    for s in result["plans"][0]["stages"]}
        # b's own requirements hold, and a is skipped -> dependency_blocked.
        self.assertEqual(statuses["a"], "skipped")
        self.assertEqual(statuses["b"], "skipped")
        self.assertEqual(
            result["plans"][0]["stages"][1]["reason"], "dependency_blocked"
        )

    def test_diamond_dependencies(self):
        result = self.plan(
            stages=[
                stage(id="top", requires=[requirement()], depends_on=["l", "r"]),
                stage(id="l", requires=[requirement()], depends_on=["root"]),
                stage(id="r", requires=[requirement()], depends_on=["root"]),
                stage(id="root", requires=[requirement()], depends_on=[]),
            ],
        )
        statuses = {s["id"]: s["status"]
                    for s in result["plans"][0]["stages"]}
        self.assertTrue(all(v == "ready" for v in statuses.values()))

    def test_scope_violation_raises(self):
        with self.assertRaises(ScopeViolationError):
            self.plan(findings=[finding(target="evil.net")])
        with self.assertRaises(ScopeViolationError):
            self.plan(deny=["app.example.com"])

    def test_structure_validated_before_scope_gate(self):
        with self.assertRaises(ValueError):
            self.plan(
                findings=[finding(target="evil.net", confidence=200)],
            )
        with self.assertRaises(ValueError):
            self.plan(
                findings=[finding(target="evil.net")],
                stages=[stage(id="x"), stage(id="x")],
            )

    def test_duplicate_finding_key_is_invalid(self):
        with self.assertRaises(ValueError):
            self.plan(
                findings=[finding(), finding(name="Other")],
            )
        with self.assertRaises(ValueError):
            self.plan(
                findings=[
                    finding(),
                    finding(target="APP.Example.COM."),
                ],
            )

    def test_validation_errors(self):
        bad_payloads = [
            None,
            [],
            {},
            {"allow": [], "deny": [], "findings": []},
            plan_payload(extra=1),
            plan_payload(allow="*.example.com"),
            plan_payload(deny=1),
            plan_payload(allow=["not a host!!"]),
            plan_payload(findings={}),
            plan_payload(findings="x"),
            plan_payload(findings=[None]),
            plan_payload(findings=["x"]),
            plan_payload(findings=[{"target": "app.example.com"}]),
            plan_payload(findings=[finding(extra=1)]),
            plan_payload(findings=[finding(target="bad_host")]),
            plan_payload(findings=[finding(target="*.example.com")]),
            plan_payload(findings=[finding(template_id="")]),
            plan_payload(findings=[finding(severity="fatal")]),
            plan_payload(findings=[finding(confidence=-1)]),
            plan_payload(findings=[finding(confidence=101)]),
            plan_payload(findings=[finding(confidence="50")]),
            plan_payload(findings=[finding(confidence=True)]),
            plan_payload(findings=[finding(evidence=[True])]),
            plan_payload(stages=[]),
            plan_payload(stages={}),
            plan_payload(stages="x"),
            plan_payload(stages=[None]),
            plan_payload(stages=[{"id": "s1"}]),
            plan_payload(stages=[stage(extra=1)]),
            plan_payload(stages=[stage(id="")]),
            plan_payload(stages=[stage(id=3)]),
            plan_payload(stages=[stage(name="")]),
            plan_payload(stages=[stage(name=4)]),
            plan_payload(stages=[stage(logic="nope")]),
            plan_payload(stages=[stage(logic="ALL")]),
            plan_payload(stages=[stage(requires=[])]),
            plan_payload(stages=[stage(requires={})]),
            plan_payload(stages=[stage(requires=[None])]),
            plan_payload(stages=[stage(requires=["x"])]),
            plan_payload(
                stages=[stage(requires=[{"template_id": "t",
                                         "min_severity": "high"}])]
            ),
            plan_payload(
                stages=[stage(requires=[requirement(template_id="")])]
            ),
            plan_payload(
                stages=[stage(requires=[requirement(min_severity="nope")])]
            ),
            plan_payload(
                stages=[stage(requires=[requirement(min_confidence=-1)])]
            ),
            plan_payload(
                stages=[stage(requires=[requirement(min_confidence=101)])]
            ),
            plan_payload(
                stages=[stage(requires=[requirement(min_confidence="50")])]
            ),
            plan_payload(
                stages=[stage(requires=[requirement(min_confidence=True)])]
            ),
            plan_payload(
                stages=[stage(requires=[requirement(extra=1)])]
            ),
            plan_payload(stages=[stage(depends_on={})]),
            plan_payload(stages=[stage(depends_on=[1])]),
            plan_payload(stages=[stage(depends_on=[""])]),
            plan_payload(stages=[stage(depends_on=["s1"])]),
            plan_payload(stages=[stage(depends_on=["s1", "s1"])]),
            plan_payload(
                stages=[
                    stage(id="a", depends_on=["b"]),
                    stage(id="b", depends_on=["a"]),
                ]
            ),
            plan_payload(
                stages=[
                    stage(id="a"),
                    stage(id="b", depends_on=["c"]),
                ]
            ),
        ]
        for payload in bad_payloads:
            with self.subTest(payload=repr(payload)[:90]):
                with self.assertRaises(ValueError):
                    self.service.plan_attack_chains(payload)

    def test_order_is_stable_for_same_input(self):
        payload = plan_payload(
            findings=[
                finding(target="b.example.com", template_id="x"),
                finding(target="a.example.com", template_id="y"),
            ],
            stages=[
                stage(id="s2", requires=[requirement(template_id="x")]),
                stage(id="s1", requires=[requirement(template_id="y")]),
            ],
        )
        first = self.service.plan_attack_chains(payload)
        second = self.service.plan_attack_chains(payload)
        self.assertEqual(first, second)


class AttackChainHttpTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        cls.port = cls.server.server_address[1]
        cls.thread = threading.Thread(target=cls.server.serve_forever,
                                      daemon=True)
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
                    finding(target="a.example.com", template_id="p"),
                    finding(target="b.example.com", template_id="q"),
                ],
                stages=[
                    stage(id="s1",
                          requires=[requirement(template_id="p")]),
                    stage(id="s2",
                          requires=[requirement(template_id="q")],
                          depends_on=["s1"]),
                ],
            )
        )
        self.assertEqual(status, 200)
        self.assertEqual(list(payload), ["plans"])
        self.assertEqual([p["target"] for p in payload["plans"]],
                         ["a.example.com", "b.example.com"])
        first = payload["plans"][0]["stages"]
        self.assertEqual([s["status"] for s in first], ["ready", "skipped"])
        self.assertEqual(first[1]["reason"], "missing_requirements")
        # On b, s2's own requirement holds but dependency s1 is skipped.
        second = payload["plans"][1]["stages"]
        self.assertEqual([s["status"] for s in second], ["skipped", "skipped"])
        self.assertEqual(second[0]["reason"], "missing_requirements")
        self.assertEqual(second[1]["reason"], "dependency_blocked")

    def test_empty_findings_ok(self):
        status, payload = self.post(plan_payload(findings=[]))
        self.assertEqual(status, 200)
        self.assertEqual(payload, {"plans": []})

    def test_scope_violation_403(self):
        status, payload = self.post(
            plan_payload(findings=[finding(target="evil.net")])
        )
        self.assertEqual(status, 403)
        self.assertEqual(payload["error"]["code"], "scope_violation")
        self.assertNotIn("plans", payload)

    def test_invalid_request_400(self):
        status, payload = self.post(plan_payload(stages=[]))
        self.assertEqual(status, 400)
        self.assertEqual(payload["error"]["code"], "invalid_request")

    def test_duplicate_finding_key_400(self):
        status, payload = self.post(
            plan_payload(findings=[finding(), finding(name="X")])
        )
        self.assertEqual(status, 400)
        self.assertEqual(payload["error"]["code"], "invalid_request")

    def test_cycle_400(self):
        status, payload = self.post(
            plan_payload(
                stages=[
                    stage(id="a", depends_on=["b"]),
                    stage(id="b", depends_on=["a"]),
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
                self.assertEqual(payload["error"]["code"],
                                 "method_not_allowed")

    def test_existing_routes_unchanged(self):
        status, payload = self.request("GET", "/healthz")
        self.assertEqual(status, 200)
        self.assertEqual(payload["status"], "ok")


if __name__ == "__main__":
    unittest.main()
