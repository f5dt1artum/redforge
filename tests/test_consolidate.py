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
        "severity": "low",
        "evidence": [0],
    }
    finding.update(overrides)
    return finding


def make_run(**overrides):
    run = {"id": "run-1", "reliability": 50, "findings": [make_finding()]}
    run.update(overrides)
    return run


def consolidate_payload(**overrides):
    payload = {
        "allow": ["*.example.com", "10.0.0.0/8"],
        "deny": [],
        "runs": [make_run()],
    }
    payload.update(overrides)
    return payload


class ConsolidateServiceTest(unittest.TestCase):
    def setUp(self):
        self.service = Service()

    def consolidate(self, **overrides):
        return self.service.consolidate_findings(
            consolidate_payload(**overrides)
        )["consolidated"]

    def test_single_run_single_finding(self):
        consolidated = self.consolidate()
        self.assertEqual(len(consolidated), 1)
        item = consolidated[0]
        self.assertEqual(item["target"], "app.example.com")
        self.assertEqual(item["template_id"], "tpl-1")
        self.assertEqual(item["name"], "Demo template")
        self.assertEqual(item["severity"], "low")
        self.assertEqual(item["observation_ids"], ["obs-1"])
        self.assertEqual(item["sources"], ["run-1"])
        self.assertEqual(item["evidence"], [0])
        self.assertEqual(item["confidence"], 50)

    def test_empty_findings_returns_empty_list(self):
        self.assertEqual(self.consolidate(runs=[make_run(findings=[])]), [])

    def test_target_is_normalized_in_key_and_output(self):
        run = make_run(
            findings=[
                make_finding(target="APP.Example.COM."),
                make_finding(target="app.example.com", observation_id="obs-2"),
            ]
        )
        consolidated = self.consolidate(runs=[run])
        self.assertEqual(len(consolidated), 1)
        self.assertEqual(consolidated[0]["target"], "app.example.com")
        self.assertEqual(consolidated[0]["observation_ids"], ["obs-1", "obs-2"])

    def test_template_id_is_case_sensitive(self):
        run = make_run(
            findings=[
                make_finding(template_id="TPL-1"),
                make_finding(template_id="tpl-1", observation_id="obs-2"),
            ]
        )
        consolidated = self.consolidate(runs=[run])
        self.assertEqual([c["template_id"] for c in consolidated], ["TPL-1", "tpl-1"])

    def test_first_occurrence_ordering(self):
        runs = [
            make_run(id="r1", findings=[make_finding(template_id="b")]),
            make_run(
                id="r2",
                findings=[
                    make_finding(template_id="a", target="api.example.com"),
                    make_finding(template_id="b", observation_id="obs-2"),
                ],
            ),
        ]
        consolidated = self.consolidate(runs=runs)
        self.assertEqual(
            [(c["target"], c["template_id"]) for c in consolidated],
            [("app.example.com", "b"), ("api.example.com", "a")],
        )

    def test_first_name_is_kept(self):
        runs = [
            make_run(id="r1", findings=[make_finding(name="First")]),
            make_run(
                id="r2",
                findings=[make_finding(name="First", observation_id="obs-2")],
            ),
        ]
        self.assertEqual(self.consolidate(runs=runs)[0]["name"], "First")

    def test_conflicting_name_is_invalid(self):
        runs = [
            make_run(id="r1", findings=[make_finding(name="First")]),
            make_run(
                id="r2",
                findings=[make_finding(name="Second", observation_id="obs-2")],
            ),
        ]
        with self.assertRaises(ValueError):
            self.consolidate(runs=runs)

    def test_highest_severity_wins_in_rank_order(self):
        runs = [
            make_run(id="r1", findings=[make_finding(severity="critical")]),
            make_run(
                id="r2",
                findings=[make_finding(severity="info", observation_id="o2")],
            ),
        ]
        self.assertEqual(self.consolidate(runs=runs)[0]["severity"], "critical")
        runs = [
            make_run(id="r1", findings=[make_finding(severity="info")]),
            make_run(
                id="r2",
                findings=[make_finding(severity="medium", observation_id="o2")],
            ),
            make_run(
                id="r3",
                findings=[make_finding(severity="low", observation_id="o3")],
            ),
        ]
        self.assertEqual(self.consolidate(runs=runs)[0]["severity"], "medium")

    def test_observation_ids_dedup_in_first_order(self):
        runs = [
            make_run(
                id="r1",
                findings=[
                    make_finding(observation_id="o2", evidence=[2]),
                    make_finding(observation_id="o1", evidence=[0]),
                ],
            ),
            make_run(
                id="r2",
                reliability=10,
                findings=[
                    make_finding(observation_id="o1", evidence=[0, 1]),
                    make_finding(observation_id="o3", evidence=[3]),
                ],
            ),
        ]
        item = self.consolidate(runs=runs)[0]
        self.assertEqual(item["observation_ids"], ["o2", "o1", "o3"])
        self.assertEqual(item["evidence"], [0, 1, 2, 3])
        self.assertEqual(item["sources"], ["r1", "r2"])

    def test_in_run_duplicates_merge_but_run_counts_once(self):
        # One run, reliability 50, two duplicate findings for the same key.
        run = make_run(
            id="r1",
            reliability=50,
            findings=[
                make_finding(observation_id="o1", evidence=[0]),
                make_finding(observation_id="o1", evidence=[1]),
            ],
        )
        item = self.consolidate(runs=[run])[0]
        self.assertEqual(item["observation_ids"], ["o1"])
        self.assertEqual(item["evidence"], [0, 1])
        self.assertEqual(item["sources"], ["r1"])
        self.assertEqual(item["confidence"], 50)

    def test_confidence_formula(self):
        # 0 -> +floor(100*50/100)=50 -> +floor(50*50/100)=25 ->
        # +floor(25*100/100)=25 => 100
        runs = [
            make_run(id="r1", reliability=50),
            make_run(
                id="r2",
                reliability=50,
                findings=[make_finding(observation_id="o2")],
            ),
            make_run(
                id="r3",
                reliability=100,
                findings=[make_finding(observation_id="o3")],
            ),
        ]
        self.assertEqual(self.consolidate(runs=runs)[0]["confidence"], 100)

    def test_confidence_floors_and_skips_runs_without_key(self):
        # r1 (10) -> 10; r2 has no matching key, skipped; r3 (10) ->
        # 10 + floor(90*10/100) = 19; r4 (0) stays 19.
        runs = [
            make_run(id="r1", reliability=10),
            make_run(
                id="r2",
                reliability=90,
                findings=[make_finding(template_id="other")],
            ),
            make_run(
                id="r3",
                reliability=10,
                findings=[make_finding(observation_id="o2")],
            ),
            make_run(
                id="r4",
                reliability=0,
                findings=[make_finding(observation_id="o3")],
            ),
        ]
        by_tpl = {c["template_id"]: c for c in self.consolidate(runs=runs)}
        self.assertEqual(by_tpl["tpl-1"]["confidence"], 19)
        self.assertEqual(by_tpl["tpl-1"]["sources"], ["r1", "r3", "r4"])
        self.assertEqual(by_tpl["other"]["confidence"], 90)
        self.assertEqual(by_tpl["other"]["sources"], ["r2"])

    def test_reliability_100_caps_confidence(self):
        runs = [
            make_run(id="r1", reliability=100),
            make_run(
                id="r2",
                reliability=100,
                findings=[make_finding(observation_id="o2")],
            ),
        ]
        self.assertEqual(self.consolidate(runs=runs)[0]["confidence"], 100)

    def test_scope_violation_raises_and_no_partial_results(self):
        runs = [
            make_run(),
            make_run(
                id="r2",
                findings=[make_finding(target="evil.net", observation_id="o2")],
            ),
        ]
        with self.assertRaises(ScopeViolationError):
            self.consolidate(runs=runs)

    def test_deny_rule_triggers_scope_violation(self):
        with self.assertRaises(ScopeViolationError):
            self.consolidate(deny=["app.example.com"])

    def test_ip_target_allowed_by_network(self):
        run = make_run(findings=[make_finding(target="10.1.2.3")])
        item = self.consolidate(runs=[run])[0]
        self.assertEqual(item["target"], "10.1.2.3")

    def test_validation_errors(self):
        bad_payloads = [
            None,
            [],
            {},
            {"allow": [], "deny": []},
            {"allow": [], "deny": [], "runs": []},
            consolidate_payload(extra=1),
            consolidate_payload(allow="*.example.com"),
            consolidate_payload(allow=["bad_host"]),
            consolidate_payload(runs={}),
            consolidate_payload(runs=[{}]),
            consolidate_payload(runs=[{"id": "r1"}]),
            consolidate_payload(runs=[{"id": "r1", "reliability": 50}]),
            consolidate_payload(runs=[make_run(extra=1)]),
            consolidate_payload(runs=[make_run(id="")]),
            consolidate_payload(runs=[make_run(id=1)]),
            consolidate_payload(runs=[make_run(reliability=-1)]),
            consolidate_payload(runs=[make_run(reliability=101)]),
            consolidate_payload(runs=[make_run(reliability="50")]),
            consolidate_payload(runs=[make_run(reliability=True)]),
            consolidate_payload(runs=[make_run(findings={})]),
            consolidate_payload(runs=[make_run(), make_run()]),
            # findings
            consolidate_payload(runs=[make_run(findings=[{}])]),
            consolidate_payload(runs=[make_run(findings=[make_finding(extra=1)])]),
            consolidate_payload(runs=[make_run(findings=[make_finding(observation_id="")])]),
            consolidate_payload(runs=[make_run(findings=[make_finding(observation_id=3)])]),
            consolidate_payload(runs=[make_run(findings=[make_finding(target="")])]),
            consolidate_payload(runs=[make_run(findings=[make_finding(target="*.example.com")])]),
            consolidate_payload(runs=[make_run(findings=[make_finding(template_id="")])]),
            consolidate_payload(runs=[make_run(findings=[make_finding(name="")])]),
            consolidate_payload(runs=[make_run(findings=[make_finding(severity="fatal")])]),
            consolidate_payload(runs=[make_run(findings=[make_finding(evidence={})])]),
            consolidate_payload(runs=[make_run(findings=[make_finding(evidence=["0"])])]),
            consolidate_payload(runs=[make_run(findings=[make_finding(evidence=[-1])])]),
            consolidate_payload(runs=[make_run(findings=[make_finding(evidence=[True])])]),
            consolidate_payload(runs=[make_run(findings=["nope"])]),
        ]
        for payload in bad_payloads:
            with self.subTest(payload=repr(payload)[:100]):
                with self.assertRaises(ValueError):
                    self.service.consolidate_findings(payload)


class ConsolidateHttpTest(unittest.TestCase):
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
        req = urllib.request.Request(url, method=method, data=body, headers=headers or {})
        try:
            with urllib.request.urlopen(req) as resp:
                return resp.status, json.loads(resp.read())
        except urllib.error.HTTPError as exc:
            status, payload = exc.code, json.loads(exc.read())
            exc.close()
            return status, payload

    def post_consolidate(self, payload):
        return self.request(
            "POST", "/v1/findings/consolidate", json.dumps(payload).encode()
        )

    def test_consolidate_ok(self):
        runs = [
            make_run(id="r1", reliability=80, findings=[
                make_finding(evidence=[0, 2]),
                make_finding(
                    observation_id="obs-2",
                    template_id="tpl-2",
                    name="Other",
                    severity="high",
                    evidence=[1],
                ),
            ]),
            make_run(id="r2", reliability=50, findings=[
                make_finding(evidence=[2, 3]),
            ]),
        ]
        status, payload = self.post_consolidate(
            consolidate_payload(runs=runs)
        )
        self.assertEqual(status, 200)
        self.assertEqual(list(payload), ["consolidated"])
        first, second = payload["consolidated"]
        self.assertEqual(first["target"], "app.example.com")
        self.assertEqual(first["template_id"], "tpl-1")
        self.assertEqual(first["observation_ids"], ["obs-1"])
        self.assertEqual(first["sources"], ["r1", "r2"])
        self.assertEqual(first["evidence"], [0, 2, 3])
        # 80 then 50: 80 + floor(20*50/100) = 90
        self.assertEqual(first["confidence"], 90)
        self.assertEqual(second["confidence"], 80)

    def test_empty_consolidated(self):
        status, payload = self.post_consolidate(
            consolidate_payload(runs=[make_run(findings=[])])
        )
        self.assertEqual(status, 200)
        self.assertEqual(payload, {"consolidated": []})

    def test_scope_violation_403(self):
        runs = [
            make_run(),
            make_run(
                id="r2",
                findings=[make_finding(target="evil.net", observation_id="o2")],
            ),
        ]
        status, payload = self.post_consolidate(consolidate_payload(runs=runs))
        self.assertEqual(status, 403)
        self.assertEqual(payload["error"]["code"], "scope_violation")
        self.assertNotIn("consolidated", payload)

    def test_invalid_request_400(self):
        status, payload = self.post_consolidate({"allow": [], "deny": [], "runs": []})
        self.assertEqual(status, 400)
        self.assertEqual(payload["error"]["code"], "invalid_request")

    def test_malformed_json_400(self):
        status, payload = self.request("POST", "/v1/findings/consolidate", b"{nope")
        self.assertEqual(status, 400)
        self.assertEqual(payload["error"]["code"], "invalid_request")

    def test_oversized_body_413(self):
        import http.client

        conn = http.client.HTTPConnection("127.0.0.1", self.port)
        conn.putrequest("POST", "/v1/findings/consolidate")
        conn.putheader("Content-Length", str(1024 * 1024 + 1))
        conn.endheaders()
        resp = conn.getresponse()
        payload = json.loads(resp.read())
        conn.close()
        self.assertEqual(resp.status, 413)
        self.assertEqual(payload["error"]["code"], "request_too_large")

    def test_method_not_allowed_405(self):
        for method in ("GET", "PUT", "DELETE"):
            with self.subTest(method=method):
                status, payload = self.request(
                    method, "/v1/findings/consolidate"
                )
                self.assertEqual(status, 405)
                self.assertEqual(payload["error"]["code"], "method_not_allowed")

    def test_unknown_route_404(self):
        status, payload = self.request("POST", "/v1/nope", b"{}")
        self.assertEqual(status, 404)
        self.assertEqual(payload["error"]["code"], "not_found")


if __name__ == "__main__":
    unittest.main()
