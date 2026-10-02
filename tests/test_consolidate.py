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


def consolidate_payload(**overrides):
    payload = {
        "allow": ["*.example.com"],
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
        (item,) = self.consolidate()
        self.assertEqual(item["target"], "app.example.com")
        self.assertEqual(item["template_id"], "tpl-1")
        self.assertEqual(item["name"], "Demo template")
        self.assertEqual(item["severity"], "high")
        self.assertEqual(item["observation_ids"], ["obs-1"])
        self.assertEqual(item["sources"], ["run-1"])
        self.assertEqual(item["evidence"], [0])
        self.assertEqual(item["confidence"], 50)

    def test_empty_findings_returns_empty_list(self):
        self.assertEqual(self.consolidate(runs=[make_run(findings=[])]), [])
        self.assertEqual(
            self.consolidate(
                runs=[make_run(findings=[]), make_run(id="run-2", findings=[])]
            ),
            [],
        )

    def test_response_contains_only_consolidated(self):
        result = self.service.consolidate_findings(consolidate_payload())
        self.assertEqual(list(result), ["consolidated"])

    def test_dedup_by_normalized_target_and_template_id(self):
        runs = [
            make_run(
                id="r1",
                findings=[
                    make_finding(observation_id="o1", evidence=[0]),
                    make_finding(
                        observation_id="o2",
                        target="APP.Example.COM.",
                        evidence=[1, 1, 0],
                    ),
                ],
            ),
            make_run(
                id="r2",
                reliability=80,
                findings=[
                    make_finding(observation_id="o3", evidence=[2]),
                ],
            ),
        ]
        (item,) = self.consolidate(runs=runs)
        self.assertEqual(item["target"], "app.example.com")
        self.assertEqual(item["observation_ids"], ["o1", "o2", "o3"])
        self.assertEqual(item["sources"], ["r1", "r2"])
        self.assertEqual(item["evidence"], [0, 1, 2])
        # c = 50, then 50 + floor(50*80/100) = 90
        self.assertEqual(item["confidence"], 90)

    def test_template_id_is_case_sensitive(self):
        runs = [
            make_run(
                id="r1",
                findings=[
                    make_finding(template_id="TPL", name="A"),
                    make_finding(template_id="tpl", name="B"),
                ],
            ),
        ]
        items = self.consolidate(runs=runs)
        self.assertEqual([item["template_id"] for item in items], ["TPL", "tpl"])
        self.assertEqual([item["name"] for item in items], ["A", "B"])

    def test_different_targets_stay_separate(self):
        runs = [
            make_run(
                id="r1",
                findings=[
                    make_finding(target="a.example.com"),
                    make_finding(target="b.example.com"),
                ],
            ),
        ]
        items = self.consolidate(runs=runs)
        self.assertEqual([item["target"] for item in items], [
            "a.example.com", "b.example.com"
        ])

    def test_first_occurrence_ordering(self):
        runs = [
            make_run(
                id="r1",
                findings=[
                    make_finding(target="b.example.com", template_id="x"),
                    make_finding(target="a.example.com", template_id="y"),
                ],
            ),
            make_run(
                id="r2",
                reliability=10,
                findings=[
                    make_finding(target="a.example.com", template_id="y"),
                    make_finding(target="b.example.com", template_id="x"),
                    make_finding(target="c.example.com", template_id="z"),
                ],
            ),
        ]
        items = self.consolidate(runs=runs)
        self.assertEqual(
            [(item["target"], item["template_id"]) for item in items],
            [("b.example.com", "x"), ("a.example.com", "y"), ("c.example.com", "z")],
        )

    def test_first_name_wins_and_severity_is_max(self):
        runs = [
            make_run(
                id="r1",
                findings=[make_finding(name="First", severity="low")],
            ),
            make_run(
                id="r2",
                reliability=10,
                findings=[make_finding(name="First", severity="critical")],
            ),
            make_run(
                id="r3",
                reliability=10,
                findings=[make_finding(name="First", severity="medium")],
            ),
        ]
        (item,) = self.consolidate(runs=runs)
        self.assertEqual(item["name"], "First")
        self.assertEqual(item["severity"], "critical")

    def test_conflicting_name_is_invalid(self):
        runs = [
            make_run(id="r1", findings=[make_finding(name="A")]),
            make_run(
                id="r2",
                reliability=10,
                findings=[make_finding(name="B")],
            ),
        ]
        with self.assertRaises(ValueError):
            self.consolidate(runs=runs)

    def test_confidence_counts_each_run_once(self):
        # Two findings with the same key inside one run must not advance
        # confidence twice, but must still merge observation ids/evidence.
        runs = [
            make_run(
                id="r1",
                reliability=50,
                findings=[
                    make_finding(observation_id="o1", evidence=[0]),
                    make_finding(observation_id="o2", evidence=[1]),
                ],
            ),
        ]
        (item,) = self.consolidate(runs=runs)
        self.assertEqual(item["confidence"], 50)
        self.assertEqual(item["sources"], ["r1"])
        self.assertEqual(item["observation_ids"], ["o1", "o2"])
        self.assertEqual(item["evidence"], [0, 1])

    def test_confidence_formula(self):
        # A run that never carries the key does not influence confidence.
        payload = consolidate_payload(
            runs=[
                make_run(id="r1", reliability=0, findings=[]),
                make_run(id="r2", reliability=100, findings=[make_finding()]),
                make_run(
                    id="r3",
                    reliability=100,
                    findings=[make_finding(observation_id="o2")],
                ),
            ]
        )
        (item,) = self.service.consolidate_findings(payload)["consolidated"]
        self.assertEqual(item["sources"], ["r2", "r3"])
        self.assertEqual(item["confidence"], 100)

    def test_confidence_floor_never_exceeds_100(self):
        runs = [
            make_run(id=f"r{i}", reliability=99, findings=[make_finding()])
            for i in range(20)
        ]
        (item,) = self.consolidate(runs=runs)
        self.assertLessEqual(item["confidence"], 100)
        self.assertEqual(len(item["sources"]), 20)

    def test_reliability_zero_still_a_source(self):
        runs = [
            make_run(id="r1", reliability=0, findings=[make_finding()]),
        ]
        (item,) = self.consolidate(runs=runs)
        self.assertEqual(item["sources"], ["r1"])
        self.assertEqual(item["confidence"], 0)

    def test_observation_ids_dedup_preserve_order(self):
        runs = [
            make_run(
                id="r1",
                findings=[
                    make_finding(observation_id="o2"),
                    make_finding(observation_id="o1"),
                    make_finding(observation_id="o2"),
                ],
            ),
            make_run(
                id="r2",
                reliability=10,
                findings=[
                    make_finding(observation_id="o1"),
                    make_finding(observation_id="o3"),
                ],
            ),
        ]
        (item,) = self.consolidate(runs=runs)
        self.assertEqual(item["observation_ids"], ["o2", "o1", "o3"])

    def test_scope_violation_raises_without_partial_results(self):
        with self.assertRaises(ScopeViolationError):
            self.consolidate(
                runs=[
                    make_run(
                        id="r1",
                        findings=[
                            make_finding(target="ok.example.com"),
                            make_finding(target="evil.net"),
                        ],
                    )
                ]
            )
        with self.assertRaises(ScopeViolationError):
            self.consolidate(
                deny=["app.example.com"],
            )

    def test_scope_gate_uses_deny_and_ip_rules(self):
        payload = consolidate_payload(
            allow=["10.0.0.0/8"],
            runs=[
                make_run(
                    id="r1",
                    findings=[make_finding(target="10.1.2.3")],
                )
            ],
        )
        (item,) = self.service.consolidate_findings(payload)["consolidated"]
        self.assertEqual(item["target"], "10.1.2.3")
        payload["deny"] = ["10.1.2.3"]
        with self.assertRaises(ScopeViolationError):
            self.service.consolidate_findings(payload)

    def test_validation_errors(self):
        bad_payloads = [
            None,
            [],
            {},
            {"allow": [], "deny": []},
            {"allow": [], "runs": [make_run()]},
            consolidate_payload(extra=1),
            consolidate_payload(allow="*.example.com"),
            consolidate_payload(deny=1),
            consolidate_payload(allow=["not a host!!"]),
            consolidate_payload(runs=[]),
            consolidate_payload(runs={}),
            consolidate_payload(runs="x"),
            # runs
            consolidate_payload(runs=[None]),
            consolidate_payload(runs=["r"]),
            consolidate_payload(runs=[{"id": "r1", "reliability": 0}]),
            consolidate_payload(runs=[make_run(extra=1)]),
            consolidate_payload(runs=[make_run(id="")]),
            consolidate_payload(runs=[make_run(id=5)]),
            consolidate_payload(runs=[make_run(id=None)]),
            consolidate_payload(runs=[make_run(reliability=-1)]),
            consolidate_payload(runs=[make_run(reliability=101)]),
            consolidate_payload(runs=[make_run(reliability="50")]),
            consolidate_payload(runs=[make_run(reliability=True)]),
            consolidate_payload(runs=[make_run(findings={})]),
            consolidate_payload(runs=[make_run(findings=None)]),
            consolidate_payload(runs=[make_run(), make_run(id="run-1")]),
            # findings
            consolidate_payload(runs=[make_run(findings=[None])]),
            consolidate_payload(runs=[make_run(findings=["f"])]),
            consolidate_payload(runs=[make_run(findings=[{"id": "x"}])]),
            consolidate_payload(runs=[make_run(findings=[make_finding(extra=1)])]),
            consolidate_payload(
                runs=[make_run(findings=[make_finding(observation_id="")])]
            ),
            consolidate_payload(
                runs=[make_run(findings=[make_finding(observation_id=3)])]
            ),
            consolidate_payload(
                runs=[make_run(findings=[make_finding(template_id="")])]
            ),
            consolidate_payload(
                runs=[make_run(findings=[make_finding(name="")])]
            ),
            consolidate_payload(
                runs=[make_run(findings=[make_finding(name=4)])]
            ),
            consolidate_payload(
                runs=[make_run(findings=[make_finding(severity="fatal")])]
            ),
            consolidate_payload(
                runs=[make_run(findings=[make_finding(target="bad_host")])]
            ),
            consolidate_payload(
                runs=[make_run(findings=[make_finding(target="*.example.com")])]
            ),
            consolidate_payload(
                runs=[make_run(findings=[make_finding(evidence=[])])]
            ),
            consolidate_payload(
                runs=[make_run(findings=[make_finding(evidence="0")])]
            ),
            consolidate_payload(
                runs=[make_run(findings=[make_finding(evidence=[-1])])]
            ),
            consolidate_payload(
                runs=[make_run(findings=[make_finding(evidence=[True])])]
            ),
            consolidate_payload(
                runs=[make_run(findings=[make_finding(evidence=[1.5])])]
            ),
            consolidate_payload(
                runs=[make_run(findings=[make_finding(evidence=[1, "2"])])]
            ),
        ]
        for payload in bad_payloads:
            with self.subTest(payload=repr(payload)[:90]):
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
            "POST", "/v1/findings/consolidate", json.dumps(payload).encode()
        )

    def test_consolidate_ok(self):
        status, payload = self.post(
            consolidate_payload(
                runs=[
                    make_run(
                        id="r1",
                        reliability=50,
                        findings=[
                            make_finding(observation_id="o1", evidence=[0, 2]),
                        ],
                    ),
                    make_run(
                        id="r2",
                        reliability=80,
                        findings=[
                            make_finding(observation_id="o2", evidence=[1]),
                        ],
                    ),
                ]
            )
        )
        self.assertEqual(status, 200)
        self.assertEqual(list(payload), ["consolidated"])
        (item,) = payload["consolidated"]
        self.assertEqual(item["observation_ids"], ["o1", "o2"])
        self.assertEqual(item["sources"], ["r1", "r2"])
        self.assertEqual(item["evidence"], [0, 1, 2])
        self.assertEqual(item["confidence"], 90)
        self.assertEqual(item["severity"], "high")

    def test_empty_runs_findings_200_empty_array(self):
        status, payload = self.post(
            consolidate_payload(runs=[make_run(findings=[])])
        )
        self.assertEqual(status, 200)
        self.assertEqual(payload, {"consolidated": []})

    def test_scope_violation_403(self):
        status, payload = self.post(
            consolidate_payload(
                runs=[make_run(findings=[make_finding(target="evil.net")])]
            )
        )
        self.assertEqual(status, 403)
        self.assertEqual(payload["error"]["code"], "scope_violation")
        self.assertNotIn("consolidated", payload)

    def test_invalid_request_400(self):
        status, payload = self.post({"allow": [], "deny": [], "runs": []})
        self.assertEqual(status, 400)
        self.assertEqual(payload["error"]["code"], "invalid_request")

    def test_conflicting_name_400(self):
        status, payload = self.post(
            consolidate_payload(
                runs=[
                    make_run(id="r1", findings=[make_finding(name="A")]),
                    make_run(
                        id="r2",
                        reliability=1,
                        findings=[make_finding(name="B")],
                    ),
                ]
            )
        )
        self.assertEqual(status, 400)
        self.assertEqual(payload["error"]["code"], "invalid_request")

    def test_malformed_json_400(self):
        status, payload = self.request(
            "POST", "/v1/findings/consolidate", b"{nope"
        )
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
        for method in ("GET", "PUT", "DELETE", "PATCH"):
            with self.subTest(method=method):
                status, payload = self.request(method, "/v1/findings/consolidate")
                self.assertEqual(status, 405)
                self.assertEqual(payload["error"]["code"], "method_not_allowed")

    def test_unknown_route_404_and_existing_routes_unchanged(self):
        status, payload = self.request("POST", "/v1/findings/nope", b"{}")
        self.assertEqual(status, 404)
        self.assertEqual(payload["error"]["code"], "not_found")
        status, payload = self.request("GET", "/healthz")
        self.assertEqual(status, 200)
        self.assertEqual(payload["status"], "ok")


if __name__ == "__main__":
    unittest.main()
