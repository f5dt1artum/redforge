import json
import threading
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

from redforge.server import Handler
from redforge.service import ScopeViolationError, Service


def make_session(sid="s1", target="web.example.com", privilege="user"):
    return {"id": sid, "target": target, "privilege": privilege}


def make_transition(tid="t1", frm="s1", to="s2", technique="ssh", cost=1):
    return {"id": tid, "from": frm, "to": to, "technique": technique, "cost": cost}


def make_goal(gid="g1", target="db.example.com", min_privilege="admin"):
    return {"id": gid, "target": target, "min_privilege": min_privilege}


def paths_payload(**overrides):
    payload = {
        "allow": ["*.example.com", "10.0.0.0/8"],
        "deny": [],
        "sessions": [
            make_session("s1", "web.example.com", "user"),
            make_session("s2", "db.example.com", "admin"),
        ],
        "transitions": [make_transition("t1", "s1", "s2", "ssh", 3)],
        "starts": ["s1"],
        "goals": [make_goal("g1", "db.example.com", "admin")],
    }
    payload.update(overrides)
    return payload


class EscalationPathsServiceTest(unittest.TestCase):
    def setUp(self):
        self.service = Service()

    def paths(self, **overrides):
        return self.service.compute_escalation_paths(paths_payload(**overrides))[
            "paths"
        ]

    def test_simple_reachable_path(self):
        (entry,) = self.paths()
        self.assertEqual(
            entry,
            {
                "goal_id": "g1",
                "target": "db.example.com",
                "min_privilege": "admin",
                "status": "reachable",
                "path": {
                    "start_session_id": "s1",
                    "end_session_id": "s2",
                    "total_cost": 3,
                    "session_ids": ["s1", "s2"],
                    "transition_ids": ["t1"],
                },
            },
        )

    def test_start_session_satisfies_goal(self):
        (entry,) = self.paths(goals=[make_goal("g1", "web.example.com", "user")])
        self.assertEqual(entry["status"], "reachable")
        self.assertEqual(
            entry["path"],
            {
                "start_session_id": "s1",
                "end_session_id": "s1",
                "total_cost": 0,
                "session_ids": ["s1"],
                "transition_ids": [],
            },
        )

    def test_unreachable_goal(self):
        (entry,) = self.paths(goals=[make_goal("g1", "other.example.com", "user")])
        self.assertEqual(entry["status"], "unreachable")
        self.assertIsNone(entry["path"])

    def test_privilege_below_minimum_is_unreachable(self):
        (entry,) = self.paths(goals=[make_goal("g1", "db.example.com", "system")])
        self.assertEqual(entry["status"], "unreachable")

    def test_higher_privilege_satisfies_lower_minimum(self):
        (entry,) = self.paths(goals=[make_goal("g1", "db.example.com", "user")])
        self.assertEqual(entry["status"], "reachable")
        self.assertEqual(entry["path"]["end_session_id"], "s2")

    def test_goal_target_is_normalized(self):
        (entry,) = self.paths(goals=[make_goal("g1", "DB.Example.COM.", "admin")])
        self.assertEqual(entry["target"], "db.example.com")
        self.assertEqual(entry["status"], "reachable")

    def test_empty_arrays_yield_empty_paths(self):
        self.assertEqual(
            self.paths(sessions=[], transitions=[], starts=[], goals=[]), []
        )

    def test_empty_starts_makes_everything_unreachable(self):
        (entry,) = self.paths(starts=[])
        self.assertEqual(entry["status"], "unreachable")

    def test_goals_keep_input_order(self):
        entries = self.paths(
            goals=[
                make_goal("g2", "other.example.com", "user"),
                make_goal("g1", "db.example.com", "admin"),
            ]
        )
        self.assertEqual([e["goal_id"] for e in entries], ["g2", "g1"])
        self.assertEqual(
            [e["status"] for e in entries], ["unreachable", "reachable"]
        )

    def test_cycles_do_not_change_best_path(self):
        transitions = [
            make_transition("t1", "s1", "s2", "ssh", 3),
            make_transition("t2", "s2", "s1", "ssh", 1),
        ]
        (entry,) = self.paths(transitions=transitions)
        self.assertEqual(entry["path"]["total_cost"], 3)
        self.assertEqual(entry["path"]["transition_ids"], ["t1"])

    def test_cross_target_edges_are_allowed(self):
        sessions = [
            make_session("s1", "a.example.com", "user"),
            make_session("s2", "b.example.com", "system"),
        ]
        (entry,) = self.paths(
            sessions=sessions,
            transitions=[make_transition("t1", "s1", "s2", "vpn", 2)],
            goals=[make_goal("g1", "b.example.com", "system")],
        )
        self.assertEqual(entry["status"], "reachable")
        self.assertEqual(entry["path"]["total_cost"], 2)

    # --- tie-breaking --------------------------------------------------------

    def test_lower_total_cost_wins(self):
        sessions = [
            make_session("s1", "web.example.com", "user"),
            make_session("s2", "mid.example.com", "user"),
            make_session("s3", "db.example.com", "admin"),
        ]
        transitions = [
            make_transition("cheap", "s1", "s3", "ssh", 5),
            make_transition("hop1", "s1", "s2", "ssh", 4),
            make_transition("hop2", "s2", "s3", "ssh", 4),
        ]
        (entry,) = self.paths(sessions=sessions, transitions=transitions)
        self.assertEqual(entry["path"]["transition_ids"], ["cheap"])
        self.assertEqual(entry["path"]["total_cost"], 5)

    def test_fewer_transitions_wins_on_equal_cost(self):
        sessions = [
            make_session("s1", "web.example.com", "user"),
            make_session("s2", "mid.example.com", "user"),
            make_session("s3", "db.example.com", "admin"),
        ]
        transitions = [
            make_transition("hop1", "s1", "s2", "ssh", 2),
            make_transition("hop2", "s2", "s3", "ssh", 3),
            make_transition("direct", "s1", "s3", "ssh", 5),
        ]
        (entry,) = self.paths(sessions=sessions, transitions=transitions)
        self.assertEqual(entry["path"]["transition_ids"], ["direct"])

    def test_earlier_start_wins_on_equal_cost_and_count(self):
        sessions = [
            make_session("s1", "a.example.com", "user"),
            make_session("s2", "b.example.com", "user"),
            make_session("s3", "db.example.com", "admin"),
        ]
        transitions = [
            make_transition("from-s2", "s2", "s3", "ssh", 2),
            make_transition("from-s1", "s1", "s3", "ssh", 2),
        ]
        (entry,) = self.paths(
            sessions=sessions, transitions=transitions, starts=["s1", "s2"]
        )
        self.assertEqual(entry["path"]["start_session_id"], "s1")
        self.assertEqual(entry["path"]["transition_ids"], ["from-s1"])

    def test_earlier_transition_position_wins_between_parallel_edges(self):
        # Two transitions between the same sessions with equal cost; the one
        # earlier in the transitions array wins regardless of its id.
        transitions = [
            make_transition("zz", "s1", "s2", "ssh", 3),
            make_transition("aa", "s1", "s2", "rdp", 3),
        ]
        (entry,) = self.paths(transitions=transitions)
        self.assertEqual(entry["path"]["transition_ids"], ["zz"])

    def test_transition_sequence_breaks_ties_lexicographically(self):
        sessions = [
            make_session("s1", "a.example.com", "user"),
            make_session("s2", "b.example.com", "user"),
            make_session("s3", "c.example.com", "user"),
            make_session("s4", "db.example.com", "admin"),
        ]
        # Both paths cost 4 with 2 transitions from the same start; the path
        # whose first transition sits earlier in the input wins.
        transitions = [
            make_transition("t0", "s1", "s2", "ssh", 1),
            make_transition("t1", "s1", "s3", "ssh", 1),
            make_transition("t2", "s3", "s4", "ssh", 3),
            make_transition("t3", "s2", "s4", "ssh", 3),
        ]
        (entry,) = self.paths(sessions=sessions, transitions=transitions)
        self.assertEqual(entry["path"]["transition_ids"], ["t0", "t3"])
        self.assertEqual(entry["path"]["session_ids"], ["s1", "s2", "s4"])

    def test_multiple_goals_are_evaluated_independently(self):
        entries = self.paths(
            goals=[
                make_goal("g1", "db.example.com", "admin"),
                make_goal("g2", "web.example.com", "user"),
            ]
        )
        self.assertEqual(entries[0]["path"]["transition_ids"], ["t1"])
        self.assertEqual(entries[1]["path"]["total_cost"], 0)

    # --- structural validation -----------------------------------------------

    def test_bad_payloads(self):
        good_session = make_session("s1", "web.example.com", "user")
        bad_payloads = [
            None,
            [],
            {},
            {"allow": [], "deny": [], "sessions": [], "transitions": [],
             "starts": [], "goals": [], "x": 1},
            {"deny": [], "sessions": [], "transitions": [], "starts": [],
             "goals": []},
            {"allow": "notlist", "deny": [], "sessions": [], "transitions": [],
             "starts": [], "goals": []},
            {"allow": [], "deny": [], "sessions": {}, "transitions": [],
             "starts": [], "goals": []},
            {"allow": [], "deny": [], "sessions": [], "transitions": {},
             "starts": [], "goals": []},
            {"allow": [], "deny": [], "sessions": [], "transitions": [],
             "starts": {}, "goals": []},
            {"allow": [], "deny": [], "sessions": [], "transitions": [],
             "starts": [], "goals": {}},
            # session problems
            {"allow": [], "deny": [], "sessions": [{"id": "s1"}], "transitions": [],
             "starts": [], "goals": []},
            {"allow": [], "deny": [], "sessions": [
                {"id": "s1", "target": "a.example.com", "privilege": "user",
                 "extra": 1}], "transitions": [], "starts": [], "goals": []},
            {"allow": [], "deny": [], "sessions": [
                make_session("", "a.example.com")], "transitions": [],
             "starts": [], "goals": []},
            {"allow": [], "deny": [], "sessions": [
                make_session("s1", "*.example.com")], "transitions": [],
             "starts": [], "goals": []},
            {"allow": [], "deny": [], "sessions": [
                make_session("s1", "a.example.com", "root")], "transitions": [],
             "starts": [], "goals": []},
            {"allow": [], "deny": [], "sessions": [good_session, good_session],
             "transitions": [], "starts": [], "goals": []},
            # transition problems
            {"allow": [], "deny": [], "sessions": [good_session],
             "transitions": [make_transition("t1", "s1", "s1")],
             "starts": [], "goals": []},
            {"allow": [], "deny": [], "sessions": [good_session],
             "transitions": [make_transition("t1", "s1", "ghost")],
             "starts": [], "goals": []},
            {"allow": [], "deny": [], "sessions": [good_session],
             "transitions": [make_transition("t1", "ghost", "s1")],
             "starts": [], "goals": []},
            {"allow": [], "deny": [], "sessions": [good_session],
             "transitions": [make_transition("t1", 1, "s1")],
             "starts": [], "goals": []},
            {"allow": [], "deny": [], "sessions": [good_session],
             "transitions": [make_transition("t1", "s1", "s1", "", 1)],
             "starts": [], "goals": []},
            {"allow": [], "deny": [], "sessions": [good_session],
             "transitions": [make_transition("t1", "s1", "s1", "ssh", 0)],
             "starts": [], "goals": []},
            {"allow": [], "deny": [], "sessions": [good_session],
             "transitions": [make_transition("t1", "s1", "s1", "ssh", 101)],
             "starts": [], "goals": []},
            {"allow": [], "deny": [], "sessions": [good_session],
             "transitions": [make_transition("t1", "s1", "s1", "ssh", True)],
             "starts": [], "goals": []},
            {"allow": [], "deny": [], "sessions": [good_session],
             "transitions": [make_transition("t1", "s1", "s1", "ssh", "3")],
             "starts": [], "goals": []},
            # starts problems
            {"allow": [], "deny": [], "sessions": [good_session],
             "transitions": [], "starts": ["s1", "s1"], "goals": []},
            {"allow": [], "deny": [], "sessions": [good_session],
             "transitions": [], "starts": ["ghost"], "goals": []},
            {"allow": [], "deny": [], "sessions": [good_session],
             "transitions": [], "starts": [""], "goals": []},
            {"allow": [], "deny": [], "sessions": [good_session],
             "transitions": [], "starts": [7], "goals": []},
            # goal problems
            {"allow": [], "deny": [], "sessions": [], "transitions": [],
             "starts": [], "goals": [{"id": "g1", "target": "a.example.com"}]},
            {"allow": [], "deny": [], "sessions": [], "transitions": [],
             "starts": [],
             "goals": [make_goal("g1", "*.example.com", "user")]},
            {"allow": [], "deny": [], "sessions": [], "transitions": [],
             "starts": [],
             "goals": [make_goal("g1", "a.example.com", "root")]},
            {"allow": [], "deny": [], "sessions": [], "transitions": [],
             "starts": [],
             "goals": [make_goal("g1"), make_goal("g1")]},
        ]
        for payload in bad_payloads:
            with self.subTest(payload=repr(payload)[:90]):
                with self.assertRaises(ValueError):
                    self.service.compute_escalation_paths(payload)

    def test_duplicate_transition_ids(self):
        transitions = [
            make_transition("dup", "s1", "s2", "ssh", 1),
            make_transition("dup", "s1", "s2", "rdp", 2),
        ]
        with self.assertRaises(ValueError):
            self.paths(transitions=transitions)

    def test_structural_error_takes_precedence_over_scope(self):
        # Malformed transition -> 400 even though a target is out of scope.
        payload = paths_payload(
            sessions=[make_session("s1", "other.example.org", "user")],
            transitions=[make_transition("t1", "s1", "s1")],
            starts=[],
            goals=[],
        )
        with self.assertRaises(ValueError):
            self.service.compute_escalation_paths(payload)

    def test_session_target_out_of_scope_is_403(self):
        with self.assertRaises(ScopeViolationError):
            self.paths(sessions=[make_session("s1", "other.example.org")],
                       transitions=[], starts=[], goals=[])

    def test_goal_target_out_of_scope_is_403(self):
        with self.assertRaises(ScopeViolationError):
            self.paths(goals=[make_goal("g1", "other.example.org", "user")])

    def test_deny_wins_over_allow(self):
        with self.assertRaises(ScopeViolationError):
            self.paths(deny=["db.example.com"])

    def test_cidr_allow_covers_ip_targets(self):
        sessions = [
            make_session("s1", "10.1.0.5", "user"),
            make_session("s2", "10.2.0.5", "system"),
        ]
        (entry,) = self.paths(
            sessions=sessions,
            transitions=[make_transition("t1", "s1", "s2", "smb", 1)],
            goals=[make_goal("g1", "10.2.0.5", "system")],
        )
        self.assertEqual(entry["status"], "reachable")

    def test_deterministic_across_calls(self):
        payload = paths_payload()
        first = self.service.compute_escalation_paths(payload)
        second = self.service.compute_escalation_paths(payload)
        self.assertEqual(first, second)


class EscalationPathsHttpTest(unittest.TestCase):
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

    def test_paths_ok(self):
        status, payload = self.request(
            "POST",
            "/v1/sessions/escalation-paths",
            json.dumps(paths_payload()).encode(),
            {"Content-Type": "application/json"},
        )
        self.assertEqual(status, 200)
        self.assertEqual(set(payload), {"paths"})
        (entry,) = payload["paths"]
        self.assertEqual(entry["status"], "reachable")
        self.assertEqual(entry["path"]["transition_ids"], ["t1"])

    def test_invalid_request_400(self):
        status, payload = self.request(
            "POST", "/v1/sessions/escalation-paths", b'{"allow": []}'
        )
        self.assertEqual(status, 400)
        self.assertEqual(payload["error"]["code"], "invalid_request")

    def test_malformed_json_400(self):
        status, payload = self.request(
            "POST", "/v1/sessions/escalation-paths", b"{nope"
        )
        self.assertEqual(status, 400)
        self.assertEqual(payload["error"]["code"], "invalid_request")

    def test_scope_violation_403(self):
        body = json.dumps(
            paths_payload(goals=[make_goal("g1", "elsewhere.example.net", "user")])
        ).encode()
        status, payload = self.request(
            "POST", "/v1/sessions/escalation-paths", body
        )
        self.assertEqual(status, 403)
        self.assertEqual(payload["error"]["code"], "scope_violation")

    def test_oversized_body_413(self):
        import http.client

        conn = http.client.HTTPConnection("127.0.0.1", self.port)
        conn.putrequest("POST", "/v1/sessions/escalation-paths")
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
                    method, "/v1/sessions/escalation-paths"
                )
                self.assertEqual(status, 405)
                self.assertEqual(payload["error"]["code"], "method_not_allowed")

    def test_healthz_unchanged(self):
        status, payload = self.request("GET", "/healthz")
        self.assertEqual(status, 200)
        self.assertEqual(payload["status"], "ok")


if __name__ == "__main__":
    unittest.main()
