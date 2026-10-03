import json
import threading
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

from redforge.server import Handler
from redforge.service import ScopeViolationError, Service


def session(sid, target="app.example.com", privilege="user"):
    return {"id": sid, "target": target, "privilege": privilege}


def transition(tid, source, destination, cost=1, technique="t"):
    return {
        "id": tid,
        "from": source,
        "to": destination,
        "technique": technique,
        "cost": cost,
    }


def goal(gid, target="app.example.com", min_privilege="admin"):
    return {"id": gid, "target": target, "min_privilege": min_privilege}


def make_payload(**overrides):
    payload = {
        "allow": ["*.example.com", "10.0.0.0/8"],
        "deny": [],
        "sessions": [session("s0"), session("s1", privilege="admin")],
        "transitions": [transition("t0", "s0", "s1", cost=5)],
        "starts": ["s0"],
        "goals": [goal("g0")],
    }
    payload.update(overrides)
    return payload


class EscalationPathsServiceTest(unittest.TestCase):
    def setUp(self):
        self.service = Service()

    def compute(self, **overrides):
        return self.service.compute_escalation_paths(make_payload(**overrides))[
            "paths"
        ]

    def test_basic_reachable_path(self):
        (entry,) = self.compute()
        self.assertEqual(entry["goal_id"], "g0")
        self.assertEqual(entry["target"], "app.example.com")
        self.assertEqual(entry["min_privilege"], "admin")
        self.assertEqual(entry["status"], "reachable")
        self.assertEqual(
            entry["path"],
            {
                "start_session_id": "s0",
                "end_session_id": "s1",
                "total_cost": 5,
                "session_ids": ["s0", "s1"],
                "transition_ids": ["t0"],
            },
        )
        self.assertEqual(
            set(entry), {"goal_id", "target", "min_privilege", "status", "path"}
        )
        self.assertEqual(set(entry["path"]), {
            "start_session_id",
            "end_session_id",
            "total_cost",
            "session_ids",
            "transition_ids",
        })

    def test_start_session_satisfies_goal_is_zero_cost_empty_path(self):
        (entry,) = self.compute(starts=["s1"])
        self.assertEqual(entry["status"], "reachable")
        self.assertEqual(entry["path"]["start_session_id"], "s1")
        self.assertEqual(entry["path"]["end_session_id"], "s1")
        self.assertEqual(entry["path"]["total_cost"], 0)
        self.assertEqual(entry["path"]["session_ids"], ["s1"])
        self.assertEqual(entry["path"]["transition_ids"], [])

    def test_unreachable_returns_null_path(self):
        (entry,) = self.compute(transitions=[])
        self.assertEqual(entry["status"], "unreachable")
        self.assertIsNone(entry["path"])

    def test_privilege_threshold_matches_equal_and_above(self):
        sessions = [
            session("u", privilege="user"),
            session("a", privilege="admin"),
            session("x", privilege="system"),
        ]
        paths = self.compute(sessions=sessions, transitions=[], starts=["u", "a", "x"])
        (entry,) = paths
        self.assertEqual(entry["status"], "reachable")
        self.assertEqual(entry["path"]["end_session_id"], "a")
        # A system-only goal is unreachable from the admin start.
        (system_entry,) = self.compute(
            sessions=sessions,
            transitions=[],
            starts=["a"],
            goals=[goal("g0", min_privilege="system")],
        )
        self.assertEqual(system_entry["status"], "unreachable")

    def test_goal_requires_same_normalized_target(self):
        sessions = [
            session("s0", "app.example.com", "user"),
            session("db", "DB.Example.COM", "system"),
        ]
        # Cross-target edge is traversable, but the admin goal on app is not
        # satisfied by a session on db even at system privilege.
        (entry,) = self.compute(
            sessions=sessions,
            transitions=[transition("t0", "s0", "db", cost=1)],
            goals=[goal("g0", target="app.example.com", min_privilege="admin")],
        )
        self.assertEqual(entry["status"], "unreachable")
        # The normalized db target does satisfy a db goal.
        (db_entry,) = self.compute(
            sessions=sessions,
            transitions=[transition("t0", "s0", "db", cost=1)],
            goals=[goal("g0", target="db.example.com", min_privilege="system")],
        )
        self.assertEqual(db_entry["status"], "reachable")
        self.assertEqual(db_entry["target"], "db.example.com")
        self.assertEqual(db_entry["path"]["end_session_id"], "db")
        self.assertEqual(db_entry["path"]["total_cost"], 1)

    def test_cheapest_total_cost_wins(self):
        sessions = [
            session("s0"),
            session("mid", privilege="admin"),
            session("direct", privilege="admin"),
        ]
        transitions = [
            transition("cheap", "s0", "mid", cost=2),
            transition("pricey", "s0", "direct", cost=9),
        ]
        (entry,) = self.compute(sessions=sessions, transitions=transitions)
        self.assertEqual(entry["path"]["total_cost"], 2)
        self.assertEqual(entry["path"]["end_session_id"], "mid")
        self.assertEqual(entry["path"]["transition_ids"], ["cheap"])

    def test_fewer_transitions_breaks_cost_tie(self):
        sessions = [
            session("s0"),
            session("a"),
            session("onehop", privilege="admin"),
            session("twohop", privilege="admin"),
        ]
        transitions = [
            transition("t-direct", "s0", "onehop", cost=4),
            transition("t1", "s0", "a", cost=2),
            transition("t2", "a", "twohop", cost=2),
        ]
        (entry,) = self.compute(sessions=sessions, transitions=transitions)
        self.assertEqual(entry["path"]["total_cost"], 4)
        self.assertEqual(entry["path"]["transition_ids"], ["t-direct"])
        self.assertEqual(entry["path"]["session_ids"], ["s0", "onehop"])

    def test_transition_input_sequence_breaks_remaining_tie(self):
        # Two two-hop routes of equal cost: the route whose transition input
        # positions compare smaller wins.
        sessions = [
            session("s0"),
            session("a"),
            session("b"),
            session("ga", privilege="admin"),
            session("gb", privilege="admin"),
        ]
        transitions = [
            transition("e0", "s0", "a", cost=1),
            transition("e1", "s0", "b", cost=1),
            transition("e2", "a", "ga", cost=1),
            transition("e3", "b", "gb", cost=1),
        ]
        (entry,) = self.compute(sessions=sessions, transitions=transitions)
        self.assertEqual(entry["path"]["end_session_id"], "ga")
        self.assertEqual(entry["path"]["transition_ids"], ["e0", "e2"])

    def test_parallel_edges_between_same_session_pair(self):
        # Same cost/hops: the earlier transition input position wins.
        sessions = [session("s0"), session("s1", privilege="admin")]
        transitions = [
            transition("later", "s0", "s1", cost=3, technique="x"),
            transition("earlier", "s0", "s1", cost=3, technique="y"),
        ]
        # Input order puts "later" at position 0, "earlier" at 1.
        (entry,) = self.compute(sessions=sessions, transitions=transitions)
        self.assertEqual(entry["path"]["transition_ids"], ["later"])
        # A cheaper parallel edge wins regardless of input position.
        transitions[1]["cost"] = 2
        (entry,) = self.compute(sessions=sessions, transitions=transitions)
        self.assertEqual(entry["path"]["transition_ids"], ["earlier"])

    def test_start_input_position_breaks_tie_for_zero_hop_starts(self):
        sessions = [
            session("s0"),
            session("s1", privilege="admin"),
            session("s2", privilege="admin"),
        ]
        (entry,) = self.compute(
            sessions=sessions, transitions=[], starts=["s1", "s2"]
        )
        self.assertEqual(entry["path"]["end_session_id"], "s1")
        (entry,) = self.compute(
            sessions=sessions, transitions=[], starts=["s2", "s1"]
        )
        self.assertEqual(entry["path"]["end_session_id"], "s2")

    def test_cycles_and_self_privilege_are_handled(self):
        # Cycle s0 -> s1 -> s0 with cheap edges must not trap the search; the
        # goal sits behind a cost-10 edge.
        sessions = [session("s0"), session("s1"), session("g", privilege="admin")]
        transitions = [
            transition("loop1", "s0", "s1", cost=1),
            transition("loop2", "s1", "s0", cost=1),
            transition("exit", "s1", "g", cost=10),
        ]
        (entry,) = self.compute(sessions=sessions, transitions=transitions)
        self.assertEqual(entry["status"], "reachable")
        self.assertEqual(entry["path"]["total_cost"], 11)
        self.assertEqual(entry["path"]["session_ids"], ["s0", "s1", "g"])

    def test_paths_keep_goal_input_order(self):
        sessions = [session("s0", privilege="system")]
        goals = [goal("g2"), goal("g0"), goal("g1")]
        entries = self.compute(
            sessions=sessions, transitions=[], starts=["s0"], goals=goals
        )
        self.assertEqual([e["goal_id"] for e in entries], ["g2", "g0", "g1"])
        self.assertTrue(all(e["status"] == "reachable" for e in entries))

    def test_empty_arrays(self):
        self.assertEqual(
            self.compute(sessions=[], transitions=[], starts=[], goals=[]), []
        )

    def test_response_contains_only_paths(self):
        self.assertEqual(set(self.service.compute_escalation_paths(make_payload())),
                         {"paths"})

    def test_scope_violation_on_session_target(self):
        with self.assertRaises(ScopeViolationError):
            self.compute(
                sessions=[
                    session("s0"),
                    session("s1", target="secret.example.org", privilege="admin"),
                ]
            )

    def test_scope_violation_on_goal_target(self):
        with self.assertRaises(ScopeViolationError):
            self.compute(goals=[goal("g0", target="secret.example.org")])

    def test_denied_target_wins_over_allow(self):
        with self.assertRaises(ScopeViolationError):
            self.compute(
                sessions=[
                    session("s0", target="bad.app.example.com"),
                    session("s1", target="bad.app.example.com", privilege="admin"),
                ],
                deny=["bad.app.example.com"],
            )

    def test_invalid_payloads(self):
        bad_payloads = [
            None,
            [],
            {},
            {"deny": [], "sessions": [], "transitions": [], "starts": [],
             "goals": []},
            {"allow": [], "deny": [], "sessions": [], "transitions": [],
             "starts": [], "goals": [], "extra": 1},
            {"allow": {}, "deny": [], "sessions": [], "transitions": [],
             "starts": [], "goals": []},
            {"allow": [], "deny": [], "sessions": {}, "transitions": [],
             "starts": [], "goals": []},
            {"allow": [], "deny": [], "sessions": [], "transitions": {},
             "starts": [], "goals": []},
            {"allow": [], "deny": [], "sessions": [], "transitions": [],
             "starts": {}, "goals": []},
            {"allow": [], "deny": [], "sessions": [], "transitions": [],
             "starts": [], "goals": {}},
            # sessions
            {"allow": ["*.example.com"], "deny": [],
             "sessions": [{"id": "", "target": "app.example.com",
                           "privilege": "user"}],
             "transitions": [], "starts": [], "goals": []},
            {"allow": ["*.example.com"], "deny": [],
             "sessions": [{"id": "s0", "target": "app.example.com"}],
             "transitions": [], "starts": [], "goals": []},
            {"allow": ["*.example.com"], "deny": [],
             "sessions": [{"id": "s0", "target": "app.example.com",
                           "privilege": "root"}],
             "transitions": [], "starts": [], "goals": []},
            {"allow": ["*.example.com"], "deny": [],
             "sessions": [{"id": "s0", "target": "app.example.com",
                           "privilege": True}],
             "transitions": [], "starts": [], "goals": []},
            {"allow": ["*.example.com"], "deny": [],
             "sessions": [{"id": "s0", "target": "*.example.com",
                           "privilege": "user"}],
             "transitions": [], "starts": [], "goals": []},
            {"allow": ["*.example.com"], "deny": [],
             "sessions": [session("s0"), session("s0")],
             "transitions": [], "starts": [], "goals": []},
            # transitions
            {"allow": ["*.example.com"], "deny": [],
             "sessions": [session("s0")],
             "transitions": [{"id": "t0", "from": "s0", "to": "s0",
                             "technique": "x", "cost": 1}],
             "starts": [], "goals": []},
            {"allow": ["*.example.com"], "deny": [],
             "sessions": [session("s0")],
             "transitions": [{"id": "t0", "from": "s0", "to": "ghost",
                             "technique": "x", "cost": 1}],
             "starts": [], "goals": []},
            {"allow": ["*.example.com"], "deny": [],
             "sessions": [session("s0")],
             "transitions": [transition("t0", "s0", "s0")],
             "starts": [], "goals": []},
            {"allow": ["*.example.com"], "deny": [],
             "sessions": [session("s0"), session("s1")],
             "transitions": [transition("t0", "s0", "s1", cost=0)],
             "starts": [], "goals": []},
            {"allow": ["*.example.com"], "deny": [],
             "sessions": [session("s0"), session("s1")],
             "transitions": [transition("t0", "s0", "s1", cost=101)],
             "starts": [], "goals": []},
            {"allow": ["*.example.com"], "deny": [],
             "sessions": [session("s0"), session("s1")],
             "transitions": [transition("t0", "s0", "s1", cost=True)],
             "starts": [], "goals": []},
            {"allow": ["*.example.com"], "deny": [],
             "sessions": [session("s0"), session("s1")],
             "transitions": [transition("t0", "s0", "s1", cost="5")],
             "starts": [], "goals": []},
            {"allow": ["*.example.com"], "deny": [],
             "sessions": [session("s0"), session("s1")],
             "transitions": [transition("t0", "s0", "s1", technique="")],
             "starts": [], "goals": []},
            {"allow": ["*.example.com"], "deny": [],
             "sessions": [session("s0"), session("s1")],
             "transitions": [transition("t0", "s0", "s1"),
                             transition("t0", "s1", "s0")],
             "starts": [], "goals": []},
            # starts
            {"allow": ["*.example.com"], "deny": [],
             "sessions": [session("s0")],
             "transitions": [], "starts": ["s0", "s0"], "goals": []},
            {"allow": ["*.example.com"], "deny": [],
             "sessions": [session("s0")],
             "transitions": [], "starts": ["ghost"], "goals": []},
            {"allow": ["*.example.com"], "deny": [],
             "sessions": [session("s0")],
             "transitions": [], "starts": [""], "goals": []},
            {"allow": ["*.example.com"], "deny": [],
             "sessions": [session("s0")],
             "transitions": [], "starts": [0], "goals": []},
            # goals
            {"allow": ["*.example.com"], "deny": [],
             "sessions": [session("s0")],
             "transitions": [], "starts": [],
             "goals": [{"id": "g0", "target": "app.example.com"}]},
            {"allow": ["*.example.com"], "deny": [],
             "sessions": [session("s0")],
             "transitions": [], "starts": [],
             "goals": [goal("g0", min_privilege="root")]},
            {"allow": ["*.example.com"], "deny": [],
             "sessions": [session("s0")],
             "transitions": [], "starts": [],
             "goals": [goal("g0"), goal("g0")]},
        ]
        for bad in bad_payloads:
            with self.subTest(payload=repr(bad)[:80]):
                with self.assertRaises(ValueError):
                    self.service.compute_escalation_paths(bad)

    def test_structural_error_precedes_scope_gate(self):
        # Duplicate session id is a 400 even though the target is in scope;
        # pair it with an out-of-scope goal to prove ordering.
        with self.assertRaises(ValueError):
            self.service.compute_escalation_paths(
                make_payload(
                    sessions=[session("s0"), session("s0")],
                    goals=[goal("g0", target="secret.example.org")],
                )
            )


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

    def test_ok(self):
        status, payload = self.request(
            "POST",
            "/v1/sessions/escalation-paths",
            json.dumps(make_payload()).encode(),
            {"Content-Type": "application/json"},
        )
        self.assertEqual(status, 200)
        self.assertEqual(set(payload), {"paths"})
        self.assertEqual(payload["paths"][0]["status"], "reachable")

    def test_invalid_request_400(self):
        status, payload = self.request(
            "POST", "/v1/sessions/escalation-paths", b"{}"
        )
        self.assertEqual(status, 400)
        self.assertEqual(payload["error"]["code"], "invalid_request")

    def test_scope_violation_403(self):
        bad = make_payload(
            sessions=[
                session("s0", target="secret.example.org"),
                session("s1", target="secret.example.org", privilege="admin"),
            ]
        )
        status, payload = self.request(
            "POST",
            "/v1/sessions/escalation-paths",
            json.dumps(bad).encode(),
        )
        self.assertEqual(status, 403)
        self.assertEqual(payload["error"]["code"], "scope_violation")

    def test_get_not_allowed(self):
        status, payload = self.request("GET", "/v1/sessions/escalation-paths")
        self.assertEqual(status, 405)
        self.assertEqual(payload["error"]["code"], "method_not_allowed")


if __name__ == "__main__":
    unittest.main()
