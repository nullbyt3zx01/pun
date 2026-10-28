import unittest

from pun_mcp.authgraph import normalize_path, endpoints, authorization_graph, assess_replay
from pun_mcp.logichunter import discover_workflows, create_plan
from pun_mcp.reports import report_markdown
from pun_mcp.bridge import PunBridge, BridgeError


TRAFFIC = [
    {"id": "r1", "timestamp": 1000, "host": "app.test", "role": "userB", "method": "GET", "path": "/api/users/123/orders/246", "status": 200, "input_keys": [], "output_keys": ["id", "email"], "response_sha256": "abc"},
    {"id": "r2", "timestamp": 2000, "host": "app.test", "role": "userB", "method": "POST", "path": "/api/orders/246/checkout", "status": 200, "input_keys": ["order_id"], "output_keys": ["status"], "response_sha256": "def"},
    {"id": "r3", "timestamp": 3000, "host": "app.test", "role": "userB", "method": "POST", "path": "/api/orders/246/confirm", "status": 200, "input_keys": ["confirmed"], "output_keys": ["status"], "response_sha256": "ghi"},
]


class Tests(unittest.TestCase):
    def test_path_normalization(self):
        self.assertEqual(normalize_path("/api/orders/123?token=secret"), "/api/orders/{id}")

    def test_authgraph_never_claims_confirmed(self):
        graph = authorization_graph(TRAFFIC)
        self.assertTrue(graph["test_candidates"])
        self.assertTrue(all(not c["confirmed"] for c in graph["test_candidates"]))

    def test_inventory(self):
        self.assertEqual(len(endpoints(TRAFFIC)), 3)
        self.assertTrue(any("{id}" in e["path_pattern"] for e in endpoints(TRAFFIC)))

    def test_workflows(self):
        flows = discover_workflows(TRAFFIC)
        self.assertEqual(len(flows), 1)
        self.assertEqual(len(flows[0]["steps"]), 2)

    def test_workflow_plan(self):
        p = create_plan(["r2", "r3"], TRAFFIC)
        self.assertEqual(len(p["hypotheses"]), 3)
        with self.assertRaises(ValueError):
            create_plan(["r3", "r2"], TRAFFIC)

    def test_replay_stays_unconfirmed(self):
        replay = {"id": "j1", "request_id": "r1", "role": "userA", "status": "COMPLETED",
                  "result": {"status": 200, "response_sha256": "abc", "output_keys": ["id", "email"]}}
        outcome = assess_replay(TRAFFIC[0], replay)
        self.assertFalse(outcome["confirmed"])
        self.assertEqual(outcome["verdict"], "review_required")
        self.assertIn("Needs manual validation", report_markdown(TRAFFIC[0], replay))

    def test_bridge_rejects_remote_endpoint(self):
        with self.assertRaises(BridgeError):
            PunBridge(url="https://evil.example", token="x")
        with self.assertRaises(BridgeError):
            PunBridge(url="http://127.0.0.1.evil.example:8765", token="x")


if __name__ == "__main__":
    unittest.main()
