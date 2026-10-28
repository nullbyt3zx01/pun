"""Real loopback HTTP test with a fake Burp bridge; does not touch external targets."""
import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from pun_mcp.bridge import PunBridge, BridgeError


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_GET(self):
        if self.headers.get("Authorization") != "Bearer LOCAL_TEST_TOKEN":
            self.send_response(401)
            self.end_headers()
            self.wfile.write(b'{}')
            return
        data = {
            "/health": {"name": "Pun", "version": "test"},
            "/roles": {"roles": ["userA", "userB"]},
            "/traffic": {"items": [{"id": "req-1", "host": "test.local", "method": "GET",
                                    "path": "/orders/123", "role": "userB", "status": 200,
                                    "output_keys": ["id"], "input_keys": [], "response_sha256": "abc"}]},
            "/jobs": {"jobs": []},
        }.get(self.path)
        if data is None:
            self.send_response(404)
            self.end_headers()
            return
        encoded = json.dumps(data).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def do_POST(self):
        if self.headers.get("Authorization") != "Bearer LOCAL_TEST_TOKEN":
            self.send_response(401)
            self.end_headers()
            return
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        assert body["role"] == "userA"
        assert body["request_id"] == "req-1"
        self.send_response(202)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"id":"job-test","status":"PENDING"}')


class TestBridge(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()
        cls.thread.join()

    def test_connection_and_auth(self):
        bridge = PunBridge(url=f"http://127.0.0.1:{self.httpd.server_port}", token="LOCAL_TEST_TOKEN")
        self.assertEqual(bridge.health()["name"], "Pun")
        self.assertEqual(bridge.roles()["roles"], ["userA", "userB"])
        self.assertEqual(bridge.traffic()["items"][0]["path"], "/orders/123")
        self.assertEqual(bridge.prepare_replay("req-1", "userA", "my test account")["status"], "PENDING")
        with self.assertRaises(BridgeError):
            bridge.prepare_replay("req-1", "userA", "")

    def test_wrong_token(self):
        bridge = PunBridge(url=f"http://127.0.0.1:{self.httpd.server_port}", token="WRONG")
        with self.assertRaisesRegex(BridgeError, "HTTP 401"):
            bridge.health()


if __name__ == "__main__":
    unittest.main()
