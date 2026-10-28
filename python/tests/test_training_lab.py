"""Optional lab regressions prove the toy findings exist on loopback only."""
import importlib.util
import json
from pathlib import Path
from http.server import ThreadingHTTPServer
import threading
import unittest
from urllib.request import Request, urlopen


lab_file = Path(__file__).resolve().parents[2] / "examples" / "local_lab.py"
spec = importlib.util.spec_from_file_location("pun_lab", lab_file)
lab = importlib.util.module_from_spec(spec)
spec.loader.exec_module(lab)


class LabTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), lab.Handler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join()

    def call_lab(self, path, role="userA", method="GET"):
        request = Request(f"http://127.0.0.1:{self.server.server_port}{path}",
                          method=method, headers={"Cookie": f"session={role}"})
        with urlopen(request, timeout=3) as reply:
            return reply.status, json.load(reply)

    def test_demo_idor_is_intentionally_present(self):
        status, result = self.call_lab("/api/orders/2002", role="userA")
        self.assertEqual(status, 200)
        self.assertEqual(result["owner"], "userB")

    def test_demo_logic_skip_is_intentionally_present(self):
        self.call_lab("/api/checkout/create", role="userB", method="POST")
        status, data = self.call_lab("/api/checkout/complete", role="userB", method="POST")
        self.assertEqual(status, 200)
        self.assertEqual(data["status"], "completed")


if __name__ == "__main__":
    unittest.main()
