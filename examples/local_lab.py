"""Intentionally vulnerable LOCAL-ONLY training API for Pun, using Python stdlib.

Never expose this toy server to the internet. Data are fake and reset on restart.
This lab is deliberately broken to demonstrate how Pun creates *candidates*,
not how to target real systems without authorization.
"""
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

ORDERS = {
    "1001": {"id": 1001, "owner": "userA", "email": "alice@example.invalid", "amount": 30},
    "2002": {"id": 2002, "owner": "userB", "email": "bob@example.invalid", "amount": 50},
}
CHECKOUTS = {}


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        print("LOCAL TRAINING LAB:", fmt % args)

    def actor(self):
        # Fake sessions only; use "session=userA" or "session=userB".
        cookie = self.headers.get("Cookie", "")
        if "session=userA" in cookie:
            return "userA"
        if "session=userB" in cookie:
            return "userB"
        return None

    def respond(self, code, data):
        raw = json.dumps(data).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):
        path = urlsplit(self.path).path
        if path == "/":
            self.respond(200, {"lab": "Pun local only", "users": ["userA", "userB"]})
            return
        if not self.actor():
            self.respond(401, {"error": "login required"})
            return
        if path.startswith("/api/orders/"):
            order_id = path.removeprefix("/api/orders/")
            order = ORDERS.get(order_id)
            if not order:
                self.respond(404, {"error": "not found"})
                return
            # INTENTIONAL IDOR: order ownership is not checked.
            self.respond(200, order)
            return
        self.respond(404, {"error": "no route"})

    def do_POST(self):
        actor = self.actor()
        if not actor:
            self.respond(401, {"error": "login required"})
            return
        path = urlsplit(self.path).path
        if path == "/api/checkout/create":
            CHECKOUTS[actor] = {"status": "created", "total": 10}
            self.respond(201, CHECKOUTS[actor])
        elif path == "/api/checkout/pay":
            if actor not in CHECKOUTS:
                self.respond(409, {"error": "create checkout first"})
                return
            CHECKOUTS[actor]["status"] = "paid"
            self.respond(200, CHECKOUTS[actor])
        elif path == "/api/checkout/complete":
            if actor not in CHECKOUTS:
                self.respond(409, {"error": "create checkout first"})
                return
            # INTENTIONAL LOGIC FLAW: payment state not verified.
            CHECKOUTS[actor]["status"] = "completed"
            self.respond(200, CHECKOUTS[actor])
        else:
            self.respond(404, {"error": "no route"})


def main():
    address = ("127.0.0.1", 8888)
    print("Pun deliberately vulnerable training lab at http://127.0.0.1:8888")
    print("FAKE cookies: session=userA or session=userB. Never bind to a public interface.")
    ThreadingHTTPServer(address, Handler).serve_forever()


if __name__ == "__main__":
    main()
