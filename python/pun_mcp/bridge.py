"""Authenticated loopback bridge client; the Burp extension owns outbound traffic."""
from __future__ import annotations

import json
import os
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, build_opener, ProxyHandler, HTTPRedirectHandler


class BridgeError(RuntimeError):
    pass


class PunBridge:
    def __init__(self, url: str | None = None, token: str | None = None):
        self.url = (url or os.getenv("PUN_BRIDGE_URL") or "http://127.0.0.1:8765").rstrip("/")
        self.token = token if token is not None else os.getenv("PUN_BRIDGE_TOKEN", "")
        parsed = urlparse(self.url)
        if (parsed.scheme != "http" or parsed.hostname != "127.0.0.1"
                or parsed.username or parsed.password or parsed.path not in {"", "/"}
                or parsed.query or parsed.fragment):
            raise BridgeError("Only a local HTTP Pun bridge is allowed")
        if not self.token:
            raise BridgeError("Set PUN_BRIDGE_TOKEN to the token shown in Burp's Pun tab")

    def _call(self, method: str, path: str, payload: dict | None = None) -> dict:
        if not path.startswith("/") or path.startswith("//") or "://" in path:
            raise BridgeError("Invalid bridge route")
        body = json.dumps(payload).encode("utf-8") if payload is not None else None
        request = Request(
            self.url + path, data=body, method=method,
            headers={"Authorization": "Bearer " + self.token, "Accept": "application/json",
                     "Content-Type": "application/json"},
        )
        try:
            # Disable proxies and redirects: never forward the bearer token elsewhere.
            class NoRedirect(HTTPRedirectHandler):
                def redirect_request(self, req, fp, code, msg, headers, newurl):
                    raise BridgeError("Refusing HTTP redirect from local Pun bridge")
            with build_opener(ProxyHandler({}), NoRedirect()).open(request, timeout=8) as response:
                return json.load(response)
        except HTTPError as exc:
            message = exc.read(512).decode("utf-8", "replace")
            raise BridgeError(f"Pun bridge HTTP {exc.code}: {message}") from exc
        except (URLError, TimeoutError, ValueError) as exc:
            raise BridgeError(f"Cannot talk to Pun bridge: {exc}") from exc

    def health(self):
        return self._call("GET", "/health")

    def traffic(self):
        return self._call("GET", "/traffic")

    def roles(self):
        return self._call("GET", "/roles")

    def jobs(self):
        return self._call("GET", "/jobs")

    def prepare_replay(self, request_id: str, role: str, reason: str):
        if not reason.strip() or len(reason) > 350:
            raise BridgeError("A short justification is required (max 350 chars)")
        return self._call("POST", "/replays", {"request_id": request_id, "role": role, "reason": reason})
