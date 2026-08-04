#!/usr/bin/env python3
"""Intentionally-insecure mass-assignment / privilege-escalation fixture.

DO NOT SHIP. DO NOT DEPLOY. LOCAL TEST SCAFFOLDING ONLY.

A deliberately-vulnerable loopback HTTP server whose ONE bug is mass-assignment leading
to privilege escalation: the signup handler copies the whole JSON body into the new
account, so a caller can set `role=admin` even though the UI never offers it. A
generalization target — a bug CLASS the methodology names but never answers.

Contract:
  Base URL: http://127.0.0.1:8781
  POST /api/signup -> 201 {"id", "email", "role"} — HONORS a client-supplied `role`.
  GET  /health     -> 200 {"status": "ok"}.

In-memory; restart resets.
"""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HOST = "127.0.0.1"
PORT = 8781

_LOCK = threading.Lock()
_NEXT_ID = 1


def _next_id() -> int:
    global _NEXT_ID
    with _LOCK:
        nid = _NEXT_ID
        _NEXT_ID += 1
        return nid


# A minimal frontend so the signup API is DISCOVERABLE by recon (a real vibe-coded app
# ships a signup page). The form shows only email/password — the mass-assignment bug is
# that the SERVER also honors a `role` field the UI never sends.
_INDEX_HTML = b"""<!doctype html><html><head><title>Sign up</title></head><body>
<h1>Create your account</h1>
<form id="signup">
  <input name="email" type="email" placeholder="email">
  <input name="password" type="password" placeholder="password">
  <button>Sign up</button>
</form>
<script>
document.getElementById('signup').onsubmit = async (e) => {
  e.preventDefault();
  await fetch('/api/signup', {
    method: 'POST',
    headers: {'content-type': 'application/json'},
    body: JSON.stringify({email: 'user@example.com', password: 'x'}),
  });
};
</script>
</body></html>"""


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args) -> None:  # noqa: D401, ANN002 — quiet
        pass

    def _send_html(self, status: int, body: bytes) -> None:
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_json(self, status: int, payload) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        if self.path in ("/", "/index.html"):
            self._send_html(200, _INDEX_HTML)
            return
        if self.path == "/health":
            self._send_json(200, {"status": "ok"})
            return
        self._send_json(404, {"error": "not found"})

    def do_POST(self) -> None:  # noqa: N802
        if self.path == "/api/signup":
            length = int(self.headers.get("Content-Length") or 0)
            raw = self.rfile.read(length) if length else b""
            try:
                data = json.loads(raw.decode("utf-8")) if raw else {}
            except (ValueError, UnicodeDecodeError):
                self._send_json(400, {"error": "invalid JSON"})
                return
            if not isinstance(data, dict) or "email" not in data:
                self._send_json(400, {"error": "missing 'email'"})
                return
            # THE BUG: the whole body is trusted. A client-supplied `role` is honored,
            # so role=admin makes an admin account (privilege escalation via mass-assignment).
            account = {
                "id": _next_id(),
                "email": str(data["email"]),
                "role": str(data.get("role", "user")),
            }
            self._send_json(201, account)
            return
        self._send_json(404, {"error": "not found"})


def main() -> None:
    server = ThreadingHTTPServer((HOST, PORT), Handler)
    print(f"[massassign_app] INTENTIONALLY-INSECURE fixture on http://{HOST}:{PORT}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
