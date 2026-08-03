#!/usr/bin/env python3
"""Intentionally-insecure fixture app for Kill-Ur-Vibe's own test suite.

DO NOT SHIP. DO NOT DEPLOY. LOCAL TEST SCAFFOLDING ONLY.

This is a deliberately-vulnerable HTTP server bound to loopback. It exists so the
Kill-Ur-Vibe active-assessment CLI (and its eval) can prove they reproduce two
known findings against a controlled target on localhost:

  - unauth_read_sensitive : GET /api/ideas returns PII (email) with NO auth.
  - unauth_write          : POST /api/ideas creates a record with NO auth. (Critical)

The "vulnerabilities" here are simply the deliberate ABSENCE of authentication and
authorization. There is no real user data, no persistence, and no external
dependency — an in-memory store seeded with two fake records. Restarting the
server resets all state.

Contract (fixture and eval both build to THIS exact spec):
  Base URL: http://127.0.0.1:8779
  GET  /api/ideas  -> 200 JSON list; each item {id, title, email}; email is PII; NO auth.
  POST /api/ideas  -> 201 created from JSON body {title}; NO auth.
  GET  /health     -> 200 {"status": "ok"}.

Run:
  python fixtures/vuln_app/server.py
"""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HOST = "127.0.0.1"
PORT = 8779

# In-memory store, seeded with two fake ideas. Each idea deliberately carries an
# `email` field (PII) that is served to unauthenticated clients — that exposure
# is the `unauth_read_sensitive` finding this fixture reproduces.
_LOCK = threading.Lock()
_IDEAS = [
    {"id": 1, "title": "Realtime fraud scoring", "email": "dana@example.com"},
    {"id": 2, "title": "Founder matchmaking", "email": "amir@example.com"},
]
_NEXT_ID = 3


def _next_id() -> int:
    global _NEXT_ID
    nid = _NEXT_ID
    _NEXT_ID += 1
    return nid


class Handler(BaseHTTPRequestHandler):
    # Quiet the default per-request stderr logging so test output stays clean.
    def log_message(self, *args) -> None:  # noqa: D401, ANN002
        pass

    def _send_json(self, status: int, payload) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        if self.path == "/health":
            self._send_json(200, {"status": "ok"})
            return
        if self.path == "/api/ideas":
            # NO auth check on purpose: unauthenticated read of PII (email).
            with _LOCK:
                self._send_json(200, list(_IDEAS))
            return
        self._send_json(404, {"error": "not found"})

    def do_POST(self) -> None:  # noqa: N802
        if self.path == "/api/ideas":
            # NO auth check on purpose: unauthenticated write (the Critical).
            length = int(self.headers.get("Content-Length") or 0)
            raw = self.rfile.read(length) if length else b""
            try:
                data = json.loads(raw.decode("utf-8")) if raw else {}
            except (ValueError, UnicodeDecodeError):
                self._send_json(400, {"error": "invalid JSON"})
                return
            if not isinstance(data, dict) or "title" not in data:
                self._send_json(400, {"error": "missing 'title'"})
                return

            with _LOCK:
                idea = {
                    "id": _next_id(),
                    "title": str(data["title"]),
                    "email": "",
                }
                _IDEAS.append(idea)
            self._send_json(201, idea)
            return
        self._send_json(404, {"error": "not found"})


def main() -> None:
    server = ThreadingHTTPServer((HOST, PORT), Handler)
    banner = (
        f"[vuln_app] INTENTIONALLY-INSECURE fixture listening on "
        f"http://{HOST}:{PORT}  (Ctrl-C to stop)"
    )
    print(banner, flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
