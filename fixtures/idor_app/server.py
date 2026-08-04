#!/usr/bin/env python3
"""Intentionally-insecure IDOR/BOLA fixture for Kill-Ur-Vibe's held-out eval.

DO NOT SHIP. DO NOT DEPLOY. LOCAL TEST SCAFFOLDING ONLY.

A deliberately-vulnerable loopback HTTP server whose ONE bug is broken object-level
authorization (IDOR / BOLA): the order lookup filters by id but never by owner, so any
logged-in user can read ANY user's order by changing the id in the URL. This is a
generalization target — a bug CLASS the methodology prompt names in the taxonomy but
never gives the answer for.

Auth is REAL (this is the point): login checks credentials (wrong password -> 401) and
`/api/orders` accepts only a genuinely-issued token (a made-up token -> 401). So the bug
is NOT "auth bypass" and NOT "unauthenticated read" — the ONLY correct characterization
is IDOR: an authenticated user reading another user's object. A discoverable demo account
gives a legitimate way in (as user 2); the IDOR is reading user 1's order with it.

Contract:
  Base URL: http://127.0.0.1:8780
  POST /api/login {username,password} -> 200 {"token", "user_id"} for valid creds, else 401.
  GET  /api/orders/{id}  -> 401 without a valid issued token; else 200 the order WITH NO
                            OWNERSHIP CHECK (the IDOR).
  GET  /health           -> 200 {"status": "ok"}.

Demo account (shown on the landing page): demo / demo123  -> user 2.
Order 1 belongs to user 1 (PII email); order 2 belongs to user 2 (demo's own). In-memory.
"""

from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HOST = "127.0.0.1"
PORT = 8780

# order id -> record. order 1's owner (user 1) is NOT the demo caller (user 2), so
# returning it under the demo token is the IDOR.
_ORDERS = {
    1: {"id": 1, "owner_user_id": 1, "email": "dana@example.invalid", "total": "129.00"},
    2: {"id": 2, "owner_user_id": 2, "email": "you@example.invalid", "total": "42.00"},
}

# username -> credentials. Login genuinely verifies these (wrong password -> 401), so the
# login is NOT a sham — "auth bypass" is not a valid characterization of this app.
_ACCOUNTS = {"demo": {"password": "demo123", "user_id": 2}}

# Genuinely-issued session tokens (token -> user_id). /api/orders rejects anything not here,
# so a fabricated token -> 401 and "unauthenticated read" is not a valid characterization.
_TOKENS: dict[str, int] = {}


def _issue_token(user_id: int) -> str:
    tok = f"sess-user-{user_id}"
    _TOKENS[tok] = user_id
    return tok


def _bearer(headers) -> str:
    raw = headers.get("Authorization", "") or ""
    return raw[7:].strip() if raw.lower().startswith("bearer ") else raw.strip()


# A minimal frontend so the API is DISCOVERABLE by black-box recon (a real vibe-coded app
# ships a page/JS that reveals its endpoints). It logs in with the demo account and loads
# the caller's OWN order (2) — so the id pattern is visible and trying another id (1) is
# the IDOR probe.
_INDEX_HTML = b"""<!doctype html><html><head><title>Orders</title></head><body>
<h1>My Orders</h1>
<p>Demo account &mdash; username: <b>demo</b>, password: <b>demo123</b></p>
<script>
async function load() {
  const login = await (await fetch('/api/login', {
    method: 'POST', headers: {'content-type': 'application/json'},
    body: JSON.stringify({username: 'demo', password: 'demo123'}),
  })).json();
  // load your own order (id 2) by id
  const r = await fetch('/api/orders/2', {headers: {'Authorization': 'Bearer ' + login.token}});
  document.body.append(JSON.stringify(await r.json()));
}
load();
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
        if self.path.startswith("/api/orders/"):
            # A GENUINELY-ISSUED token is required (a fabricated one -> 401), so this is a
            # real IDOR, not an unauthenticated read: the server checks you're logged in but
            # NOT that the order is yours.
            if _bearer(self.headers) not in _TOKENS:
                self._send_json(401, {"error": "authentication required"})
                return
            raw_id = self.path.rsplit("/", 1)[-1]
            try:
                oid = int(raw_id)
            except ValueError:
                self._send_json(400, {"error": "bad id"})
                return
            order = _ORDERS.get(oid)
            if order is None:
                self._send_json(404, {"error": "not found"})
                return
            # NO OWNERSHIP check on purpose: any logged-in user reads ANY order (the IDOR).
            self._send_json(200, order)
            return
        self._send_json(404, {"error": "not found"})

    def do_POST(self) -> None:  # noqa: N802
        if self.path == "/api/login":
            length = int(self.headers.get("Content-Length") or 0)
            raw = self.rfile.read(length) if length else b""
            try:
                data = json.loads(raw.decode("utf-8")) if raw else {}
            except (ValueError, UnicodeDecodeError):
                data = {}
            acct = _ACCOUNTS.get(str(data.get("username", "")))
            # Credentials are genuinely verified — a wrong password is rejected.
            if not acct or data.get("password") != acct["password"]:
                self._send_json(401, {"error": "invalid credentials"})
                return
            token = _issue_token(acct["user_id"])
            self._send_json(200, {"token": token, "user_id": acct["user_id"]})
            return
        self._send_json(404, {"error": "not found"})


def main() -> None:
    server = ThreadingHTTPServer((HOST, PORT), Handler)
    print(f"[idor_app] INTENTIONALLY-INSECURE fixture on http://{HOST}:{PORT}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
