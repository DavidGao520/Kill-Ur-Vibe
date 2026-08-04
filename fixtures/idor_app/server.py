#!/usr/bin/env python3
"""Intentionally-insecure IDOR/BOLA fixture for Kill-Ur-Vibe's held-out eval.

DO NOT SHIP. DO NOT DEPLOY. LOCAL TEST SCAFFOLDING ONLY.

A deliberately-vulnerable loopback HTTP server whose ONE bug is broken object-level
authorization (IDOR / BOLA): the order lookup filters by id but never by owner, so any
logged-in user can read ANY user's order by changing the id in the URL. This is a
generalization target — a bug CLASS the methodology prompt names in the taxonomy but
never gives the answer for.

Contract:
  Base URL: http://127.0.0.1:8780
  POST /api/login  -> 200 {"token": "user-2"}   (any body; you are "user 2")
  GET  /api/orders/{id} -> 200 the order, WITH NO OWNERSHIP CHECK (the IDOR).
  GET  /health     -> 200 {"status": "ok"}.

Orders are seeded so order 1 belongs to user 1 (carrying a PII email) — fetching it
while "user 2" proves the cross-owner read. In-memory; restart resets.
"""

from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HOST = "127.0.0.1"
PORT = 8780

# order id -> record. Each order has an owner; order 1's owner (user 1) is NOT the
# caller (user 2), so returning it is the IDOR.
_ORDERS = {
    1: {"id": 1, "owner_user_id": 1, "email": "dana@example.invalid", "total": "129.00"},
    2: {"id": 2, "owner_user_id": 2, "email": "you@example.invalid", "total": "42.00"},
}


# A minimal frontend so the API is DISCOVERABLE by black-box recon (a real vibe-coded
# app ships a page/JS that reveals its endpoints). Without this, the vulnerable route is
# unreachable and the eval would test path-guessing, not authorization reasoning.
_INDEX_HTML = b"""<!doctype html><html><head><title>Orders</title></head><body>
<h1>My Orders</h1>
<script>
async function load() {
  // log in (you become user 2), then load an order by id with your token
  const login = await (await fetch('/api/login', {method: 'POST', headers: {'content-type': 'application/json'}, body: '{}'})).json();
  const r = await fetch('/api/orders/1', {headers: {'Authorization': 'Bearer ' + login.token}});
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
            # Auth IS required (a token from /api/login) — this is a real IDOR, not an
            # unauthenticated read: the server checks you're logged in but NOT that the
            # order is yours.
            if not self.headers.get("Authorization"):
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
            # Any credentials "work"; you are issued a token for user 2.
            self._send_json(200, {"token": "user-2", "user_id": 2})
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
