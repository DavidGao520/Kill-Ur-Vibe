#!/usr/bin/env python3
"""Intentionally-insecure unauthenticated-websocket fixture.

DO NOT SHIP. DO NOT DEPLOY. LOCAL TEST SCAFFOLDING ONLY.

A deliberately-vulnerable loopback websocket server whose bug is that it requires NO
token and checks NO Origin: any anonymous, cross-origin client can connect, read
production-shaped records, and write a new one. This exercises the websocket probe
end-to-end (the one tool the tiny HTTP fixtures can't reach).

Contract:
  URL: ws://127.0.0.1:8782/
  On any text frame:
    {"op":"create", ...} -> replies {"ok": true, "created": {...}}   (unauth write)
    anything else        -> replies {"records": [ ... ]}             (unauth read)
  No auth, no Origin check. In-memory; restart resets.

Requires the `websockets` library (in the project's `dev`/`probe` extras).
"""

from __future__ import annotations

import asyncio
import json

import websockets

HOST = "127.0.0.1"
PORT = 8782

# Records returned on an unauth read — shaped like production data (carry a PII-ish
# field so the probe's field summary has something to flag), but entirely synthetic.
_RECORDS = [
    {"id": 1, "email": "dana@example.invalid", "note": "synthetic record"},
    {"id": 2, "email": "amir@example.invalid", "note": "synthetic record"},
]


async def handler(websocket, *_args) -> None:
    """NO auth, NO Origin check — the vulnerability. `*_args` tolerates both the modern
    (websocket-only) and legacy (websocket, path) handler signatures."""
    async for raw in websocket:
        try:
            msg = json.loads(raw)
        except (ValueError, TypeError):
            msg = {}
        if isinstance(msg, dict) and msg.get("op") == "create":
            await websocket.send(json.dumps({"ok": True, "created": {"id": 99, "title": msg.get("title", "")}}))
        else:
            await websocket.send(json.dumps({"records": _RECORDS}))


async def _main() -> None:
    async with websockets.serve(handler, HOST, PORT):
        print(f"[ws_app] INTENTIONALLY-INSECURE websocket fixture on ws://{HOST}:{PORT}", flush=True)
        await asyncio.Future()  # run forever


def main() -> None:
    try:
        asyncio.run(_main())
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
