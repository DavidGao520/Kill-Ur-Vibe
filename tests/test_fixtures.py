"""CI (no-LLM) integration tests for the held-out fixtures.

These prove the tools + pipeline handle the broader authz-bug classes end-to-end
WITHOUT an API key: the websocket probe is driven against a real unauth ws server,
and each HTTP fixture is checked to actually exhibit the bug its ground truth claims.
"""

from __future__ import annotations

import asyncio
import json
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from contextlib import contextmanager
from pathlib import Path

from kuv.recon.websocket import flags_sensitive, summarize_fields, websockets_probe

_FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"


def _wait_tcp(port: int, timeout_s: float = 10.0) -> bool:
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                return True
        except OSError:
            time.sleep(0.05)
    return False


def _wait_http_health(port: int, timeout_s: float = 10.0) -> bool:
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{port}/health", timeout=1) as resp:
                if resp.status == 200:
                    return True
        except (urllib.error.URLError, OSError):
            time.sleep(0.05)
    return False


@contextmanager
def _serve(rel_path: str, port: int, *, http_health: bool):
    proc = subprocess.Popen(
        [sys.executable, str(_FIXTURES / rel_path)],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    try:
        ready = _wait_http_health(port) if http_health else _wait_tcp(port)
        assert ready, f"fixture {rel_path} did not become ready on :{port}"
        yield
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()


def _post_json(url: str, body: dict) -> tuple[int, dict]:
    req = urllib.request.Request(
        url, data=json.dumps(body).encode(), method="POST",
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=3) as resp:
        return resp.status, json.loads(resp.read().decode())


def _get_json(url: str) -> tuple[int, dict]:
    with urllib.request.urlopen(url, timeout=3) as resp:
        return resp.status, json.loads(resp.read().decode())


# --- idor_app: broken object-level authorization ---------------------------

def test_idor_app_serves_another_owners_order():
    with _serve("idor_app/server.py", 8780, http_health=True):
        # We "log in" (issued a token for user 2) ...
        status, login = _post_json("http://127.0.0.1:8780/api/login", {"user": "x"})
        assert status == 200 and login["user_id"] == 2
        # ... yet can read order 1, which belongs to user 1 (the IDOR).
        status, order = _get_json("http://127.0.0.1:8780/api/orders/1")
        assert status == 200
        assert order["owner_user_id"] == 1        # a DIFFERENT owner than the caller
        assert "@" in order["email"]              # cross-owner PII exposed


# --- massassign_app: privilege escalation via mass-assignment ---------------

def test_massassign_app_honors_client_role_admin():
    with _serve("massassign_app/server.py", 8781, http_health=True):
        status, acct = _post_json(
            "http://127.0.0.1:8781/api/signup",
            {"email": "attacker@example.invalid", "password": "x", "role": "admin"},
        )
        assert status == 201
        assert acct["role"] == "admin"            # the server honored a privilege field


# --- ws_app: unauthenticated websocket read + write (end-to-end probe) ------

def test_ws_probe_reads_and_writes_unauth():
    with _serve("ws_app/server.py", 8782, http_health=False):
        frame = asyncio.run(websockets_probe(
            "ws://127.0.0.1:8782/",
            origin="https://evil.example",   # untrusted cross origin
            send=('{"op":"list"}', '{"op":"create","title":"synthetic-probe"}'),
            recv_timeout=2.0,
            max_messages=5,
        ))
        # Unauth, cross-origin handshake accepted — the finding signal.
        assert frame.connected is True
        assert frame.error is None
        assert frame.messages                      # unauth read returned frames
        joined = " ".join(frame.messages)
        assert "records" in joined                 # a read reply came back
        assert "created" in joined                 # the write round-tripped (unauth write)


def test_ws_field_summary_flags_the_email_field():
    with _serve("ws_app/server.py", 8782, http_health=False):
        frame = asyncio.run(websockets_probe(
            "ws://127.0.0.1:8782/", origin="https://evil.example",
            send=('{"op":"list"}',), recv_timeout=2.0, max_messages=3,
        ))
        summary = summarize_fields(frame.messages)
        fields = {row["field"] for row in summary}
        assert any(f.endswith("email") for f in fields)   # values-free field map works
        assert flags_sensitive(summary)                    # email flagged as PII-bearing
        # and the summary never contains an actual address
        assert "dana@example.invalid" not in json.dumps(summary)
