"""Session-level tests for the Wave-1 tools (fingerprint_stack, templated_checks).

Uses a route-aware fake client so per-path responses can be exercised, and verifies
the egress keystone still holds (off-scope → refused, zero I/O)."""

from __future__ import annotations

import asyncio
from datetime import date

from kuv.agent.session import AssessmentSession
from kuv.egress import EgressEngine
from kuv.gate import ActionClass, Scope

_NOW = date(2026, 7, 31)


class _Resp:
    def __init__(self, status: int, text: str = "", headers: dict | None = None):
        self.status_code = status
        self.text = text
        self.headers = headers or {}


class _RouteClient:
    """`get(url)` returns a response chosen by URL substring; default 404."""

    def __init__(self, routes: dict[str, _Resp], default: _Resp | None = None):
        self.routes = routes
        self.default = default or _Resp(404, "Not Found")
        self.calls: list[str] = []

    async def get(self, url: str):
        self.calls.append(url)
        for frag, resp in self.routes.items():
            if url.endswith(frag) or frag in url:
                return resp
        return self.default

    async def request(self, method: str, url: str, *, content=None, headers=None):
        self.calls.append(url)
        return self.default


def _session(client, *, targets=("example.com",)):
    scope = Scope(
        engagement_id="acme",
        authorized_by="owner@example.com",
        targets=targets,
        expires_at=date(2026, 12, 31),
        allowed_actions=frozenset({ActionClass.ACCOUNT_CREATE}),
        is_fixture=True,
        authorization_asserted=True,
    )
    return AssessmentSession(EgressEngine(scope, now=lambda: _NOW), client)


# --------------------------------------------------------------------------
# fingerprint_stack
# --------------------------------------------------------------------------


def test_fingerprint_stack_detects_and_gates():
    client = _RouteClient(
        {"/": _Resp(200, '<script src="/_next/static/x.js"></script>', {"Server": "Vercel"})}
    )
    session = _session(client)
    out = asyncio.run(session.fingerprint_stack("https://example.com/"))
    assert out["ok"] is True
    assert "framework:Next.js" in out["tags"]
    assert "hosting:Vercel" in out["tags"]


def test_fingerprint_stack_off_scope_refused_no_io():
    client = _RouteClient({})
    session = _session(client)
    out = asyncio.run(session.fingerprint_stack("https://evil.com/"))
    assert out["ok"] is False and "REFUSED" in out["error"]
    assert client.calls == []


# --------------------------------------------------------------------------
# templated_checks
# --------------------------------------------------------------------------


def test_templated_checks_finds_exposed_env():
    client = _RouteClient(
        {".env": _Resp(200, "SECRET_KEY=abc\nDATABASE_URL=postgres://x\n", {"content-type": "text/plain"})}
    )
    session = _session(client)
    out = asyncio.run(session.templated_checks("https://example.com/"))
    assert out["ok"] is True
    exposed = out["exposed"]
    assert any(e["finding_type"] == "exposed_secret_file" and e["path"] == ".env" for e in exposed)
    # every exposed candidate carries what record_finding needs
    e = next(e for e in exposed if e["path"] == ".env")
    assert e["location"] == "GET /.env" and e["plain_impact"] and e["recommendation"]


def test_templated_checks_clean_site_no_false_positives():
    # default 404 for everything, and even a 200 HTML shell must not trip a check
    client = _RouteClient({}, default=_Resp(200, "<!doctype html><html>app</html>"))
    session = _session(client)
    out = asyncio.run(session.templated_checks("https://example.com/"))
    assert out["ok"] is True
    assert out["exposed"] == []
    assert out["probed"] > 0  # it really did probe


def test_templated_checks_off_scope_refused_no_io():
    client = _RouteClient({".env": _Resp(200, "SECRET_KEY=abc\nAPI_KEY=def\n")})
    session = _session(client)  # scope is example.com; evil.com is off-scope
    out = asyncio.run(session.templated_checks("https://evil.com/"))
    assert out["exposed"] == []
    assert client.calls == []  # every check was gate-refused before any I/O
