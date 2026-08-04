"""The four depth tools must go through the gate like every other egress.

Fakes for the websocket and TLS probes prove: nothing connects off-scope, the
websocket write is gate-refused unless the class is allowed, and no secret VALUE
ever leaves the field summary.
"""

from __future__ import annotations

import asyncio
from datetime import date

from kuv.agent.session import AssessmentSession
from kuv.egress import EgressEngine
from kuv.gate import ActionClass, Scope
from kuv.recon.tls import TlsResult
from kuv.recon.websocket import WsFrame

_NOW = date(2026, 7, 31)


class _FakeResp:
    def __init__(self, status: int, text: str, headers: dict | None = None):
        self.status_code = status
        self.text = text
        self.headers = headers or {}


class _FakeClient:
    def __init__(self, resp: _FakeResp):
        self._resp = resp
        self.calls: list = []

    async def request(self, method, url, *, content=None, headers=None):
        self.calls.append((method, url, content))
        return self._resp

    async def get(self, url):
        self.calls.append(("GET", url, None))
        return self._resp


class _FakeWsProbe:
    def __init__(self, frame: WsFrame):
        self._frame = frame
        self.calls: list = []

    async def __call__(self, url, *, origin, send, recv_timeout, max_messages):
        self.calls.append({"url": url, "origin": origin, "send": send})
        return self._frame


class _FakeTlsProbe:
    def __init__(self, result: TlsResult):
        self._result = result
        self.calls: list = []

    def __call__(self, host, *, port, timeout):
        self.calls.append(host)
        return self._result


def _session(*, is_fixture=True, allowed=(ActionClass.ACCOUNT_CREATE,), resp=None,
             ws=None, tls=None, targets=("app.example.com", "*.example.com")):
    scope = Scope(
        engagement_id="acme", authorized_by="op@example.com", targets=targets,
        expires_at=date(2026, 12, 31), allowed_actions=frozenset(allowed),
        is_fixture=is_fixture, authorization_asserted=True,
    )
    client = _FakeClient(resp or _FakeResp(200, "hello"))
    session = AssessmentSession(
        EgressEngine(scope, now=lambda: _NOW), client, ws_probe=ws, tls_probe=tls
    )
    return session, client


# ---- websocket ----

_WS_FRAME = WsFrame(
    connected=True, handshake_status=101, origin_sent="https://evil.example",
    messages=('{"user":{"hash":"AAAA","googleAccessToken":"BBBB","name":"Al"}}',),
)


def test_probe_websocket_off_scope_refused_and_no_connect():
    ws = _FakeWsProbe(_WS_FRAME)
    session, _ = _session(ws=ws)
    out = asyncio.run(session.probe_websocket("wss://evil.com/ws", read_json='{"sub":1}'))
    assert out["ok"] is False and "REFUSED" in out["error"]
    assert ws.calls == []            # the probe was never invoked off-scope


def test_probe_websocket_handshake_only_when_frames_gated_off():
    # read-only scope (no WEBSOCKET_SAVE): the handshake still runs (passive), but the
    # subscribe frame is withheld — even a "read" frame is gated, so no field data.
    ws = _FakeWsProbe(_WS_FRAME)
    session, _ = _session(is_fixture=False, allowed=(), ws=ws)
    out = asyncio.run(session.probe_websocket(
        "wss://app.example.com/ws", read_json='{"name":"session-subscribe"}', origin="https://evil.example"
    ))
    assert out["ok"] is True and out["connected_no_auth"] is True
    assert out["origin_accepted"] is True
    assert "withheld" in out["frames_result"]
    assert ws.calls[0]["send"] == ()            # NO frame sent in read-only mode


def test_probe_websocket_read_frame_is_gated_as_a_write():
    # A subscribe placed in read_json must NOT bypass the write gate.
    ws = _FakeWsProbe(_WS_FRAME)
    session, _ = _session(is_fixture=False, allowed=(), ws=ws)
    out = asyncio.run(session.probe_websocket(
        "wss://app.example.com/ws", read_json='{"name":"session-save","userId":1}'
    ))
    assert ws.calls[0]["send"] == ()            # the frame was gate-withheld


def test_probe_websocket_frames_summarized_no_values_when_allowed():
    ws = _FakeWsProbe(_WS_FRAME)
    session, _ = _session(is_fixture=True, allowed=(ActionClass.WEBSOCKET_SAVE,), ws=ws)
    out = asyncio.run(session.probe_websocket(
        "wss://app.example.com/ws", read_json='{"name":"session-subscribe"}', origin="https://evil.example"
    ))
    assert "sent (synthetic" in out["frames_result"]
    assert out["connected_no_auth"] is True and out["origin_accepted"] is True
    assert any("googleAccessToken" in f for f in out["sensitive_fields"])
    assert "BBBB" not in str(out) and "AAAA" not in str(out)   # no VALUES leak
    assert ws.calls[0]["send"] == ('{"name":"session-subscribe"}',)


# ---- http posture ----

def test_check_http_posture_reports_gaps_from_headers():
    resp = _FakeResp(200, "", headers={
        "Access-Control-Allow-Origin": "*",
        "Content-Security-Policy": "script-src 'self' 'unsafe-inline'",
    })
    session, _ = _session(resp=resp)
    out = asyncio.run(session.check_http_posture("https://app.example.com/"))
    assert out["ok"] is True and out["cors_wildcard"] is True
    assert any("wildcard CORS" in g for g in out["gaps"])
    assert any("unsafe-inline" in g for g in out["gaps"])


def test_check_http_posture_off_scope_refused():
    session, client = _session()
    out = asyncio.run(session.check_http_posture("https://evil.com/"))
    assert out["ok"] is False and "REFUSED" in out["error"]
    assert client.calls == []


# ---- oauth (no I/O, no gate) ----

def test_analyze_oauth_passthrough_flags_gaps():
    session, _ = _session()
    out = session.analyze_oauth(
        "https://accounts.google.com/o/oauth2/v2/auth?response_type=code&client_id=1"
    )
    assert out["ok"] is True and out["is_oauth"] is True
    assert out["has_state"] is False
    assert any("state" in g for g in out["gaps"])


# ---- tls ----

def test_check_tls_off_scope_refused_and_no_probe():
    tls = _FakeTlsProbe(TlsResult(True, True, True, False, False, 90, "TLSv1.3", "R3", ()))
    session, _ = _session(tls=tls)
    out = session.check_tls("evil.com")
    assert out["ok"] is False and "REFUSED" in out["error"]
    assert tls.calls == []


def test_subdomain_takeover_and_email_spoofing_are_recordable_finding_types():
    # The methodology tells the agent to file these; the enum must accept them.
    session, _ = _session()
    a = session.record_finding("subdomain_takeover", "Dangling CNAME", "conga.example.com", "dangling")
    b = session.record_finding("email_spoofing", "DMARC p=none", "example.com", "unenforced")
    assert a["ok"] is True and a["severity"] == "High"
    assert b["ok"] is True and b["severity"] == "Medium"


def test_check_tls_in_scope_reports_gaps():
    tls = _FakeTlsProbe(TlsResult(
        reachable=True, valid_chain=False, hostname_match=True, expired=True,
        self_signed=False, days_to_expiry=-5, protocol="TLSv1.2", issuer="R3",
        gaps=("certificate is expired",),
    ))
    session, _ = _session(tls=tls)
    out = session.check_tls("app.example.com")
    assert out["ok"] is True and out["expired"] is True
    assert "certificate is expired" in out["gaps"]
    assert tls.calls == ["app.example.com"]
