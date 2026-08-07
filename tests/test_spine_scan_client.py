"""`build_scan_client` / `build_scan_transport`: live (non-fixture) scans get the
connect-time-pinned client AND pinned socket probes; fixtures keep the plain ones
(loopback fixtures are exempt from the SSRF pin)."""

from __future__ import annotations

import asyncio
from datetime import date

import httpx
import pytest

from kuv.agent.spine import build_scan_client, build_scan_transport
from kuv.egress.ssrf import _PinnedHTTPTransport
from kuv.gate import Scope


def _res(mapping):
    return lambda h: mapping.get(h, [])


def _scope(is_fixture, host):
    return Scope(
        engagement_id="t",
        authorized_by="t",
        targets=(host,),
        expires_at=date(2027, 1, 1),
        allowed_actions=frozenset(),
        is_fixture=is_fixture,
        authorization_asserted=True,
    )


def test_fixture_scope_uses_plain_client():
    client = build_scan_client(_scope(True, "127.0.0.1"), "http://127.0.0.1:8779/")
    try:
        transport = client._transport_for_url(httpx.URL("http://127.0.0.1:8779/"))
        assert not isinstance(transport, _PinnedHTTPTransport)
        assert client.follow_redirects is False
    finally:
        asyncio.run(client.aclose())


def test_live_scope_uses_pinned_client():
    client = build_scan_client(
        _scope(False, "example.com"),
        "https://example.com/",
        resolve=_res({"example.com": ["93.184.216.34"]}),
    )
    try:
        transport = client._transport_for_url(httpx.URL("https://example.com/"))
        assert isinstance(transport, _PinnedHTTPTransport)
        assert client.follow_redirects is False
    finally:
        asyncio.run(client.aclose())


# --- the socket probes (TLS / websocket) share the SAME pin as the HTTP client ------------

_SIBLINGS = _res({
    "example.com": ["93.184.216.34"],
    "intra.example.com": ["10.0.0.5"],       # an in-scope subdomain pointed at a private IP
})


def _transport(is_fixture=False, target="https://example.com/"):
    return build_scan_transport(_scope(is_fixture, "example.com"), target, resolve=_SIBLINGS)


def test_live_connector_translates_an_ssrf_refusal_into_oserror():
    """Probes report an OSError as data; an SsrfError (a ValueError) would sail past their
    `except OSError` and abort the whole assessment over one blocked host."""
    t = _transport()
    try:
        with pytest.raises(OSError) as exc:
            t.connect("intra.example.com", 443, 1.0)
        assert "non-public" in str(exc.value)
    finally:
        asyncio.run(t.client.aclose())


def test_live_connector_dials_the_pinned_ip_not_the_hostname(monkeypatch):
    t = _transport()
    dialed = []

    def capture(address, timeout=None):
        dialed.append(address)
        return "SOCK"

    monkeypatch.setattr("socket.create_connection", capture)
    try:
        assert t.connect("example.com", 443, 1.0) == "SOCK"
        assert dialed == [("93.184.216.34", 443)]   # an IP, never the hostname
    finally:
        asyncio.run(t.client.aclose())


def test_live_tls_probe_refuses_a_private_sibling_without_touching_the_network():
    t = _transport()
    try:
        result = t.tls_probe("intra.example.com", port=443, timeout=1.0)
        assert result.reachable is False
    finally:
        asyncio.run(t.client.aclose())


def test_live_ws_probe_refuses_a_private_sibling_without_touching_the_network():
    t = _transport()
    try:
        frame = asyncio.run(
            t.ws_probe(
                "wss://intra.example.com/socket", origin=None, send=(),
                recv_timeout=1.0, max_messages=1,
            )
        )
        assert frame.connected is False
        assert "non-public" in (frame.error or "")
    finally:
        asyncio.run(t.client.aclose())


# --- the browser goes through the loopback pinning proxy ---------------------------------


def test_live_transport_carries_a_pinning_proxy_and_a_fixture_does_not():
    live = _transport()
    fixture = build_scan_transport(_scope(True, "127.0.0.1"), "http://127.0.0.1:8779/")
    try:
        assert live.proxy is not None
        assert fixture.proxy is None
    finally:
        asyncio.run(live.client.aclose())
        asyncio.run(fixture.client.aclose())


def test_entering_the_transport_starts_the_proxy_and_leaving_stops_it():
    """The browser probe's proxy URL is only real while the transport is open."""
    async def go():
        t = _transport()
        async with t:
            assert t.proxy.port > 0
            assert t.browser_probe is not None
            # Reachable while open ...
            _, w = await asyncio.open_connection(t.proxy.host, t.proxy.port)
            w.close()
            port = t.proxy.port
        with pytest.raises(OSError):                # ... and gone afterwards
            await asyncio.open_connection("127.0.0.1", port)

    asyncio.run(go())


def test_fixture_transport_has_no_browser_probe_override():
    """A fixture renders loopback, which the pin would refuse — it keeps the plain probe."""
    async def go():
        async with build_scan_transport(_scope(True, "127.0.0.1"), "http://127.0.0.1:8779/") as t:
            assert t.browser_probe is None

    asyncio.run(go())


def test_run_assessment_hands_the_session_the_pinned_probes(monkeypatch):
    """The pin is worthless if the run builds it and then gives the session the DEFAULT
    probes anyway — an unwired pin is exactly the shape the original bug had."""
    import kuv.agent.spine as spine
    from claude_agent_sdk import ResultMessage

    async def fake_query(*, prompt, options):
        yield ResultMessage(
            subtype="success", duration_ms=1, duration_api_ms=1, is_error=False, num_turns=1,
            session_id="s", stop_reason="end_turn", total_cost_usd=0.0, usage=None, result="ok",
            structured_output=None, model_usage=None, permission_denials=[],
            deferred_tool_use=None, errors=[], api_error_status=None, uuid="u",
            terminal_reason=None)

    captured: dict = {}
    real_session = spine.AssessmentSession

    class Recording(real_session):
        def __init__(self, engine, client, **kw):
            captured.update(kw)
            super().__init__(engine, client, **kw)

    tls_sentinel, ws_sentinel, browser_sentinel = object(), object(), object()

    class _Stub(spine.ScanTransport):
        @property
        def browser_probe(self):
            return browser_sentinel

    monkeypatch.setattr(spine, "AssessmentSession", Recording)
    monkeypatch.setattr(spine, "query", fake_query)
    monkeypatch.setattr(
        spine, "build_scan_transport",
        lambda scope, target, **kw: _Stub(
            client=httpx.AsyncClient(), connect=lambda *a: None,
            tls_probe=tls_sentinel, ws_probe=ws_sentinel,
        ),
    )

    asyncio.run(spine.run_assessment(_scope(True, "127.0.0.1"), "http://127.0.0.1/",
                                     now=date.today))

    assert captured["tls_probe"] is tls_sentinel
    assert captured["ws_probe"] is ws_sentinel
    assert captured["browser_probe"] is browser_sentinel


def test_fixture_scope_gets_no_pinned_connector():
    """Loopback fixtures must keep working — pinning 127.0.0.1 would refuse them outright."""
    t = build_scan_transport(_scope(True, "127.0.0.1"), "http://127.0.0.1:8779/")
    try:
        assert t.connect is None
        assert t.tls_probe is None
        assert t.ws_probe is None
    finally:
        asyncio.run(t.client.aclose())
