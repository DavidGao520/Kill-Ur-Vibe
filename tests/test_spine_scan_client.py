"""`build_scan_client`: live (non-fixture) scans get the connect-time-pinned client;
fixtures keep the plain client (loopback fixtures are exempt from the SSRF pin)."""

from __future__ import annotations

import asyncio
from datetime import date

import httpx

from kuv.agent.spine import build_scan_client
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
