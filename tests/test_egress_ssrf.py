"""SSRF guard: a target that is / resolves to a non-public IP must be refused."""

from __future__ import annotations

import asyncio
import ssl

import httpx
import pytest

from kuv.egress.ssrf import (
    SsrfError,
    _PinnedBackend,
    PinnedHost,
    _PinnedHTTPTransport,
    host_ip_safety,
    pinned_async_client,
)


def _res(mapping):
    return lambda h: mapping.get(h, [])


def _rebinding(first, then):
    """A resolver that returns `first` on the first call and `then` on every call after
    (i.e. DNS rebinding: public at resolve/pin time, private at connect time)."""
    state = {"n": 0}

    def resolve(host):
        state["n"] += 1
        return first if state["n"] == 1 else then

    resolve.calls = state
    return resolve


class _RecordingBackend:
    """Fake httpcore inner backend: records the (host, port) it is asked to connect to."""

    def __init__(self):
        self.calls: list[tuple[str, int]] = []

    async def connect_tcp(self, host, port, timeout=None, local_address=None, socket_options=None):
        self.calls.append((host, port))
        return object()  # sentinel "stream"; never exercised further by these tests

    async def connect_unix_socket(self, *a, **k):  # pragma: no cover - not used
        raise NotImplementedError

    async def sleep(self, seconds):  # pragma: no cover - not used
        pass


def test_ip_literal_private_is_blocked():
    ok, why = host_ip_safety("192.168.1.1", _res({}))
    assert ok is False
    assert "non-public" in why.lower() or "private" in why.lower()


def test_loopback_linklocal_cgnat_metadata_ipv6_blocked():
    for h in ("127.0.0.1", "169.254.169.254", "100.64.0.1", "::1", "0.0.0.0"):
        assert host_ip_safety(h, _res({}))[0] is False, h


def test_public_name_resolving_public_ip_is_ok():
    assert host_ip_safety("example.com", _res({"example.com": ["93.184.216.34"]}))[0] is True


def test_name_resolving_private_is_blocked():
    # a hostname that resolves to a private IP (internal DNS / SSRF) is refused
    assert host_ip_safety("evil.internal", _res({"evil.internal": ["10.0.0.5"]}))[0] is False


def test_mixed_public_and_private_is_blocked():
    # if ANY resolved address is non-public, refuse (rebinding / dual-record trickery)
    assert host_ip_safety("mix.example", _res({"mix.example": ["93.184.216.34", "127.0.0.1"]}))[0] is False


def test_unresolvable_is_blocked():
    assert host_ip_safety("nope.invalid", _res({}))[0] is False


# --- connect-time IP pinning (anti-DNS-rebinding) ----------------------------------------


def test_pinned_client_refuses_private_host():
    # A host that resolves private must never yield a client (fail closed, not silently plain).
    with pytest.raises(SsrfError):
        pinned_async_client("evil.internal", resolve=_res({"evil.internal": ["10.0.0.5"]}))


def test_pinned_client_refuses_unresolvable_host():
    with pytest.raises(SsrfError):
        pinned_async_client("nope.invalid", resolve=_res({}))


def test_pinned_client_is_asyncclient_without_redirect_following():
    client = pinned_async_client("example.com", resolve=_res({"example.com": ["93.184.216.34"]}))
    try:
        assert isinstance(client, httpx.AsyncClient)
        assert client.follow_redirects is False  # redirects are re-judged by the engine, not auto-followed
    finally:
        asyncio.run(client.aclose())


def test_pinned_client_keeps_tls_verification_on():
    # Pinning must NOT disable cert verification — SNI/cert stay the hostname (httpcore uses
    # origin.host for server_hostname; we only swap the TCP destination).
    client = pinned_async_client("example.com", resolve=_res({"example.com": ["93.184.216.34"]}))
    try:
        transport = client._transport_for_url(httpx.URL("https://example.com/"))
        ctx = transport._pool._ssl_context
        assert ctx.check_hostname is True
        assert ctx.verify_mode == ssl.CERT_REQUIRED
    finally:
        asyncio.run(client.aclose())


def test_pin_resolves_once_and_holds_public_ip_across_rebind():
    resolve = _rebinding(["93.184.216.34"], ["127.0.0.1"])  # public at pin time, rebinds to loopback
    pin = PinnedHost("example.com", resolve=resolve)
    assert pin.ip == "93.184.216.34"
    # a later connection for the pinned host still targets the pinned public IP...
    assert pin.target_ip("example.com") == "93.184.216.34"
    assert pin.target_ip("EXAMPLE.com") == "93.184.216.34"  # host match is case-insensitive
    # ...and the host was resolved exactly once — never re-resolved, so a rebind can't land.
    assert resolve.calls["n"] == 1


def test_backend_connects_to_pinned_ip_not_hostname_after_rebind():
    resolve = _rebinding(["93.184.216.34"], ["127.0.0.1"])
    pin = PinnedHost("example.com", resolve=resolve)
    inner = _RecordingBackend()
    backend = _PinnedBackend(pin, inner)
    asyncio.run(backend.connect_tcp("example.com", 443))
    # connected to the pinned IP — NOT the hostname, NOT the rebound 127.0.0.1.
    assert inner.calls == [("93.184.216.34", 443)]


def test_backend_refuses_nonpinned_host_that_resolves_private():
    # A different host reached at connect time (e.g. a sibling) is re-verified, and refused
    # if it is non-public — no connection is attempted.
    pin = PinnedHost(
        "example.com",
        resolve=_res({"example.com": ["93.184.216.34"], "sibling.internal": ["10.0.0.9"]}),
    )
    inner = _RecordingBackend()
    backend = _PinnedBackend(pin, inner)
    with pytest.raises(SsrfError):
        asyncio.run(backend.connect_tcp("sibling.internal", 443))
    assert inner.calls == []


def test_pinned_client_request_path_reaches_pinned_ip():
    # End-to-end through httpx's real request machinery: a GET for the hostname must reach the
    # pinned IP at the TCP layer — proving the network-backend swap is actually wired in, not
    # merely correct when the backend is called directly.
    client = pinned_async_client("example.com", resolve=_res({"example.com": ["93.184.216.34"]}))
    transport = client._transport_for_url(httpx.URL("http://example.com/"))
    inner = transport._pool._network_backend._inner
    seen: dict[str, object] = {}

    async def _capture(host, port, timeout=None, local_address=None, socket_options=None):
        seen["host"], seen["port"] = host, port
        raise RuntimeError("stop before real socket")

    inner.connect_tcp = _capture  # intercept the innermost (real) connect

    async def _go():
        with pytest.raises(Exception):
            await client.get("http://example.com/")
        await client.aclose()

    asyncio.run(_go())
    assert seen == {"host": "93.184.216.34", "port": 80}  # httpx used the pinned IP + scheme port
