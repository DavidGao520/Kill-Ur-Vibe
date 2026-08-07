"""The headless browser resolves DNS in its own C++ stack, so no Python-side pin reaches it.

Routing Chromium through a loopback proxy moves the lookup back into our process: the proxy
resolves each CONNECT / absolute-form target ONCE, verifies it public, and dials that IP.
A page can then no longer reach an internal address by rebinding an in-scope subdomain.
"""

from __future__ import annotations

import asyncio

from kuv.egress.proxy import PinningProxy
from kuv.egress.ssrf import PinnedHost


def _res(mapping):
    return lambda h: mapping.get(h, [])


def _rebinding(first, then):
    state = {"n": 0}

    def resolve(host):
        state["n"] += 1
        return first if state["n"] == 1 else then

    return resolve


_SIBLINGS = _res({
    "example.com": ["93.184.216.34"],
    "api.example.com": ["93.184.216.99"],
    "intra.example.com": ["10.0.0.5"],
})


class _NullWriter:
    """Upstream writer stand-in; keeps whatever the proxy forwarded."""

    def __init__(self):
        self.buf = bytearray()

    def write(self, data):
        self.buf.extend(data)

    async def drain(self):
        pass

    def close(self):
        pass

    async def wait_closed(self):
        pass

    def is_closing(self):
        return False


_UPSTREAM_REPLY = b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n"


class _Dialled:
    """Records what the proxy asked to connect to; never opens a real socket. The stand-in
    upstream answers immediately and hangs up, so the proxy's pipes drain and the client
    is not left waiting on a peer that will never speak."""

    def __init__(self):
        self.calls: list[tuple[str, int]] = []
        self.writers: list[_NullWriter] = []

    async def __call__(self, host, port):
        self.calls.append((host, port))
        reader = asyncio.StreamReader()
        reader.feed_data(_UPSTREAM_REPLY)
        reader.feed_eof()
        writer = _NullWriter()
        self.writers.append(writer)
        return reader, writer

    @property
    def forwarded(self) -> bytes:
        return bytes(self.writers[0].buf) if self.writers else b""


async def _exchange(pin, request: bytes):
    """Run one raw proxy request end to end; return (dialled, reply bytes)."""
    dialled = _Dialled()
    proxy = PinningProxy(pin, open_conn=dialled)
    await proxy.start()
    try:
        reader, writer = await asyncio.open_connection(proxy.host, proxy.port)
        writer.write(request)
        await writer.drain()
        reply = await asyncio.wait_for(reader.read(4096), timeout=5)
        writer.close()
    finally:
        await proxy.close()
    return dialled, reply


def test_connect_dials_the_pinned_ip_after_a_rebind():
    pin = PinnedHost("evil.example", resolve=_rebinding(["93.184.216.34"], ["127.0.0.1"]))
    dialled, reply = asyncio.run(_exchange(pin, b"CONNECT evil.example:443 HTTP/1.1\r\n\r\n"))

    assert dialled.calls == [("93.184.216.34", 443)]   # never the rebound 127.0.0.1
    assert reply.startswith(b"HTTP/1.1 200")


def test_connect_to_a_private_sibling_is_refused_and_never_dialled():
    pin = PinnedHost("example.com", resolve=_SIBLINGS)
    dialled, reply = asyncio.run(
        _exchange(pin, b"CONNECT intra.example.com:443 HTTP/1.1\r\n\r\n")
    )

    assert dialled.calls == []                  # refused BEFORE any socket was opened
    assert reply.startswith(b"HTTP/1.1 403")
    assert b"non-public" in reply


def test_connect_to_a_public_sibling_is_allowed_at_its_own_pinned_ip():
    pin = PinnedHost("example.com", resolve=_SIBLINGS)
    dialled, _ = asyncio.run(_exchange(pin, b"CONNECT api.example.com:443 HTTP/1.1\r\n\r\n"))

    assert dialled.calls == [("93.184.216.99", 443)]


def test_plain_http_absolute_form_is_pinned_and_rewritten():
    """Chromium sends `GET http://host/path` in the clear for http:// — same lookup, same gap."""
    pin = PinnedHost("example.com", resolve=_SIBLINGS)
    dialled, _ = asyncio.run(
        _exchange(pin, b"GET http://example.com/a?b=c HTTP/1.1\r\nHost: example.com\r\n\r\n")
    )

    assert dialled.calls == [("93.184.216.34", 80)]
    # The request line must be rewritten to origin-form for the upstream server.
    assert dialled.forwarded.startswith(b"GET /a?b=c HTTP/1.1\r\n")
    assert b"Host: example.com\r\n" in dialled.forwarded


def test_plain_http_to_a_private_host_is_refused():
    pin = PinnedHost("example.com", resolve=_SIBLINGS)
    dialled, reply = asyncio.run(
        _exchange(pin, b"GET http://intra.example.com/ HTTP/1.1\r\nHost: intra.example.com\r\n\r\n")
    )

    assert dialled.calls == []
    assert reply.startswith(b"HTTP/1.1 403")


def test_a_malformed_request_is_rejected_without_dialling():
    pin = PinnedHost("example.com", resolve=_SIBLINGS)
    dialled, reply = asyncio.run(_exchange(pin, b"GARBAGE\r\n\r\n"))

    assert dialled.calls == []
    assert reply.startswith(b"HTTP/1.1 400")


def test_origin_form_request_without_an_absolute_url_is_rejected():
    """Not CONNECT and not absolute-form → no target we can verify. Fail closed."""
    pin = PinnedHost("example.com", resolve=_SIBLINGS)
    dialled, reply = asyncio.run(_exchange(pin, b"GET /relative HTTP/1.1\r\n\r\n"))

    assert dialled.calls == []
    assert reply.startswith(b"HTTP/1.1 400")


class _NeverEofDialled(_Dialled):
    """Upstream that connects and then stays silent — a live tunnel with traffic pending."""

    async def __call__(self, host, port):
        self.calls.append((host, port))
        reader = asyncio.StreamReader()          # no feed_eof: this peer never hangs up
        writer = _NullWriter()
        self.writers.append(writer)
        return reader, writer


def test_close_does_not_hang_while_a_tunnel_is_still_open():
    """Shutting the proxy down must never wedge the run. `Server.wait_closed()` waits for
    every handler, and a tunnel's pipes only end when a peer hangs up — so a browser that
    is still holding a connection would block shutdown forever."""

    async def go():
        pin = PinnedHost("example.com", resolve=_SIBLINGS)
        proxy = PinningProxy(pin, open_conn=_NeverEofDialled())
        await proxy.start()
        reader, writer = await asyncio.open_connection(proxy.host, proxy.port)
        writer.write(b"CONNECT example.com:443 HTTP/1.1\r\n\r\n")
        await writer.drain()
        assert (await asyncio.wait_for(reader.read(64), timeout=5)).startswith(b"HTTP/1.1 200")
        # The client deliberately stays connected, exactly like a browser mid-page.
        await asyncio.wait_for(proxy.close(), timeout=5)
        writer.close()

    asyncio.run(go())


def test_proxy_binds_loopback_only():
    """Reachable by our own Chromium and nothing else on the network."""

    async def go():
        proxy = PinningProxy(PinnedHost("example.com", resolve=_SIBLINGS))
        await proxy.start()
        try:
            return proxy.host, proxy.port, proxy.url
        finally:
            await proxy.close()

    host, port, url = asyncio.run(go())
    assert host == "127.0.0.1"
    assert port > 0
    assert url == f"http://127.0.0.1:{port}"
