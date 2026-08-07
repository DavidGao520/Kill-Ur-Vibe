"""The TLS and websocket probes must dial the PINNED IP, never a fresh DNS lookup.

`pinned_async_client` closed the rebinding window for HTTP only. `ssl_tls_probe` and
`websockets_probe` each opened their own socket with `socket.create_connection((host, port))`
— which re-resolves the hostname inside the stdlib, so a host that resolved public at gate
time could rebind to 127.0.0.1 / 169.254.169.254 by the time the probe connected.
"""

from __future__ import annotations

import asyncio
import socket as socket_mod

import pytest

from kuv.egress.ssrf import PinnedHost, SsrfError, connect_pinned
from kuv.recon import tls as tls_mod
from kuv.recon.tls import ssl_tls_probe
from kuv.recon.websocket import websockets_probe


def _res(mapping):
    return lambda h: mapping.get(h, [])


def _rebinding(first, then):
    """Public on the first lookup, private on every one after — i.e. DNS rebinding."""
    state = {"n": 0}

    def resolve(host):
        state["n"] += 1
        return first if state["n"] == 1 else then

    resolve.calls = state
    return resolve


# --- the shared pinned connector ---------------------------------------------------------


def test_connect_pinned_dials_the_pinned_ip_after_a_rebind():
    resolve = _rebinding(["93.184.216.34"], ["127.0.0.1"])
    pin = PinnedHost("evil.example", resolve=resolve)
    dialed: list[tuple[str, int]] = []

    def fake_connect(address, timeout):
        dialed.append(address)
        return "SOCK"

    sock = connect_pinned(pin, "evil.example", 443, 5.0, connect=fake_connect)

    assert sock == "SOCK"
    assert dialed == [("93.184.216.34", 443)]  # the pinned IP, never the rebound 127.0.0.1


def test_connect_pinned_refuses_a_sibling_host_that_resolves_private():
    pin = PinnedHost(
        "example.com",
        resolve=_res({"example.com": ["93.184.216.34"], "intra.example.com": ["10.0.0.5"]}),
    )
    with pytest.raises(SsrfError):
        connect_pinned(pin, "intra.example.com", 443, 5.0, connect=lambda *a, **k: "SOCK")


def test_connect_pinned_allows_a_public_sibling_host():
    pin = PinnedHost(
        "example.com",
        resolve=_res({"example.com": ["93.184.216.34"], "api.example.com": ["93.184.216.99"]}),
    )
    dialed: list[tuple[str, int]] = []
    connect_pinned(
        pin, "api.example.com", 8443, 5.0,
        connect=lambda addr, timeout: dialed.append(addr) or "SOCK",
    )
    assert dialed == [("93.184.216.99", 8443)]


# --- TLS probe ---------------------------------------------------------------------------


def test_tls_probe_verifying_handshake_uses_the_injected_connector(monkeypatch):
    """A direct socket.create_connection would re-resolve and reopen the rebinding gap."""
    monkeypatch.setattr(
        socket_mod, "create_connection",
        lambda *a, **k: pytest.fail("ssl_tls_probe resolved DNS itself"),
    )
    calls: list[tuple[str, int]] = []

    def fake_connect(host, port, timeout):
        calls.append((host, port))
        raise OSError("connection refused")

    result = ssl_tls_probe("example.com", port=443, timeout=1.0, connect=fake_connect)

    assert calls == [("example.com", 443)]
    assert result.reachable is False


def test_tls_probe_protocol_only_path_uses_the_injected_connector(monkeypatch):
    """With no CA trust store the probe takes the `_negotiated_protocol` branch — a SECOND
    create_connection call site, which must be pinned too."""
    import ssl

    monkeypatch.setattr(tls_mod, "_verifying_context", lambda: (ssl.create_default_context(), False))
    monkeypatch.setattr(
        socket_mod, "create_connection",
        lambda *a, **k: pytest.fail("_negotiated_protocol resolved DNS itself"),
    )
    calls: list[tuple[str, int]] = []

    def fake_connect(host, port, timeout):
        calls.append((host, port))
        raise OSError("connection refused")

    result = ssl_tls_probe("example.com", port=443, timeout=1.0, connect=fake_connect)

    assert calls == [("example.com", 443)]
    assert result.reachable is False


def test_tls_probe_without_a_connector_still_works():
    """Default arg keeps the standalone/CLI call sites (assess.py, tests) unchanged."""
    result = ssl_tls_probe("no-such-host.invalid", port=443, timeout=1.0)
    assert result.reachable is False


# --- websocket probe ---------------------------------------------------------------------


def test_ws_probe_uses_the_injected_connector(monkeypatch):
    monkeypatch.setattr(
        socket_mod, "create_connection",
        lambda *a, **k: pytest.fail("websockets_probe resolved DNS itself"),
    )
    calls: list[tuple[str, int]] = []

    def fake_connect(host, port, timeout):
        calls.append((host, port))
        raise OSError("connection refused")

    frame = asyncio.run(
        websockets_probe(
            "wss://example.com/socket", origin=None, send=(), recv_timeout=1.0,
            max_messages=1, connect=fake_connect,
        )
    )

    assert calls == [("example.com", 443)]
    assert frame.connected is False
    assert "connect failed" in (frame.error or "")


def test_ws_probe_reports_a_refusal_as_data_not_an_exception():
    """A pin refusal reaches the probe as OSError (spine translates SsrfError, see
    test_spine_scan_client) and must come back as a WsFrame, never raised into the agent
    loop — a raised error would abort the whole assessment over one blocked host."""
    def refusing_connect(host, port, timeout):
        raise OSError("SSRF pin refused evil.example: resolves to a non-public address")

    frame = asyncio.run(
        websockets_probe(
            "wss://evil.example/socket", origin=None, send=(), recv_timeout=1.0,
            max_messages=1, connect=refusing_connect,
        )
    )

    assert frame.connected is False
    assert "non-public" in (frame.error or "")
