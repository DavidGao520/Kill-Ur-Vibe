"""SSRF guard — refuse targets that are, or resolve to, non-public IPs.

The egress engine's scope check is a hostname string match; when the scope is built
from user input (e.g. a hosted web front-end), that authorizes whatever the user types,
including `127.0.0.1`, `192.168.x`, `169.254.169.254`, Tailscale `100.64/10`, `localhost`.
This module resolves the target and blocks any non-public address so a live (non-fixture)
scan cannot be steered at internal/loopback/metadata hosts. Connection-time IP pinning
(`pinned_async_client`) closes the DNS-rebinding gap between resolve and connect.
"""

from __future__ import annotations

import ipaddress
import socket
from typing import Callable

import httpcore
import httpx

# CGNAT / Tailscale space (100.64.0.0/10) is not flagged by ipaddress.is_private.
_CGNAT = ipaddress.ip_network("100.64.0.0/10")


class SsrfError(ValueError):
    """A host is, or resolves to, a non-public IP — refuse to pin/connect (fail closed)."""


def _normalize(host: str) -> str:
    return (host or "").strip().strip("[]").lower()


def _default_resolve(host: str) -> list[str]:
    try:
        return list({info[4][0] for info in socket.getaddrinfo(host, None)})
    except OSError:
        return []


def _is_non_public(addr: ipaddress._BaseAddress) -> bool:
    return bool(
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_reserved
        or addr.is_multicast
        or addr.is_unspecified
        or addr in _CGNAT
    )


def host_ip_safety(
    host: str, resolve: Callable[[str], list[str]] = _default_resolve
) -> tuple[bool, str]:
    """Return (ok, reason). ok=False if `host` is, or resolves to, a private / reserved /
    loopback / link-local / CGNAT / multicast / unspecified address. If ANY resolved
    address is non-public, refuse (defends against dual-record / rebinding trickery)."""
    host = _normalize(host)
    if not host:
        return False, "empty host"
    try:
        ipaddress.ip_address(host)
        ips: list[str] = [host]          # host is itself an IP literal
    except ValueError:
        ips = resolve(host)
    if not ips:
        return False, f"{host} did not resolve"
    for ip in ips:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False, f"{host} resolved to a non-IP {ip!r}"
        if _is_non_public(addr):
            return False, f"{host} resolves to a non-public address ({ip})"
    return True, ""


# --- connect-time IP pinning (anti-DNS-rebinding) ----------------------------------------
#
# `host_ip_safety` runs at EVALUATE time; a host can resolve public then rebind to a private
# IP by CONNECT time. Pinning closes that window: resolve the scan host ONCE, verify it is
# public, and force every TCP connection for that host to the pinned IP for the whole scan.
# We intercept only the TCP destination (httpcore's network-backend `connect_tcp`); the URL
# host is untouched, so httpcore still uses it for TLS SNI + certificate verification — we
# connect to an IP while validating the cert against the original hostname, never disabling
# verification.


def _pin_ip(host: str, resolve: Callable[[str], list[str]]) -> str:
    """Resolve `host` ONCE, require it (and every address it resolves to) to be public via
    `host_ip_safety`, and return one public IP to pin/connect to. Raise `SsrfError` otherwise."""
    h = _normalize(host)
    try:
        ipaddress.ip_address(h)
        resolved = [h]                       # an IP literal "resolves" to itself
    except ValueError:
        resolved = list(resolve(h))
    ok, why = host_ip_safety(h, lambda _h: resolved)   # validate without a second lookup
    if not ok:
        raise SsrfError(why)
    return resolved[0]                        # every address is public here → any is safe


class _PinnedHost:
    """The scan host resolved once to a verified-public IP. `target_ip` returns that pinned
    IP for the pinned host (a rebind cannot land — we never re-resolve it); any other host
    reached at connect time is re-verified public and refused otherwise."""

    def __init__(self, host: str, resolve: Callable[[str], list[str]] = _default_resolve):
        self.host = _normalize(host)
        self._resolve = resolve
        self.ip = _pin_ip(self.host, resolve)   # raises SsrfError on non-public / unresolvable

    def target_ip(self, host: str) -> str:
        if _normalize(host) == self.host:
            return self.ip                       # pinned — do NOT re-resolve
        return _pin_ip(host, self._resolve)      # sibling/other host: verify + pin at connect


class _PinnedBackend(httpcore.AsyncNetworkBackend):
    """httpcore network backend that rewrites the TCP destination to the pinned IP, then
    delegates to the real backend. Only the connect target changes — TLS SNI/cert stay the
    hostname (httpcore derives `server_hostname` from the untouched URL host)."""

    def __init__(self, pin: _PinnedHost, inner: httpcore.AsyncNetworkBackend):
        self._pin = pin
        self._inner = inner

    async def connect_tcp(self, host, port, timeout=None, local_address=None, socket_options=None):
        ip = self._pin.target_ip(host)          # raises SsrfError if the host is non-public
        return await self._inner.connect_tcp(
            ip, port, timeout=timeout, local_address=local_address, socket_options=socket_options
        )

    async def connect_unix_socket(self, *args, **kwargs):
        return await self._inner.connect_unix_socket(*args, **kwargs)

    async def sleep(self, seconds):
        await self._inner.sleep(seconds)


class _PinnedHTTPTransport(httpx.AsyncHTTPTransport):
    """An `AsyncHTTPTransport` whose connection pool connects only to the pinned IP."""

    def __init__(self, pin: _PinnedHost, **kwargs):
        super().__init__(**kwargs)
        self._pool._network_backend = _PinnedBackend(pin, self._pool._network_backend)


def pinned_async_client(
    host: str,
    *,
    resolve: Callable[[str], list[str]] = _default_resolve,
    timeout: float = 15.0,
    follow_redirects: bool = False,
    **client_kwargs,
) -> httpx.AsyncClient:
    """An `httpx.AsyncClient` pinned to `host` for the whole scan: `host` is resolved once and
    verified public (raising `SsrfError` if not), and every connection to it is forced to that
    pinned IP — closing the DNS-rebinding window while keeping TLS SNI/cert = the hostname."""
    pin = _PinnedHost(host, resolve=resolve)
    transport = _PinnedHTTPTransport(pin)
    return httpx.AsyncClient(
        transport=transport, timeout=timeout, follow_redirects=follow_redirects, **client_kwargs
    )
