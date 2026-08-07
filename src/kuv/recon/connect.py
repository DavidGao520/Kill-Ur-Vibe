"""How a probe opens a TCP connection — the one seam where DNS rebinding is closed.

`socket.create_connection((host, port))` resolves the hostname *itself*, inside the stdlib.
That is a SECOND lookup, independent of whatever the SSRF guard checked earlier, so a host
that answered with a public IP at gate time can answer `127.0.0.1` / `169.254.169.254` by
the time the probe actually connects. Every probe that opens its own socket therefore takes
a `Connect` callable instead of calling the stdlib directly, and a live scan injects one
that dials an already-verified, pinned IP (`kuv.egress.ssrf.connect_pinned`).

`recon` stays dependency-free by design (it is the SDK-free, fake-testable core), so the
pinning itself lives in `kuv.egress.ssrf` and arrives here only as an injected callable.
A connector reports refusal or failure by raising `OSError`; probes return that as data.
"""

from __future__ import annotations

from typing import Any, Callable

# (host, port, timeout) -> a connected socket.
Connect = Callable[[str, int, float], Any]


def default_connect(host: str, port: int, timeout: float) -> Any:
    """Plain, UNPINNED connect — resolves `host` via the stdlib. The default for standalone
    call sites (the CLI, fixtures, tests); a live scan overrides it with a pinned connector."""
    import socket

    return socket.create_connection((host, port), timeout=timeout)
