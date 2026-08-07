"""A loopback HTTP proxy that pins every destination — the browser's anti-rebinding fix.

Every other probe opens its socket in Python, so injecting a pinned connector is enough.
The headless browser cannot be fixed that way: Chromium resolves DNS in its own C++ stack,
which no Python pin reaches, and `--host-resolver-rules` can only map hostnames known at
launch. An in-scope host discovered mid-render (a subdomain the page fetches) would still
be resolved by Chromium, and an attacker who controls DNS for the target's registrable
domain controls those answers.

Pointing Chromium at this proxy moves the lookup back into our process. The proxy accepts
CONNECT (https) and absolute-form plain HTTP, resolves the target ONCE via `PinnedHost`
(the scan host keeps its pin; any other host is resolved and verified public here), and
dials the resulting IP. A destination that is, or resolves to, a non-public address is
refused with 403 before any socket is opened.

TLS is untouched: for CONNECT we tunnel bytes, so the browser still performs its own
handshake and certificate verification against the hostname end-to-end. The proxy sees
ciphertext, never plaintext.

No proxy authentication: it binds 127.0.0.1 on an ephemeral port, and it can only ever
reach verified-public addresses. It therefore grants a local process nothing it does not
already have, while the internal reach that would matter is exactly what it refuses.

Scope is NOT enforced here — that stays in the browser's request gate, which aborts
off-scope requests before they are made. The consequence is that a speculative socket the
gate never sees (an explicit `<link rel=preconnect>`) still reaches an off-scope PUBLIC
host through this proxy; it simply can no longer reach an internal one. Closing that last
residual means giving the proxy the scope check too.

Keep-alive: after the first request on a plain-HTTP connection the remaining bytes are
piped to the SAME already-pinned upstream, so a follow-up request naming a different host
cannot change the destination — it reaches the pinned IP or nothing.
"""

from __future__ import annotations

import asyncio
from typing import Awaitable, Callable
from urllib.parse import urlsplit

from .ssrf import PinnedHost, SsrfError

# (host, port) -> (reader, writer). Injected so tests never open a real socket.
OpenConn = Callable[[str, int], Awaitable[tuple[asyncio.StreamReader, asyncio.StreamWriter]]]

_MAX_HEADER_BYTES = 64 * 1024        # a request head larger than this is not a browser
_DEFAULT_PORT = {"http": 80, "https": 443}


class PinningProxy:
    """A loopback proxy whose every destination is a verified-public, already-resolved IP."""

    host = "127.0.0.1"

    def __init__(self, pin: PinnedHost, *, open_conn: OpenConn | None = None) -> None:
        self._pin = pin
        self._open_conn = open_conn or asyncio.open_connection
        self._server: asyncio.AbstractServer | None = None
        self._handlers: set[asyncio.Task] = set()
        self.port = 0

    @property
    def url(self) -> str:
        return f"http://{self.host}:{self.port}"

    async def start(self) -> None:
        self._server = await asyncio.start_server(self._handle, self.host, 0)
        self.port = self._server.sockets[0].getsockname()[1]

    async def close(self) -> None:
        """Shut down without waiting on live tunnels.

        A tunnel's pipes only finish when one of its peers hangs up, and `wait_closed()`
        waits for every handler — so a browser still holding a connection would block
        shutdown forever (it did: it wedged a real Chromium run). Cancel the handlers
        first, and treat a slow `wait_closed` as done rather than wedging the scan.
        """
        if self._server is None:
            return
        self._server.close()
        for task in list(self._handlers):
            task.cancel()
        if self._handlers:
            await asyncio.gather(*self._handlers, return_exceptions=True)
        try:
            await asyncio.wait_for(self._server.wait_closed(), timeout=5)
        except (asyncio.TimeoutError, asyncio.CancelledError):
            pass
        self._server = None

    # --- request handling -----------------------------------------------------------------

    async def _handle(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        task = asyncio.current_task()
        if task is not None:
            self._handlers.add(task)
        try:
            head = await self._read_head(reader)
            if head is None:
                return await self._refuse(writer, 400, "malformed proxy request")

            request_line, headers_blob = head
            parts = request_line.split(" ")
            if len(parts) != 3:
                return await self._refuse(writer, 400, "malformed request line")
            method, target, version = parts

            if method.upper() == "CONNECT":
                host, port = _split_authority(target, default_port=443)
                if not host:
                    return await self._refuse(writer, 400, "malformed CONNECT target")
                return await self._tunnel(reader, writer, host, port)

            split = urlsplit(target)
            if not split.scheme or not split.hostname:
                # Origin-form ("GET /path") has no verifiable destination — a proxy should
                # never receive one, and guessing from the Host header would defeat the pin.
                return await self._refuse(writer, 400, "proxy requires an absolute-form URL")
            port = split.port or _DEFAULT_PORT.get(split.scheme, 0)
            if not port:
                return await self._refuse(writer, 400, f"unsupported scheme {split.scheme!r}")

            origin_form = split.path or "/"
            if split.query:
                origin_form += "?" + split.query
            forward = f"{method} {origin_form} {version}\r\n".encode() + headers_blob
            return await self._forward(reader, writer, split.hostname, port, forward)
        except (ConnectionError, asyncio.IncompleteReadError):
            pass                                   # client hung up mid-request
        except asyncio.CancelledError:
            pass                                   # proxy shutting down; drop the tunnel
        finally:
            if task is not None:
                self._handlers.discard(task)
            await _close(writer)

    async def _read_head(self, reader: asyncio.StreamReader) -> tuple[str, bytes] | None:
        """Read up to the end of the request head. Returns (request_line, remaining headers)."""
        try:
            blob = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=30)
        except (asyncio.LimitOverrunError, asyncio.IncompleteReadError, asyncio.TimeoutError):
            return None
        if len(blob) > _MAX_HEADER_BYTES:
            return None
        line, _, rest = blob.partition(b"\r\n")
        try:
            return line.decode("latin-1"), rest
        except UnicodeDecodeError:                 # pragma: no cover — latin-1 never raises
            return None

    async def _dial(self, host: str, port: int):
        """Resolve+verify ONCE via the pin, then connect to that IP. Raises SsrfError."""
        ip = self._pin.target_ip(host)             # the whole point: no second lookup
        return await self._open_conn(ip, port)

    async def _tunnel(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        host: str,
        port: int,
    ) -> None:
        try:
            up_reader, up_writer = await self._dial(host, port)
        except SsrfError as exc:
            return await self._refuse(writer, 403, str(exc))
        except OSError as exc:
            return await self._refuse(writer, 502, f"upstream connect failed: {exc}")

        writer.write(b"HTTP/1.1 200 Connection established\r\n\r\n")
        await writer.drain()
        await _pipe_both(reader, writer, up_reader, up_writer)

    async def _forward(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        host: str,
        port: int,
        head: bytes,
    ) -> None:
        try:
            up_reader, up_writer = await self._dial(host, port)
        except SsrfError as exc:
            return await self._refuse(writer, 403, str(exc))
        except OSError as exc:
            return await self._refuse(writer, 502, f"upstream connect failed: {exc}")

        up_writer.write(head)
        await up_writer.drain()
        await _pipe_both(reader, writer, up_reader, up_writer)

    async def _refuse(self, writer: asyncio.StreamWriter, status: int, reason: str) -> None:
        body = reason.encode("utf-8", "replace")[:500]
        text = {400: "Bad Request", 403: "Forbidden", 502: "Bad Gateway"}.get(status, "Error")
        writer.write(
            f"HTTP/1.1 {status} {text}\r\n"
            f"Content-Length: {len(body)}\r\n"
            f"Content-Type: text/plain\r\n"
            f"Connection: close\r\n\r\n".encode()
            + body
        )
        try:
            await writer.drain()
        except ConnectionError:                    # pragma: no cover — client already gone
            pass


def _split_authority(target: str, *, default_port: int) -> tuple[str, int]:
    """`host:port` from a CONNECT target, IPv6 literals included."""
    target = target.strip()
    if target.startswith("["):                     # [::1]:443
        close = target.find("]")
        if close == -1:
            return "", 0
        host = target[1:close]
        rest = target[close + 1:]
        port = rest[1:] if rest.startswith(":") else ""
    elif ":" in target:
        host, _, port = target.rpartition(":")
    else:
        host, port = target, ""
    if not host:
        return "", 0
    try:
        return host, int(port) if port else default_port
    except ValueError:
        return "", 0


async def _pipe_both(
    client_reader: asyncio.StreamReader,
    client_writer: asyncio.StreamWriter,
    up_reader: asyncio.StreamReader,
    up_writer: asyncio.StreamWriter,
) -> None:
    await asyncio.gather(
        _pipe(client_reader, up_writer),
        _pipe(up_reader, client_writer),
        return_exceptions=True,
    )
    await _close(up_writer)


async def _pipe(reader: asyncio.StreamReader, writer) -> None:
    try:
        while True:
            chunk = await reader.read(65536)
            if not chunk:
                break
            writer.write(chunk)
            await writer.drain()
    except (ConnectionError, asyncio.IncompleteReadError, OSError):
        pass


async def _close(writer) -> None:
    try:
        if not writer.is_closing():
            writer.close()
        await writer.wait_closed()
    except (ConnectionError, OSError):
        pass
