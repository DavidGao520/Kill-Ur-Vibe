"""WebSocket unauth read-probe — connect with no creds, summarize returned fields.

This closes the single biggest gap vs the reference report: C-01 (an unauthenticated
websocket that reads/writes business data) and C-03 (sensitive credential fields
leaked through the websocket serialization). Two safety properties are load-bearing:

  1. The field summary is presence/count/length ONLY — never a value (guardrail #4).
     Dict KEYS are untrusted too: a frame keyed by a secret/PII value (e.g. a map of
     reset-token -> record) must not leak that key, so key segments are sanitized.
  2. The connection is PINNED to the already-gated host by opening the socket
     ourselves and handing it to the library, which then REFUSES any cross-origin
     handshake redirect — so the egress engine's scope decision cannot be bypassed by
     an in-scope host redirecting the probe off-scope.

The connect is an injected async probe so the core stays testable with a fake;
production uses the `websockets` lib.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any, Protocol

from .connect import Connect, default_connect


@dataclass(frozen=True)
class WsFrame:
    connected: bool                 # handshake completed with no cookie/token
    handshake_status: int           # 101 = accepted; else the rejecting HTTP status, or 0
    origin_sent: str | None         # the Origin we offered (to test cross-origin acceptance)
    messages: tuple[str, ...]       # raw text frames received (bounded)
    error: str | None = None


class WsProbe(Protocol):
    async def __call__(
        self,
        url: str,
        *,
        origin: str | None,
        send: tuple[str, ...],
        recv_timeout: float,
        max_messages: int,
    ) -> WsFrame: ...


# Distinguishing a schema field name (keep) from a secret/PII value used AS a dict key
# (redact) cannot be a character-class allowlist: a 32-char MD5 token or a 28-char session
# id is "identifier-shaped" too. So we keep only keys that look like real field names and
# redact anything that looks value-bearing by structure — prefix, hex run, digit density,
# or a long mixed-case+digit string. Bias is toward redaction: never leak a value.
_IDENT = re.compile(r"[A-Za-z0-9_]{1,40}\Z")
_HEX_RUN = re.compile(r"[0-9a-fA-F]{16,}")
# Well-known secret/token prefixes (case-insensitive) that only appear on VALUES.
_TOKEN_PREFIXES = ("sk_", "rk_", "ghp_", "gho_", "ghs_", "xox", "akia", "asia", "eyj", "aiza", "sg.")


def _looks_like_value(k: str) -> bool:
    """True if a dict key looks like a secret/PII VALUE rather than a schema field name."""
    if not _IDENT.match(k):
        return True                                   # has @ . - / + = : etc. → email/JWT/token
    low = k.lower()
    if any(low.startswith(p) for p in _TOKEN_PREFIXES):
        return True
    if _HEX_RUN.search(k):
        return True                                   # MD5/SHA/hex id
    digits = sum(c.isdigit() for c in k)
    if len(k) >= 12 and digits / len(k) >= 0.30:
        return True                                   # random id / high digit density
    if len(k) >= 20 and digits and any(c.isupper() for c in k) and any(c.islower() for c in k):
        return True                                   # long mixed-case+digit token
    return False


def _safe_key(k: Any) -> str:
    k = str(k)
    return f"<key:{len(k)}chars>" if _looks_like_value(k) else k


def _walk(obj: Any, out: dict[str, list], prefix: str = "") -> None:
    """Recursively collect leaf field names -> list of observed values (for length/
    non-empty stats only; the values never leave this function). Dict keys are
    sanitized because a server may key a map BY a secret/PII value."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            seg = _safe_key(k)
            key = f"{prefix}.{seg}" if prefix else seg
            if isinstance(v, (dict, list)):
                _walk(v, out, key)
            else:
                out.setdefault(key, []).append(v)
    elif isinstance(obj, list):
        for item in obj:
            _walk(item, out, prefix)


def summarize_fields(messages: tuple[str, ...] | list[str]) -> list[dict]:
    """Deterministic C-03-style field summary over JSON frames:
    `field · observed count · non-empty · max length` — values are NEVER included."""
    collected: dict[str, list] = {}
    for msg in messages:
        try:
            data = json.loads(msg)
        except (ValueError, TypeError):
            continue
        _walk(data, collected)
    summary: list[dict] = []
    for field, values in sorted(collected.items()):
        non_empty = sum(1 for v in values if v not in (None, "", [], {}, 0, False))
        max_len = max((len(str(v)) for v in values), default=0)
        summary.append({
            "field": field,
            "count": len(values),
            "non_empty": non_empty,
            "max_len": max_len,
        })
    return summary


# Fields whose mere presence over an unauth channel implies credential/PII exposure.
SENSITIVE_FIELD_HINTS: tuple[str, ...] = (
    "password", "hash", "salt", "token", "secret", "resettoken", "reset_token",
    "accesstoken", "refreshtoken", "apikey", "api_key", "ssn", "creditcard",
    "googleid", "googleaccesstoken", "sessionid", "email", "phone",
)


def flags_sensitive(summary: list[dict]) -> list[str]:
    """Field names in the summary that look credential/PII-bearing (name-based, not value)."""
    hits: list[str] = []
    for row in summary:
        low = row["field"].lower().replace("_", "")
        if any(hint.replace("_", "") in low for hint in SENSITIVE_FIELD_HINTS):
            hits.append(row["field"])
    return hits


async def websockets_probe(
    url: str,
    *,
    origin: str | None,
    send: tuple[str, ...],
    recv_timeout: float,
    max_messages: int,
    connect: Connect | None = None,
) -> WsFrame:
    """Production probe (lazy-imports `websockets`). Opens the socket ourselves so the
    library REFUSES any cross-origin handshake redirect — the probe can only ever reach the
    host the caller gated. `connect` dials that socket; pass a pinned connector to also hold
    the connection to an already-verified IP (anti-DNS-rebinding), since the default resolves
    the hostname afresh. Connects with NO cookies and the given Origin; any failure is
    returned as data."""
    import asyncio
    from urllib.parse import urlparse

    connect = connect or default_connect

    try:
        import websockets
    except ImportError:
        return WsFrame(False, 0, origin, (), error="websocket probe unavailable — pip install '.[probe]'")

    parsed = urlparse(url)
    host = parsed.hostname or ""
    secure = parsed.scheme == "wss"
    port = parsed.port or (443 if secure else 80)
    if not host:
        return WsFrame(False, 0, origin, (), error="unparseable websocket host")

    loop = asyncio.get_event_loop()
    try:
        sock = await loop.run_in_executor(None, lambda: connect(host, port, recv_timeout))
    except OSError as exc:
        return WsFrame(False, 0, origin, (), error=f"connect failed: {exc}"[:200])

    # Preexisting socket => the library REFUSES a cross-origin redirect (keystone-safe).
    kwargs: dict[str, Any] = {"sock": sock, "open_timeout": recv_timeout}
    if secure:
        import ssl

        kwargs["ssl"] = ssl.create_default_context()
        kwargs["server_hostname"] = host
    if origin is not None:
        kwargs["origin"] = origin

    try:
        try:
            conn = websockets.connect(url, **kwargs)
        except TypeError as exc:
            # Do NOT retry without the sock pin — that would reopen the redirect gap.
            sock.close()
            return WsFrame(False, 0, origin, (), error=f"unsupported websockets client API: {exc}"[:160])
        async with conn as ws:
            # Reaching here means the unauth handshake succeeded (101) — that alone is the
            # finding signal, so send/recv are best-effort: a server that closes mid-probe
            # must NOT flip us back to "not connected".
            messages: list[str] = []
            try:
                for message in send:
                    await ws.send(message)
                while len(messages) < max_messages:
                    frame = await asyncio.wait_for(ws.recv(), timeout=recv_timeout)
                    messages.append(frame if isinstance(frame, str) else frame.decode("utf-8", "replace"))
            except (asyncio.TimeoutError, Exception):  # noqa: BLE001 — closed / no more frames
                pass
            return WsFrame(True, 101, origin, tuple(messages))
    except Exception as exc:  # noqa: BLE001 — rejected handshake / refused redirect / unreachable = signal
        try:
            sock.close()
        except Exception:  # noqa: BLE001
            pass
        status = getattr(getattr(exc, "response", None), "status_code", 0) or 0
        return WsFrame(False, status, origin, (), error=str(exc)[:200])
