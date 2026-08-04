"""Headless-browser probe — renders a JS SPA and observes its REAL runtime traffic.

The deferred capability both live runs kept pointing at: a static bundle scan can't see
the API origin a React/Next SPA calls at runtime, its websocket frame protocol, or a
route the router builds client-side. A browser can — but a browser is the biggest keystone
risk in the whole tool, because it autonomously fires dozens of requests (scripts, XHR,
trackers, websockets, WebRTC) to many hosts. So the design is:

  EVERY request the page attempts is intercepted (page.route) and run through the SAME
  egress gate the caller injects. Off-scope requests are aborted BEFORE they leave the
  machine and recorded as "discovered but blocked" — so the tool can reveal a SPA's real
  off-scope API origin WITHOUT ever contacting it. Websockets (which page.route does not
  cover) are gated via route_web_socket when available, else the WebSocket constructor is
  neutered so the page cannot open an ungated one; WebRTC is always neutered.

The probe is injected so the SDK-free core stays testable with a fake; production uses
Playwright (an optional dependency).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Callable, Protocol
from urllib.parse import urlparse

# gate(method, url) -> (allow, reason). The caller wires this to the EgressEngine so the
# browser has exactly one mediation point — the keystone — like every other tool.
Gate = Callable[[str, str], "tuple[bool, str]"]


def strip_query(url: str) -> str:
    """Path-only URL (scheme://host/path) — drops query/fragment so a token in a query
    string is never recorded (values-free discipline)."""
    p = urlparse(url)
    if not p.scheme:
        return url.split("?", 1)[0].split("#", 1)[0]
    return f"{p.scheme}://{p.netloc}{p.path}"


# --- observed-value redaction (a token can hide in a PATH segment, a title, or a console
# error, none of which strip_query touches) --------------------------------------------
_TOKEN_PREFIXES = ("sk_", "rk_", "ghp_", "gho_", "ghs_", "xox", "akia", "asia", "aiza")
_HEX16 = re.compile(r"[0-9a-fA-F]{16,}")
_TOKEN_RE = re.compile(
    r"eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{5,}\.[A-Za-z0-9_\-]{5,}"   # JWT
    r"|(?:sk|pk|rk|ghp|gho|ghs)_[A-Za-z0-9_]{8,}"                       # prefixed keys (may contain _)
    r"|AKIA[0-9A-Z]{12,}"                                               # AWS
    r"|AIza[0-9A-Za-z_\-]{20,}"                                         # Google
    r"|xox[baprs]-[A-Za-z0-9\-]{10,}"                                   # Slack
    r"|\b[0-9a-fA-F]{32,}\b"                                            # long hex
)


def _token_segment(seg: str) -> bool:
    """True if a URL path segment looks like a token/secret (not a normal route slug)."""
    if len(seg) < 8:
        return False
    low = seg.lower()
    if any(low.startswith(p) for p in _TOKEN_PREFIXES) or _HEX16.search(seg):
        return True
    # A hyphenated word-slug (product-12345, 2024-01-15-my-post) is a route, not a token —
    # exempt it from the entropy heuristics (bare high-entropy runs are still caught).
    if "-" in seg and re.search(r"[A-Za-z]{3,}", seg):
        return False
    digits = sum(c.isdigit() for c in seg)
    if len(seg) >= 12 and digits / len(seg) >= 0.35:
        return True
    if len(seg) >= 20 and digits and any(c.isupper() for c in seg) and any(c.islower() for c in seg):
        return True
    if len(seg) >= 24 and re.fullmatch(r"[A-Za-z0-9_]+", seg) and not re.search(r"[aeiouAEIOU]", seg):
        return True
    return False


def redact_path(path: str) -> str:
    """Redact token-shaped path segments, keeping normal route slugs (yoga-apparel, 5012).
    Input is length-capped: the redaction pass downstream uses a quadratic email regex, so
    an uncapped adversarial path must not reach it (ReDoS guard)."""
    return "/".join("<redacted>" if _token_segment(s) else s for s in (path or "")[:1024].split("/"))


def redact_url(url: str) -> str:
    """host + path with token-shaped path segments redacted (query already dropped)."""
    url = (url or "")[:1024]
    p = urlparse(url)
    if not p.scheme:
        return redact_path(url.split("?", 1)[0].split("#", 1)[0])
    return f"{p.scheme}://{p.netloc}{redact_path(p.path)}"


def mask_tokens(text: str) -> str:
    """Mask secret-shaped tokens (JWT/prefixed-key/AWS/hex) in free text (title, console).
    Input is length-capped — _TOKEN_RE is quadratic on some repeats (ReDoS guard)."""
    return _TOKEN_RE.sub("<redacted-token>", (text or "")[:4096])


@dataclass(frozen=True)
class RequestObs:
    method: str
    url: str                 # query-stripped
    host: str
    resource_type: str       # document/script/xhr/fetch/image/stylesheet/websocket/...
    status: int | None       # None if blocked before send
    allowed: bool
    reason: str


@dataclass(frozen=True)
class WsObs:
    url: str
    host: str
    allowed: bool
    messages: tuple[str, ...] = ()   # in-scope frames only; summarized (never raw) upstream


@dataclass(frozen=True)
class BrowserResult:
    ok: bool
    title: str = ""
    rendered_html: str = ""          # for path/form extraction; never returned raw upstream
    requests: tuple[RequestObs, ...] = ()
    websockets: tuple[WsObs, ...] = ()
    console_errors: tuple[str, ...] = ()
    error: str | None = None


class BrowserProbe(Protocol):
    async def __call__(
        self, url: str, *, gate: Gate, timeout: float, max_requests: int
    ) -> BrowserResult: ...


# The page must not open an egress channel request-routing can't gate. Neuter every such
# vector that isn't covered by context.route: WebRTC (data channels), WebTransport (HTTP/3
# QUIC — not a Fetch request), and Web/Shared Workers (a separate JS realm the init script
# and the websocket-route shim don't reach, so a worker's socket/fetch could bypass the
# gate — fail closed by disabling worker creation). WebSocket is neutered ONLY when
# route_web_socket is unavailable to gate it.
_HARDEN = (
    "try{window.RTCPeerConnection=undefined;window.webkitRTCPeerConnection=undefined;}catch(e){}"
    "try{window.WebTransport=function(){throw new Error('blocked');};}catch(e){}"
    "try{window.Worker=function(){throw new Error('blocked');};"
    "window.SharedWorker=function(){throw new Error('blocked');};}catch(e){}"
)
_NEUTER_WEBSOCKET = "try{window.WebSocket=function(){throw new Error('blocked');};}catch(e){}"


async def playwright_probe(
    url: str, *, gate: Gate, timeout: float = 20.0, max_requests: int = 45
) -> BrowserResult:
    """Production probe (lazy-imports Playwright). Renders `url` in a fresh, cookie-less
    headless context; every HTTP request is gated (off-scope → aborted, recorded)."""
    import asyncio

    try:
        from playwright.async_api import async_playwright
    except ImportError:
        return BrowserResult(
            ok=False,
            error="browser probe unavailable — pip install '.[browser]' && playwright install chromium",
        )

    requests: list[RequestObs] = []
    ws_list: list[WsObs] = []
    errors: list[str] = []
    statuses: dict[str, int] = {}
    count = 0

    try:
        async with async_playwright() as pw:
            # Curb Chrome's connection prediction (dns-prefetch / speculative preconnect open
            # a socket with no HTTP request, which request routing can't intercept). Residual:
            # an EXPLICIT <link rel=preconnect href=off-scope> may still open a TCP+TLS socket
            # (a DNS + SNI metadata leak — never an HTTP payload/secret). Documented, not fully
            # closable via flags.
            browser = await pw.chromium.launch(headless=True, args=[
                "--dns-prefetch-disable",
                "--disable-features=NetworkPrediction,PreconnectToSearch,Prerender2",
            ])
            try:
                # Block service workers (they can fetch outside the page's routing) and
                # downloads; neuter WebRTC (a data channel routing can't see).
                context = await browser.new_context(
                    ignore_https_errors=True, service_workers="block", accept_downloads=False,
                )
                await context.add_init_script(_HARDEN)

                async def handler(route):
                    nonlocal count
                    req = route.request
                    count += 1
                    if count > max_requests:
                        allow, reason = False, "browser per-call request cap reached"
                    else:
                        allow, reason = gate(req.method, req.url)
                    requests.append(RequestObs(
                        req.method, strip_query(req.url), (urlparse(req.url).hostname or ""),
                        req.resource_type, None, allow, reason,
                    ))
                    try:
                        await (route.continue_() if allow else route.abort())
                    except Exception:  # noqa: BLE001 — route already handled/closed
                        pass

                # Route at the CONTEXT level so requests from popups / new tabs / iframes are
                # gated too, not just the main page.
                await context.route("**/*", handler)

                # Websockets: gate via route_web_socket if the installed Playwright has it;
                # otherwise neuter the constructor so the page can't open an ungated one.
                ws_gated = hasattr(context, "route_web_socket")
                if ws_gated:
                    async def ws_route(ws_route_obj):
                        ws_url = ws_route_obj.url
                        host = urlparse(ws_url).hostname or ""
                        allow, _ = gate("GET", ws_url)   # a ws handshake is a read (GET upgrade)
                        frames: list[str] = []
                        if allow:
                            ws_route_obj.on_message(lambda m: frames.append(m if isinstance(m, str) else "<binary>"))
                            await ws_route_obj.connect_to_server()
                        else:
                            await ws_route_obj.close()
                        ws_list.append(WsObs(strip_query(ws_url), host, allow, tuple(frames[:8])))
                    try:
                        await context.route_web_socket("**/*", ws_route)
                    except Exception:  # noqa: BLE001
                        ws_gated = False
                if not ws_gated:
                    await context.add_init_script(_NEUTER_WEBSOCKET)

                page = await context.new_page()
                page.on("response", lambda r: statuses.__setitem__(strip_query(r.url), r.status))
                page.on("console", lambda m: errors.append(m.text[:200]) if m.type == "error" else None)

                try:
                    await page.goto(url, wait_until="load", timeout=timeout * 1000)
                    await page.wait_for_timeout(2500)   # let client XHR/render settle (bounded)
                except Exception as exc:  # noqa: BLE001 — timeout/partial render is still useful
                    errors.append(f"navigation: {str(exc)[:150]}")

                title, html = "", ""
                try:
                    title = (await page.title())[:300]
                    html = (await page.content())[:2_000_000]   # cap the DOM (OOM guard)
                except Exception:  # noqa: BLE001
                    pass
            finally:
                await browser.close()
    except Exception as exc:  # noqa: BLE001
        return BrowserResult(ok=False, error=f"browser probe error: {str(exc)[:200]}")

    # fill in observed statuses for allowed requests
    filled = tuple(
        RequestObs(r.method, r.url, r.host, r.resource_type, statuses.get(r.url), r.allowed, r.reason)
        for r in requests
    )
    return BrowserResult(
        ok=True, title=title, rendered_html=html,
        requests=filled, websockets=tuple(ws_list), console_errors=tuple(errors[:20]),
    )
