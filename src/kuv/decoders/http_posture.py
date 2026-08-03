"""Deterministic HTTP security-posture analysis — CSP / cookies / CORS / transport.

The reference report's M-02/M-03 (permissive CORS + cookie posture, CSP allowing
unsafe execution and leftover dev origins) are exactly the checks a scanner half-does
and an LLM eyeballs inconsistently. This decoder parses the response headers once,
deterministically, and emits the concrete gaps — so the `weak_transport_or_cors`
finding is evidenced, not vibes. Pure: it takes already-fetched header material.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

# Dev/loopback origins that should never ship in a production CSP. `[::1]` is matched
# without \b — word boundaries don't apply next to brackets, so \b…\[::1\]…\b never fires.
_DEV_ORIGIN = re.compile(r"\b(?:localhost|127\.0\.0\.1|0\.0\.0\.0)\b|\[::1\]")


@dataclass(frozen=True)
class CookiePosture:
    name: str
    secure: bool
    httponly: bool
    samesite: str | None           # "Strict" / "Lax" / "None" / None (unset)


@dataclass(frozen=True)
class Posture:
    hsts: bool
    hsts_long: bool                 # max-age >= ~180 days
    csp_present: bool
    csp_unsafe_inline: bool
    csp_unsafe_eval: bool
    csp_dev_origins: tuple[str, ...]
    csp_wildcard_script: bool
    cors_acao: str | None
    cors_wildcard: bool
    cors_allow_credentials: bool
    xcto_nosniff: bool
    x_frame_options: str | None
    referrer_policy: str | None
    permissions_policy: bool
    cookies: tuple[CookiePosture, ...]
    gaps: tuple[str, ...]


def _parse_cookie(set_cookie: str) -> CookiePosture:
    parts = [p.strip() for p in set_cookie.split(";")]
    name = parts[0].split("=", 1)[0].strip() if parts and "=" in parts[0] else parts[0]
    lower = {p.lower(): p for p in parts[1:]}
    samesite = None
    for key, raw in lower.items():
        if key.startswith("samesite"):
            samesite = raw.split("=", 1)[1].strip() if "=" in raw else ""
    return CookiePosture(
        name=name,
        secure="secure" in lower,
        httponly="httponly" in lower,
        samesite=samesite or None,
    )


def analyze_http_posture(
    status: int,
    headers: dict,
    set_cookies: list[str] | None = None,
) -> Posture:
    """Analyze one response's security posture. `headers` keys are matched
    case-insensitively; `set_cookies` is the list of raw Set-Cookie header values
    (HTTP allows several, which a flat dict would collapse)."""
    h = {str(k).lower(): str(v) for k, v in (headers or {}).items()}
    cookie_lines = list(set_cookies or [])
    if not cookie_lines and "set-cookie" in h:
        cookie_lines = [h["set-cookie"]]

    hsts_raw = h.get("strict-transport-security", "")
    hsts = bool(hsts_raw)
    m = re.search(r"max-age=(\d+)", hsts_raw)
    hsts_long = bool(m and int(m.group(1)) >= 15_552_000)

    csp = h.get("content-security-policy", "")
    csp_l = csp.lower()
    csp_present = bool(csp)
    csp_unsafe_inline = "'unsafe-inline'" in csp_l
    csp_unsafe_eval = "'unsafe-eval'" in csp_l
    dev = tuple(sorted({m if isinstance(m, str) else m[0] for m in _DEV_ORIGIN.findall(csp)} - {""}))

    def _directive(name: str) -> str | None:
        m = re.search(rf"{name}\s+([^;]*)", csp_l)
        return m.group(1) if m else None

    # A bare `*` source (not a host-wildcard like *.cdn.com); fall back to default-src
    # when script-src is absent, per CSP fetch-directive fallback semantics.
    script_val = _directive("script-src")
    if script_val is None:
        script_val = _directive("default-src")
    csp_wildcard_script = bool(script_val and "*" in script_val.split())

    acao = h.get("access-control-allow-origin")
    cors_wildcard = acao == "*"
    cors_creds = h.get("access-control-allow-credentials", "").lower() == "true"

    cookies = tuple(_parse_cookie(c) for c in cookie_lines if c)

    gaps: list[str] = []
    if not hsts:
        gaps.append("no HSTS (Strict-Transport-Security) header")
    elif not hsts_long:
        gaps.append("HSTS max-age is short (< 180 days)")
    if not csp_present:
        gaps.append("no Content-Security-Policy")
    else:
        if csp_unsafe_inline:
            gaps.append("CSP allows 'unsafe-inline' scripts/styles")
        if csp_unsafe_eval:
            gaps.append("CSP allows 'unsafe-eval'")
        if dev:
            gaps.append(f"CSP ships dev-mode origins in production: {', '.join(dev)}")
        if csp_wildcard_script:
            gaps.append("CSP script-src contains a wildcard")
    if cors_wildcard:
        gaps.append("Access-Control-Allow-Origin: * (wildcard CORS)")
    if cors_wildcard and cors_creds:
        gaps.append("wildcard CORS combined with Allow-Credentials: true")
    if not h.get("x-content-type-options", "").lower().startswith("nosniff"):
        gaps.append("missing X-Content-Type-Options: nosniff")
    if not h.get("x-frame-options") and "frame-ancestors" not in csp_l:
        gaps.append("no clickjacking defense (X-Frame-Options / frame-ancestors)")
    if not h.get("referrer-policy"):
        gaps.append("no Referrer-Policy")
    for c in cookies:
        missing = []
        if not c.secure:
            missing.append("Secure")
        if not c.samesite:
            missing.append("SameSite")
        if missing:
            gaps.append(f"cookie `{c.name}` missing {', '.join(missing)}")

    return Posture(
        hsts=hsts,
        hsts_long=hsts_long,
        csp_present=csp_present,
        csp_unsafe_inline=csp_unsafe_inline,
        csp_unsafe_eval=csp_unsafe_eval,
        csp_dev_origins=dev,
        csp_wildcard_script=csp_wildcard_script,
        cors_acao=acao,
        cors_wildcard=cors_wildcard,
        cors_allow_credentials=cors_creds,
        xcto_nosniff=h.get("x-content-type-options", "").lower().startswith("nosniff"),
        x_frame_options=h.get("x-frame-options"),
        referrer_policy=h.get("referrer-policy"),
        permissions_policy=bool(h.get("permissions-policy")),
        cookies=cookies,
        gaps=tuple(gaps),
    )
