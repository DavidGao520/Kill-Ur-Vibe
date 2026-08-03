"""Path/route discovery — the attack-surface map KUV was missing.

`enumerate_subdomains` finds other HOSTS; this finds PATHS on one host. Two mechanisms,
both deterministic and pure over already-fetched bytes:

  1. Extraction — pull every `/path`-shaped string out of the page HTML and its shipped
     JS bundles. For a SPA the router table ships in the bundle, so this is how routes
     like `/account/login` and `/events` are surfaced without guessing.
  2. A curated wordlist — high-signal common/sensitive paths to probe when the linked
     surface isn't enough (`/admin`, `/api`, `/.env`, `/.git/config`, …).

Static assets (JS/CSS/images/fonts) are excluded from routes; `.js`/`.mjs` are collected
separately as bundles to fetch. The actual fetching/probing is done by the gated session
method — this module never touches the network.
"""

from __future__ import annotations

import re

# A `/path` immediately preceded by a QUOTE (paths in HTML/JS are always quoted;
# requiring a quote — not a paren/space — keeps JS regex literals like `split(/admin/)`
# and `replace(/config/g,…)` from leaking in as phantom routes). Captures the path,
# stopping at ? # " ' space. `//host` protocol-relative and `a/b` division don't match.
_PATH = re.compile(r"""['"`](/[A-Za-z0-9_][A-Za-z0-9_\-./~]*)""")

# An absolute URL. When the host is in scope, the path component is a real route too —
# canonical <link href="https://host/…">, absolute fetch() calls, absolute-URL bundles.
_ABS = re.compile(r"""(https?)://([A-Za-z0-9.\-]+)(/[A-Za-z0-9_\-./~]*)""")

# Extensions that mark a static asset, not a route.
_ASSET_EXT = (
    ".js", ".mjs", ".css", ".map", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
    ".webp", ".avif", ".woff", ".woff2", ".ttf", ".otf", ".eot", ".mp4", ".webm",
    ".mp3", ".wasm",
)

# Substrings that make a path high-signal (ranked first, worth probing).
_HIGH_SIGNAL = (
    "/.env", ".git", "/admin", "/api", "/graphql", "/v1", "/v2", "/oauth", "/auth",
    "/login", "/signin", "/signup", "/account", "/config", "/internal", "/debug",
    "/backup", "/swagger", "/openapi", "/actuator", "/.well-known", "/users",
)

# Curated high-signal paths to probe when extraction isn't enough (leading slash added).
PATH_WORDLIST: tuple[str, ...] = (
    "admin", "login", "signin", "signup", "register", "account", "account/login",
    "dashboard", "settings", "profile", "users", "user", "api", "api/v1", "api/health",
    "graphql", "graphiql", "events", "config", "status", "health", "metrics", "debug",
    "robots.txt", "sitemap.xml", ".env", ".git/config", ".well-known/security.txt",
    "swagger", "openapi.json", "api-docs", "docs", "logout", "auth", "oauth",
    "internal", "backup", "test", "staging",
)


def is_static_asset(path: str) -> bool:
    p = path.split("?", 1)[0].split("#", 1)[0].lower()
    return p.endswith(_ASSET_EXT)


def _normalize(path: str) -> str:
    p = path.split("?", 1)[0].split("#", 1)[0]
    return p.rstrip("/") if len(p) > 1 else p


def _accept(raw: str) -> str | None:
    """Normalize + keep only route-like paths (not assets / bare ids / too short)."""
    p = _normalize(raw)
    if len(p) < 3:                           # drop '/', '/g' (single-char noise)
        return None
    if is_static_asset(p):
        return None
    if re.fullmatch(r"/\d+", p):             # a bare numeric id, not a route
        return None
    return p


def extract_paths(text: str, in_scope=None) -> set[str]:
    """Every route/endpoint-like path referenced in HTML/JS text (assets excluded).

    `in_scope(host) -> bool` (optional) additionally mines paths out of ABSOLUTE URLs
    whose host is in scope — so `fetch("https://app.example.com/api/x")` and canonical
    absolute links contribute routes too, not just root-relative refs."""
    out: set[str] = set()
    text = text or ""
    for match in _PATH.finditer(text):
        p = _accept(match.group(1))
        if p:
            out.add(p)
    if in_scope is not None:
        for match in _ABS.finditer(text):
            if in_scope(match.group(2)):
                p = _accept(match.group(3))
                if p:
                    out.add(p)
    return out


def extract_scripts(html: str, in_scope=None) -> set[str]:
    """`.js`/`.mjs` bundle URLs the page references (root-relative, plus in-scope
    absolute URLs) — to fetch + scan. Absolute refs are returned as full URLs so the
    caller resolves them to the right host, not the page origin."""
    out: set[str] = set()
    html = html or ""
    for match in _PATH.finditer(html):
        p = match.group(1).split("?", 1)[0]
        if p.lower().endswith((".js", ".mjs")):
            out.add(p)
    if in_scope is not None:
        for match in _ABS.finditer(html):
            scheme, host, path = match.group(1), match.group(2), match.group(3)
            p = path.split("?", 1)[0]
            if p.lower().endswith((".js", ".mjs")) and in_scope(host):
                out.add(f"{scheme}://{host}{p}")
    return out


def rank_paths(paths) -> list[str]:
    """High-signal paths (auth/api/admin/secrets) first, then alphabetical."""
    def key(p: str):
        low = p.lower()
        return (0 if any(h in low for h in _HIGH_SIGNAL) else 1, low)

    return sorted(set(paths), key=key)
