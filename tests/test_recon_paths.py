"""Tests for path/route discovery: pure extraction + the gated session method."""

from __future__ import annotations

import asyncio
from datetime import date

from kuv.agent.session import AssessmentSession
from kuv.egress import EgressEngine, RunBudget
from kuv.gate import Scope
from kuv.recon.paths import extract_paths, extract_scripts, is_static_asset, rank_paths

_NOW = date(2026, 7, 31)


# ---- pure extraction ----

def test_extract_paths_finds_routes_from_html_and_js():
    text = (
        '<a href="/account/login">login</a> <a href="/events?tab=1">events</a>'
        'const routes=[{path:"/dashboard"},{path:"/settings/profile"}];'
        'fetch("/api/v1/users"); axios.get(\'/api/health\');'
    )
    paths = extract_paths(text)
    for expected in {"/account/login", "/events", "/dashboard", "/settings/profile",
                     "/api/v1/users", "/api/health"}:
        assert expected in paths


def test_extract_paths_excludes_assets_and_noise():
    text = '"/static/js/main.abc.js" "/logo.svg" "/g" "/42" "//cdn.example.com/x" "a/b/c"'
    paths = extract_paths(text)
    assert "/static/js/main.abc.js" not in paths     # asset
    assert "/logo.svg" not in paths                  # asset
    assert "/g" not in paths                          # too short (regex-flag noise)
    assert "/42" not in paths                         # bare numeric id
    assert not any("cdn.example.com" in p for p in paths)   # protocol-relative URL


def test_extract_scripts_and_static_asset():
    html = '<script src="/static/js/main.9f.js"></script><script src="/vendor.mjs"></script>'
    assert extract_scripts(html) == {"/static/js/main.9f.js", "/vendor.mjs"}
    assert is_static_asset("/x.PNG") and is_static_asset("/a/b.woff2")
    assert not is_static_asset("/api/data.json")     # json kept — could be an endpoint


def test_rank_puts_high_signal_first():
    ranked = rank_paths({"/blog", "/api/users", "/.env", "/about"})
    assert ranked[0] in {"/.env", "/api/users"}      # sensitive/api before marketing pages


def test_extract_ignores_js_regex_literals():
    # regex literals are paren/space-preceded, never quote-preceded -> not phantom routes
    text = 'x.split(/admin/); s.replace(/config/g,""); p.test(/events/i); m.match(/api/)'
    assert extract_paths(text) == set()              # no phantom /admin,/config,/events,/api
    # a genuine quoted route on the same blob is still found
    assert "/admin" in extract_paths('x.split(/admin/); a.href="/admin"')


def test_extract_absolute_same_origin_paths_when_in_scope():
    def in_scope(h):
        return h in {"app.example.com", "cdn.example.com"}
    text = ('fetch("https://app.example.com/api/private/keys");'
            'link="https://cdn.example.com/assets/data.json";'
            'ext="https://google.com/search";')                # off-scope -> ignored
    paths = extract_paths(text, in_scope)
    assert "/api/private/keys" in paths
    assert "/assets/data.json" in paths
    assert not any("search" in p for p in paths)     # off-scope host's path not mined
    # without in_scope, absolute paths are not mined (back-compat)
    assert extract_paths(text) == set()


def test_extract_scripts_handles_absolute_in_scope_bundle():
    def in_scope(h):
        return h == "app.example.com"
    html = '<script src="https://app.example.com/static/app.9f.js"></script>'
    assert extract_scripts(html, in_scope) == {"https://app.example.com/static/app.9f.js"}
    # off-scope CDN bundle is not returned
    off = '<script src="https://cdn.evil.com/x.js"></script>'
    assert extract_scripts(off, in_scope) == set()


# ---- gated session method ----

class _Resp:
    def __init__(self, status, text):
        self.status_code = status
        self.text = text
        self.headers = {}


class _MapClient:
    """Returns a canned response per URL; 404 for anything not in the map."""

    def __init__(self, pages: dict):
        self.pages = pages
        self.gets: list[str] = []

    async def get(self, url):
        self.gets.append(url)
        return self.pages.get(url, _Resp(404, "not found"))

    async def request(self, method, url, *, content=None, headers=None):
        return await self.get(url)


def _session(pages, *, budget=None, targets=("app.example.com", "*.example.com")):
    scope = Scope(
        engagement_id="acme", authorized_by="op@example.com", targets=targets,
        expires_at=date(2026, 12, 31), authorization_asserted=True,
    )
    client = _MapClient(pages)
    return AssessmentSession(EgressEngine(scope, now=lambda: _NOW, budget=budget), client), client


def test_discover_paths_extracts_from_page_and_bundle():
    pages = {
        "https://app.example.com/": _Resp(200,
            '<script src="/static/main.js"></script><a href="/account/login">x</a>'),
        "https://app.example.com/static/main.js": _Resp(200,
            'const r=[{path:"/events"},{path:"/api/v1/orders"}];'),
    }
    session, client = _session(pages)
    out = asyncio.run(session.discover_paths("https://app.example.com/"))
    found = {p["path"]: p["source"] for p in out["paths"]}
    assert found.get("/account/login") == "html"
    assert found.get("/events") == "bundle"
    assert found.get("/api/v1/orders") == "bundle"
    assert "/static/main.js" in out["bundles_scanned"]


def test_discover_paths_off_scope_refused_no_io():
    session, client = _session({})
    out = asyncio.run(session.discover_paths("https://evil.com/"))
    assert out["ok"] is False and "REFUSED" in out["error"]
    assert client.gets == []


def test_discover_paths_wordlist_probe_reports_existing():
    pages = {
        "https://app.example.com/": _Resp(200, "<html>home</html>"),
        "https://app.example.com/admin": _Resp(200, "admin panel"),
        "https://app.example.com/api": _Resp(200, "api root"),
        # everything else 404 via the map default
    }
    session, _ = _session(pages)
    out = asyncio.run(session.discover_paths("https://app.example.com/", probe_wordlist=True))
    statuses = {p["path"]: p["status"] for p in out["probed"]}
    assert statuses.get("/admin") == 200 and statuses.get("/api") == 200
    assert statuses.get("/.env") == 404
    found = {p["path"] for p in out["paths"]}
    assert "/admin" in found and "/api" in found     # 200s promoted into the surface map
    assert "/.env" not in found                       # 404 not promoted


def test_discover_paths_fetches_absolute_same_origin_bundle():
    # A SPA that references its bundle by ABSOLUTE same-origin URL must still be fetched.
    pages = {
        "https://app.example.com/": _Resp(200,
            '<script src="https://app.example.com/static/app.js"></script>'),
        "https://app.example.com/static/app.js": _Resp(200, 'r=[{path:"/events"}]'),
    }
    session, client = _session(pages)
    out = asyncio.run(session.discover_paths("https://app.example.com/"))
    found = {p["path"] for p in out["paths"]}
    assert "/events" in found                          # route inside the absolute-URL bundle
    assert "https://app.example.com/static/app.js" in client.gets


def test_discover_paths_off_scope_bundle_is_skipped_not_fetched():
    # A bundle on an off-scope CDN must be gate-skipped, not fetched.
    pages = {
        "https://app.example.com/": _Resp(200,
            '<script src="https://cdn.evil.com/app.js"></script><a href="/x/y">l</a>'),
    }
    session, client = _session(pages)
    out = asyncio.run(session.discover_paths("https://app.example.com/"))
    assert all("evil.com" not in g for g in client.gets)   # never fetched the off-scope bundle
    assert any(p["path"] == "/x/y" for p in out["paths"])


def test_discover_paths_probe_stops_when_budget_exhausted():
    # A tiny budget: the root fetch + a couple probes, then REFUSE(budget) halts probing.
    pages = {"https://app.example.com/": _Resp(200, "<html></html>")}
    session, client = _session(pages, budget=RunBudget(max_requests=3))
    out = asyncio.run(session.discover_paths("https://app.example.com/", probe_wordlist=True))
    assert out["ok"] is True
    assert len(client.gets) <= 3                       # budget bounded the probing
