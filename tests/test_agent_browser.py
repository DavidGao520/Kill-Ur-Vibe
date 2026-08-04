"""The headless-browser render_page tool must keep the keystone: every browser request
is gated, off-scope is blocked (and reported), writes are blocked, no value leaks."""

from __future__ import annotations

import asyncio
from datetime import date

from kuv.agent.session import AssessmentSession
from kuv.egress import EgressEngine
from kuv.gate import ActionClass, Scope
from kuv.recon.browser import BrowserResult, RequestObs, WsObs, strip_query

_NOW = date(2026, 7, 31)


class _FakeResp:
    def __init__(self, status=200, text="", headers=None):
        self.status_code, self.text, self.headers = status, text, headers or {}


class _FakeClient:
    async def request(self, method, url, *, content=None, headers=None):
        return _FakeResp()

    async def get(self, url):
        return _FakeResp()


class _FakeBrowser:
    """Records the URL, exercises the injected gate with probe inputs, returns a canned result."""

    def __init__(self, result: BrowserResult, gate_inputs=()):
        self.result = result
        self.calls: list[str] = []
        self.gate_inputs = gate_inputs
        self.gate_results: dict = {}

    async def __call__(self, url, *, gate, timeout, max_requests):
        self.calls.append(url)
        self.max_requests = max_requests
        for method, u in self.gate_inputs:
            self.gate_results[(method, u)] = gate(method, u)[0]   # (allow, reason) -> allow
        return self.result


_RESULT = BrowserResult(
    ok=True,
    title="Dashboard — contact ops@acme.com",
    rendered_html='<a href="/dashboard">d</a><a href="/api/v1/me">m</a>',
    requests=(
        RequestObs("GET", "https://app.example.com/api/v1/me", "app.example.com", "xhr", 200, True, "passive read of in-scope host"),
        RequestObs("GET", "https://api.hidden-backend.com/v1/data", "api.hidden-backend.com", "fetch", None, False, "api.hidden-backend.com is out of authorized scope"),
        RequestObs("POST", "https://track.evil.com/collect", "track.evil.com", "xhr", None, False, "track.evil.com is out of authorized scope"),
        RequestObs("GET", "https://app.example.com/static/main.js", "app.example.com", "script", 200, True, "passive read of in-scope host"),
    ),
    websockets=(WsObs("wss://app.example.com/ws", "app.example.com", True, ('{"user":{"hash":"SECRETVAL","name":"al"}}',)),),
    console_errors=("TypeError from bundle",),
)


def _session(browser, *, allowed=(), targets=("app.example.com", "*.example.com")):
    scope = Scope(
        engagement_id="acme", authorized_by="op@example.com", targets=targets,
        expires_at=date(2026, 12, 31), allowed_actions=frozenset(allowed),
        authorization_asserted=True,
    )
    client = _FakeClient()
    return AssessmentSession(EgressEngine(scope, now=lambda: _NOW, ip_resolver=lambda h: ["93.184.216.34"]), client, browser_probe=browser)


def test_strip_query_removes_token_bearing_query():
    assert strip_query("https://h/x?token=abc#f") == "https://h/x"
    assert strip_query("/reset?tok=1") == "/reset"


def test_hardening_neuters_uncovered_egress_realms():
    from kuv.recon.browser import _HARDEN
    for vector in ("WebTransport", "Worker", "SharedWorker", "RTCPeerConnection"):
        assert vector in _HARDEN, f"{vector} not neutered"


def test_redact_url_redacts_token_path_keeps_slugs():
    from kuv.recon.browser import redact_url, redact_path
    # a hex/JWT/prefixed-key token in a PATH segment is redacted...
    assert "7c9e6679742540de8a3b1c9d0f2e4a6b" not in redact_url("https://h/api/session/7c9e6679742540de8a3b1c9d0f2e4a6b")
    assert "<redacted>" in redact_url("https://h/reset/7c9e6679742540de8a3b1c9d0f2e4a6b")
    # ...but normal route slugs / numeric ids are kept
    assert redact_path("/r/acmecorp/yoga-apparel/5012") == "/r/acmecorp/yoga-apparel/5012"


def test_mask_tokens_masks_secrets_keeps_prose():
    from kuv.recon.browser import mask_tokens
    assert "sk_live_ABCDEFGHIJKL" not in mask_tokens("key sk_live_ABCDEFGHIJKL leaked")
    assert "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abcDEFghiJKL" not in mask_tokens(
        "jwt eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abcDEFghiJKL here")
    assert mask_tokens("a normal console message") == "a normal console message"


def test_word_slug_with_digits_kept_but_bare_id_redacted():
    from kuv.recon.browser import redact_path
    # hyphenated word-slugs (route names) are kept even with embedded digits
    assert redact_path("/products/product-12345") == "/products/product-12345"
    assert redact_path("/blog/2024-01-15-my-post") == "/blog/2024-01-15-my-post"
    # a bare high-entropy id / session token is still redacted
    assert "26vosl5pn3g4h9k2m7q1r8s4t6ab" not in redact_path("/s/26vosl5pn3g4h9k2m7q1r8s4t6ab")


def test_redaction_inputs_are_length_capped_redos_guard():
    from kuv.recon.browser import redact_url, redact_path, mask_tokens
    # uncapped adversarial input must not blow up the downstream quadratic email regex
    assert len(redact_url("https://h/" + "a.b." * 100000)) < 4000
    assert len(redact_path("/" + "x.y." * 100000)) < 4000
    assert len(mask_tokens("eyJ" * 100000)) < 6000


def test_render_page_passes_bounded_request_cap():
    b = _FakeBrowser(_RESULT)
    asyncio.run(_session(b).render_page("https://app.example.com/"))
    assert b.max_requests == 45          # bounded so one render can't starve the run budget


def test_render_page_off_scope_refused_no_browser_launch():
    b = _FakeBrowser(_RESULT)
    session = _session(b)
    out = asyncio.run(session.render_page("https://evil.com/"))
    assert out["ok"] is False and "REFUSED" in out["error"]
    assert b.calls == []                                   # the browser never launched


def test_render_page_gate_allows_inscope_blocks_offscope_and_writes():
    b = _FakeBrowser(_RESULT, gate_inputs=[
        ("GET", "https://app.example.com/x"),              # in-scope read -> allow
        ("GET", "https://evil.com/x"),                     # off-scope -> block
        ("POST", "https://app.example.com/x"),             # write (no action_class) -> block
    ])
    session = _session(b)
    asyncio.run(session.render_page("https://app.example.com/"))
    assert b.gate_results[("GET", "https://app.example.com/x")] is True
    assert b.gate_results[("GET", "https://evil.com/x")] is False
    assert b.gate_results[("POST", "https://app.example.com/x")] is False   # browser never writes


def test_render_page_reports_offscope_api_origin_without_contact():
    b = _FakeBrowser(_RESULT)
    session = _session(b)
    out = asyncio.run(session.render_page("https://app.example.com/"))
    assert out["ok"] is True
    # the real (off-scope) backend origins are surfaced for a follow-up, though blocked
    assert "api.hidden-backend.com" in out["off_scope_hosts_discovered"]
    assert "track.evil.com" in out["off_scope_hosts_discovered"]
    # the in-scope XHR endpoint is reported as an api_call
    assert any(a["url"].endswith("/api/v1/me") and a["allowed"] for a in out["api_calls"])


def test_render_page_reports_blocked_writes():
    b = _FakeBrowser(_RESULT)
    out = asyncio.run(_session(b).render_page("https://app.example.com/"))
    assert any("POST" in w and "track.evil.com" in w for w in out["blocked_writes"])


def test_render_page_websocket_summary_is_values_free():
    b = _FakeBrowser(_RESULT)
    out = asyncio.run(_session(b).render_page("https://app.example.com/"))
    assert "SECRETVAL" not in str(out)                     # ws frame value never leaks
    ws = out["websockets"][0]
    assert any("hash" in f["field"] for f in ws["field_summary"])


def test_render_page_redacts_tokens_in_paths_title_and_console():
    result = BrowserResult(
        ok=True,
        title="error: bearer sk_live_ABCDEFGHIJKLMNOP",
        rendered_html='<a href="/reset/7c9e6679742540de8a3b1c9d0f2e4a6b">r</a><a href="/yoga-apparel/5012">y</a>',
        requests=(RequestObs("GET", "https://app.example.com/api/session/7c9e6679742540de8a3b1c9d0f2e4a6b",
                             "app.example.com", "xhr", 200, True, "ok"),),
        websockets=(),
        console_errors=("token eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abcDEFghiJKL",),
    )
    out = asyncio.run(_session(_FakeBrowser(result)).render_page("https://app.example.com/"))
    blob = str(out)
    assert "7c9e6679742540de8a3b1c9d0f2e4a6b" not in blob     # token in api url + rendered path
    assert "sk_live_ABCDEFGHIJKLMNOP" not in blob             # token in title
    assert "eyJhbGciOiJIUzI1NiJ9" not in blob                 # JWT in console error
    assert any(p["path"] == "/yoga-apparel/5012" for p in out["rendered_paths"])   # slug kept


def test_render_page_extracts_rendered_routes_and_redacts_pii():
    b = _FakeBrowser(_RESULT)
    out = asyncio.run(_session(b).render_page("https://app.example.com/"))
    paths = {p["path"] for p in out["rendered_paths"]}
    assert "/api/v1/me" in paths and "/dashboard" in paths
    assert "ops@acme.com" not in str(out)                  # email in title redacted
