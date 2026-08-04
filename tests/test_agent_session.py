"""Tests for the SDK-free tool core: the agent's tools MUST go through the gate.

No Claude Agent SDK and no httpx needed — the HTTP client is a fake, so this
verifies the egress↔tool enforcement in isolation from the LLM loop.
"""

from __future__ import annotations

import asyncio
from datetime import date

from kuv.agent.session import AssessmentSession, parse_evidence_rows
from kuv.egress import EgressEngine
from kuv.gate import ActionClass, Scope

_NOW = date(2026, 7, 31)


class _FakeResp:
    def __init__(self, status: int, text: str, headers: dict | None = None):
        self.status_code = status
        self.text = text
        self.headers = headers or {}


class _FakeClient:
    """Records calls; returns a canned response. Proves I/O only happens on ALLOW."""

    def __init__(self, resp: _FakeResp):
        self._resp = resp
        self.calls: list[tuple[str, str, object]] = []

    async def request(self, method: str, url: str, *, content=None, headers=None):
        self.calls.append((method, url, content))
        self.last_headers = headers
        return self._resp

    async def get(self, url: str):
        self.calls.append(("GET", url, None))
        return self._resp


def _session(*, is_fixture=True, resp: _FakeResp | None = None, resolver=None, targets=("ideas.example.com",)):
    scope = Scope(
        engagement_id="example",
        authorized_by="authorized@example.com",
        targets=targets,
        expires_at=date(2026, 12, 31),
        allowed_actions=frozenset({ActionClass.ACCOUNT_CREATE}),
        is_fixture=is_fixture,
        authorization_asserted=True,
    )
    client = _FakeClient(resp or _FakeResp(200, "hello"))
    return AssessmentSession(EgressEngine(scope, now=lambda: _NOW, ip_resolver=lambda h: ["93.184.216.34"]), client, resolver), client


def test_get_in_scope_performs_request():
    session, client = _session()
    out = asyncio.run(session.http_request("GET", "https://ideas.example.com/api/ideas"))
    assert out["ok"] is True and out["status"] == 200
    assert len(client.calls) == 1


def test_get_off_scope_refused_and_no_io():
    session, client = _session()
    out = asyncio.run(session.http_request("GET", "https://evil.com/x"))
    assert out["ok"] is False and "REFUSED" in out["error"]
    assert client.calls == []  # the tool performed NO network I/O


def test_write_to_fixture_allowed():
    session, _ = _session(is_fixture=True)
    out = asyncio.run(
        session.http_request("POST", "https://ideas.example.com/api/ideas", '{"title":"x"}', ActionClass.ACCOUNT_CREATE)
    )
    assert out["ok"] is True


def test_write_sets_content_type_header():
    # Regression: without a Content-Type, JSON write APIs reject with 415 / can't parse.
    session, client = _session(is_fixture=True)
    asyncio.run(session.http_request(
        "POST", "https://ideas.example.com/v1/users", '{"email":"x@y.invalid"}',
        ActionClass.ACCOUNT_CREATE, content_type="application/json",
    ))
    assert client.last_headers == {"content-type": "application/json"}


def test_first_live_write_blocked_pending_confirmation():
    session, client = _session(is_fixture=False)
    out = asyncio.run(
        session.http_request("POST", "https://ideas.example.com/api/ideas", '{"title":"x"}', ActionClass.ACCOUNT_CREATE)
    )
    assert out["ok"] is False and "CONFIRMATION" in out["error"]
    assert client.calls == []


def test_record_finding_assigns_severity_from_rules():
    session, _ = _session()
    out = session.record_finding("unauth_write", "Unauth create", "POST /api/ideas", "created id 3 unauth")
    assert out["ok"] is True and out["severity"] == "Critical"
    assert len(session.findings) == 1


def test_record_finding_escape_hatch_accepts_novel_type():
    # A genuinely novel class is recorded (never dropped), tagged for operator
    # triage, and its severity is the fixed sentinel — never LLM-set.
    session, _ = _session()
    out = session.record_finding(
        "graphql_batching_dos", "Novel finding", "POST /graphql",
        "10 aliased mutations in one request all executed",
        plain_impact="An attacker could multiply one request into many to overload the server.",
    )
    assert out["ok"] is True
    assert out["severity"] == "Needs operator triage"
    assert out.get("novel") is True
    assert session.findings[-1].finding_type == "graphql_batching_dos"


def test_record_finding_novel_requires_plain_impact():
    # The hatch demands a plain-language summary — it's the operator's only human
    # handle on an unrated class. Without it, refuse (don't record a mute novelty).
    session, _ = _session()
    out = session.record_finding("i_made_this_up", "x", "y", "z", plain_impact="")
    assert out["ok"] is False
    assert session.findings == []


def test_decode_and_classify_are_passthrough():
    session, _ = _session()
    assert session.classify_secret("pk_live_abc")["is_public"] is True
    assert session.classify_secret("sk_live_abc")["is_public"] is False


def test_record_finding_captures_rows_and_recommendation():
    session, _ = _session()
    session.record_finding(
        "unauth_read_sensitive",
        "Unauth search",
        "GET /v1/search",
        "returns data unauth",
        contains_pii_or_secrets=True,
        recommendation="Add the auth check.",
        evidence_rows=(("GET /v1/search", "200 full records"),),
    )
    f = session.findings[0]
    assert f.evidence_rows == (("GET /v1/search", "200 full records"),)
    assert f.recommendation == "Add the auth check."


def test_parse_evidence_rows_accepts_pairs_and_objects():
    pairs = parse_evidence_rows('[["GET /a", "200"], ["GET /b", "401"]]')
    assert pairs == (("GET /a", "200"), ("GET /b", "401"))
    objs = parse_evidence_rows('[{"probe": "GET /a", "result": "200"}]')
    assert objs == (("GET /a", "200"),)


def test_parse_evidence_rows_degrades_on_garbage():
    assert parse_evidence_rows("") == ()
    assert parse_evidence_rows("not json") == ()
    assert parse_evidence_rows('{"not": "a list"}') == ()


# --- new tools: scan_js / enumerate_subdomains / check_email_auth ---------

def test_scan_js_gated_and_returns_only_summary():
    session, _ = _session(resp=_FakeResp(200, "x=sk_live_abcdef0123456789ABCDEF; y=2"))
    out = asyncio.run(session.scan_js("https://ideas.example.com/app.js"))
    assert out["ok"] is True
    assert any(s["type"] == "stripe_secret_key" for s in out["secrets"])
    assert "sk_live" not in str(out)  # only type/count/length, never the value


def test_scan_js_off_scope_refused():
    session, client = _session()
    out = asyncio.run(session.scan_js("https://evil.com/app.js"))
    assert out["ok"] is False and "REFUSED" in out["error"]
    assert client.calls == []


def _dns(records):
    def resolve(name, rrtype):
        return list(records.get((name, rrtype), []))
    return resolve


def test_enumerate_subdomains_flags_dns_only_dangling():
    # CNAME to a takeover service with NO A record — dangling from DNS alone.
    resolver = _dns({
        ("www.example.com", "A"): ["1.2.3.4"],
        ("gateway.example.com", "CNAME"): ["dead.onrender.com."],
    })
    session, _ = _session(targets=("example.com", "*.example.com"), resolver=resolver)
    out = asyncio.run(session.enumerate_subdomains("example.com"))
    assert out["ok"] is True
    dead = [h for h in out["hosts"] if h["name"] == "gateway.example.com"][0]
    assert dead["dangling"] is True and dead["takeover_service"] == "onrender.com"


def test_enumerate_subdomains_http_fingerprint_catches_resolving_dead_app():
    # gateway RESOLVES (has an A record) but the Render app is gone — DNS alone
    # would miss it; the gated HTTP GET returns a dead-app status/fingerprint.
    resolver = _dns({
        ("gateway.example.com", "A"): ["1.2.3.4"],
        ("gateway.example.com", "CNAME"): ["dead.onrender.com."],
    })
    session, _ = _session(
        targets=("example.com", "*.example.com"),
        resolver=resolver,
        resp=_FakeResp(404, "x-render-routing: no-server"),
    )
    out = asyncio.run(session.enumerate_subdomains("example.com"))
    dead = [h for h in out["hosts"] if h["name"] == "gateway.example.com"][0]
    assert dead["dangling"] is True
    assert dead["takeover_service"] == "onrender.com"
    assert dead["http_status"] == 404


def test_enumerate_subdomains_off_scope_apex_refused():
    session, _ = _session(resolver=_dns({}))
    out = asyncio.run(session.enumerate_subdomains("evil.com"))
    assert out["ok"] is False and "REFUSED" in out["error"]


def test_check_email_auth_reports_unenforced_dmarc():
    resolver = _dns({("_dmarc.example.com", "TXT"): ["v=DMARC1; p=none"]})
    session, _ = _session(targets=("example.com", "*.example.com"), resolver=resolver)
    out = session.check_email_auth("example.com")
    assert out["ok"] is True and out["dmarc_enforced"] is False
