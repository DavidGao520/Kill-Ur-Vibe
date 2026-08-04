"""Thin Claude Agent SDK wrappers around the SDK-free AssessmentSession core.

These are the ONLY tools the agent gets — no bash, no built-in network. Each
delegates to the session, which gates every request through the egress engine.
"""

from __future__ import annotations

import json

from claude_agent_sdk import create_sdk_mcp_server, tool

from kuv.gate import ActionClass
from kuv.severity import FindingType

from .session import AssessmentSession, parse_evidence_rows

_ACTIONS = ", ".join(a.value for a in ActionClass)
_TYPES = ", ".join(f.value for f in FindingType)

SERVER_NAME = "kuvnet"
TOOL_NAMES = (
    "mcp__kuvnet__http_get",
    "mcp__kuvnet__http_write",
    "mcp__kuvnet__record_finding",
    "mcp__kuvnet__decode_jwt_role",
    "mcp__kuvnet__classify_secret",
    "mcp__kuvnet__check_source_map",
    "mcp__kuvnet__scan_js",
    "mcp__kuvnet__enumerate_subdomains",
    "mcp__kuvnet__check_email_auth",
    "mcp__kuvnet__probe_websocket",
    "mcp__kuvnet__check_http_posture",
    "mcp__kuvnet__analyze_oauth",
    "mcp__kuvnet__check_tls",
    "mcp__kuvnet__discover_paths",
    "mcp__kuvnet__render_page",
)


def _ok(obj) -> dict:
    return {"content": [{"type": "text", "text": json.dumps(obj)}]}


def _err(message: str) -> dict:
    return {"content": [{"type": "text", "text": message}], "is_error": True}


def _wrap(result: dict) -> dict:
    if result.get("ok") is False:
        return _err(result.get("error", "error"))
    return _ok(result)


def build_network_server(session: AssessmentSession):
    """Build the in-process MCP server exposing the six gated tools."""

    @tool("http_get", "HTTP GET an in-scope URL (passive read). Returns status, headers, body.", {"url": str})
    async def http_get(args):
        return _wrap(await session.http_request("GET", args["url"]))

    @tool(
        "http_write",
        f"Synthetic HTTP write (POST/PUT/PATCH/DELETE) to an in-scope URL. "
        f"action_class must be one of: {_ACTIONS}. `content_type` sets the request's "
        f"Content-Type (default application/json) — REQUIRED for most JSON write APIs, which "
        f"return 415 or fail to parse the body without it; use e.g. "
        f"'application/x-www-form-urlencoded' or 'image/png' when appropriate.",
        {"url": str, "method": str, "body": str, "action_class": str, "content_type": str},
    )
    async def http_write(args):
        try:
            action = ActionClass(args["action_class"])
        except ValueError:
            return _err(f"unknown action_class {args['action_class']!r}; one of: {_ACTIONS}")
        return _wrap(await session.http_request(
            args["method"], args["url"], args.get("body"), action,
            args.get("content_type") or "application/json",
        ))

    @tool(
        "record_finding",
        f"Record a PROVEN finding. finding_type must be one of: {_TYPES}. Severity is "
        f"assigned deterministically by the tool, not by you. `evidence` is a one-line "
        f"summary; `evidence_json` is a JSON array of [probe, result] pairs (the exact "
        f"requests you sent and the responses that proved it); `recommendation` is the fix. "
        f"`plain_impact` is REQUIRED: one or two sentences in PLAIN language (no jargon, no "
        f"acronyms) telling a non-technical founder what could actually go wrong and who is "
        f"harmed — calibrated to severity, never dramatized. It is the first line they read.",
        {
            "finding_type": str,
            "title": str,
            "location": str,
            "evidence": str,
            "contains_pii_or_secrets": bool,
            "recommendation": str,
            "evidence_json": str,
            "plain_impact": str,
        },
    )
    async def record_finding(args):
        return _wrap(
            session.record_finding(
                args["finding_type"],
                args["title"],
                args["location"],
                args["evidence"],
                bool(args.get("contains_pii_or_secrets", False)),
                args.get("recommendation", ""),
                parse_evidence_rows(args.get("evidence_json", "")),
                args.get("plain_impact", ""),
            )
        )

    @tool("decode_jwt_role", "Deterministically decode a JWT and return its Supabase role.", {"token": str})
    async def decode_jwt_role_tool(args):
        return _ok(session.decode_jwt(args["token"]))

    @tool("classify_secret", "Public-by-design vs candidate real leak for a flagged token.", {"token": str})
    async def classify_secret_tool(args):
        return _ok(session.classify_secret(args["token"]))

    @tool("check_source_map", "Is a JS file's sibling .map exposed? (gated GET).", {"js_url": str})
    async def check_source_map_tool(args):
        return _wrap(await session.check_source_map(args["js_url"]))

    @tool(
        "scan_js",
        "Fetch a JS/asset URL in full and scan it for secrets (AWS/Stripe/OpenAI/"
        "Google/Slack/GitHub keys, JWTs, private keys, DB URIs). Returns type/count/"
        "length only — the bundle never enters your context. Use on every shipped bundle.",
        {"url": str},
    )
    async def scan_js_tool(args):
        return _wrap(await session.scan_js(args["url"]))

    @tool(
        "enumerate_subdomains",
        "Enumerate common subdomains under an in-scope apex domain (e.g. 'example.com') via "
        "DNS, flagging dangling CNAMEs that are subdomain-takeover candidates. Use this "
        "FIRST to map the wider attack surface, then probe each live host.",
        {"apex": str},
    )
    async def enumerate_subdomains_tool(args):
        return _wrap(await session.enumerate_subdomains(args["apex"]))

    @tool(
        "check_email_auth",
        "Check an in-scope apex domain's SPF + DMARC posture (DMARC p=none/unset means "
        "email spoofing is possible).",
        {"apex": str},
    )
    async def check_email_auth_tool(args):
        return _wrap(session.check_email_auth(args["apex"]))

    @tool(
        "probe_websocket",
        "Probe an in-scope websocket (ws://|wss://) with NO cookie/token. The unauth "
        "handshake is passive; sending ANY frame is an active interaction, so BOTH "
        "`read_json` (subscribe) and `write_json` (synthetic save) route through the write "
        "gate as action_class=websocket_save and are sent ONLY when that class is enabled "
        "(`frames_result` reports which). `origin` sets an Origin header to test cross-origin "
        "acceptance. The connection is pinned to the given host (cross-origin handshake "
        "redirects are refused). Returns handshake status, whether it connected "
        "unauthenticated, and a field summary (name/count/non-empty/max-len ONLY — never "
        "values). This proves the unauth-websocket read/write and sensitive-field-leak classes.",
        {"url": str, "read_json": str, "write_json": str, "origin": str},
    )
    async def probe_websocket_tool(args):
        return _wrap(await session.probe_websocket(
            args["url"], args.get("read_json", ""), args.get("write_json", ""),
            args.get("origin") or None,
        ))

    @tool(
        "check_http_posture",
        "GET an in-scope URL and deterministically analyze its security posture: CSP "
        "(unsafe-inline/eval, leftover localhost dev origins), Set-Cookie flags "
        "(Secure/SameSite/HttpOnly), CORS (ACAO:* / Allow-Credentials), HSTS, and the "
        "security-header set. Returns a concrete `gaps` list — file weak_transport_or_cors "
        "findings from it instead of eyeballing raw headers.",
        {"url": str},
    )
    async def check_http_posture_tool(args):
        return _wrap(await session.check_http_posture(args["url"]))

    @tool(
        "analyze_oauth",
        "Deterministically analyze an OAuth authorize URL you already found in a fetched "
        "page (e.g. a Google/Microsoft/GitHub login link). Reports response_type and whether "
        "`state` (CSRF), `code_challenge` (PKCE), `nonce`, and Google `hd` are present, plus "
        "a `gaps` list. File oauth_config_gap findings from it — do not eyeball the URL.",
        {"authorize_url": str},
    )
    async def analyze_oauth_tool(args):
        return _wrap(session.analyze_oauth(args["authorize_url"]))

    @tool(
        "check_tls",
        "Validate an in-scope host's TLS certificate: chain validity, expiry, hostname "
        "match, and negotiated protocol version. Returns a `gaps` list (expired / "
        "self-signed / hostname-mismatch / obsolete-protocol). File insecure_tls findings "
        "from it. Pass a bare host (e.g. 'app.example.com').",
        {"host": str},
    )
    async def check_tls_tool(args):
        return _wrap(session.check_tls(args["host"]))

    @tool(
        "discover_paths",
        "Discover routes/endpoints on an in-scope host. Fetches the page + its same-origin "
        "JS bundles and extracts every `/path` they reference (SPA router tables, links, "
        "fetch() calls) — this surfaces routes like /account/login and /events that live in "
        "the bundle, not just the HTML. Set probe_wordlist=true to ALSO probe a curated list "
        "of common/sensitive paths (/admin, /api, /.env, /.git/config, …) and report which "
        "exist. Every fetch/probe is egress-gated and budget-charged. Returns deduped paths "
        "(high-signal first) with how each was found. Run in recon, then http_get the "
        "interesting ones.",
        {"url": str, "probe_wordlist": bool},
    )
    async def discover_paths_tool(args):
        return _wrap(await session.discover_paths(
            args["url"], bool(args.get("probe_wordlist", False))
        ))

    @tool(
        "render_page",
        "Render a JS single-page app in a headless browser and report its REAL runtime "
        "traffic — the XHR/fetch API endpoints it actually calls (its true backend origin, "
        "even when that origin is a different host you'd then add to scope), the routes its "
        "client-side router builds, and in-scope websocket frames. Use this when a static "
        "http_get/discover_paths only returns an app shell and the real API/websocket lives "
        "in runtime JS. EVERY browser request is egress-gated: off-scope ones are blocked "
        "before they're sent and reported under off_scope_hosts_discovered (so you learn the "
        "backend origin without contacting it); in a read-only run the page's own writes are "
        "blocked too. Values-free (query strings stripped, ws frames summarized).",
        {"url": str},
    )
    async def render_page_tool(args):
        return _wrap(await session.render_page(args["url"]))

    return create_sdk_mcp_server(
        SERVER_NAME,
        "0.1.0",
        tools=[
            http_get,
            http_write,
            record_finding,
            decode_jwt_role_tool,
            classify_secret_tool,
            check_source_map_tool,
            scan_js_tool,
            enumerate_subdomains_tool,
            check_email_auth_tool,
            probe_websocket_tool,
            check_http_posture_tool,
            analyze_oauth_tool,
            check_tls_tool,
            discover_paths_tool,
            render_page_tool,
        ],
    )
