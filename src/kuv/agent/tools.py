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
    "mcp__kuvnet__probe_api_unauth",
    "mcp__kuvnet__render_page",
    "mcp__kuvnet__fingerprint_stack",
    "mcp__kuvnet__templated_checks",
    "mcp__kuvnet__backend_rls_probe",
    "mcp__kuvnet__webhook_sig_probe",
    "mcp__kuvnet__error_leak_probe",
    "mcp__kuvnet__cors_credentialed_probe",
    "mcp__kuvnet__mass_assignment_probe",
    "mcp__kuvnet__user_enum_probe",
    "mcp__kuvnet__ssrf_probe",
    "mcp__kuvnet__func_authz_probe",
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

    @tool(
        "http_get",
        "HTTP GET an in-scope URL (passive read). Returns status, headers, body. Optional "
        "`headers` may carry a session token for authenticated flows — only Authorization/"
        "Cookie/Accept are honored; Host/proxy/framing headers are dropped.",
        {"url": str, "headers": dict},
    )
    async def http_get(args):
        return _wrap(await session.http_request("GET", args["url"], headers=args.get("headers")))

    @tool(
        "http_write",
        f"Synthetic HTTP write (POST/PUT only — DELETE/PATCH are refused; kuv is non-destructive) "
        f"to an in-scope URL. action_class must be one of: {_ACTIONS}. `content_type` sets the "
        f"request's Content-Type (default application/json) — REQUIRED for most JSON write APIs, "
        f"which return 415 or fail to parse the body without it; use e.g. "
        f"'application/x-www-form-urlencoded' or 'image/png' when appropriate. Optional `headers` "
        f"may carry a session token (only Authorization/Cookie/Accept honored).",
        {"url": str, "method": str, "body": str, "action_class": str, "content_type": str, "headers": dict},
    )
    async def http_write(args):
        try:
            action = ActionClass(args["action_class"])
        except ValueError:
            return _err(f"unknown action_class {args['action_class']!r}; one of: {_ACTIONS}")
        return _wrap(await session.http_request(
            args["method"], args["url"], args.get("body"), action,
            args.get("content_type") or "application/json", headers=args.get("headers"),
        ))

    @tool(
        "record_finding",
        f"Record a PROVEN finding. finding_type SHOULD be one of: {_TYPES}. Severity is "
        f"assigned deterministically by the tool, not by you. If — and ONLY if — no listed "
        f"type fits a genuinely novel class you PROVED, pass your own short snake_case type: "
        f"it is recorded for operator triage (severity 'Needs operator triage' — you still do "
        f"NOT set severity). Prefer the closest listed type; never use this hatch to dodge "
        f"type discipline. `evidence` is a one-line summary; `evidence_json` is a JSON array of "
        f"[probe, result] pairs (the exact requests you sent and the responses that proved it); "
        f"`recommendation` is the fix. `plain_impact` is REQUIRED (doubly so for a novel type — "
        f"it is the operator's only human handle): one or two sentences in PLAIN language (no "
        f"jargon, no acronyms) telling a non-technical founder what could actually go wrong and "
        f"who is harmed — calibrated to severity, never dramatized. It is the first line they read.",
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
        "probe_api_unauth",
        "Deterministically UNAUTHENTICATED-probe every API endpoint on an in-scope host — "
        "the way to catch an unguarded data route (e.g. a /v1/search that ignores the auth "
        "the REST routes enforce) that ad-hoc probing skips. Discovers paths (page + JS "
        "bundles), then GETs each /v1|/api|/graphql route with NO auth: REST routes bare, "
        "search/query routes ALSO with generic variants (?q=…, ?index=<resource> derived "
        "from the other discovered resources). Returns `exposed` = endpoints that handed "
        "back a 2xx DATA COLLECTION unauthenticated (record `unauth_read_sensitive` unless "
        "the field names are clearly public), and `auth_enforced` (a sibling 401/403 → an "
        "exposure is an authorization BYPASS). Read-only; returns status/shape/count/field-"
        "NAMES only, never values. Run right after discover_paths.",
        {"url": str},
    )
    async def probe_api_unauth_tool(args):
        return _wrap(await session.probe_api_unauth(args["url"]))

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

    @tool(
        "fingerprint_stack",
        "Deterministically fingerprint an in-scope URL's tech stack (framework / CMS / "
        "BaaS / hosting / payment / auth) from headers + body + shipped-script hosts. "
        "Recon only, no finding. Run it EARLY: the `tags`/`detections` it returns tell "
        "you which stack-specific probes to run (Supabase → unauth /rest/v1 + RLS, "
        "WordPress → /wp-json user enum, Stripe → webhook-signature test) instead of the "
        "same generic sequence on every site.",
        {"url": str},
    )
    async def fingerprint_stack_tool(args):
        return _wrap(await session.fingerprint_stack(args["url"]))

    @tool(
        "templated_checks",
        "Run the curated SAFE exposure-check library against an in-scope base URL: a "
        "single GET per check, each matched on a POSITIVE content signature (so a SPA's "
        "200-for-everything shell is never a false hit). Catches served `.env` / `.git` / "
        "DB-dump/backup files (exposed_secret_file), unauth admin/ops panels — Spring "
        "actuator / phpinfo / mod_status (exposed_service_interface), and public "
        "OpenAPI/Swagger schemas (info_disclosure). Returns deterministic `exposed` "
        "candidates — record each with record_finding using the given finding_type "
        "(severity comes from the rule table, not you). Run in recon on every live host.",
        {"url": str},
    )
    async def templated_checks_tool(args):
        return _wrap(await session.templated_checks(args["url"]))

    @tool(
        "backend_rls_probe",
        "Stack-specific (run after fingerprint_stack detects a BaaS: Supabase / Firebase / "
        "PocketBase / Appwrite): does the backend data API return rows with NO auth — i.e. "
        "Row-Level Security not enforced (the #1 vibe-coded bug)? One gated GET per common "
        "table name; a candidate is returned ONLY on a positive JSON-data signature, never an "
        "empty result / error / SPA HTML shell. Pass the BaaS base `url` and, for Supabase, the "
        "anon `apikey` scan_js surfaced (without it Supabase 401s everything). `style` "
        "auto-detects (firebase vs supabase). Record each `open_tables` entry with "
        "record_finding (type unauth_read_sensitive; severity from the rule table).",
        {"url": str, "apikey": str, "style": str},
    )
    async def backend_rls_probe_tool(args):
        return _wrap(await session.backend_rls_probe(
            args["url"], apikey=args.get("apikey") or None, style=args.get("style") or None))

    @tool(
        "webhook_sig_probe",
        "Stack-specific WRITE probe: to each receiver path carrying a PAYMENT-provider signal, "
        "POST an UNSIGNED event AND the same body with a BOGUS signature; a receiver that accepts "
        "BOTH does no signature verification, so payment events are forgeable (webhook_unverified). "
        "Set `payment_detected=true` when fingerprint_stack detected Stripe/a payment provider — "
        "otherwise only paths that NAME a provider (…/stripe, …/paddle) are probed; a bare 200 at a "
        "generic webhook path is NOT reported. Bounded, one finding per provider. Gated as an "
        "OBJECT_PUT write (needs write-auth + operator confirmation on a live target, else it "
        "returns that requirement). Record each `unverified` entry with record_finding.",
        {"url": str, "payment_detected": bool},
    )
    async def webhook_sig_probe_tool(args):
        return _wrap(await session.webhook_sig_probe(
            args["url"], payment_detected=bool(args.get("payment_detected", False))))

    @tool(
        "error_leak_probe",
        "Probe discovered endpoints with a malformed query and report REAL debug / stack-trace "
        "pages (framework debug mode left on in production), collapsed to one per framework. Pass "
        "`url` (base) and `paths` (the relative endpoints discover_paths / render_page surfaced; a "
        "small starter set is used if omitted). Single GET each; a leak is returned only on a "
        "positive traceback signature, never a normal styled error page. Record each `leaks` entry "
        "with record_finding (type verbose_error_disclosure; severity from the rule table).",
        {"url": str, "paths": list},
    )
    async def error_leak_probe_tool(args):
        return _wrap(await session.error_leak_probe(args["url"], args.get("paths")))

    @tool(
        "cors_credentialed_probe",
        "Detect the exploitable CORS case check_http_posture misses: the server REFLECTS an "
        "arbitrary Origin AND sets Access-Control-Allow-Credentials: true, so any website can read "
        "a logged-in user's data (credentialed_cors). One gated GET per target carrying a benign "
        "attacker-shaped Origin; a finding only when the response reflects that Origin (or 'null') "
        "WITH credentials true. Pass `url` (base) and optional `paths`. Record each `misconfigured` "
        "entry with record_finding (severity from the rule table).",
        {"url": str, "paths": list},
    )
    async def cors_credentialed_probe_tool(args):
        return _wrap(await session.cors_credentialed_probe(args["url"], args.get("paths")))

    @tool(
        "mass_assignment_probe",
        "WRITE probe: POST a benign synthetic object, then the same with injected privileged "
        "fields (role/is_admin/credits/plan/...), then READ BACK the created record with a second "
        "GET. A `mass_assignment` finding is returned ONLY when an injected field is confirmed "
        "PERSISTED on read-back — an echo alone is never reported, and this probe never emits "
        "privilege_escalation (that needs a two-identity scan). Pass `url` (base) and `endpoints` "
        "(POST-able collections discover_paths found; a default set otherwise). Gated as OBJECT_PUT "
        "(needs write-auth + confirm). It creates synthetic `kuvprobe` rows that persist — the "
        "finding notes them for manual purge. Record each `findings` entry.",
        {"url": str, "endpoints": list},
    )
    async def mass_assignment_probe_tool(args):
        return _wrap(await session.mass_assignment_probe(args["url"], args.get("endpoints")))

    @tool(
        "user_enum_probe",
        "Detect an account-existence oracle (login/signup/forgot that reveals which emails are "
        "registered). Uses ONLY synthetic kuv-probe identifiers — never a real user email. "
        "Availability GETs are passive; login/forgot POSTs gate as auth_change. A finding only on "
        "a boolean existence indicator or an explicit existence-disclosing differential (never a "
        "uniform non-disclosing response). Pass `url` (base) and optional `endpoints`. Record each "
        "`findings` entry (type user_enumeration).",
        {"url": str, "endpoints": list},
    )
    async def user_enum_probe_tool(args):
        return _wrap(await session.user_enum_probe(args["url"], args.get("endpoints")))

    @tool(
        "ssrf_probe",
        "Detect RESPONSE-REFLECTED SSRF: a URL parameter the server fetches and echoes back "
        "(proving it fetches arbitrary/internal URLs). Sends a benign external canary and flags "
        "only when the FETCHED content is reflected; internal targets add a status differential "
        "only (never their content — no metadata dumped). Pass `url` (base) and optional `sinks` "
        "([[path, param], ...]; default = root × a URL-param catalog). Induces server-side "
        "requests, so it is gated behind OBJECT_PUT write authorization. Record each `findings` "
        "entry (type ssrf). Reflected-only — blind SSRF needs an out-of-band collaborator.",
        {"url": str, "sinks": list},
    )
    async def ssrf_probe_tool(args):
        return _wrap(await session.ssrf_probe(args["url"], args.get("sinks")))

    @tool(
        "func_authz_probe",
        "Detect broken function-level authorization (BFLA), unauthenticated slice: a "
        "privileged/admin-NAMED route reachable with NO auth returning privileged data. GET only "
        "(safe). Distinct from object-level IDOR and from templated file-exposure. Pass `url` "
        "(base) and optional `routes` (a default admin/internal catalog is used otherwise). "
        "Record each `findings` entry (type broken_function_auth). The full BFLA (a normal user "
        "calling an admin route) needs the Wave-2b two-identity scan.",
        {"url": str, "routes": list},
    )
    async def func_authz_probe_tool(args):
        return _wrap(await session.func_authz_probe(args["url"], args.get("routes")))

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
            probe_api_unauth_tool,
            render_page_tool,
            fingerprint_stack_tool,
            templated_checks_tool,
            backend_rls_probe_tool,
            webhook_sig_probe_tool,
            error_leak_probe_tool,
            cors_credentialed_probe_tool,
            mass_assignment_probe_tool,
            user_enum_probe_tool,
            ssrf_probe_tool,
            func_authz_probe_tool,
        ],
    )
