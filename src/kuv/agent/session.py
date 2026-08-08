"""The tool core — SDK-free, so the egress↔tool enforcement is unit-testable.

Every network method asks the egress engine first and performs NO I/O unless the
verdict is ALLOW. The HTTP client is dependency-injected (any object with async
`request`/`get`), so tests use a fake and production passes an httpx.AsyncClient.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any, Callable, Protocol

from kuv.decoders import (
    analyze_http_posture,
    analyze_oauth_url,
    check_source_map_exposed,
    classify_secret_prefix,
    decode_jwt_role,
    source_map_url_for,
)
from kuv.egress import Decision, EgressEngine, EgressRequest
from kuv.gate import ActionClass
from kuv.recon.dns import (
    Resolver,
    dnspython_resolver,
    email_auth,
    is_takeover,
    takeover_suffix,
)
from kuv.recon.browser import BrowserProbe, mask_tokens, playwright_probe, redact_path, redact_url
from kuv.recon.dns import enumerate_subdomains as _dns_enumerate
from kuv.recon.fingerprint import fingerprint as _fingerprint
from kuv.recon.templated import CHECKS as _TEMPLATED_CHECKS, run_templated_checks as _run_templated_checks
from kuv.recon.backend_rls import DEFAULT_TABLES as _RLS_TABLES, probe_backend_rls as _probe_backend_rls
from kuv.recon.webhook_sig import DEFAULT_ENDPOINTS as _WEBHOOK_ENDPOINTS, probe_webhook_sig as _probe_webhook_sig
# `_malformed` is the module's deterministic "endpoint -> malformed path" transform; the
# session pre-fetches on that exact key so the sync analyzer's fetch(path) is a cache hit.
from kuv.recon.error_leak import _malformed as _err_malformed, probe_error_leak as _probe_error_leak
from kuv.recon.cors_credentialed import PROBE_ORIGIN as _CORS_ORIGIN, probe_cors as _probe_cors
from kuv.recon.mass_assignment import DEFAULT_ENDPOINTS as _MASS_ENDPOINTS, probe_mass_assignment as _probe_mass_assignment
from kuv.recon.user_enum import DEFAULT_ENDPOINTS as _USERENUM_ENDPOINTS, probe_user_enum as _probe_user_enum
from kuv.recon.ssrf_probe import probe_ssrf as _probe_ssrf
from kuv.recon.func_authz import probe_func_authz as _probe_func_authz
from kuv.recon.endpoints import (
    classify_json_body,
    is_api_path,
    is_exposed,
    is_search_path,
    resource_name,
)
from kuv.recon.paths import PATH_WORDLIST, extract_paths, extract_scripts, rank_paths
from kuv.recon.tls import TlsProbe, ssl_tls_probe
from kuv.recon.websocket import WsProbe, flags_sensitive, summarize_fields, websockets_probe
from kuv.report import Finding
from kuv.report.redaction import redact_pii
from kuv.scanners import scan_secrets
from kuv.severity import FindingType


def _sync_bridge(loop, async_fn):
    """Wrap an async, egress-gated request coroutine as a SYNC callable that a recon
    analyzer (run in a worker thread via asyncio.to_thread) can call directly. Each call
    submits the coroutine to `loop` and blocks the worker thread for the result — so a
    synchronous, response-branching probe (mass_assignment / ssrf / user_enum) drives
    real gated async I/O without the module knowing anything about asyncio. The main loop
    is free to run the coroutine while the worker blocks, so there is no deadlock."""
    def sync(*args):
        return asyncio.run_coroutine_threadsafe(async_fn(*args), loop).result()
    return sync


def _probe_row_to_dict(row, *, location: str | None = None) -> dict:
    """Normalize a recon-probe result row (backend_rls / webhook_sig / error_leak /
    cors_credentialed all share the same fields) into the record_finding shape. The
    caller may override `location` with the concrete probed URL (rows carry a relative
    path). finding_type stays a plain string — severity is the rule table's job."""
    return {
        "finding_type": row.finding_type,
        "title": row.title,
        "location": location if location is not None else row.location,
        "evidence": row.evidence,
        "recommendation": row.recommendation,
        "plain_impact": row.plain_impact,
        "contains_pii_or_secrets": row.contains_pii_or_secrets,
    }


def parse_evidence_rows(raw: str) -> tuple[tuple[str, str], ...]:
    """Parse the agent's evidence_json into (probe, result) rows.

    Accepts a JSON array of either [probe, result] pairs or {"probe","result"}
    objects. Malformed input degrades to no rows (the evidence string still shows).
    """
    if not raw or not raw.strip():
        return ()
    try:
        data = json.loads(raw)
    except (ValueError, TypeError):
        return ()
    if not isinstance(data, list):
        return ()
    rows: list[tuple[str, str]] = []
    for item in data:
        if isinstance(item, dict) and "probe" in item and "result" in item:
            rows.append((str(item["probe"]), str(item["result"])))
        elif isinstance(item, (list, tuple)) and len(item) >= 2:
            rows.append((str(item[0]), str(item[1])))
    return tuple(rows)


def _host_of(url_or_host: str) -> str:
    """Hostname from a URL (any scheme incl. ws/wss) or a bare host string."""
    from urllib.parse import urlparse

    raw = (url_or_host or "").strip()
    if "://" in raw:
        return (urlparse(raw).hostname or "").lower()
    # bare host, possibly host:port/path
    return raw.split("/")[0].split(":")[0].lower()


def _set_cookie_list(headers: Any) -> list[str]:
    """All Set-Cookie header values (HTTP allows several). httpx exposes `get_list`;
    a plain-dict fake collapses to at most one — tolerate both."""
    getter = getattr(headers, "get_list", None)
    if callable(getter):
        try:
            return list(getter("set-cookie"))
        except Exception:  # noqa: BLE001
            pass
    try:
        one = headers.get("set-cookie") if hasattr(headers, "get") else dict(headers).get("set-cookie")
    except Exception:  # noqa: BLE001
        one = None
    return [one] if one else []


class _Response(Protocol):
    status_code: int
    text: str
    headers: Any


class _AsyncClient(Protocol):
    async def request(self, method: str, url: str, *, content: Any = ..., headers: Any = ...) -> _Response: ...
    async def get(self, url: str) -> _Response: ...


class AssessmentSession:
    def __init__(
        self,
        engine: EgressEngine,
        client: _AsyncClient,
        resolver: Resolver | None = None,
        ws_probe: WsProbe | None = None,
        tls_probe: TlsProbe | None = None,
        browser_probe: BrowserProbe | None = None,
        on_event: Callable[[dict], None] | None = None,
    ) -> None:
        self.engine = engine
        self.client = client
        self.resolver: Resolver = resolver or dnspython_resolver
        self.ws_probe: WsProbe = ws_probe or websockets_probe
        self.tls_probe: TlsProbe = tls_probe or ssl_tls_probe
        self.browser_probe: BrowserProbe = browser_probe or playwright_probe
        self.findings: list[Finding] = []
        # Optional live-progress sink (VibeCheck streams these to the browser). Additive:
        # None by default, so assess.py / wizard / eval are unchanged.
        self._on_event = on_event

    # Request headers a caller (the agent) may set — an allowlist. Everything else
    # (Host, X-Forwarded-*, Connection/hop-by-hop, Content-Length, Transfer-Encoding, …)
    # is DROPPED: a `Host`/`X-Forwarded-Host` could route a vhost/proxy to another tenant
    # even while the URL host is in scope (a scope bypass); hop-by-hop/framing headers
    # enable request smuggling.
    _ALLOWED_REQ_HEADERS = frozenset({"authorization", "cookie", "accept"})

    async def http_request(
        self,
        method: str,
        url: str,
        body: str | None = None,
        action_class: ActionClass | None = None,
        content_type: str | None = None,
        headers: dict | None = None,
    ) -> dict:
        # Never-destructive as CODE, not just prompt: DELETE/PATCH cannot be issued at all
        # (none of the write action classes is a delete — account_create=POST, object_put=PUT).
        if method.upper() in ("DELETE", "PATCH"):
            return {"ok": False,
                    "error": "DELETE/PATCH are refused — kuv writes are non-destructive (POST/PUT only)"}
        verdict = self.engine.evaluate(EgressRequest(method.upper(), url, action_class=action_class))
        if verdict.decision is Decision.REFUSE:
            return {"ok": False, "error": f"REFUSED by egress gate: {verdict.reason}"}
        if verdict.decision is Decision.CONFIRM:
            return {"ok": False, "error": f"NEEDS OPERATOR CONFIRMATION: {verdict.reason}"}
        # Without a Content-Type, most JSON APIs reject a write with 415 / fail to parse the
        # body — so a write MUST declare one (default application/json for a JSON body). Then
        # merge in the caller's allowlisted headers (an Authorization/Cookie for auth depth).
        hdrs: dict[str, str] = {}
        if content_type and body is not None:
            hdrs["content-type"] = content_type
        for k, v in (headers or {}).items():
            if str(k).strip().lower() in self._ALLOWED_REQ_HEADERS and len(str(k)) <= 64 and len(str(v)) <= 4096:
                hdrs[str(k)] = str(v)
        try:
            resp = await self.client.request(method.upper(), url, content=body, headers=hdrs or None)
        except Exception as exc:  # noqa: BLE001 — surface the network error to the agent
            return {"ok": False, "error": f"request error: {exc}"}
        return {
            "ok": True,
            "status": resp.status_code,
            "headers": dict(resp.headers),
            "body": resp.text[:6000],
        }

    def record_finding(
        self,
        finding_type: str,
        title: str,
        location: str,
        evidence: str,
        contains_pii_or_secrets: bool = False,
        recommendation: str = "",
        evidence_rows: tuple[tuple[str, str], ...] = (),
        plain_impact: str = "",
    ) -> dict:
        try:
            ft: FindingType | str = FindingType(finding_type)
            novel = False
        except ValueError:
            # Escape hatch: a genuinely novel class with no rule. Record it (never
            # drop it) and tag it for operator triage — the severity becomes the
            # fixed NEEDS_OPERATOR sentinel, never an LLM guess. Require plain_impact:
            # it is the operator's only plain-language handle on an unrated class.
            if not str(plain_impact).strip():
                return {
                    "ok": False,
                    "error": (
                        f"novel finding_type {finding_type!r} requires plain_impact — it is "
                        f"the operator's only plain-language summary for triage. (Prefer one "
                        f"of {[f.value for f in FindingType]} if any fits.)"
                    ),
                }
            ft = str(finding_type)
            novel = True
        rows = tuple(
            (str(p), str(r)) for p, r in evidence_rows if p is not None
        )
        finding = Finding(
            ft,
            title,
            location,
            evidence,
            bool(contains_pii_or_secrets),
            evidence_rows=rows,
            recommendation=recommendation,
            plain_impact=plain_impact,
        )
        self.findings.append(finding)
        if self._on_event is not None:
            self._on_event({
                "type": "finding",
                "severity": finding.severity().value,
                "finding_type": getattr(finding.finding_type, "value", finding.finding_type),
                "title": finding.title,
                "location": finding.location,
                "plain_impact": finding.plain_impact,
            })
        result = {"ok": True, "severity": finding.severity().value, "priority": finding.priority()}
        if novel:
            result["novel"] = True
        return result

    def decode_jwt(self, token: str) -> dict:
        result = decode_jwt_role(token)
        return {
            "role": result.role.value,
            "is_finding": result.is_finding,
            "alg": result.alg,
            # alg=none/empty → the server would accept an unsigned token → file
            # a `jwt_forgeable` finding (Critical) if you PROVE the server honors it.
            "forgeable": result.forgeable,
        }

    def classify_secret(self, token: str) -> dict:
        result = classify_secret_prefix(token)
        return {
            "is_public": result.is_public,
            "matched_prefix": result.matched_prefix,
            "length": result.length,
        }

    async def check_source_map(self, js_url: str) -> dict:
        map_url = source_map_url_for(js_url)
        verdict = self.engine.evaluate(EgressRequest("GET", map_url))
        if verdict.decision is not Decision.ALLOW:
            return {"ok": False, "error": f"REFUSED: {verdict.reason}"}
        try:
            resp = await self.client.get(map_url)
        except Exception as exc:  # noqa: BLE001
            return {"ok": False, "error": f"request error: {exc}"}
        result = check_source_map_exposed(js_url, lambda _u: (resp.status_code, resp.text))
        return {"ok": True, "exposed": result.exposed, "map_url": result.map_url, "reason": result.reason}

    async def scan_js(self, url: str) -> dict:
        """Fetch a JS/asset URL in full and scan it for secrets, returning only the
        hit summary (type/count/length) — the full bundle never enters agent context."""
        verdict = self.engine.evaluate(EgressRequest("GET", url))
        if verdict.decision is not Decision.ALLOW:
            return {"ok": False, "error": f"REFUSED: {verdict.reason}"}
        try:
            resp = await self.client.get(url)
        except Exception as exc:  # noqa: BLE001
            return {"ok": False, "error": f"request error: {exc}"}
        hits = scan_secrets(resp.text)
        return {
            "ok": True,
            "url": url,
            "bytes_scanned": len(resp.text),
            "secrets": [{"type": h.detector, "count": h.count, "max_len": h.max_len} for h in hits],
        }

    async def _sweep_posture(self, name: str) -> tuple[int | None, str, list[str]]:
        """Gated GET of ``https://{name}/`` → ``(status, body, posture_gaps)``.

        Returns ``(None, "", [])`` when the host is off-scope, unreachable, or the GET
        errors. One fetch serves two purposes: the takeover fingerprint needs the
        body, the deterministic header sweep needs the headers.
        """
        url = f"https://{name}/"
        if self.engine.evaluate(EgressRequest("GET", url)).decision is not Decision.ALLOW:
            return None, "", []
        try:
            resp = await self.client.get(url)
        except Exception:  # noqa: BLE001 — an unreachable host is itself a signal
            return None, "", []
        gaps = analyze_http_posture(
            resp.status_code, dict(resp.headers), _set_cookie_list(resp.headers)
        ).gaps
        return resp.status_code, getattr(resp, "text", "") or "", list(gaps)

    async def enumerate_subdomains(self, apex: str) -> dict:
        """Map the attack surface under an in-scope apex: DNS-enumerate subdomains,
        flag subdomain-takeover candidates, AND run the deterministic HTTP security-
        posture sweep on the apex plus every live host it finds.

        The posture sweep is done here, in code, on EVERY reachable host — not left to
        per-host LLM discretion. That discretion was a real recall hole: an agent that
        posture-checked the marketing site + app hosts but skipped a sibling API host
        would silently miss that host's missing-header finding. Each host now carries a
        `posture_gaps` list; a non-empty one is a `weak_transport_or_cors` finding the
        agent must record. The takeover check still uses a gated GET to catch the
        "resolves but dead app" case DNS alone (CNAME + no A) misses.
        """
        allowed, reason = self.engine.check_host(apex, kind="dns")
        if not allowed:
            return {"ok": False, "error": f"REFUSED: {reason}"}

        hosts = _dns_enumerate(apex, self.resolver)
        out: list[dict] = []
        # The apex itself is not in the subdomain wordlist — sweep it explicitly so a
        # gap on the primary host is always covered.
        apex_status, _, apex_gaps = await self._sweep_posture(apex)
        out.append({
            "name": apex, "a": [], "cname": None, "dangling": False,
            "takeover_service": None, "http_status": apex_status, "posture_gaps": apex_gaps,
        })
        for host in hosts:
            dangling, service = host.dangling, host.takeover_service
            status, body, posture_gaps = None, "", []
            if host.a or host.cname:                       # resolves → sweep it
                status, body, posture_gaps = await self._sweep_posture(host.name)
            suffix = takeover_suffix(host.cname)
            if suffix and (status is None or is_takeover(suffix, status, body)):
                dangling, service = True, suffix           # dead app, or won't load at all
            out.append({
                "name": host.name, "a": list(host.a), "cname": host.cname,
                "dangling": dangling, "takeover_service": service,
                "http_status": status, "posture_gaps": posture_gaps,
            })
        return {"ok": True, "apex": apex, "hosts": out}

    def check_email_auth(self, apex: str) -> dict:
        """SPF + DMARC posture for an in-scope apex."""
        allowed, reason = self.engine.check_host(apex, kind="dns")
        if not allowed:
            return {"ok": False, "error": f"REFUSED: {reason}"}
        return {"ok": True, "apex": apex, **email_auth(apex, self.resolver)}

    def analyze_oauth(self, authorize_url: str) -> dict:
        """Deterministically analyze an OAuth authorize URL the agent already found in
        a fetched page — no I/O, so no gate (nothing leaves the process)."""
        cfg = analyze_oauth_url(authorize_url)
        return {
            "ok": True,
            "is_oauth": cfg.is_oauth,
            "provider": cfg.provider,
            "response_type": cfg.response_type,
            "has_state": cfg.has_state,
            "has_pkce": cfg.has_pkce,
            "has_nonce": cfg.has_nonce,
            "hosted_domain": cfg.hosted_domain,
            "redirect_host": cfg.redirect_host,
            "scopes": list(cfg.scopes),
            "gaps": list(cfg.gaps),
        }

    async def check_http_posture(self, url: str) -> dict:
        """Gated GET, then a deterministic parse of the response's security posture
        (CSP / cookies / CORS / transport headers) into a concrete gap list."""
        verdict = self.engine.evaluate(EgressRequest("GET", url))
        if verdict.decision is not Decision.ALLOW:
            return {"ok": False, "error": f"REFUSED: {verdict.reason}"}
        try:
            resp = await self.client.get(url)
        except Exception as exc:  # noqa: BLE001
            return {"ok": False, "error": f"request error: {exc}"}
        set_cookies = _set_cookie_list(resp.headers)
        posture = analyze_http_posture(resp.status_code, dict(resp.headers), set_cookies)
        return {
            "ok": True,
            "url": url,
            "status": resp.status_code,
            "hsts": posture.hsts,
            "csp_present": posture.csp_present,
            "csp_unsafe_inline": posture.csp_unsafe_inline,
            "csp_unsafe_eval": posture.csp_unsafe_eval,
            "csp_dev_origins": list(posture.csp_dev_origins),
            "cors_acao": posture.cors_acao,
            "cors_wildcard": posture.cors_wildcard,
            "cors_allow_credentials": posture.cors_allow_credentials,
            "cookies": [
                {"name": c.name, "secure": c.secure, "httponly": c.httponly, "samesite": c.samesite}
                for c in posture.cookies
            ],
            "gaps": list(posture.gaps),
        }

    async def fingerprint_stack(self, url: str) -> dict:
        """Gated GET, then deterministic tech-stack detection (framework / CMS / BaaS /
        hosting / payment / auth) from headers + body + shipped-script hosts. Recon only
        — it records no finding; its job is to let the methodology BRANCH into stack-
        specific probes (Supabase→RLS, WordPress→wp-json, Stripe→webhooks) instead of
        running one generic sequence against every site."""
        verdict = self.engine.evaluate(EgressRequest("GET", url))
        if verdict.decision is not Decision.ALLOW:
            return {"ok": False, "error": f"REFUSED: {verdict.reason}"}
        try:
            resp = await self.client.get(url)
        except Exception as exc:  # noqa: BLE001
            return {"ok": False, "error": f"request error: {exc}"}
        body = getattr(resp, "text", "") or ""
        fp = _fingerprint(
            resp.status_code,
            dict(resp.headers),
            body,
            cookies=_set_cookie_list(resp.headers),
            js_urls=list(extract_scripts(body)),
        )
        return {
            "ok": True,
            "url": url,
            "status": resp.status_code,
            "tags": fp.tags(),
            "detections": [
                {"category": d.category, "name": d.name, "evidence": d.evidence}
                for d in fp.detections
            ],
        }

    async def templated_checks(self, url: str, *, cap: int = 40) -> dict:
        """Run the curated safe-exposure check library against an in-scope base URL.

        Each check is a single GATED GET whose matcher requires a POSITIVE content
        signature (a body that actually looks like an env file / git config / actuator
        dump), so a SPA that answers 200 for every path is never a false finding. Every
        candidate paths is fetched once (deduped, capped, in-scope-only) and returned as
        deterministic exposure candidates for record_finding — severity comes from the
        rule table keyed on each `finding_type`, never the model.
        """
        base = url if url.endswith("/") else url + "/"
        paths: list[str] = []
        seen: set[str] = set()
        for spec in _TEMPLATED_CHECKS:
            for p in spec.paths:
                if p not in seen:
                    seen.add(p)
                    paths.append(p)
        cache: dict[str, tuple | None] = {}
        probed = 0
        truncated = False
        for p in paths:
            if probed >= cap:
                truncated = True
                break
            target = base + p
            probed += 1
            if self.engine.evaluate(EgressRequest("GET", target)).decision is not Decision.ALLOW:
                cache[p] = None
                continue
            try:
                resp = await self.client.get(target)
                cache[p] = (resp.status_code, dict(resp.headers), getattr(resp, "text", "") or "")
            except Exception:  # noqa: BLE001 — an unreachable path is just "not exposed"
                cache[p] = None
        exposures, _, _ = _run_templated_checks(lambda p: cache.get(p), cap=len(paths) + 1)
        return {
            "ok": True,
            "base": base,
            "probed": probed,
            "truncated": truncated,
            "exposed": [
                {
                    "path": e.path,
                    "finding_type": e.finding_type,
                    "title": e.title,
                    "location": f"GET /{e.path}",
                    "evidence": e.evidence,
                    "recommendation": e.recommendation,
                    "plain_impact": e.plain_impact,
                }
                for e in exposures
            ],
        }

    async def backend_rls_probe(
        self, url: str, *, apikey: str | None = None, style: str | None = None, cap: int = 30
    ) -> dict:
        """Fingerprint-gated (Supabase / Firebase) unauthenticated-read probe: does the
        BaaS data API return rows with NO auth (Row-Level Security not enforced)? Run it
        AFTER fingerprint_stack detects a BaaS and scan_js has surfaced the anon `apikey`.
        One gated GET per curated table name; a candidate is reported ONLY on a positive
        JSON-data signature (a non-empty row set) — never on an empty result / error object
        / SPA HTML shell. It reads real rows, so evidence is value-free (status, row count,
        field KEY names only). `style` auto-detects from the host ('firebase' vs the default
        'supabase'/PostgREST shape) unless given. Record each returned candidate with
        record_finding — severity comes from the rule table, not the model."""
        base = url.rstrip("/")
        host = (_host_of(url) or "").lower()
        if style is None:
            style = "firebase" if ("firebaseio" in host or "firebasedatabase" in host) else "supabase"
        hdrs = {"apikey": apikey, "Authorization": f"Bearer {apikey}"} if apikey else None

        def build(candidate: str) -> str:
            if style == "firebase":
                return f"{base}/{candidate}.json?limitToFirst=2"
            return f"{base}/rest/v1/{candidate}?select=*&limit=2"

        cache: dict[str, tuple | None] = {}
        probed = 0
        for cand in _RLS_TABLES:
            if probed >= cap:
                break
            target = build(cand)
            probed += 1
            if self.engine.evaluate(EgressRequest("GET", target)).decision is not Decision.ALLOW:
                cache[cand] = None
                continue
            try:
                resp = await self.client.get(target, headers=hdrs)
                cache[cand] = (resp.status_code, dict(resp.headers), getattr(resp, "text", "") or "")
            except Exception:  # noqa: BLE001 — an unreachable table is just "not exposed"
                cache[cand] = None

        rows, _, _ = _probe_backend_rls(lambda c: cache.get(c), cap=len(_RLS_TABLES) + 1)
        return {
            "ok": True,
            "base": base,
            "style": style,
            "probed": probed,
            "open_tables": [_probe_row_to_dict(r, location=build(r.location)) for r in rows],
        }

    async def webhook_sig_probe(self, url: str, *, payment_detected: bool = False, cap: int = 12) -> dict:
        """WRITE probe: to each receiver path that carries a PAYMENT-provider signal (the path
        names a provider, or `payment_detected` from fingerprint_stack), POST an UNSIGNED event
        AND the same body with a BOGUS signature header; a receiver that accepts BOTH identically
        does no signature verification, so payment events are forgeable. Paths with no payment
        signal are not probed (a bare 200 at a generic webhook path is not evidence). BLAST
        RADIUS: fake ids + no valid signature mean a non-verifying handler has no real object to
        touch; bounded by `cap`, one finding per provider. Gated as an OBJECT_PUT write — on a
        live target needs write-auth + operator confirmation, else returns that requirement."""
        base = url if url.endswith("/") else url + "/"
        # Pre-check the write class once so an unauthorized/unconfirmed run gets a clear reason.
        pre = self.engine.evaluate(EgressRequest("POST", base, action_class=ActionClass.OBJECT_PUT))
        if pre.decision is Decision.REFUSE:
            return {"ok": False, "error": f"REFUSED by egress gate: {pre.reason}"}
        if pre.decision is Decision.CONFIRM:
            return {"ok": False,
                    "error": f"NEEDS OPERATOR CONFIRMATION (write class object_put): {pre.reason}"}
        loop = asyncio.get_running_loop()

        async def _post(path, body, headers):
            target = base + str(path).lstrip("/")
            if self.engine.evaluate(
                EgressRequest("POST", target, action_class=ActionClass.OBJECT_PUT)
            ).decision is not Decision.ALLOW:
                return None
            try:
                resp = await self.client.request("POST", target, content=body, headers=dict(headers or {}))
                return (resp.status_code, dict(resp.headers), getattr(resp, "text", "") or "")
            except Exception:  # noqa: BLE001 — an unreachable path is just "no receiver"
                return None

        findings, probed, _ = await asyncio.to_thread(
            _probe_webhook_sig, _sync_bridge(loop, _post), _WEBHOOK_ENDPOINTS, cap, payment_detected)
        return {
            "ok": True,
            "base": base,
            "probed": probed,
            "unverified": [_probe_row_to_dict(f, location=base + f.location.removeprefix("POST /"))
                           for f in findings],
        }

    async def error_leak_probe(self, url: str, paths=None, *, cap: int = 20) -> dict:
        """Probe discovered endpoints with a malformed query and report REAL debug/stack-
        trace pages (framework debug mode left on in prod), collapsed to one per framework.
        `paths` are relative endpoint paths (pass the ones discover_paths / render_page
        surfaced; a small built-in starter set is used if omitted). Each is a single GET;
        a finding is recorded only on a positive traceback signature, never a normal styled
        error page. Record each returned leak with record_finding (severity: rule table)."""
        base = url if url.endswith("/") else url + "/"
        endpoints = list(paths) if paths else ["", "api", "api/health", "search", "login"]
        cache: dict[str, tuple | None] = {}
        probed = 0
        for ep in endpoints:
            if probed >= cap:
                break
            mpath = _err_malformed(ep)  # the exact key the analyzer will fetch()
            target = base + mpath.lstrip("/")
            probed += 1
            if self.engine.evaluate(EgressRequest("GET", target)).decision is not Decision.ALLOW:
                cache[mpath] = None
                continue
            try:
                resp = await self.client.get(target)
                cache[mpath] = (resp.status_code, dict(resp.headers), getattr(resp, "text", "") or "")
            except Exception:  # noqa: BLE001
                cache[mpath] = None

        leaks, _, _ = _probe_error_leak(lambda p: cache.get(p), endpoints, cap=len(endpoints) + 1)
        return {
            "ok": True,
            "base": base,
            "probed": probed,
            "leaks": [_probe_row_to_dict(lk, location=base + str(lk.location).lstrip("/")) for lk in leaks],
        }

    async def cors_credentialed_probe(self, url: str, paths=None, *, cap: int = 8) -> dict:
        """Detect the exploitable CORS case a static header check misses: the server
        REFLECTS an arbitrary Origin AND sets Access-Control-Allow-Credentials: true, so any
        website can read a logged-in user's data. One gated GET per target carrying a benign
        attacker-shaped Origin; a finding only when the response reflects that Origin (or
        'null') WITH credentials true. `paths` are relative endpoints to test (a small
        built-in set if omitted). Record each with record_finding (severity: rule table)."""
        base = url if url.endswith("/") else url + "/"
        targets = list(paths) if paths else ["", "api", "api/me", "api/user"]
        cache: dict[str, tuple | None] = {}
        probed = 0
        for path in targets:
            if probed >= cap:
                break
            target = base + str(path).lstrip("/")
            probed += 1
            if self.engine.evaluate(EgressRequest("GET", target)).decision is not Decision.ALLOW:
                cache[path] = None
                continue
            try:
                resp = await self.client.get(target, headers={"Origin": _CORS_ORIGIN})
                cache[path] = (resp.status_code, dict(resp.headers), getattr(resp, "text", "") or "")
            except Exception:  # noqa: BLE001
                cache[path] = None

        findings, _, _ = _probe_cors(lambda p, _o: cache.get(p), targets, cap=len(targets) + 1)
        return {
            "ok": True,
            "base": base,
            "probed": probed,
            "misconfigured": [_probe_row_to_dict(f, location=base + str(f.location).lstrip("/"))
                              for f in findings],
        }

    async def mass_assignment_probe(self, url: str, endpoints=None, *, cap: int = 12) -> dict:
        """WRITE probe: POST a benign synthetic object, then the same object with injected
        privileged fields, then READ BACK the created record with a second, independent GET.
        A finding is recorded ONLY when an injected field is confirmed PERSISTED on read-back
        — an echo alone is never a finding, and this probe NEVER emits privilege_escalation
        (proving a field governs authorization needs a two-identity scan). `endpoints` are
        POST-able collections (pass ones discover_paths found; a default set otherwise). The
        POSTs are gated as an OBJECT_PUT write (needs write-auth + operator confirm on a live
        target, else this returns that requirement); the read-back GET is a passive read.
        Blast radius: it creates synthetic `kuvprobe` rows that persist (the finding notes
        them for manual purge — kuv performs no DELETE)."""
        base = url if url.endswith("/") else url + "/"
        pre = self.engine.evaluate(EgressRequest("POST", base, action_class=ActionClass.OBJECT_PUT))
        if pre.decision is Decision.REFUSE:
            return {"ok": False, "error": f"REFUSED by egress gate: {pre.reason}"}
        if pre.decision is Decision.CONFIRM:
            return {"ok": False,
                    "error": f"NEEDS OPERATOR CONFIRMATION (write class object_put): {pre.reason}"}
        eps = tuple(endpoints) if endpoints else _MASS_ENDPOINTS
        loop = asyncio.get_running_loop()

        async def _request(method, path, body):
            target = base + str(path).lstrip("/")
            m = (method or "GET").upper()
            if m == "GET":  # the read-back leg — a passive read
                if self.engine.evaluate(EgressRequest("GET", target)).decision is not Decision.ALLOW:
                    return None
                try:
                    resp = await self.client.get(target)
                except Exception:  # noqa: BLE001
                    return None
            else:  # the create legs — gated writes
                if self.engine.evaluate(
                    EgressRequest(m, target, action_class=ActionClass.OBJECT_PUT)
                ).decision is not Decision.ALLOW:
                    return None
                try:
                    resp = await self.client.request(
                        m, target, content=body, headers={"content-type": "application/json"})
                except Exception:  # noqa: BLE001
                    return None
            return (resp.status_code, dict(resp.headers), getattr(resp, "text", "") or "")

        findings, probed, _ = await asyncio.to_thread(
            _probe_mass_assignment, _sync_bridge(loop, _request), eps, cap)
        return {
            "ok": True, "base": base, "probed": probed,
            "findings": [_probe_row_to_dict(f) for f in findings],
        }

    async def user_enum_probe(self, url: str, endpoints=None, *, cap: int = 16) -> dict:
        """Detect an account-existence oracle (login/signup/reset that reveals which emails are
        registered). Uses ONLY synthetic kuv-probe identifiers — never a real/guessed user email.
        Availability-check paths are GETs (passive); login/forgot POSTs are gated as auth_change
        (sent only when that class is authorized). A finding is recorded only on a boolean
        existence indicator or an explicit existence-disclosing differential — never a uniform
        non-disclosing response. `endpoints` default to a curated set. finding_type user_enumeration."""
        base = url if url.endswith("/") else url + "/"
        eps = tuple(endpoints) if endpoints else _USERENUM_ENDPOINTS
        loop = asyncio.get_running_loop()

        async def _request(path, method, body):
            target = base + str(path).lstrip("/")
            m = (method or "GET").upper()
            if m == "GET":
                if self.engine.evaluate(EgressRequest("GET", target)).decision is not Decision.ALLOW:
                    return None
                try:
                    resp = await self.client.get(target)
                except Exception:  # noqa: BLE001
                    return None
            else:
                if self.engine.evaluate(
                    EgressRequest(m, target, action_class=ActionClass.AUTH_CHANGE)
                ).decision is not Decision.ALLOW:
                    return None
                try:
                    resp = await self.client.request(
                        m, target, content=body, headers={"content-type": "application/json"})
                except Exception:  # noqa: BLE001
                    return None
            return (resp.status_code, dict(resp.headers), getattr(resp, "text", "") or "")

        findings, probed, _ = await asyncio.to_thread(
            _probe_user_enum, _sync_bridge(loop, _request), eps, cap)
        return {
            "ok": True, "base": base, "probed": probed,
            "findings": [_probe_row_to_dict(f) for f in findings],
        }

    async def ssrf_probe(self, url: str, sinks=None, *, cap: int = 12) -> dict:
        """Detect RESPONSE-REFLECTED SSRF: a URL parameter the server fetches and echoes back
        (proving it will fetch arbitrary/internal URLs). Sends a benign external canary and
        flags only when the FETCHED canary content is reflected; internal targets contribute a
        coarse status differential only (never their content). `sinks` = [[path, param], ...]
        (default: site root × a URL-param-name catalog). It induces server-side requests, so it
        is gated behind OBJECT_PUT write authorization even though the probe requests are GETs.
        Blast radius: makes the target fetch a benign external + well-known internal addresses;
        value-free evidence; bounded by cap. Reflected-only (blind SSRF needs an OOB collaborator)."""
        base = url if url.endswith("/") else url + "/"
        pre = self.engine.evaluate(EgressRequest("POST", base, action_class=ActionClass.OBJECT_PUT))
        if pre.decision is Decision.REFUSE:
            return {"ok": False, "error": f"REFUSED by egress gate: {pre.reason}"}
        if pre.decision is Decision.CONFIRM:
            return {"ok": False,
                    "error": f"NEEDS OPERATOR CONFIRMATION (write class object_put — ssrf induces server-side requests): {pre.reason}"}
        parsed = tuple((str(s[0]), str(s[1])) for s in sinks) if sinks else None
        loop = asyncio.get_running_loop()

        async def _request(path, method, param, url_value):
            target = base + str(path).lstrip("/")
            if self.engine.evaluate(EgressRequest("GET", target)).decision is not Decision.ALLOW:
                return None
            try:
                resp = await self.client.get(target, params={param: url_value})
                return (resp.status_code, dict(resp.headers), getattr(resp, "text", "") or "")
            except Exception:  # noqa: BLE001
                return None

        findings, probed, _ = await asyncio.to_thread(
            _probe_ssrf, _sync_bridge(loop, _request), parsed, cap)
        return {
            "ok": True, "base": base, "probed": probed,
            "findings": [_probe_row_to_dict(f) for f in findings],
        }

    async def func_authz_probe(self, url: str, routes=None, *, cap: int = 20) -> dict:
        """Detect broken function-level authorization (BFLA), unauthenticated slice: a
        privileged/admin-NAMED route reachable with NO auth that returns privileged data.
        GET only (safe). Distinct from object-level IDOR and from templated file-exposure.
        `routes` default to a curated admin/internal-route catalog. finding_type
        broken_function_auth. (The full BFLA — a normal user calling an admin route — needs
        the Wave-2b two-identity scan.)"""
        base = url if url.endswith("/") else url + "/"
        rts = tuple(routes) if routes else None
        loop = asyncio.get_running_loop()

        async def _fetch(path):
            target = base + str(path).lstrip("/")
            if self.engine.evaluate(EgressRequest("GET", target)).decision is not Decision.ALLOW:
                return None
            try:
                resp = await self.client.get(target)
                return (resp.status_code, dict(resp.headers), getattr(resp, "text", "") or "")
            except Exception:  # noqa: BLE001
                return None

        findings, probed, _ = await asyncio.to_thread(
            _probe_func_authz, _sync_bridge(loop, _fetch), rts, cap)
        return {
            "ok": True, "base": base, "probed": probed,
            "findings": [_probe_row_to_dict(f) for f in findings],
        }

    async def probe_websocket(
        self,
        url: str,
        read_json: str = "",
        write_json: str = "",
        origin: str | None = None,
    ) -> dict:
        """Unauthenticated websocket probe. The unauth HANDSHAKE is a passive read,
        scope/budget-gated via check_host. Sending ANY application frame — a subscribe
        (`read_json`) OR a save (`write_json`) — is treated as an active interaction: the
        server may process any frame as a mutation, and the parameter name is not a
        security classification. So every frame goes through the FULL write gate
        (action_class=websocket_save); in a read-only run nothing is sent and only the
        handshake/Origin result is reported. The field summary is presence/count/length
        only — never a value (guardrail #4)."""
        host = _host_of(url)
        allowed, reason = self.engine.check_host(host, kind="websocket")
        if not allowed:
            return {"ok": False, "error": f"REFUSED: {reason}"}

        frames: list[str] = [m for m in (read_json, write_json) if m]
        frames_note: str | None = None
        if frames:
            # Every outbound frame is gated as a write — the read/write parameter name is
            # NOT trusted to classify it (a "subscribe" can be a server-side mutation).
            wv = self.engine.evaluate(
                EgressRequest("POST", url, action_class=ActionClass.WEBSOCKET_SAVE)
            )
            if wv.decision is Decision.ALLOW:
                frames_note = f"{len(frames)} frame(s) sent (synthetic, gate-allowed)"
            else:
                frames = []          # withhold ALL frames — connection/Origin test only
                frames_note = (
                    f"frames withheld ({wv.decision.value}: {wv.reason}) — enable the "
                    f"websocket_save write class to send subscribe/save frames"
                )

        frame = await self.ws_probe(
            url, origin=origin, send=tuple(frames), recv_timeout=5.0, max_messages=8
        )
        summary = summarize_fields(frame.messages)
        return {
            "ok": True,
            "url": url,
            "connected_no_auth": frame.connected,
            "handshake_status": frame.handshake_status,
            "origin_sent": frame.origin_sent,
            "origin_accepted": (frame.connected and origin is not None),
            "messages_received": len(frame.messages),
            "field_summary": summary,
            "sensitive_fields": flags_sensitive(summary),
            "frames_result": frames_note,
            "error": frame.error,
        }

    async def discover_paths(
        self, url: str, probe_wordlist: bool = False, max_bundles: int = 6
    ) -> dict:
        """Discover routes/endpoints on an in-scope host: extract every `/path` from the
        page HTML + its same-origin JS bundles (SPA router tables, links, fetch() calls),
        and — if `probe_wordlist` — additionally probe a curated list of common/sensitive
        paths. Every fetch/probe is egress-gated and charges the run budget; probing stops
        when the budget refuses. Returns deduped, ranked paths with how each was found."""
        from urllib.parse import urljoin, urlparse

        verdict = self.engine.evaluate(EgressRequest("GET", url))
        if verdict.decision is not Decision.ALLOW:
            return {"ok": False, "error": f"REFUSED: {verdict.reason}"}
        try:
            resp = await self.client.get(url)
        except Exception as exc:  # noqa: BLE001
            return {"ok": False, "error": f"request error: {exc}"}

        html = resp.text
        in_scope = self.engine.in_scope
        source: dict[str, str] = {p: "html" for p in extract_paths(html, in_scope)}

        bundles: list[str] = []
        for rel in sorted(extract_scripts(html, in_scope))[:max_bundles]:
            burl = urljoin(url, rel)
            bv = self.engine.evaluate(EgressRequest("GET", burl))
            if bv.decision is not Decision.ALLOW:
                continue                              # off-scope CDN / budget → skip bundle
            try:
                br = await self.client.get(burl)
            except Exception:  # noqa: BLE001
                continue
            bundles.append(rel)
            for p in extract_paths(br.text, in_scope):
                source.setdefault(p, "bundle")

        probed: list[dict] = []
        if probe_wordlist:
            parsed = urlparse(url)
            origin = f"{parsed.scheme}://{parsed.netloc}/"
            for word in PATH_WORDLIST:
                purl = urljoin(origin, word)
                pv = self.engine.evaluate(EgressRequest("GET", purl))
                if pv.decision is not Decision.ALLOW:
                    if "budget" in pv.reason.lower():
                        break                          # budget exhausted → stop probing
                    continue                           # off-scope → skip this word
                try:
                    pr = await self.client.get(purl)
                except Exception:  # noqa: BLE001
                    continue
                probed.append({"path": "/" + word, "status": pr.status_code})
                if pr.status_code < 400:
                    source.setdefault("/" + word, "probe")

        ranked = rank_paths(source.keys())
        cap = 120
        truncated = max(0, len(ranked) - cap)
        return {
            "ok": True,
            "url": url,
            "count": len(ranked),
            "truncated": truncated,
            "paths": [{"path": p, "source": source.get(p, "?")} for p in ranked[:cap]],
            "bundles_scanned": bundles,
            "probed": probed,
        }

    async def probe_api_unauth(self, url: str, *, max_variants: int = 8, cap: int = 40) -> dict:
        """Deterministically unauthenticated-probe every API endpoint discovered on
        `url`'s host, so an unguarded data route can't be silently skipped.

        Discovers paths (page + JS bundles via `discover_paths`), selects the API
        routes (`/v1`, `/api`, `/graphql`, `/rest`), and GETs each with NO auth. REST
        routes are probed bare; search/query routes are ALSO probed with generic
        variants (`?q=…`, and `?index=<resource>` where `<resource>` is derived from
        the OTHER discovered resources — never a hardcoded value) because they need
        params to return data. An endpoint returning a 2xx DATA COLLECTION
        unauthenticated is an `exposed` candidate — the agent files
        `unauth_read_sensitive` for it unless the field names are clearly public.
        `auth_enforced` is true when any sibling returned 401/403 (an exposure next to
        it is an authorization BYPASS). Read-only (GET only); values are never
        returned — only status / shape / count / field NAMES.
        """
        from urllib.parse import urlparse

        disc = await self.discover_paths(url)
        if not disc.get("ok"):
            return {"ok": False, "error": disc.get("error", "path discovery failed")}
        parsed = urlparse(url)
        origin = f"{parsed.scheme}://{parsed.netloc}"

        discovered_api = [p["path"] for p in disc["paths"] if is_api_path(p["path"])]
        api_paths = discovered_api[:cap]
        truncated = len(discovered_api) - len(api_paths)     # coverage we dropped (no silent caps)
        resources: list[str] = []
        for p in api_paths:
            r = resource_name(p)
            if r and r not in resources:
                resources.append(r)

        budget_hit = False

        async def _get(target: str):
            nonlocal budget_hit
            verdict = self.engine.evaluate(EgressRequest("GET", target))
            if verdict.decision is not Decision.ALLOW:
                if "budget" in (verdict.reason or "").lower():
                    budget_hit = True                        # coverage was cut short, not clean
                return None
            try:
                return await self.client.get(target)
            except Exception:  # noqa: BLE001 — unreachable endpoint is not an exposure
                return None

        def _classify(resp) -> dict:
            return classify_json_body(
                resp.status_code, dict(resp.headers).get("content-type", ""),
                getattr(resp, "text", "") or "",
            )

        endpoints: list[dict] = []
        exposed: list[dict] = []
        auth_enforced = False
        probed = 0

        for p in api_paths:
            resp = await _get(origin + p)
            if resp is None:
                continue
            probed += 1
            if resp.status_code in (401, 403):
                auth_enforced = True
            cls = _classify(resp)
            rec = {"path": p, "status": resp.status_code, **cls}
            endpoints.append(rec)
            if is_exposed(resp.status_code, cls):
                rec["exposed"] = True
                exposed.append(rec)
                continue
            if not is_search_path(p):
                continue
            # Search routes need params to return data — try generic variants (bounded).
            # Query-param NAMES are common conventions; `index=<resource>` values come
            # from what we discovered on THIS host, not a fixed target-specific list.
            variants = ["?q=a", "?query=a", "?search=a", "?term=a"] + [
                f"?q=a&index={r}" for r in resources[:4]
            ]
            for qs in variants[:max_variants]:
                vresp = await _get(origin + p + qs)
                if vresp is None:
                    continue
                probed += 1
                if vresp.status_code in (401, 403):
                    auth_enforced = True
                vcls = _classify(vresp)
                if is_exposed(vresp.status_code, vcls):
                    hit = {"path": p + qs, "status": vresp.status_code, "exposed": True, **vcls}
                    endpoints.append(hit)
                    exposed.append(hit)
                    break

        # An exposure NEXT TO a protected sibling (a 401/403 somewhere in the family) is
        # an authorization BYPASS — the high-severity case. Flag those specifically so a
        # wall of `exposed` on a fully-public API doesn't drown the real bypass.
        for e in exposed:
            e["bypass"] = auth_enforced
        partial = budget_hit or truncated > 0                # coverage was NOT exhaustive

        return {
            "ok": True, "url": url, "auth_enforced": auth_enforced,
            "resources": resources, "endpoints": endpoints, "exposed": exposed,
            "discovered_api_count": len(discovered_api), "probed": probed,
            "truncated": truncated, "partial": partial,
        }

    async def render_page(self, url: str) -> dict:
        """Render a JS SPA in a headless browser and report its REAL runtime traffic —
        the XHR/fetch endpoints it calls (its true API origin, even when that origin is
        off-scope and therefore never contacted), the routes its client-side router builds,
        and any in-scope websocket frames. EVERY request the page makes is run through the
        egress gate: off-scope requests are aborted before they leave and reported as
        'discovered but blocked' (so you learn the API origin without touching it); in a
        read-only run the page's own writes/telemetry are blocked too. Values-free:
        query strings are stripped and websocket frames are summarized, never dumped."""
        host = _host_of(url)
        allowed, reason = self.engine.check_host(host, kind="browser")
        if not allowed:
            return {"ok": False, "error": f"REFUSED: {reason}"}

        def gate(method: str, req_url: str) -> tuple[bool, str]:
            verdict = self.engine.evaluate(EgressRequest(method.upper(), req_url))
            return (verdict.decision is Decision.ALLOW, verdict.reason)

        result = await self.browser_probe(url, gate=gate, timeout=20.0, max_requests=45)
        if not result.ok:
            return {"ok": False, "error": result.error or "browser probe failed"}

        def red_url(u: str) -> str:                  # host + token-redacted path, no query
            return redact_pii(redact_url(u))

        def red_txt(s: str) -> str:                  # mask secret-shaped tokens + emails
            return redact_pii(mask_tokens(s))

        api = [
            {"method": r.method, "url": red_url(r.url), "host": r.host,
             "status": r.status, "allowed": r.allowed}
            for r in result.requests if r.resource_type in ("xhr", "fetch")
        ]
        # Hosts the app tried to reach but the gate blocked as off-scope — i.e. the real
        # backend/API origins to consider adding to scope for a follow-up.
        off_scope_hosts = sorted({
            r.host for r in result.requests
            if not r.allowed and r.host and "scope" in r.reason.lower()
        })
        blocked_writes = sorted({
            f"{r.method} {red_url(r.url)}" for r in result.requests
            if not r.allowed and r.method.upper() not in ("GET", "HEAD", "OPTIONS")
        })
        websockets = [
            {"url": red_url(w.url), "host": w.host, "allowed": w.allowed,
             "field_summary": summarize_fields(w.messages), "sensitive_fields": flags_sensitive(summarize_fields(w.messages))}
            for w in result.websockets
        ]
        rendered_paths = [
            redact_pii(redact_path(p))
            for p in rank_paths(extract_paths(result.rendered_html, self.engine.in_scope))
        ]

        return {
            "ok": True,
            "url": url,
            "title": red_txt(result.title),
            "api_calls": api[:80],
            "off_scope_hosts_discovered": off_scope_hosts,
            "blocked_writes": blocked_writes[:40],
            "websockets": websockets,
            "rendered_paths": [{"path": p} for p in rendered_paths[:120]],
            "console_errors": [red_txt(e) for e in result.console_errors[:20]],
            "requests_seen": len(result.requests),
        }

    def check_tls(self, host: str) -> dict:
        """Validate a host's TLS certificate (validity / expiry / hostname / protocol).
        The handshake is scope/budget-gated via check_host."""
        host = _host_of(host) or host
        allowed, reason = self.engine.check_host(host, kind="tls")
        if not allowed:
            return {"ok": False, "error": f"REFUSED: {reason}"}
        result = self.tls_probe(host, port=443, timeout=8.0)
        return {
            "ok": True,
            "host": host,
            "reachable": result.reachable,
            "valid_chain": result.valid_chain,
            "hostname_match": result.hostname_match,
            "expired": result.expired,
            "self_signed": result.self_signed,
            "days_to_expiry": result.days_to_expiry,
            "protocol": result.protocol,
            "issuer": result.issuer,
            "gaps": list(result.gaps),
        }
