"""The tool core — SDK-free, so the egress↔tool enforcement is unit-testable.

Every network method asks the egress engine first and performs NO I/O unless the
verdict is ALLOW. The HTTP client is dependency-injected (any object with async
`request`/`get`), so tests use a fake and production passes an httpx.AsyncClient.
"""

from __future__ import annotations

import json
from typing import Any, Protocol

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
from kuv.recon.paths import PATH_WORDLIST, extract_paths, extract_scripts, rank_paths
from kuv.recon.tls import TlsProbe, ssl_tls_probe
from kuv.recon.websocket import WsProbe, flags_sensitive, summarize_fields, websockets_probe
from kuv.report import Finding
from kuv.report.redaction import redact_pii
from kuv.scanners import scan_secrets
from kuv.severity import FindingType


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
    async def request(self, method: str, url: str, *, content: Any = ...) -> _Response: ...
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
    ) -> None:
        self.engine = engine
        self.client = client
        self.resolver: Resolver = resolver or dnspython_resolver
        self.ws_probe: WsProbe = ws_probe or websockets_probe
        self.tls_probe: TlsProbe = tls_probe or ssl_tls_probe
        self.browser_probe: BrowserProbe = browser_probe or playwright_probe
        self.findings: list[Finding] = []

    async def http_request(
        self,
        method: str,
        url: str,
        body: str | None = None,
        action_class: ActionClass | None = None,
    ) -> dict:
        verdict = self.engine.evaluate(EgressRequest(method.upper(), url, action_class=action_class))
        if verdict.decision is Decision.REFUSE:
            return {"ok": False, "error": f"REFUSED by egress gate: {verdict.reason}"}
        if verdict.decision is Decision.CONFIRM:
            return {"ok": False, "error": f"NEEDS OPERATOR CONFIRMATION: {verdict.reason}"}
        try:
            resp = await self.client.request(method.upper(), url, content=body)
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
            ft = FindingType(finding_type)
        except ValueError:
            return {
                "ok": False,
                "error": (
                    f"unrecognized finding_type {finding_type!r}; do not invent one — "
                    f"use one of {[f.value for f in FindingType]}"
                ),
            }
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
        return {"ok": True, "severity": finding.severity().value, "priority": finding.priority()}

    def decode_jwt(self, token: str) -> dict:
        result = decode_jwt_role(token)
        return {"role": result.role.value, "is_finding": result.is_finding}

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

    async def enumerate_subdomains(self, apex: str) -> dict:
        """Enumerate common subdomains under an in-scope apex, flagging subdomain-
        takeover candidates. For each host whose CNAME points at a takeover-prone
        service, a gated HTTP GET checks whether the upstream app is actually gone
        (a deleted-app fingerprint or 404/5xx) — catching the "resolves but dead app"
        case that DNS alone (CNAME + no A) misses."""
        allowed, reason = self.engine.check_host(apex, kind="dns")
        if not allowed:
            return {"ok": False, "error": f"REFUSED: {reason}"}

        hosts = _dns_enumerate(apex, self.resolver)
        out: list[dict] = []
        for host in hosts:
            dangling, service, status = host.dangling, host.takeover_service, None
            suffix = takeover_suffix(host.cname)
            if suffix:
                url = f"https://{host.name}/"
                verdict = self.engine.evaluate(EgressRequest("GET", url))
                if verdict.decision is Decision.ALLOW:
                    try:
                        resp = await self.client.get(url)
                        status = resp.status_code
                        if is_takeover(suffix, status, resp.text):
                            dangling, service = True, suffix
                    except Exception:  # noqa: BLE001 — unreachable host is itself a signal
                        dangling, service = True, suffix
            out.append({
                "name": host.name, "a": list(host.a), "cname": host.cname,
                "dangling": dangling, "takeover_service": service, "http_status": status,
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
