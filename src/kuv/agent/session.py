"""The tool core — SDK-free, so the egress↔tool enforcement is unit-testable.

Every network method asks the egress engine first and performs NO I/O unless the
verdict is ALLOW. The HTTP client is dependency-injected (any object with async
`request`/`get`), so tests use a fake and production passes an httpx.AsyncClient.
"""

from __future__ import annotations

import json
from typing import Any, Protocol

from kuv.decoders import (
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
from kuv.recon.dns import enumerate_subdomains as _dns_enumerate
from kuv.report import Finding
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
    ) -> None:
        self.engine = engine
        self.client = client
        self.resolver: Resolver = resolver or dnspython_resolver
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
