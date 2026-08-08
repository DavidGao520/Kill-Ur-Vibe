"""Deterministic detection of the *exploitable* CORS misconfiguration a static
header check misses: a server that **reflects an arbitrary requesting Origin**
(or answers ``Access-Control-Allow-Origin: null``) **while also** setting
``Access-Control-Allow-Credentials: true``. That combination tells the browser to
hand a logged-in user's *credentialed* response to any website that asks — a
cross-site read of private data. (``Access-Control-Allow-Origin: *`` alone is NOT
this: browsers refuse to attach credentials to a wildcard, so it is not exploitable.)

Pure and I/O-free. Every classification is over already-fetched headers; the one
network primitive is the INJECTED ``fetch_with_origin`` callable — this module does
NO network, NO disk, NO shell.

Safety properties:

* **Non-mutating**: the only request is a plain GET with an added ``Origin`` header
  (``fetch_with_origin(path, origin)``). It reads, never writes.
* **Bounded**: at most one request per target, and never more than ``cap`` requests
  total (``probe_cors`` returns ``truncated=True`` if it hits the cap).
* **Zero false positives from SPA catch-alls**: the positive signal is a *header
  combination* (a reflected/``null`` Origin PLUS credentials) that a vibe-coded SPA
  shell cannot fake — it serves ``200`` + an HTML body for any path, but it does not
  echo an attacker-chosen Origin back with ``Allow-Credentials: true``. A 200 + HTML
  document with no such headers therefore yields nothing.
* **Value-free evidence**: evidence names the two response headers and their literal
  CORS tokens only. No response body, cookie, token, or PII is ever recorded.
* This module NEVER imports or assigns a severity — it reports what it deterministically
  observed; the session/severity layer decides the rest.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Callable, Iterable, Optional

# The benign, attacker-shaped Origin we ask each target to trust. It is a fixed
# public example domain (RFC 6761 reserved TLD) that the target does not own, so a
# server echoing it back into Access-Control-Allow-Origin *is* reflecting an
# arbitrary origin — the defining signal of the exploitable pattern.
PROBE_ORIGIN = "https://kuv-probe.example"

FINDING_TYPE = "credentialed_cors"

_TITLE = "Any website can read your users' logged-in data (CORS misconfiguration)"
_RECOMMENDATION = (
    "Never reflect an arbitrary request Origin (or 'null') into "
    "Access-Control-Allow-Origin while Access-Control-Allow-Credentials is true. "
    "Replace the reflected/'null' origin with an explicit allowlist of trusted "
    "origins and enable credentials only for those; if the endpoint does not need "
    "cookies/authorization, drop Access-Control-Allow-Credentials entirely."
)
_PLAIN_IMPACT = (
    "Your server tells the browser to share your logged-in users' private responses "
    "with any website. A malicious page a user visits while signed in can silently "
    "read their account data — profile, messages, tokens — as if it were them."
)


# --------------------------------------------------------------------------
# result row (field names the session layer maps to record_finding)
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class CorsFinding:
    finding_type: str
    title: str
    location: str
    evidence: str
    recommendation: str
    plain_impact: str
    contains_pii_or_secrets: bool = False


# --------------------------------------------------------------------------
# header helpers
# --------------------------------------------------------------------------


def _header(headers: dict, name: str) -> Optional[str]:
    """Case-insensitive single-header lookup; returns the raw value or ``None``."""
    target = name.lower()
    for k, v in (headers or {}).items():
        if str(k).lower() == target:
            return str(v)
    return None


def _verdict(sent_origin: str, resp_headers: dict) -> Optional[str]:
    """Return ``"reflected"``, ``"null"``, or ``None`` for the dangerous pattern.

    Dangerous iff ``Access-Control-Allow-Credentials`` is exactly ``true``
    (case-insensitive) AND ``Access-Control-Allow-Origin`` either byte-matches the
    Origin we sent (reflection) or is the literal ``null``. A missing ACAO, ACAO
    fixed to some other (site-owned) origin, or ACAO ``*`` all return ``None`` — the
    wildcard case is explicitly excluded because browsers refuse to send credentials
    with it, so it is not exploitable.
    """
    acac = _header(resp_headers, "access-control-allow-credentials")
    if acac is None or acac.strip().lower() != "true":
        return None
    acao = _header(resp_headers, "access-control-allow-origin")
    if acao is None:
        return None
    value = acao.strip()
    if value == "*":  # not exploitable with credentials
        return None
    if value.lower() == "null":
        return "null"
    sent = (sent_origin or "").strip()
    # Reflection: the server echoed the exact arbitrary Origin we chose. `sent` is a
    # unique domain the target does not own, so an equality here can only be a reflect.
    if sent and value.lower() == sent.lower():
        return "reflected"
    return None


def _evidence(kind: str, sent_origin: str) -> str:
    if kind == "null":
        return (
            "Access-Control-Allow-Origin: null with "
            "Access-Control-Allow-Credentials: true"
        )
    return (
        f"Access-Control-Allow-Origin reflected the request Origin ({sent_origin}) "
        "with Access-Control-Allow-Credentials: true"
    )


def classify_cors(sent_origin: str, resp_headers: dict) -> Optional[CorsFinding]:
    """Given the Origin we sent and the response headers, return a :class:`CorsFinding`
    for the exploitable credentialed-CORS pattern, or ``None``.

    ``location`` on the returned row defaults to ``sent_origin`` (the cross-origin
    caller that was granted credentialed access). :func:`probe_cors` overrides it with
    the concrete endpoint path it observed.
    """
    kind = _verdict(sent_origin, resp_headers)
    if kind is None:
        return None
    return CorsFinding(
        finding_type=FINDING_TYPE,
        title=_TITLE,
        location=sent_origin,
        evidence=_evidence(kind, sent_origin),
        recommendation=_RECOMMENDATION,
        plain_impact=_PLAIN_IMPACT,
        contains_pii_or_secrets=False,
    )


def probe_cors(
    fetch_with_origin: Callable[[str, str], Optional[tuple]],
    targets: Iterable[str],
    cap: int = 8,
) -> tuple[list[CorsFinding], int, bool]:
    """Send one credentialed-CORS probe per target and collect findings.

    ``fetch_with_origin(path, origin)`` issues a GET carrying ``Origin: <origin>`` and
    returns ``(status, headers, body)`` or ``None`` (refused/error). At most one
    request per target and never more than ``cap`` requests total. Returns
    ``(findings, probed_count, truncated)``.
    """
    out: list[CorsFinding] = []
    probed = 0
    truncated = False
    for path in targets:
        if probed >= cap:
            truncated = True
            return out, probed, truncated
        res = fetch_with_origin(path, PROBE_ORIGIN)
        probed += 1
        if res is None:
            continue
        # Only the headers matter for CORS; tolerate a 2- or 3-element response tuple.
        headers = res[1] if len(res) > 1 else {}
        finding = classify_cors(PROBE_ORIGIN, headers)
        if finding is not None:
            out.append(replace(finding, location=path))
    return out, probed, truncated
