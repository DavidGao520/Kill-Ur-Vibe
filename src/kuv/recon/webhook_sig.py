"""Detect a payment/webhook receiver that does NOT verify event signatures.

A signature-checking webhook endpoint (Stripe, Clerk, GitHub, …) rejects any event
that does not carry a valid provider signature. A vibe-coded handler that skips that
check — the `res.json({received: true})` tutorial pattern — will happily accept a
**forged** event: an attacker can POST a fake ``payment_intent.succeeded`` and unlock
paid features, mark an order paid, or grant credits without ever paying. This probe
proves the flaw the only way that is sound — by sending one unsigned event and seeing
whether it is accepted — while doing **zero damage to the third party's production**.

Safety / blast-radius properties (the whole reason this is legitimate to run):

* **Pure and I/O-free.** This module does NO network, disk, or shell. Every request
  goes through the INJECTED ``post`` callable (gated egress), exactly like
  ``run_templated_checks(fetch, …)`` in :mod:`kuv.recon.templated`.
* **No valid signature is ever sent.** The probe deliberately omits the
  ``Stripe-Signature`` (and any signing) header — that omission is the entire test.
* **References a NON-EXISTENT object id.** The synthetic event points at
  ``evt_kuvprobe000`` / ``cus_kuvprobe000`` — ids that do not exist — so even a
  non-verifying handler that *proceeds* has no real object to look up or mutate.
* **Benign, non-mutating event type.** The event type is ``customer.created`` (an
  informational type), not a fulfillment/payment trigger, so a naive handler hits a
  no-op branch rather than a "grant value" branch.
* **Single POST per candidate, bounded by ``cap``.** Aliases of the same provider are
  probed at most once (dedup by provider), so a match short-circuits its siblings.
* **Zero false positives.** A vibe-coded SPA answers ``200`` + its HTML shell for any
  path, so an HTML-document body is REJECTED. A body that acknowledges a signature
  check (``"No signatures found…"``, ``"invalid signature"``, ``"unauthorized"``, …)
  is REJECTED — that means the endpoint *did* verify. Only a real 2xx acceptance of an
  unsigned event, that is neither HTML nor a signature rejection, is a finding.

The module never imports :mod:`kuv.severity` and never decides a severity — it emits a
plain ``finding_type`` string; the deterministic severity table maps it downstream.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Callable, Optional

# --------------------------------------------------------------------------
# result row  (field names are mapped 1:1 to session.record_finding)
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class WebhookFinding:
    finding_type: str
    title: str
    location: str
    evidence: str
    recommendation: str
    plain_impact: str
    contains_pii_or_secrets: bool = False


# --------------------------------------------------------------------------
# common webhook-receiver paths (the search space)
# --------------------------------------------------------------------------

DEFAULT_ENDPOINTS: tuple[str, ...] = (
    "api/webhooks/stripe",
    "api/webhook/stripe",
    "api/stripe/webhook",
    "webhooks/stripe",
    "api/webhooks",
    "webhook",
    "api/webhook",
    "stripe/webhook",
    "api/webhooks/clerk",
    "api/webhooks/github",
)

# --------------------------------------------------------------------------
# the synthetic, NON-MUTATING probe event
# --------------------------------------------------------------------------

# A minimal Stripe-shaped event. `type` is informational (not a payment/fulfillment
# trigger) and BOTH ids are non-existent probe ids, so a handler that fails to verify
# and proceeds anyway still has no real object to touch.
_PROBE_EVENT_ID = "evt_kuvprobe000"
_PROBE_OBJECT_ID = "cus_kuvprobe000"

_SYNTHETIC_EVENT: dict = {
    "id": _PROBE_EVENT_ID,
    "object": "event",
    "type": "customer.created",
    "api_version": "2020-08-27",
    "livemode": False,
    "data": {"object": {"id": _PROBE_OBJECT_ID, "object": "customer"}},
}

# Deterministic serialization (sorted keys) so the request body is byte-stable.
PROBE_BODY: str = json.dumps(_SYNTHETIC_EVENT, sort_keys=True, separators=(",", ":"))

# Note the ABSENCE of any `Stripe-Signature` / signing header — that omission is the
# whole test. `content-type` only.
PROBE_HEADERS: dict = {"content-type": "application/json"}

# --------------------------------------------------------------------------
# matchers
# --------------------------------------------------------------------------

# Body markers that mean the endpoint DID check the signature (or otherwise rejected
# the unsigned request) — any of these ⇒ NOT a finding. "signature" alone subsumes
# Stripe's "No signatures found matching…" and "invalid signature"; the rest are
# listed explicitly for clarity and to catch generic auth rejections.
_SIG_MARKERS: tuple[str, ...] = (
    "signature",
    "no signatures",
    "webhook secret",
    "signing secret",
    "signing key",
    "stripe-signature",
    "unauthorized",
    "invalid signature",
)


def _looks_html(body: str) -> bool:
    """A body starting with an HTML doctype/`<html>`, or an early `<head>`, is an SPA
    shell — a real webhook receiver returns JSON or an empty body, never a page."""
    head = (body or "")[:600].lstrip().lower()
    return head.startswith("<!doctype html") or head.startswith("<html") or "<head" in head[:200]


def _is_unverified(status: int, body: str) -> bool:
    """True iff the response proves the endpoint accepted our UNSIGNED synthetic event.

    Requires a positive acceptance signature: a 2xx status whose body is neither an
    HTML document (SPA catch-all) nor a signature-check / auth rejection. Any non-2xx
    (400/401/403 = verified/rejected, 404/405 = no receiver / wrong method) is not a
    finding.
    """
    try:
        code = int(status)
    except (TypeError, ValueError):
        return False
    if not (200 <= code < 300):
        return False
    if _looks_html(body):
        return False
    low = (body or "").lower()
    if any(m in low for m in _SIG_MARKERS):
        return False
    return True


def _provider(path: str) -> str:
    """Coarse provider bucket for a candidate path, so alias paths of ONE receiver
    (e.g. the five Stripe spellings) are not reported five times."""
    low = (path or "").lower()
    if "stripe" in low:
        return "stripe"
    if "clerk" in low:
        return "clerk"
    if "github" in low:
        return "github"
    return "generic"


# --------------------------------------------------------------------------
# entry point
# --------------------------------------------------------------------------

_TITLE = "Payment/webhook events can be forged because they are not signature-checked"
_RECOMMENDATION = (
    "Verify every incoming webhook against the provider's signing secret before acting "
    "on it — for Stripe, call stripe.webhooks.constructEvent(rawBody, the "
    "Stripe-Signature header, endpointSecret) and reject any request whose signature is "
    "missing or invalid; never trust the event body alone. Keep the signing secret out "
    "of client code."
)
_PLAIN_IMPACT = (
    "Your app accepts webhook events without checking that they truly came from the "
    "payment/service provider. Anyone who knows this URL can POST a forged event — for "
    "example a fake 'payment succeeded' — and have it treated as genuine, unlocking paid "
    "features, marking orders as paid, or granting credits without anyone ever paying."
)


def probe_webhook_sig(
    post: Callable[[str, str, dict], Optional[tuple]],
    candidates: tuple[str, ...] = DEFAULT_ENDPOINTS,
    cap: int = 12,
) -> tuple[list[WebhookFinding], int, bool]:
    """POST one unsigned synthetic event to each candidate; flag receivers that accept it.

    ``post(candidate_path, body, headers)`` returns ``(status, headers, body)`` or
    ``None`` (refused/error); the caller sends it through the gated egress. At most
    ``cap`` POSTs total. Aliases of an already-flagged provider are skipped (they cost
    no budget). Returns ``(findings, probed_count, truncated)``.
    """
    out: list[WebhookFinding] = []
    probed = 0
    truncated = False
    hit_providers: set[str] = set()

    for path in candidates:
        provider = _provider(path)
        if provider in hit_providers:
            continue  # same receiver already proven — do not re-probe or double-count
        if probed >= cap:
            truncated = True
            return out, probed, truncated
        res = post(path, PROBE_BODY, PROBE_HEADERS)
        probed += 1
        if res is None:
            continue
        status, _headers, body = res
        if _is_unverified(status, body):
            hit_providers.add(provider)
            out.append(
                WebhookFinding(
                    finding_type="webhook_unverified",
                    title=_TITLE,
                    location=f"POST /{path}",
                    # value-free: status + byte count only; the acceptance IS the signal.
                    evidence=(
                        f"POST /{path} → {status}, {len(body or '')} bytes; "
                        "unsigned synthetic event accepted, response is not HTML and "
                        "contains no signature-check marker"
                    ),
                    recommendation=_RECOMMENDATION,
                    plain_impact=_PLAIN_IMPACT,
                    contains_pii_or_secrets=False,
                )
            )
    return out, probed, truncated
