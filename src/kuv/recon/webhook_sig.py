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
* **Payment-provider signal required.** The finding is payment-framed, so it is emitted
  ONLY when there is a positive payment-provider signal for the candidate: the receiver
  path itself names a known payment provider (stripe, paddle, lemonsqueezy, braintree,
  square, razorpay, paypal, chargebee, recurly), or the caller passes
  ``payment_detected=True`` (its fingerprint already saw a payment provider on the
  target). A bare ``200`` at a generic ``/api/webhooks`` with no such signal is NOT
  evidence of a forgeable payment and emits nothing.
* **Signed-vs-unsigned differential.** Acceptance is proven with TWO requests: the
  unsigned event, and the SAME body carrying a syntactically-plausible but BOGUS
  signature header. A finding fires only when BOTH are accepted identically — that is
  what proves the endpoint ignores signatures entirely. If the bogus-signature request
  is rejected (non-2xx or a signature marker), the endpoint verifies ⇒ no finding.
* **Zero false positives.** A vibe-coded SPA answers ``200`` + its HTML shell for any
  path, so an HTML-document body is REJECTED. A body that acknowledges a signature
  check (``"No signatures found…"``, ``"invalid signature"``, ``"unauthorized"``, …)
  is REJECTED — that means the endpoint *did* verify.
* **At most one finding per provider bucket.** Aliases of one receiver (the five Stripe
  spellings, or several generic catch-alls) collapse to a single finding, so a catch-all
  is never reported four times.

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

# The DIFFERENTIAL request: the SAME body, plus a syntactically-plausible but
# cryptographically BOGUS signature. A verifying endpoint rejects this (the signature
# cannot validate against any secret); an endpoint that ignores signatures accepts it
# identically to the unsigned request. Firing ONLY when both are accepted is what proves
# the endpoint does no verification at all — a lone unsigned 200 could be an endpoint
# that merely tolerates a missing header. Stripe- and Standard-Webhooks-style header
# names are both set so the bogus signature lands whatever the provider.
_BOGUS_SIGNATURE = (
    "t=1700000000,"
    "v1=00000000000000000000000000000000000000000000000000000000deadbeef"
)
PROBE_SIGNED_HEADERS: dict = {
    "content-type": "application/json",
    "stripe-signature": _BOGUS_SIGNATURE,
    "webhook-signature": _BOGUS_SIGNATURE,
    "x-signature": _BOGUS_SIGNATURE,
}

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


# Known PAYMENT providers whose forged "payment succeeded" events do real damage. The
# finding is payment-framed, so a candidate needs one of these NAMED IN ITS PATH (or the
# caller's ``payment_detected`` flag) before it can be reported. Non-payment webhook
# providers (clerk auth, github) are deliberately absent: a forged event there is not a
# fake payment, so this probe stays silent on them.
_PAYMENT_PROVIDER_TOKENS: tuple[tuple[str, str], ...] = (
    ("stripe", "stripe"),
    ("paddle", "paddle"),
    ("lemonsqueezy", "lemonsqueezy"),
    ("lemon", "lemonsqueezy"),
    ("braintree", "braintree"),
    ("square", "square"),
    ("razorpay", "razorpay"),
    ("paypal", "paypal"),
    ("chargebee", "chargebee"),
    ("recurly", "recurly"),
)

# Bucket for a payment signal that comes from the caller's fingerprint
# (``payment_detected=True``) rather than from a provider-named path. All such
# provider-less candidates share this ONE bucket, so a set of generic catch-alls
# collapses to a single finding.
_DETECTED_BUCKET = "payment-detected"


def _payment_provider(path: str) -> Optional[str]:
    """Canonical payment-provider bucket NAMED BY the candidate path, or ``None`` when
    the path names no known payment provider. Substring match, so ``api/webhooks/stripe``
    and ``api/stripe/webhook`` both bucket to ``stripe`` and their aliases collapse."""
    low = (path or "").lower()
    for token, bucket in _PAYMENT_PROVIDER_TOKENS:
        if token in low:
            return bucket
    return None


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
    payment_detected: bool = False,
) -> tuple[list[WebhookFinding], int, bool]:
    """POST an unsigned AND a bogus-signature synthetic event to each candidate that
    carries a payment-provider signal; flag receivers that accept BOTH identically.

    ``post(candidate_path, body, headers)`` returns ``(status, headers, body)`` or
    ``None`` (refused/error); the caller sends it through the gated egress. A candidate
    is probed only when there is a positive payment-provider signal — its path names a
    known payment provider, or ``payment_detected`` is True. A finding is emitted only
    when the unsigned event AND the same body with a BOGUS signature header are BOTH
    accepted (2xx, non-HTML, no signature-check marker): that differential proves the
    endpoint does no signature verification at all. At most ``cap`` POSTs total, and at
    most one finding per provider bucket (aliases of one receiver never double-count).
    Returns ``(findings, probed_count, truncated)``.
    """
    out: list[WebhookFinding] = []
    probed = 0
    truncated = False
    hit_buckets: set[str] = set()

    for path in candidates:
        # A payment-framed finding needs a POSITIVE payment-provider signal: either the
        # receiver path names a known payment provider, or the caller's fingerprint
        # already detected a payment provider on this target. Without one, a bare 200 at
        # a generic webhook path is NOT evidence of a forgeable payment — emit nothing.
        bucket = _payment_provider(path)
        if bucket is None:
            if not payment_detected:
                continue
            bucket = _DETECTED_BUCKET

        if bucket in hit_buckets:
            continue  # this receiver is already proven — never re-probe or double-count

        if probed >= cap:
            truncated = True
            return out, probed, truncated
        res_unsigned = post(path, PROBE_BODY, PROBE_HEADERS)
        probed += 1
        if res_unsigned is None:
            continue
        s1, _h1, b1 = res_unsigned
        if not _is_unverified(s1, b1):
            continue  # unsigned event rejected / HTML / sig-marker → endpoint is fine

        if probed >= cap:
            truncated = True
            return out, probed, truncated
        # Differential: the SAME body, now carrying a bogus signature header.
        res_bogus = post(path, PROBE_BODY, PROBE_SIGNED_HEADERS)
        probed += 1
        if res_bogus is None:
            continue
        s2, _h2, b2 = res_bogus
        if not _is_unverified(s2, b2):
            continue  # forged signature REJECTED → endpoint verifies → NOT a finding

        # Unsigned AND forged-signature events were both accepted identically: the
        # endpoint ignores webhook signatures entirely.
        hit_buckets.add(bucket)
        out.append(
            WebhookFinding(
                finding_type="webhook_unverified",
                title=_TITLE,
                location=f"POST /{path}",
                # value-free: statuses + byte counts only; the dual acceptance IS the signal.
                evidence=(
                    f"POST /{path} unsigned → {s1}, {len(b1 or '')} bytes; "
                    f"same body + bogus signature → {s2}, {len(b2 or '')} bytes; "
                    "both accepted, neither HTML nor a signature-check marker — "
                    "endpoint ignores webhook signatures"
                ),
                recommendation=_RECOMMENDATION,
                plain_impact=_PLAIN_IMPACT,
                contains_pii_or_secrets=False,
            )
        )
    return out, probed, truncated
