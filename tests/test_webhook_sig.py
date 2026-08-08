"""Tests for the unverified-webhook probe (kuv.recon.webhook_sig).

No network: the injected ``post`` callable is faked to return ``(status, headers,
body)`` tuples (or ``None`` for refused). The whole point of the probe is zero false
positives, so the negative, the HTML-catch-all, the no-payment-signal, and the
verifies-the-forged-signature fixtures are as important as the positive one.

The probe emits a PAYMENT-framed finding only when (a) there is a positive
payment-provider signal (the path names a payment provider, or ``payment_detected``),
AND (b) an unsigned event AND the same body carrying a BOGUS signature are BOTH
accepted — the signed-vs-unsigned differential that proves the endpoint verifies
nothing.
"""

from __future__ import annotations

import json

from kuv.recon.webhook_sig import (
    DEFAULT_ENDPOINTS,
    PROBE_BODY,
    PROBE_HEADERS,
    PROBE_SIGNED_HEADERS,
    WebhookFinding,
    _is_unverified,
    _looks_html,
    _payment_provider,
    probe_webhook_sig,
)


# --------------------------------------------------------------------------
# the probe requests themselves are safe by construction
# --------------------------------------------------------------------------


def test_probe_body_is_a_benign_nonexistent_synthetic_event():
    ev = json.loads(PROBE_BODY)
    assert ev["id"] == "evt_kuvprobe000"
    assert ev["data"]["object"]["id"] == "cus_kuvprobe000"
    # benign, non-fulfillment event type
    assert ev["type"] == "customer.created"
    assert ev["livemode"] is False


def test_unsigned_probe_sends_no_signature_header():
    # The omission of any signing header is the entire first request.
    keys = {k.lower() for k in PROBE_HEADERS}
    assert "stripe-signature" not in keys
    assert not any("signature" in k for k in keys)


def test_signed_probe_carries_a_bogus_signature_over_the_same_body():
    # The differential request: SAME body, plus a garbage signature header. A verifying
    # endpoint rejects it; an endpoint that ignores signatures accepts it identically.
    keys = {k.lower() for k in PROBE_SIGNED_HEADERS}
    assert "stripe-signature" in keys
    assert any("signature" in k for k in keys)
    # the bogus signature is non-empty (so a verifier actually has something to reject)
    assert PROBE_SIGNED_HEADERS["stripe-signature"]


# --------------------------------------------------------------------------
# matcher-level: the anti-false-positive discipline
# --------------------------------------------------------------------------


def test_unverified_when_2xx_json_accepted():
    assert _is_unverified(200, '{"received": true}') is True


def test_unverified_when_2xx_empty_body():
    # A non-verifying handler that just returns 200 with no body still proves the flaw.
    assert _is_unverified(200, "") is True


def test_verified_signature_rejection_is_not_a_finding():
    # Stripe's real error when the signature is missing/invalid.
    body = '{"error":{"message":"No signatures found matching the expected signature for payload"}}'
    assert _is_unverified(400, body) is False


def test_unauthorized_is_not_a_finding():
    assert _is_unverified(401, "Unauthorized") is False


def test_missing_receiver_404_and_wrong_method_405_are_not_findings():
    assert _is_unverified(404, "Not Found") is False
    assert _is_unverified(405, "Method Not Allowed") is False


def test_2xx_html_shell_is_not_a_finding():
    html = "<!DOCTYPE html><html><head><title>App</title></head><body>...</body></html>"
    assert _is_unverified(200, html) is False
    assert _looks_html(html) is True


def test_2xx_that_mentions_signature_is_not_a_finding():
    # Even a 2xx body acknowledging a signature check means it verified — reject it.
    assert _is_unverified(200, '{"received": true, "note": "invalid signature ignored"}') is False


def test_2xx_missing_signing_secret_rejection_is_not_a_finding():
    # A handler that DID reject (secret not configured) but answered 200 with a body
    # naming the signing secret/key must not be flagged as unverified.
    assert _is_unverified(200, '{"error":"missing signing secret"}') is False
    assert _is_unverified(200, '{"error":"webhook signing key is not set"}') is False


def test_payment_provider_bucketing():
    # Payment providers are recognized (aliases collapse to one bucket)...
    assert _payment_provider("api/webhooks/stripe") == "stripe"
    assert _payment_provider("api/stripe/webhook") == "stripe"
    assert _payment_provider("api/webhooks/paddle") == "paddle"
    assert _payment_provider("api/webhooks/lemonsqueezy") == "lemonsqueezy"
    assert _payment_provider("hooks/lemon") == "lemonsqueezy"
    assert _payment_provider("api/webhooks/razorpay") == "razorpay"
    assert _payment_provider("api/webhooks/paypal") == "paypal"
    # ...but a generic path and non-payment providers (auth, VCS) carry NO signal.
    assert _payment_provider("api/webhooks") is None
    assert _payment_provider("webhook") is None
    assert _payment_provider("api/webhooks/clerk") is None
    assert _payment_provider("api/webhooks/github") is None


# --------------------------------------------------------------------------
# runner-level BENIGN cases — the whole point of the fix: these emit ZERO findings
# --------------------------------------------------------------------------


def test_benign_generic_catchall_200_with_no_payment_signal_is_empty():
    # THE reviewer false positive. A generic webhook catch-all answers 200
    # {"received":true} for every path, stripe paths 404, and there is NO payment
    # signal (payment_detected=False, no provider in a generic path). The old probe
    # reported this HIGH webhook_unverified with a hard-coded payment impact; the fixed
    # probe emits NOTHING — the generic catch-alls are never even probed.
    def post(path, body, headers):
        if path in ("api/webhooks", "webhook", "api/webhook"):
            return (200, {"content-type": "application/json"}, '{"received": true}')
        return (404, {}, "Not Found")

    findings, probed, truncated = probe_webhook_sig(post, payment_detected=False)
    assert findings == []


def test_benign_single_generic_received_true_is_empty():
    # The exact spec shape: {"received":true} 200 at "api/webhooks", payment_detected
    # False, no provider in the path → nothing (and never even probed).
    def post(path, body, headers):
        return (200, {"content-type": "application/json"}, '{"received": true}')

    findings, probed, truncated = probe_webhook_sig(
        post, candidates=("api/webhooks",), payment_detected=False
    )
    assert findings == []
    assert probed == 0  # no payment signal → not probed at all


def test_benign_stripe_path_that_verifies_the_forged_signature_is_empty():
    # A stripe-named receiver that accepts the UNSIGNED event (tolerates a missing
    # header) but REJECTS the bogus signature — i.e. it actually verifies. The
    # differential must clear it: no finding.
    def post(path, body, headers):
        if path != "api/webhooks/stripe":
            return (404, {}, "Not Found")
        if headers.get("stripe-signature"):  # forged signature present → verify → reject
            return (400, {}, '{"error":"No signatures found matching the expected signature"}')
        return (200, {"content-type": "application/json"}, '{"received": true}')

    findings, probed, truncated = probe_webhook_sig(post)
    assert findings == []


def test_negative_signature_verified_yields_nothing():
    def post(path, body, headers):
        # Every receiver correctly rejects the unsigned event.
        return (400, {"content-type": "application/json"},
                '{"error":"No signatures found matching the expected signature"}')

    findings, probed, truncated = probe_webhook_sig(post, payment_detected=True)
    assert findings == []
    assert probed > 0


def test_html_catchall_yields_nothing():
    def post(path, body, headers):
        return (200, {"content-type": "text/html"},
                "<!doctype html><html><head></head><body>app</body></html>")

    findings, probed, truncated = probe_webhook_sig(post, payment_detected=True)
    assert findings == []


def test_refused_post_yields_nothing():
    def post(path, body, headers):
        return None

    # payment_detected=True so every candidate is eligible and probed once.
    findings, probed, truncated = probe_webhook_sig(post, payment_detected=True)
    assert findings == []
    assert probed == len(DEFAULT_ENDPOINTS)


# --------------------------------------------------------------------------
# runner-level MALICIOUS case — the endpoint that ignores signatures entirely
# --------------------------------------------------------------------------


def test_malicious_stripe_accepts_both_yields_exactly_one_finding():
    # "api/webhooks/stripe" (payment provider in the path) accepts the unsigned event
    # AND the bogus-signature event identically → the endpoint verifies nothing →
    # exactly one High webhook_unverified with payment framing.
    seen_headers = []

    def post(path, body, headers):
        assert body == PROBE_BODY  # both requests carry the SAME body
        if path == "api/webhooks/stripe":
            seen_headers.append(tuple(sorted(k.lower() for k in headers)))
            return (200, {"content-type": "application/json"}, '{"received": true}')
        return (404, {}, "Not Found")

    findings, probed, truncated = probe_webhook_sig(post)
    assert len(findings) == 1
    f = findings[0]
    assert isinstance(f, WebhookFinding)
    assert f.finding_type == "webhook_unverified"
    assert f.contains_pii_or_secrets is False
    assert f.location == "POST /api/webhooks/stripe"
    # payment framing is present in the plain-language impact
    assert "payment" in f.plain_impact.lower()
    # evidence must be value-free: no body values leaked
    assert "received" not in f.evidence
    # the differential really ran: an unsigned request and a signed one both hit the path
    assert any("stripe-signature" not in h for h in seen_headers)
    assert any("stripe-signature" in h for h in seen_headers)
    assert not truncated
    assert probed == 2  # one unsigned + one bogus-signature POST; aliases short-circuited


def test_dedup_one_finding_per_provider_bucket():
    # Endpoint ignores signatures on EVERY path (accepts unsigned AND bogus identically).
    # With payment_detected=True the generic catch-alls are also in scope, yet the five
    # Stripe aliases collapse to one finding and every provider-less catch-all collapses
    # to one payment-detected finding: two total, never the reviewer's "up to four".
    def post(path, body, headers):
        return (200, {"content-type": "application/json"}, "")

    findings, probed, truncated = probe_webhook_sig(post, payment_detected=True)
    assert len(findings) == 2
    assert {f.finding_type for f in findings} == {"webhook_unverified"}
    assert not truncated


def test_cap_is_respected():
    def post(path, body, headers):
        return None  # refused → nothing added to hit_buckets → every path is probed

    findings, probed, truncated = probe_webhook_sig(post, cap=3, payment_detected=True)
    assert probed == 3
    assert truncated is True
