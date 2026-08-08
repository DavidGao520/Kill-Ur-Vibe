"""Tests for the unverified-webhook probe (kuv.recon.webhook_sig).

No network: the injected ``post`` callable is faked to return ``(status, headers,
body)`` tuples (or ``None`` for refused). The whole point of the probe is zero false
positives, so the negative and HTML-catch-all fixtures are as important as the
positive one.
"""

from __future__ import annotations

import json

from kuv.recon.webhook_sig import (
    DEFAULT_ENDPOINTS,
    PROBE_BODY,
    PROBE_HEADERS,
    WebhookFinding,
    _is_unverified,
    _looks_html,
    _provider,
    probe_webhook_sig,
)


# --------------------------------------------------------------------------
# the probe request itself is safe by construction
# --------------------------------------------------------------------------


def test_probe_body_is_a_benign_nonexistent_synthetic_event():
    ev = json.loads(PROBE_BODY)
    assert ev["id"] == "evt_kuvprobe000"
    assert ev["data"]["object"]["id"] == "cus_kuvprobe000"
    # benign, non-fulfillment event type
    assert ev["type"] == "customer.created"
    assert ev["livemode"] is False


def test_probe_sends_no_signature_header():
    # The omission of any signing header is the entire test.
    keys = {k.lower() for k in PROBE_HEADERS}
    assert "stripe-signature" not in keys
    assert not any("signature" in k for k in keys)


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


def test_provider_bucketing_dedupes_aliases():
    assert _provider("api/webhooks/stripe") == "stripe"
    assert _provider("api/stripe/webhook") == "stripe"
    assert _provider("api/webhooks/clerk") == "clerk"
    assert _provider("api/webhooks/github") == "github"
    assert _provider("api/webhooks") == "generic"


# --------------------------------------------------------------------------
# runner-level: fetch loop, provider dedup, cap
# --------------------------------------------------------------------------


def test_positive_unverified_stripe_yields_exactly_one_finding():
    def post(path, body, headers):
        assert body == PROBE_BODY and headers == PROBE_HEADERS
        if path == "api/webhooks/stripe":
            return (200, {"content-type": "application/json"}, '{"received": true}')
        return (404, {}, "Not Found")

    findings, probed, truncated = probe_webhook_sig(post)
    assert len(findings) == 1
    f = findings[0]
    assert isinstance(f, WebhookFinding)
    assert f.finding_type == "webhook_unverified"
    assert f.contains_pii_or_secrets is False
    assert f.location == "POST /api/webhooks/stripe"
    # evidence must be value-free: no body values leaked
    assert "received" not in f.evidence
    assert not truncated
    assert probed > 0


def test_negative_signature_verified_yields_nothing():
    def post(path, body, headers):
        # Every receiver correctly rejects the unsigned event.
        return (400, {"content-type": "application/json"},
                '{"error":"No signatures found matching the expected signature"}')

    findings, probed, truncated = probe_webhook_sig(post)
    assert findings == []
    assert probed > 0


def test_html_catchall_yields_nothing():
    def post(path, body, headers):
        return (200, {"content-type": "text/html"},
                "<!doctype html><html><head></head><body>app</body></html>")

    findings, probed, truncated = probe_webhook_sig(post)
    assert findings == []


def test_refused_post_yields_nothing():
    def post(path, body, headers):
        return None

    findings, probed, truncated = probe_webhook_sig(post)
    assert findings == []
    assert probed == len(DEFAULT_ENDPOINTS)


def test_alias_dedup_reports_one_finding_per_provider():
    # Every path accepts the unsigned event; aliases of one provider must collapse.
    def post(path, body, headers):
        return (200, {"content-type": "application/json"}, "")

    findings, probed, truncated = probe_webhook_sig(post)
    # stripe + generic + clerk + github = 4 distinct receivers
    assert len(findings) == 4
    assert {f.finding_type for f in findings} == {"webhook_unverified"}
    # only 4 real POSTs; the 6 alias paths were skipped (no budget spent)
    assert probed == 4
    assert not truncated


def test_cap_is_respected():
    def post(path, body, headers):
        return None  # refused → nothing added to hit_providers → every path is probed

    findings, probed, truncated = probe_webhook_sig(post, cap=3)
    assert probed == 3
    assert truncated is True
