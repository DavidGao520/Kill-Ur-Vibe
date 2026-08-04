"""Tests for the websocket field-summary + TLS verdict helpers (pure parts)."""

from __future__ import annotations

from kuv.recon.tls import _verifying_context, verdict_gaps
from kuv.recon.websocket import flags_sensitive, summarize_fields


# ---- websocket field summary (values must NEVER appear) ----

def test_summary_counts_fields_without_values():
    msgs = [
        '{"user":{"hash":"AAAAAAA","salt":"BBBB","name":"Alice"}}',
        '{"user":{"hash":"CCCCCCCCCC","salt":"","name":"Bob"}}',
    ]
    summary = summarize_fields(msgs)
    by = {r["field"]: r for r in summary}
    assert by["user.hash"]["count"] == 2 and by["user.hash"]["non_empty"] == 2
    assert by["user.hash"]["max_len"] == 10          # length recorded, not the value
    assert by["user.salt"]["non_empty"] == 1         # the empty "" is not counted
    # no field row leaks an actual value string
    for row in summary:
        assert "AAAAAAA" not in str(row) and "Alice" not in str(row)


def test_summary_flags_sensitive_field_names():
    summary = summarize_fields(['{"passwordResetToken":"x","googleAccessToken":"y","color":"blue"}'])
    hits = flags_sensitive(summary)
    assert "passwordResetToken" in hits and "googleAccessToken" in hits
    assert "color" not in hits


def test_summary_ignores_non_json_frames():
    assert summarize_fields(["not json", "", "{bad"]) == []


def test_summary_redacts_secret_used_as_a_dict_key():
    # A server that keys a map BY a reset-token / JWT / email must not leak that key.
    msgs = ['{"resetTokens":{"a1b2c3-secret-reset-token-value":{"userId":5}},'
            '"sessions":{"user@example.com":{"active":true}}}']
    summary = summarize_fields(msgs)
    blob = str(summary)
    assert "a1b2c3-secret-reset-token-value" not in blob    # the token-as-key is redacted
    assert "user@example.com" not in blob                   # the email-as-key is redacted
    assert "<key:" in blob                                  # replaced by presence+length
    # a normal short schema key is preserved
    assert any("userId" in r["field"] for r in summary)


def test_summary_redacts_short_alphanumeric_secret_keys():
    # The hard case: secrets used as keys that are <=32 chars and purely alphanumeric —
    # a session id, an MD5 reset token, and a Stripe-style key. None may leak.
    # (The Stripe-shaped literal is split so it is not a scannable token in source.)
    stripe_key = "sk_live_4eC39" + "HqLyjWDarjtT1zdp7dc"
    session_id = "26vosl5pn3g4h9k2m7q1r8s4t6ab"
    md5_token = "7c9e6679742540de8a3b1c9d0f2e4a6b"
    frame = ('{"sessions":{"' + session_id + '":{"user":"alice"}},'
             '"resetTokens":{"' + md5_token + '":{"userId":5}},'
             '"apiKeys":{"' + stripe_key + '":{"scope":"full"}}}')
    summary = summarize_fields([frame])
    from kuv.recon.websocket import flags_sensitive
    blob = str(summary) + str(flags_sensitive(summary))
    assert session_id not in blob        # session id
    assert md5_token not in blob         # MD5 reset token
    assert stripe_key not in blob        # Stripe-style key
    # the structural (safe) parent field names survive
    assert any(r["field"].startswith("resetTokens") for r in summary)


def test_summary_keeps_real_field_names_that_look_identifier_ish():
    # Guard against over-redaction: legitimate camelCase/underscore field names, even
    # long ones or with a trailing digit, must be preserved.
    keep = ["userId", "googleAccessToken", "passwordResetExpiration", "sessionId",
            "created_at", "address1", "sha256", "isActive"]
    frame = "{" + ",".join(f'"{k}":"v"' for k in keep) + "}"
    fields = {r["field"] for r in summarize_fields([frame])}
    for k in keep:
        assert k in fields, f"{k} was wrongly redacted"


# ---- TLS verdict ----

def test_tls_unreachable_is_single_gap():
    gaps = verdict_gaps(reachable=False, valid_chain=False, hostname_match=False,
                        expired=False, self_signed=False, protocol=None)
    assert len(gaps) == 1 and "unreachable" in gaps[0]


def test_tls_expired_and_obsolete_protocol():
    gaps = verdict_gaps(reachable=True, valid_chain=False, hostname_match=True,
                        expired=True, self_signed=False, protocol="TLSv1")
    assert any("expired" in g for g in gaps)
    assert any("obsolete" in g for g in gaps)


def test_tls_clean_cert_has_no_gaps():
    gaps = verdict_gaps(reachable=True, valid_chain=True, hostname_match=True,
                        expired=False, self_signed=False, protocol="TLSv1.3")
    assert gaps == ()


def test_verifying_context_has_a_real_trust_store():
    # Regression: on a python.org build the default SSL context can have 0 CA roots,
    # which made check_tls false-positive `insecure_tls` on EVERY site. The verifying
    # context must end up with a real trust store (falling back to certifi), so cert
    # validity is actually assessable rather than universally "failed".
    ctx, has_trust = _verifying_context()
    assert has_trust is True
    assert ctx.cert_store_stats().get("x509_ca", 0) > 0
