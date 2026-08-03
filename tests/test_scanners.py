"""Tests for the secret scanner (TruffleHog-lite)."""

from __future__ import annotations

from kuv.scanners import scan_secrets


def _types(text):
    return {h.detector for h in scan_secrets(text)}


def test_detects_high_signal_secrets():
    blob = (
        "const a='AKIAIOS" "FODNN7EXAMPLE';"
        "const s='sk_" "live_abcdef0123456789ABCDEF';"
        "const g='AIzaSy" "A1234567890abcdefghijklmnopqrstuv';"
        "const t='eyJ" "hbGciOiJIUzI1NiJ9.eyJyb2xlIjoiYW5vbiJ9.c2lnbmF0dXJlMTIz';"
        "-----BEGIN RSA PRIVATE KEY-----"
    )
    found = _types(blob)
    assert {"aws_access_key", "stripe_secret_key", "google_api_key", "jwt", "private_key_block"} <= found


def test_counts_and_carries_no_value():
    hits = scan_secrets("AKIAIOS" "FODNN7EXAMPL1 AKIAIOS" "FODNN7EXAMPL2")
    aws = [h for h in hits if h.detector == "aws_access_key"][0]
    assert aws.count == 2
    assert "AKIA" not in repr(aws)   # type/count/length only, never the value
    assert aws.max_len == 20


def test_clean_text_no_hits():
    assert scan_secrets("just some ordinary marketing copy, nothing secret here") == []


def test_publishable_key_is_not_flagged_as_secret():
    # pk_live_ is public-by-design; the secret scanner keys on sk_/rk_ only.
    assert _types("const k='pk_live_abcdefABCDEF0123456789'") == set()


def test_db_uri_with_credentials():
    assert "db_uri_with_credentials" in _types("postgres://user:secretpw@db.internal:5432/app")
