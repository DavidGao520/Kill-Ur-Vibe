"""Unit tests for the deterministic decoders.

These are the safety-critical "the LLM must not be wrong here" checks from
the design notes §Fidelity eval & safety acceptance gates (decoder correctness).
"""

from __future__ import annotations

import base64
import json

from kuv.decoders import (
    JwtRole,
    check_source_map_exposed,
    classify_secret_prefix,
    decode_jwt_role,
    source_map_url_for,
)


def _jwt(payload: dict) -> str:
    def seg(obj: dict) -> str:
        raw = base64.urlsafe_b64encode(json.dumps(obj).encode()).rstrip(b"=")
        return raw.decode()

    return f"{seg({'alg': 'HS256', 'typ': 'JWT'})}.{seg(payload)}.sig"


# --- JWT role -------------------------------------------------------------

def test_service_role_is_a_finding():
    res = decode_jwt_role(_jwt({"role": "service_role", "iss": "supabase"}))
    assert res.role is JwtRole.SERVICE_ROLE
    assert res.is_finding is True
    assert res.raw_role == "service_role"


def test_anon_is_expected_public_key():
    res = decode_jwt_role(_jwt({"role": "anon"}))
    assert res.role is JwtRole.ANON
    assert res.is_finding is False


def test_authenticated_is_scoped_not_a_finding():
    res = decode_jwt_role(_jwt({"role": "authenticated"}))
    assert res.role is JwtRole.AUTHENTICATED
    assert res.is_finding is False


def test_missing_role_claim_is_unknown():
    res = decode_jwt_role(_jwt({"iss": "supabase"}))
    assert res.role is JwtRole.UNKNOWN
    assert res.is_finding is False


def test_non_jwt_is_invalid_not_a_crash():
    assert decode_jwt_role("not-a-jwt").role is JwtRole.INVALID
    assert decode_jwt_role("only.two").role is JwtRole.INVALID
    assert decode_jwt_role("a.!!!bad-base64!!!.c").role is JwtRole.INVALID


# --- source map -----------------------------------------------------------

_VALID_MAP = json.dumps({"version": 3, "sources": ["a.ts"], "mappings": "AAAA"})


def test_source_map_exposed_when_200_and_valid():
    def fetch(url: str):
        assert url == source_map_url_for("https://t/app.js")
        return (200, _VALID_MAP)

    res = check_source_map_exposed("https://t/app.js", fetch)
    assert res.exposed is True
    assert res.map_url.endswith(".js.map")


def test_source_map_not_exposed_on_404():
    res = check_source_map_exposed("https://t/app.js", lambda _u: (404, ""))
    assert res.exposed is False


def test_source_map_not_exposed_when_body_is_not_a_map():
    res = check_source_map_exposed("https://t/app.js", lambda _u: (200, "<html>nope"))
    assert res.exposed is False


def test_source_map_requires_version_3_and_mappings():
    bad = json.dumps({"version": 3, "sources": ["a.ts"]})  # no mappings
    res = check_source_map_exposed("https://t/app.js", lambda _u: (200, bad))
    assert res.exposed is False


# --- public prefix --------------------------------------------------------

def test_publishable_key_is_public():
    res = classify_secret_prefix("pk_live_abc123def456")
    assert res.is_public is True
    assert res.matched_prefix == "pk_live_"


def test_secret_key_is_not_public():
    res = classify_secret_prefix("sk_" "live_abc123def456")
    assert res.is_public is False
    assert res.matched_prefix is None


def test_aws_access_key_is_not_public():
    assert classify_secret_prefix("AKIAIOS" "FODNN7EXAMPLE").is_public is False


def test_result_carries_no_secret_material():
    res = classify_secret_prefix("sk_" "live_super_secret_value")
    # length only, never the value itself (redaction discipline).
    assert res.length == len("sk_" "live_super_secret_value")
    assert "secret" not in repr(res)
