"""Unit tests for the user-enumeration (account-existence oracle) probe.

No network: every case injects a FAKE ``request(path, method, body)`` callable that
returns hand-built ``(status, headers, body)`` tuples (or ``None``). The probe must
flag an existence oracle only on a POSITIVE disclosure signal, must reject SPA HTML
shells and generic/uniform responses, and must only ever spray SYNTHETIC identifiers.
"""

from __future__ import annotations

from kuv.recon.user_enum import DEFAULT_ENDPOINTS, probe_user_enum

_JSON = {"content-type": "application/json"}
_HTML = {"content-type": "text/html"}
_HTML_SHELL = "<!doctype html><html><head><title>App</title></head><body>loading…</body></html>"


# --------------------------------------------------------------------------
# POSITIVE fixtures — exactly one finding, finding_type == "user_enumeration"
# --------------------------------------------------------------------------


def test_availability_boolean_flag_is_flagged():
    def fake(path, method, body):
        if "check-email" in path:
            return (200, _JSON, '{"available": false}')
        return (404, {}, "")

    findings, probed, truncated = probe_user_enum(fake, endpoints=("api/auth/check-email",))
    assert len(findings) == 1
    assert findings[0].finding_type == "user_enumeration"
    assert findings[0].location.endswith("/api/auth/check-email")
    assert findings[0].contains_pii_or_secrets is False
    assert truncated is False


def test_availability_message_is_flagged():
    def fake(path, method, body):
        return (200, _JSON, '{"message": "This email is already registered"}')

    findings, _, _ = probe_user_enum(fake, endpoints=("api/email-exists",))
    assert len(findings) == 1
    assert findings[0].finding_type == "user_enumeration"


def test_login_discloses_nonexistent_account_is_flagged():
    def fake(path, method, body):
        if "login" in path:
            return (401, _JSON, '{"error": "No account found with that email"}')
        return (404, {}, "")

    findings, _, _ = probe_user_enum(fake, endpoints=("api/auth/login",))
    assert len(findings) == 1
    assert findings[0].finding_type == "user_enumeration"
    assert findings[0].location == "POST /api/auth/login"


# --------------------------------------------------------------------------
# NEGATIVE fixtures — no findings
# --------------------------------------------------------------------------


def test_generic_json_no_indicator_is_not_flagged():
    # A benign 200/JSON with no existence indicator on an availability path.
    def fake(path, method, body):
        return (200, _JSON, '{"ok": true}')

    findings, _, _ = probe_user_enum(fake, endpoints=("api/check-email",))
    assert findings == []


def test_html_catch_all_is_not_flagged():
    # A vibe-coded SPA answers 200 + its HTML shell for ANY path/verb.
    def fake(path, method, body):
        return (200, _HTML, _HTML_SHELL)

    findings, _, _ = probe_user_enum(fake, endpoints=DEFAULT_ENDPOINTS)
    assert findings == []


def test_generic_login_failure_is_safe():
    # "Invalid email or password" lumps both together — discloses nothing.
    def fake(path, method, body):
        return (401, _JSON, '{"error": "Invalid email or password"}')

    findings, _, _ = probe_user_enum(fake, endpoints=("api/auth/login",))
    assert findings == []


def test_uniform_reset_response_is_safe_not_flagged():
    # The SAFE, non-disclosing password-reset behavior MUST NOT be flagged, even though
    # it mentions "account" and "email". This is the safe-behavior differential fixture.
    def fake(path, method, body):
        return (
            200,
            _JSON,
            '{"message": "If an account with that email exists, we have sent a password reset link."}',
        )

    findings, _, _ = probe_user_enum(fake, endpoints=("api/auth/forgot-password",))
    assert findings == []


def test_not_found_and_method_not_allowed_are_not_flagged():
    def fake(path, method, body):
        return (404, {}, "Not Found")

    findings, _, _ = probe_user_enum(fake, endpoints=DEFAULT_ENDPOINTS)
    assert findings == []


def test_refused_request_yields_nothing():
    def fake(path, method, body):
        return None

    findings, _, _ = probe_user_enum(fake, endpoints=("api/check-email", "api/auth/login"))
    assert findings == []


def test_non_auth_paths_are_never_probed():
    # Arbitrary routes must not be touched at all — tight blast radius.
    called: list[str] = []

    def fake(path, method, body):
        called.append(path)
        return (200, _JSON, '{"available": false}')

    findings, probed, _ = probe_user_enum(fake, endpoints=("api/products", "about", "index.html"))
    assert findings == []
    assert probed == 0
    assert called == []


# --------------------------------------------------------------------------
# safety / bounding invariants
# --------------------------------------------------------------------------


def test_only_synthetic_example_com_identifiers_are_sprayed():
    seen: list[str] = []

    def fake(path, method, body):
        seen.append(f"{path} || {body or ''}")
        return (200, _JSON, '{"available": false}')

    probe_user_enum(fake, endpoints=DEFAULT_ENDPOINTS)
    blob = "\n".join(seen)
    assert "kuv-probe-" in blob and "example.com" in blob
    for bad in ("@gmail.com", "@yahoo.com", "@hotmail.com", "admin@", "test@test"):
        assert bad not in blob


def test_evidence_is_value_free():
    # The response body value must never leak into the evidence string.
    def fake(path, method, body):
        return (200, _JSON, '{"available": false, "secretUser": "victim@corp.com"}')

    findings, _, _ = probe_user_enum(fake, endpoints=("api/check-email",))
    assert len(findings) == 1
    ev = findings[0].evidence
    assert "victim@corp.com" not in ev
    assert "false" not in ev
    assert "/api/check-email" in ev


def test_cap_bounds_requests_and_sets_truncated():
    # With every request refused, each availability endpoint spends 2 requests
    # (GET then POST); cap must stop the sweep and report truncation.
    def fake(path, method, body):
        return None

    findings, probed, truncated = probe_user_enum(fake, endpoints=DEFAULT_ENDPOINTS, cap=3)
    assert findings == []
    assert probed == 3
    assert truncated is True


def test_full_default_sweep_completes_under_a_generous_cap():
    # 404 everywhere: each availability endpoint spends 2 requests (GET then POST),
    # each login/forgot endpoint 1. A cap above that total lets the sweep finish clean.
    def fake(path, method, body):
        return (404, {}, "")

    findings, probed, truncated = probe_user_enum(fake, endpoints=DEFAULT_ENDPOINTS, cap=40)
    assert findings == []
    assert truncated is False
    assert probed == 10 * 2 + 5 * 1  # 25 requests total across the default candidates
