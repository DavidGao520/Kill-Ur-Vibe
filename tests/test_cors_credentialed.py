"""Tests for the credentialed-CORS probe (kuv.recon.cors_credentialed).

No network: the entry function is driven by hand-built fake ``fetch_with_origin``
callables returning ``(status, headers, body)`` tuples (or ``None`` for refused).
The whole point is determinism + zero false positives — a reflected/``null`` Origin
*with* credentials is a finding; everything else (no ACAO, a site-owned ACAO, ``*``,
missing/false credentials, or an HTML SPA catch-all) is not.
"""

from __future__ import annotations

from kuv.recon.cors_credentialed import (
    PROBE_ORIGIN,
    classify_cors,
    probe_cors,
)

ATTACKER = PROBE_ORIGIN


# --------------------------------------------------------------------------
# classify-level: the exact dangerous pattern
# --------------------------------------------------------------------------


def test_reflected_origin_plus_credentials_is_a_finding():
    headers = {
        "Access-Control-Allow-Origin": ATTACKER,  # reflected our arbitrary origin
        "Access-Control-Allow-Credentials": "true",
    }
    f = classify_cors(ATTACKER, headers)
    assert f is not None
    assert f.finding_type == "credentialed_cors"
    assert f.contains_pii_or_secrets is False


def test_null_origin_plus_credentials_is_a_finding():
    headers = {
        "access-control-allow-origin": "null",
        "access-control-allow-credentials": "true",
    }
    f = classify_cors(ATTACKER, headers)
    assert f is not None
    assert f.finding_type == "credentialed_cors"


def test_header_and_token_case_is_ignored():
    # Weird header casing + "TRUE" must still classify (spec: case-insensitive).
    headers = {
        "ACCESS-CONTROL-ALLOW-ORIGIN": ATTACKER,
        "Access-Control-Allow-Credentials": "TRUE",
    }
    assert classify_cors(ATTACKER, headers) is not None


# --------------------------------------------------------------------------
# classify-level: the must-reject cases (zero false positives)
# --------------------------------------------------------------------------


def test_no_acao_header_is_not_a_finding():
    assert classify_cors(ATTACKER, {"Access-Control-Allow-Credentials": "true"}) is None


def test_site_own_origin_not_reflected_is_not_a_finding():
    # ACAO fixed to the site's own origin (does NOT reflect our sent origin).
    headers = {
        "Access-Control-Allow-Origin": "https://app.realsite.com",
        "Access-Control-Allow-Credentials": "true",
    }
    assert classify_cors(ATTACKER, headers) is None


def test_wildcard_origin_with_credentials_is_not_a_finding():
    # "*" is not exploitable with credentials — browsers refuse the combination.
    headers = {
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Credentials": "true",
    }
    assert classify_cors(ATTACKER, headers) is None


def test_reflected_origin_without_credentials_is_not_a_finding():
    assert classify_cors(ATTACKER, {"Access-Control-Allow-Origin": ATTACKER}) is None


def test_credentials_not_true_is_not_a_finding():
    headers = {
        "Access-Control-Allow-Origin": ATTACKER,
        "Access-Control-Allow-Credentials": "false",
    }
    assert classify_cors(ATTACKER, headers) is None


def test_plain_html_response_headers_yield_nothing():
    # An HTML page with no CORS headers at all — the SPA catch-all shape.
    assert classify_cors(ATTACKER, {"Content-Type": "text/html"}) is None


# --------------------------------------------------------------------------
# probe-level: fetch loop, location, cap, refusal
# --------------------------------------------------------------------------


def test_probe_flags_reflecting_endpoint_with_path_as_location():
    vuln_headers = {
        "Access-Control-Allow-Origin": ATTACKER,
        "Access-Control-Allow-Credentials": "true",
    }

    def fetch(path, origin):
        assert origin == PROBE_ORIGIN  # caller sends the benign attacker origin
        if path == "/api/v1/me":
            return (200, vuln_headers, '{"email":"x"}')
        return (200, {"Content-Type": "application/json"}, "{}")

    findings, probed, truncated = probe_cors(fetch, ["/", "/api/v1/me"])
    assert len(findings) == 1
    assert findings[0].finding_type == "credentialed_cors"
    assert findings[0].location == "/api/v1/me"
    assert findings[0].contains_pii_or_secrets is False
    assert probed == 2
    assert truncated is False


def test_probe_clean_site_yields_no_findings():
    # RLS-closed / benign: normal responses, no credentialed reflection anywhere.
    def fetch(path, origin):
        return (200, {"Content-Type": "application/json"}, "[]")

    findings, probed, truncated = probe_cors(fetch, ["/", "/api", "/rest/v1/users"])
    assert findings == []
    assert probed == 3
    assert truncated is False


def test_probe_html_catchall_yields_no_findings():
    # A vibe-coded SPA answers 200 + its HTML shell for ANY path, no CORS headers.
    html = "<!doctype html><html><head><title>App</title></head><body>hi</body></html>"

    def fetch(path, origin):
        return (200, {"Content-Type": "text/html"}, html)

    findings, probed, truncated = probe_cors(fetch, ["/", "/api/secret", "/admin"])
    assert findings == []
    assert truncated is False


def test_probe_skips_refused_targets():
    def fetch(path, origin):
        return None  # connection refused / error

    findings, probed, truncated = probe_cors(fetch, ["/a", "/b"])
    assert findings == []
    assert probed == 2


def test_probe_respects_the_cap():
    def fetch(path, origin):
        return (404, {}, "nope")

    findings, probed, truncated = probe_cors(fetch, [f"/p{i}" for i in range(20)], cap=3)
    assert probed == 3
    assert truncated is True
