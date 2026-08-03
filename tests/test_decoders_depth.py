"""Tests for the depth decoders: OAuth authorize-URL + HTTP security posture."""

from __future__ import annotations

from kuv.decoders import analyze_http_posture, analyze_oauth_url


# ---- OAuth ----

def test_oauth_flags_missing_state_and_pkce_and_hd():
    url = (
        "https://accounts.google.com/o/oauth2/v2/auth?response_type=code"
        "&client_id=abc&redirect_uri=https://app.example.com/cb&scope=email+profile"
    )
    cfg = analyze_oauth_url(url)
    assert cfg.is_oauth and cfg.provider == "google"
    assert cfg.has_state is False and cfg.has_pkce is False
    assert cfg.redirect_host == "app.example.com"
    assert any("state" in g for g in cfg.gaps)
    assert any("PKCE" in g for g in cfg.gaps)
    assert any("hd" in g for g in cfg.gaps)          # google-specific hosted-domain gap


def test_oauth_clean_flow_has_no_gaps():
    url = (
        "https://accounts.google.com/o/oauth2/v2/auth?response_type=code&state=xyz"
        "&code_challenge=abc&hd=example.com&client_id=1&redirect_uri=https://a.example.com/cb"
    )
    cfg = analyze_oauth_url(url)
    assert cfg.has_state and cfg.has_pkce and cfg.hosted_domain == "example.com"
    assert cfg.gaps == ()


def test_oauth_blank_code_challenge_is_not_pkce():
    url = ("https://accounts.google.com/o/oauth2/v2/auth?response_type=code&state=x"
           "&code_challenge=&hd=example.com&client_id=1")
    cfg = analyze_oauth_url(url)
    assert cfg.has_pkce is False                     # a blank code_challenge= is not PKCE
    assert any("PKCE" in g for g in cfg.gaps)


def test_oauth_non_oauth_url_is_not_flagged():
    cfg = analyze_oauth_url("https://app.example.com/dashboard?tab=1")
    assert cfg.is_oauth is False and cfg.gaps == ()


def test_oauth_custom_idp_by_authorize_path():
    cfg = analyze_oauth_url("https://id.example.com/oauth/authorize?response_type=token&client_id=x")
    assert cfg.is_oauth and cfg.provider == "custom"


# ---- HTTP posture ----

def test_posture_flags_wildcard_cors_and_unsafe_csp_and_dev_origins():
    headers = {
        "Content-Security-Policy": "default-src 'self' ws://localhost:3000; "
                                   "script-src 'self' 'unsafe-inline' 'unsafe-eval'",
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Credentials": "true",
    }
    p = analyze_http_posture(200, headers, [])
    assert p.cors_wildcard and p.cors_allow_credentials
    assert p.csp_unsafe_inline and p.csp_unsafe_eval
    assert "localhost" in p.csp_dev_origins
    assert any("wildcard CORS" in g for g in p.gaps)
    assert any("Allow-Credentials" in g for g in p.gaps)
    assert any("unsafe-inline" in g for g in p.gaps)
    assert any("dev-mode origins" in g for g in p.gaps)


def test_posture_cookie_flags_and_hsts():
    headers = {"Strict-Transport-Security": "max-age=15552000; includeSubDomains"}
    cookies = ["sid=abc; Path=/; HttpOnly"]        # missing Secure + SameSite
    p = analyze_http_posture(200, headers, cookies)
    assert p.hsts and p.hsts_long
    assert p.cookies[0].httponly and not p.cookies[0].secure
    assert any("`sid` missing Secure, SameSite" in g for g in p.gaps)


def test_posture_clean_headers_have_few_gaps():
    headers = {
        "Strict-Transport-Security": "max-age=31536000",
        "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'",
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "Referrer-Policy": "no-referrer",
    }
    p = analyze_http_posture(200, headers, [])
    assert p.gaps == ()                             # a well-configured host trips nothing


def test_posture_case_insensitive_headers():
    p = analyze_http_posture(200, {"access-control-allow-origin": "*"}, [])
    assert p.cors_wildcard is True


def test_posture_ipv6_loopback_dev_origin_flagged():
    p = analyze_http_posture(200, {"Content-Security-Policy": "connect-src 'self' ws://[::1]:3002"}, [])
    assert "[::1]" in p.csp_dev_origins
    assert any("dev-mode origins" in g for g in p.gaps)


def test_posture_default_src_wildcard_flags_script():
    # No script-src -> CSP falls back to default-src; a bare * there governs scripts.
    p = analyze_http_posture(200, {"Content-Security-Policy": "default-src *"}, [])
    assert p.csp_wildcard_script is True


def test_posture_host_wildcard_is_not_a_script_wildcard():
    # *.cdn.com is a host-wildcard, not the dangerous bare * source.
    p = analyze_http_posture(200, {"Content-Security-Policy": "script-src 'self' *.cdn.com"}, [])
    assert p.csp_wildcard_script is False
