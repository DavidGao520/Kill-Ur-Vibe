"""Tests for the curated safe-exposure check library (kuv.recon.templated)."""

from __future__ import annotations

from kuv.recon.templated import (
    _m_env,
    _m_git_config,
    _m_openapi,
    run_templated_checks,
)


# --------------------------------------------------------------------------
# matcher-level: the anti-false-positive discipline
# --------------------------------------------------------------------------


def test_env_matches_real_env_file():
    body = "SECRET_KEY=supersecret\nDATABASE_URL=postgres://u:p@h/db\nDEBUG=false\n"
    assert _m_env(200, {"content-type": "text/plain"}, body) is True


def test_env_does_not_match_spa_html_catchall():
    # A SPA returns 200 + its HTML shell for /.env — must NOT be a finding.
    html = "<!DOCTYPE html><html><head><title>App</title></head><body>...</body></html>"
    assert _m_env(200, {"content-type": "text/html"}, html) is False


def test_env_does_not_match_prose_with_one_equals():
    assert _m_env(200, {}, "The answer A=B is here, nothing secret.") is False


def test_env_404_is_not_a_match():
    assert _m_env(404, {}, "SECRET_KEY=abc\nAPI_KEY=def") is False


def test_git_config_requires_real_git_content():
    assert _m_git_config(200, {}, "[core]\n\trepositoryformatversion = 0\n") is True
    assert _m_git_config(200, {}, "<html>not git</html>") is False


def test_openapi_matches_schema_not_html():
    assert _m_openapi(200, {}, '{"openapi":"3.0.0","info":{},"paths":{"/x":{}}}') is True
    assert _m_openapi(200, {}, "<!doctype html><html>app</html>") is False


# --------------------------------------------------------------------------
# runner-level: fetch loop, dedupe-per-spec, cap
# --------------------------------------------------------------------------


def test_run_finds_env_and_swagger_and_dedupes_per_spec():
    served = {
        ".env": (200, {"content-type": "text/plain"}, "SECRET_KEY=abc\nDATABASE_URL=x\n"),
        "openapi.json": (200, {"content-type": "application/json"}, '{"openapi":"3.0","info":{},"paths":{}}'),
    }

    def fetch(path):
        return served.get(path, (404, {}, "not found"))

    exposures, probed, truncated = run_templated_checks(fetch)
    types = {e.finding_type for e in exposures}
    assert "exposed_secret_file" in types  # .env
    assert "info_disclosure" in types  # openapi
    # exactly one exposure per matching spec (env spec has 4 paths, must not double-count)
    env_hits = [e for e in exposures if e.path == ".env"]
    assert len(env_hits) == 1
    assert not truncated


def test_run_returns_nothing_for_a_clean_site():
    def fetch(path):
        return (404, {}, "Not Found")

    exposures, probed, truncated = run_templated_checks(fetch)
    assert exposures == []
    assert probed > 0


def test_run_respects_the_cap():
    def fetch(path):
        return (404, {}, "nope")

    exposures, probed, truncated = run_templated_checks(fetch, cap=3)
    assert probed == 3
    assert truncated is True
