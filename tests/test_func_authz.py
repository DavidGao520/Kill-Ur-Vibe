"""Unit tests for the func_authz probe (broken FUNCTION-level authz, unauth slice).

Pure, hermetic: no network. Every fetch is a hand-built fake callable returning
``(status, headers, body)`` tuples (or ``None``). We assert the exact finding_type,
zero false positives on SPA/HTML/login/empty/public bodies, and value-free evidence.
"""

from __future__ import annotations

from kuv.recon.func_authz import (
    DEFAULT_PRIVILEGED_ROUTES,
    FuncAuthzFinding,
    probe_func_authz,
)

_JSON = {"content-type": "application/json"}
_HTML = {"content-type": "text/html"}

# A representative SPA shell served for any path by a vibe-coded app.
_SPA_SHELL = "<!doctype html><html><head><title>App</title></head><body><div id=root></div></body></html>"


def _mapfetch(pages: dict, *, default=(404, {}, '{"error":"not found"}')):
    """Build a fetch(path) that returns a canned tuple per canonical path, else default.
    Records every path fetched so tests can assert budget / skip behavior."""
    calls: list[str] = []

    def fetch(path):
        calls.append(path)
        return pages.get(path, default)

    fetch.calls = calls  # type: ignore[attr-defined]
    return fetch


# ---------------------------------------------------------------------------
# (1) KNOWN-POSITIVE: an admin route hands back a record collection with no auth
# ---------------------------------------------------------------------------

def test_positive_unauth_admin_collection_is_flagged():
    fetch = _mapfetch(
        {
            "api/admin/users": (
                200, _JSON,
                '[{"id":1,"email":"a@x.com","role":"admin"},'
                '{"id":2,"email":"b@x.com","role":"user"}]',
            ),
        },
        default=(401, _JSON, '{"error":"unauthorized"}'),
    )
    findings, probed, truncated = probe_func_authz(fetch)
    assert len(findings) == 1
    f = findings[0]
    assert isinstance(f, FuncAuthzFinding)
    assert f.finding_type == "broken_function_auth"          # exact string
    assert f.location == "GET /api/admin/users"
    assert probed >= 1 and truncated is False


def test_positive_wrapped_collection_is_flagged():
    # A privileged-NAMED route (admin) wrapping its records in {data:[...]} still fires.
    fetch = _mapfetch(
        {"api/admin": (200, _JSON, '{"data":[{"id":1},{"id":2},{"id":3}],"total":3}')},
        default=(401, _JSON, "{}"),
    )
    findings, _, _ = probe_func_authz(fetch, routes=("api/admin",))
    assert [f.finding_type for f in findings] == ["broken_function_auth"]
    assert "count=3" in findings[0].evidence


def test_positive_config_object_on_config_route_is_flagged():
    # A config-NAMED route returning a substantive config object (with an infra-ish key)
    # and no auth is the config/settings/internal-object leak.
    fetch = _mapfetch(
        {"api/config": (
            200, _JSON,
            '{"database_url":"x","stripe_key":"y","feature_flags":{"a":true},"region":"us"}',
        )},
        default=(401, _JSON, "{}"),
    )
    findings, _, _ = probe_func_authz(fetch, routes=("api/config",))
    assert [f.finding_type for f in findings] == ["broken_function_auth"]
    assert "shape=object" in findings[0].evidence


def test_positive_admin_users_and_internal_config_both_fire():
    # MALICIOUS (must still fire after the directory-name fix): a genuinely-privileged
    # route wrapping a directory (/api/admin/users → non-empty array) AND an internal
    # config route (/api/internal/config → a config object) both leak with no auth.
    fetch = _mapfetch(
        {
            "api/admin/users": (
                200, _JSON,
                '[{"id":1,"username":"root","role":"admin"},'
                '{"id":2,"username":"ops","role":"admin"}]',
            ),
            "api/internal/config": (
                200, _JSON,
                '{"database_url":"x","stripe_key":"y","jwt_secret":"z","region":"us"}',
            ),
        },
        default=(401, _JSON, '{"error":"unauthorized"}'),
    )
    findings, probed, _ = probe_func_authz(
        fetch, routes=("api/admin/users", "api/internal/config")
    )
    assert [f.finding_type for f in findings] == [
        "broken_function_auth",
        "broken_function_auth",
    ]
    locs = {f.location for f in findings}
    assert locs == {"GET /api/admin/users", "GET /api/internal/config"}
    assert probed == 2


# ---------------------------------------------------------------------------
# (2) KNOWN-NEGATIVE: benign / properly protected responses yield nothing
# ---------------------------------------------------------------------------

def test_negative_all_routes_401_403_404():
    # SAFE behavior: every privileged route is properly gated → NOT flagged.
    fetch = _mapfetch(
        {
            "api/admin": (403, _JSON, '{"error":"forbidden"}'),
            "api/admin/users": (401, _JSON, '{"error":"unauthorized"}'),
            "api/internal": (404, _JSON, '{"error":"not found"}'),
        },
        default=(401, _JSON, '{"error":"unauthorized"}'),
    )
    findings, probed, _ = probe_func_authz(fetch)
    assert findings == []
    assert probed == len([r for r in DEFAULT_PRIVILEGED_ROUTES])  # each catalog route tried once


def test_negative_empty_collection_not_flagged():
    fetch = _mapfetch(
        {
            "api/admin/users": (200, _JSON, "[]"),        # empty list
            "api/admin": (200, _JSON, '{"data":[]}'),     # empty wrapped list
        },
        default=(401, _JSON, "{}"),
    )
    findings, _, _ = probe_func_authz(fetch)
    assert findings == []


def test_negative_error_envelope_200_not_flagged():
    # Some APIs answer 200 with an error/status envelope; that is not privileged data.
    fetch = _mapfetch(
        {"api/config": (200, _JSON, '{"error":"unauthorized","code":401}')},
        default=(401, _JSON, "{}"),
    )
    findings, _, _ = probe_func_authz(fetch, routes=("api/config",))
    assert findings == []


def test_negative_public_small_settings_object_not_flagged():
    # A public /settings returning a couple of non-infra UI flags must NOT be flagged.
    fetch = _mapfetch(
        {"api/settings": (200, _JSON, '{"theme":"light","lang":"en"}')},
        default=(401, _JSON, "{}"),
    )
    findings, _, _ = probe_func_authz(fetch, routes=("api/settings",))
    assert findings == []


def test_negative_non_privileged_route_never_fetched():
    # A supplied route whose NAME is not privileged is skipped WITHOUT a request, even
    # if it would return a collection — this probe only covers privileged-named routes.
    fetch = _mapfetch(
        {"api/products": (200, _JSON, '[{"id":1},{"id":2}]')},
    )
    findings, probed, _ = probe_func_authz(fetch, routes=("api/products",))
    assert findings == []
    assert probed == 0
    assert fetch.calls == []                                # never fetched


def test_negative_public_directory_users_accounts_is_empty():
    # REPRODUCED FALSE POSITIVE (must now be EMPTY): a by-design PUBLIC directory
    # (GET /api/users → [{id, username, avatar_url, bio}]) and a public leaderboard
    # (GET /api/accounts → [...]) are NOT admin-restricted. "users"/"accounts" are
    # directory / tenancy NAMES, no longer privileged tokens, so these routes are not
    # even fetched, and the probe emits ZERO findings. (A public directory that leaks
    # PII is covered by the generic unauth API sweep + PII rating, not this probe.)
    fetch = _mapfetch(
        {
            "api/users": (
                200, _JSON,
                '[{"id":1,"username":"ada","avatar_url":"/a.png","bio":"hi"},'
                '{"id":2,"username":"bea","avatar_url":"/b.png","bio":"yo"}]',
            ),
            "api/accounts": (
                200, _JSON,
                '[{"id":1,"name":"ada","points":42},{"id":2,"name":"bea","points":7}]',
            ),
        },
    )
    findings, probed, _ = probe_func_authz(fetch, routes=("api/users", "api/accounts"))
    assert findings == []
    assert probed == 0
    assert fetch.calls == []                                # neither directory fetched


# ---------------------------------------------------------------------------
# (3) HTML CATCH-ALL: a SPA that 200s its shell for every path yields nothing
# ---------------------------------------------------------------------------

def test_negative_html_spa_catchall_not_flagged():
    fetch = _mapfetch({}, default=(200, _HTML, _SPA_SHELL))
    findings, probed, _ = probe_func_authz(fetch)
    assert findings == []
    assert probed == len(DEFAULT_PRIVILEGED_ROUTES)         # it did probe, and rejected every shell


def test_negative_html_login_redirect_page_not_flagged():
    # 200 + an HTML login page (client-side redirect-to-login) is not privileged data.
    login = "<html><head></head><body><form action='/login'>please sign in</form></body></html>"
    fetch = _mapfetch(
        {"api/admin": (200, _HTML, login)},
        default=(401, _JSON, "{}"),
    )
    findings, _, _ = probe_func_authz(fetch, routes=("api/admin",))
    assert findings == []


def test_negative_3xx_redirect_not_flagged():
    fetch = _mapfetch(
        {"api/admin/users": (302, {"location": "/login"}, "")},
        default=(401, _JSON, "{}"),
    )
    findings, _, _ = probe_func_authz(fetch, routes=("api/admin/users",))
    assert findings == []


def test_negative_metrics_prometheus_text_not_flagged():
    # /api/metrics returning Prometheus text (not JSON) must not be flagged.
    prom = "# HELP http_requests_total\nhttp_requests_total 42\n"
    fetch = _mapfetch(
        {"api/metrics": (200, {"content-type": "text/plain"}, prom)},
        default=(401, _JSON, "{}"),
    )
    findings, _, _ = probe_func_authz(fetch, routes=("api/metrics",))
    assert findings == []


# ---------------------------------------------------------------------------
# refusal / budget / dedup / evidence hygiene
# ---------------------------------------------------------------------------

def test_fetch_refusal_none_is_skipped():
    fetch = _mapfetch({})

    def refusing(path):
        fetch.calls.append(path)  # type: ignore[attr-defined]
        return None

    findings, probed, _ = probe_func_authz(refusing, routes=("api/admin", "api/config"))
    assert findings == []
    assert probed == 2                                       # both attempted, both refused


def test_cap_truncates_and_reports():
    routes = ("api/admin", "api/internal", "api/config", "api/logs", "api/export")
    fetch = _mapfetch({}, default=(401, _JSON, "{}"))
    findings, probed, truncated = probe_func_authz(fetch, routes=routes, cap=2)
    assert probed == 2 and truncated is True


def test_duplicate_routes_probed_once():
    fetch = _mapfetch(
        {"api/admin/users": (200, _JSON, '[{"id":1}]')},
        default=(401, _JSON, "{}"),
    )
    findings, probed, _ = probe_func_authz(
        fetch, routes=("api/admin/users", "/api/admin/users", "api/admin/users/")
    )
    assert probed == 1                                       # deduplicated
    assert len(findings) == 1


def test_evidence_is_value_free():
    fetch = _mapfetch(
        {"api/admin/users": (
            200, _JSON,
            '[{"id":1,"email":"secret@victim.com","ssn":"123-45-6789"}]',
        )},
        default=(401, _JSON, "{}"),
    )
    findings, _, _ = probe_func_authz(fetch, routes=("api/admin/users",))
    assert len(findings) == 1
    blob = findings[0].evidence + findings[0].plain_impact + findings[0].recommendation
    # value-free: no fetched record values leak into the finding
    assert "secret@victim.com" not in blob
    assert "123-45-6789" not in blob
    assert findings[0].contains_pii_or_secrets is False
