"""Tests for the BaaS RLS-open read probe (kuv.recon.backend_rls).

No network: every ``fetch`` is a hand-built fake returning ``(status, headers, body)``
tuples (or ``None`` for refused/error). We assert the exact finding_type string, the
PII flag, and — the whole point — ZERO false positives on RLS-closed / HTML-shell /
error-object / empty responses.
"""

from __future__ import annotations

import json

from kuv.recon.backend_rls import (
    DEFAULT_TABLES,
    _is_error_object,
    _looks_html,
    _read_open_data,
    probe_backend_rls,
)

_JSON = {"content-type": "application/json"}
_HTML = {"content-type": "text/html"}


def _serve(mapping):
    """A fake fetch: returns the mapped response, else a benign 404."""

    def fetch(candidate):
        return mapping.get(candidate, (404, _JSON, "Not Found"))

    return fetch


# --------------------------------------------------------------------------
# reader-level: the anti-false-positive discipline
# --------------------------------------------------------------------------


def test_reader_accepts_supabase_row_array():
    parsed = json.loads('[{"id":1,"email":"a@b.c","full_name":"A"}]')
    shape, count, keys = _read_open_data(parsed)
    assert shape == "JSON array"
    assert count == 1
    assert "email" in keys and "full_name" in keys


def test_reader_accepts_firebase_pushid_map_and_reads_record_keys():
    parsed = json.loads('{"-Nx1":{"email":"a@b.c","phone":"555"},"-Nx2":{"email":"d@e.f","phone":"556"}}')
    shape, count, keys = _read_open_data(parsed)
    assert shape == "JSON object"
    assert count == 2
    # keys come from the RECORDS, not the push-ids
    assert set(keys) == {"email", "phone"}


def test_reader_rejects_empty_array():
    assert _read_open_data(json.loads("[]")) is None


def test_reader_rejects_json_null():
    assert _read_open_data(json.loads("null")) is None


def test_reader_rejects_postgrest_error_object():
    err = json.loads('{"code":"42501","details":null,"hint":null,"message":"permission denied for table users"}')
    assert _is_error_object(err) is True
    assert _read_open_data(err) is None


def test_reader_rejects_firebase_permission_denied():
    err = json.loads('{"error":"Permission denied"}')
    assert _is_error_object(err) is True
    assert _read_open_data(err) is None


def test_reader_rejects_array_of_scalars():
    assert _read_open_data(json.loads("[1,2,3]")) is None


def test_reader_rejects_wrapper_envelope_object():
    # {"data":[],"status":"ok"} — a generic success/wrapper envelope with no dict-valued
    # member. Not a record map; must not manufacture a false positive.
    assert _read_open_data(json.loads('{"data":[],"status":"ok"}')) is None


def test_reader_rejects_generic_status_object():
    # {"success":false,"message":"nope"} — a generic gateway/status envelope. It is NOT
    # an error object (no "error", not a code+message pair) yet has no dict member, so
    # the push-id-shape gate rejects it rather than flagging every bare success dict.
    parsed = json.loads('{"success":false,"message":"nope"}')
    assert _is_error_object(parsed) is False
    assert _read_open_data(parsed) is None


def test_reader_rejects_firebase_index_node_and_never_surfaces_key_names():
    # A Firebase scalar-valued index node (identifier -> scalar), e.g. /usernames. Its
    # top-level keys ARE the data (usernames), so the reader must reject it outright and
    # never gather those keys — the value-free-evidence invariant.
    parsed = json.loads('{"alice_smith":1,"bob_jones":2}')
    assert _read_open_data(parsed) is None


def test_looks_html_flags_spa_shell():
    assert _looks_html("<!DOCTYPE html><html><head><title>App</title></head></html>") is True
    assert _looks_html('[{"id":1}]') is False


# --------------------------------------------------------------------------
# entry-level: POSITIVE fixture -> exactly one finding, correct type + PII flag
# --------------------------------------------------------------------------


def test_positive_open_supabase_table_yields_one_finding_with_pii():
    body = '[{"id":1,"email":"a@b.c","full_name":"Ann"},{"id":2,"email":"d@e.f","full_name":"Dee"}]'
    fetch = _serve({"users": (200, _JSON, body)})

    rows, probed, truncated = probe_backend_rls(fetch)

    assert len(rows) == 1
    row = rows[0]
    assert row.finding_type == "unauth_read_sensitive"
    assert row.location == "users"
    assert row.contains_pii_or_secrets is True
    # evidence is value-free: counts + key names only, no row VALUES
    assert "2 rows" in row.evidence
    assert "email" in row.evidence
    assert "a@b.c" not in row.evidence
    assert "Ann" not in row.evidence
    assert probed == len(DEFAULT_TABLES)
    assert truncated is False


def test_positive_firebase_node_yields_finding():
    body = '{"-Nx1":{"title":"hi","done":false},"-Nx2":{"title":"yo","done":true}}'
    fetch = _serve({"todos": (200, _JSON, body)})

    rows, _, _ = probe_backend_rls(fetch)

    assert len(rows) == 1
    assert rows[0].finding_type == "unauth_read_sensitive"
    assert rows[0].location == "todos"
    # non-PII field names -> flag stays False
    assert rows[0].contains_pii_or_secrets is False


def test_open_non_pii_table_still_reported_without_pii_flag():
    body = '[{"id":1,"slug":"hello","body":"world"}]'
    fetch = _serve({"posts": (200, _JSON, body)})

    rows, _, _ = probe_backend_rls(fetch)

    assert len(rows) == 1
    assert rows[0].contains_pii_or_secrets is False


# --------------------------------------------------------------------------
# entry-level: NEGATIVE fixtures -> zero findings
# --------------------------------------------------------------------------


def test_rls_closed_site_yields_nothing():
    # every table: RLS-closed (200 + "[]"), auth-required (401), or an error object
    def fetch(candidate):
        if candidate == "users":
            return (401, _JSON, '{"message":"JWT expired"}')
        if candidate == "orders":
            return (403, _JSON, "")
        if candidate == "payments":
            return (200, _JSON, '{"code":"42501","message":"permission denied for table payments"}')
        return (200, _JSON, "[]")

    rows, probed, truncated = probe_backend_rls(fetch)

    assert rows == []
    assert probed == len(DEFAULT_TABLES)
    assert truncated is False


def test_html_catch_all_yields_nothing():
    # A vibe-coded SPA answers 200 + its HTML shell for ANY path — must be no finding.
    html = "<!doctype html><html><head><title>App</title></head><body>app</body></html>"

    def fetch(candidate):
        return (200, _HTML, html)

    rows, _, _ = probe_backend_rls(fetch)
    assert rows == []


def test_wrapper_and_index_map_bodies_yield_nothing_without_leaking_keys():
    # Bare non-error objects with no dict-valued member: wrapper envelope, generic
    # status object, and a Firebase scalar index map whose keys are identifiers.
    # None may produce a finding, and no identifier key may appear anywhere in output.
    def fetch(candidate):
        if candidate == "users":
            return (200, _JSON, '{"alice_smith":1,"bob_jones":2}')  # index map: keys are data
        if candidate == "profiles":
            return (200, _JSON, '{"data":[],"status":"ok"}')  # wrapper envelope
        if candidate == "accounts":
            return (200, _JSON, '{"success":false,"message":"nope"}')  # generic status object
        return (404, _JSON, "Not Found")

    rows, probed, truncated = probe_backend_rls(fetch)

    assert rows == []
    assert probed == len(DEFAULT_TABLES)
    assert truncated is False


def test_mixed_firebase_node_reads_only_record_keys_not_index_keys():
    # A node mixing a real push-id record with a scalar sibling: the finding stands
    # (there IS an exposed record) but evidence carries ONLY the record's field names,
    # never the top-level ids or the scalar sibling's key.
    body = '{"-Nx1":{"email":"a@b.c","name":"Ann"},"total_count":1}'
    fetch = _serve({"users": (200, _JSON, body)})

    rows, _, _ = probe_backend_rls(fetch)

    assert len(rows) == 1
    ev = rows[0].evidence
    assert "email" in ev and "name" in ev
    assert "-Nx1" not in ev          # push-id never surfaced
    assert "total_count" not in ev   # scalar sibling key never surfaced
    assert "1 rows" in ev            # count = dict records only
    assert rows[0].contains_pii_or_secrets is True


def test_non_json_and_refused_yield_nothing():
    def fetch(candidate):
        if candidate == "users":
            return None  # refused / network error
        if candidate == "profiles":
            return (200, {"content-type": "text/plain"}, "OK")  # non-JSON
        if candidate == "accounts":
            return (200, _JSON, "null")  # JSON null
        return (404, _JSON, "Not Found")

    rows, _, _ = probe_backend_rls(fetch)
    assert rows == []


# --------------------------------------------------------------------------
# entry-level: cap / truncation bounds the work
# --------------------------------------------------------------------------


def test_cap_bounds_requests_and_sets_truncated():
    def fetch(candidate):
        return (404, _JSON, "Not Found")

    rows, probed, truncated = probe_backend_rls(fetch, cap=3)
    assert rows == []
    assert probed == 3
    assert truncated is True


def test_multiple_open_tables_each_reported():
    users = '[{"id":1,"email":"a@b.c"}]'
    leads = '[{"id":9,"phone":"555","name":"L"}]'
    fetch = _serve({"users": (200, _JSON, users), "leads": (200, _JSON, leads)})

    rows, _, truncated = probe_backend_rls(fetch)

    locs = {r.location for r in rows}
    assert locs == {"users", "leads"}
    assert all(r.finding_type == "unauth_read_sensitive" for r in rows)
    assert all(r.contains_pii_or_secrets for r in rows)
    assert truncated is False
