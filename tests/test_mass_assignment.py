"""Tests for the mass-assignment / privilege-escalation write probe.

No network: every case drives ``probe_mass_assignment`` with a hand-built fake ``post``
callable that returns ``(status, headers, body)`` tuples (or ``None``). The fake
distinguishes the baseline POST from the injected POST by whether the serialized body
carries the injected ``role`` field.
"""

from __future__ import annotations

import json

from kuv.recon.mass_assignment import (
    BASELINE_BODY,
    INJECTED_BODY,
    MassAssignmentFinding,
    probe_mass_assignment,
)

_HTML_SHELL = "<!doctype html><html><head><title>App</title></head><body>root</body></html>"


def make_post(responses: dict):
    """Build a fake ``post``. ``responses`` maps path -> {"baseline": resp, "injected": resp}
    where each resp is a ``(status, headers, body)`` tuple or ``None`` (or the key omitted,
    which also yields ``None``)."""
    calls: list[tuple[str, str]] = []

    def post(path, body, headers):
        parsed = json.loads(body)
        phase = "injected" if "role" in parsed else "baseline"
        calls.append((path, phase))
        spec = responses.get(path)
        if spec is None:
            return None
        return spec.get(phase)

    post.calls = calls  # type: ignore[attr-defined]
    return post


def _json(obj) -> str:
    return json.dumps(obj)


# --------------------------------------------------------------------------
# sanity: the injected body actually carries the whole catalog
# --------------------------------------------------------------------------

def test_bodies_are_shaped_as_expected():
    base = json.loads(BASELINE_BODY)
    inj = json.loads(INJECTED_BODY)
    assert base == {"name": "kuvprobe", "title": "kuvprobe"}
    # baseline carries NO privileged fields; injected carries role + the rest.
    assert "role" not in base
    for key in ("role", "is_admin", "isAdmin", "admin", "is_superuser", "permissions",
                "credits", "balance", "is_verified", "email_verified", "verified",
                "plan", "subscription_tier", "owner_id", "user_id"):
        assert key in inj
    assert inj["credits"] == 999999 and inj["permissions"] == ["admin"]


# --------------------------------------------------------------------------
# (1) known-POSITIVE — privilege field accepted -> exactly one finding
# --------------------------------------------------------------------------

def test_positive_role_admin_accepted_is_privilege_escalation():
    responses = {
        "api/users": {
            # server default role is "user" ...
            "baseline": (201, {}, _json({"id": "1", "name": "kuvprobe", "role": "user"})),
            # ... but it stored the injected role="admin" -> vulnerable
            "injected": (201, {}, _json({"id": "2", "name": "kuvprobe", "role": "admin"})),
        }
    }
    post = make_post(responses)
    findings, probed, truncated = probe_mass_assignment(post, ("api/users",))

    assert len(findings) == 1
    assert isinstance(findings[0], MassAssignmentFinding)
    assert findings[0].finding_type == "privilege_escalation"
    assert findings[0].location == "POST /api/users"
    assert "role" in findings[0].evidence
    assert findings[0].contains_pii_or_secrets is False
    assert probed == 2 and truncated is False
    assert post.calls == [("api/users", "baseline"), ("api/users", "injected")]


def test_positive_mass_field_accepted_is_mass_assignment():
    responses = {
        "api/account": {
            "baseline": (200, {}, _json({"id": 1, "name": "kuvprobe", "credits": 0})),
            "injected": (200, {}, _json({"id": 2, "name": "kuvprobe", "credits": 999999})),
        }
    }
    post = make_post(responses)
    findings, probed, truncated = probe_mass_assignment(post, ("api/account",))

    assert len(findings) == 1
    assert findings[0].finding_type == "mass_assignment"
    assert "credits" in findings[0].evidence
    # value-free: the injected VALUE never leaks into evidence
    assert "999999" not in findings[0].evidence


def test_positive_nested_wrapped_object_is_detected():
    # naive handlers often wrap the created row: {"data": {"user": {...}}}
    responses = {
        "api/register": {
            "baseline": (201, {}, _json({"data": {"user": {"id": 1, "isAdmin": False}}})),
            "injected": (201, {}, _json({"data": {"user": {"id": 2, "isAdmin": True}}})),
        }
    }
    post = make_post(responses)
    findings, _probed, _t = probe_mass_assignment(post, ("api/register",))
    assert len(findings) == 1
    assert findings[0].finding_type == "privilege_escalation"
    assert "isAdmin" in findings[0].evidence


def test_positive_permissions_list_accepted():
    responses = {
        "api/users": {
            "baseline": (201, {}, _json({"id": 1, "permissions": ["read"]})),
            "injected": (201, {}, _json({"id": 2, "permissions": ["admin"]})),
        }
    }
    post = make_post(responses)
    findings, _p, _t = probe_mass_assignment(post, ("api/users",))
    assert len(findings) == 1
    assert findings[0].finding_type == "privilege_escalation"
    assert "permissions" in findings[0].evidence


def test_positive_both_types_yield_two_findings():
    responses = {
        "api/users": {
            "baseline": (201, {}, _json({"id": 1, "role": "user", "credits": 0})),
            "injected": (201, {}, _json({"id": 2, "role": "admin", "credits": 999999})),
        }
    }
    post = make_post(responses)
    findings, _p, _t = probe_mass_assignment(post, ("api/users",))
    assert len(findings) == 2
    assert {f.finding_type for f in findings} == {"privilege_escalation", "mass_assignment"}


def test_positive_when_baseline_refused_but_injected_echoes_admin():
    # baseline POST refused/blocked (None) -> no suppression data, but the injected
    # extreme value is self-evidently attacker-supplied and still flagged.
    responses = {
        "api/users": {
            "baseline": None,
            "injected": (201, {}, _json({"id": 2, "role": "admin"})),
        }
    }
    post = make_post(responses)
    findings, probed, _t = probe_mass_assignment(post, ("api/users",))
    assert len(findings) == 1
    assert findings[0].finding_type == "privilege_escalation"
    assert probed == 2


# --------------------------------------------------------------------------
# (2) known-NEGATIVE benign — server ignores the injected fields
# --------------------------------------------------------------------------

def test_negative_server_ignores_injected_fields():
    responses = {
        "api/users": {
            "baseline": (201, {}, _json({"id": 1, "name": "kuvprobe", "role": "user", "credits": 0})),
            # server dropped every injected field; row is unchanged shape
            "injected": (201, {}, _json({"id": 2, "name": "kuvprobe", "role": "user", "credits": 0})),
        }
    }
    post = make_post(responses)
    findings, probed, truncated = probe_mass_assignment(post, ("api/users",))
    assert findings == []
    assert probed == 2 and truncated is False


def test_negative_generic_ack_with_no_object_echo():
    responses = {
        "api/users": {
            "baseline": (200, {}, _json({"ok": True})),
            "injected": (200, {}, _json({"ok": True, "message": "created"})),
        }
    }
    post = make_post(responses)
    findings, _p, _t = probe_mass_assignment(post, ("api/users",))
    assert findings == []


def test_negative_4xx_rejection():
    responses = {
        "api/users": {
            "baseline": (201, {}, _json({"id": 1, "name": "kuvprobe"})),
            "injected": (400, {}, _json({"error": "unknown field: role", "role": "admin"})),
        }
    }
    post = make_post(responses)
    findings, _p, _t = probe_mass_assignment(post, ("api/users",))
    # 4xx -> rejected, even though the error body happens to echo the field name
    assert findings == []


def test_negative_post_returns_none_everywhere():
    post = make_post({})  # every path -> None
    findings, probed, truncated = probe_mass_assignment(post, ("api/users", "api/account"))
    assert findings == []
    assert probed == 4 and truncated is False


# --------------------------------------------------------------------------
# (3) HTML catch-all — SPA answers 200 + its shell for any path
# --------------------------------------------------------------------------

def test_html_catch_all_is_not_flagged():
    responses = {
        "api/users": {
            "baseline": (200, {"content-type": "text/html"}, _HTML_SHELL),
            "injected": (200, {"content-type": "text/html"}, _HTML_SHELL),
        }
    }
    post = make_post(responses)
    findings, probed, _t = probe_mass_assignment(post, ("api/users",))
    assert findings == []
    assert probed == 2


# --------------------------------------------------------------------------
# (4) SAFE-behavior differential — must NOT be flagged
# --------------------------------------------------------------------------

def test_safe_server_default_true_is_suppressed():
    # The server ALWAYS sets is_verified=true on new records (its own default). The
    # injected value happens to match, but the baseline proves it is server-controlled.
    responses = {
        "api/users": {
            "baseline": (201, {}, _json({"id": 1, "name": "kuvprobe", "is_verified": True})),
            "injected": (201, {}, _json({"id": 2, "name": "kuvprobe", "is_verified": True})),
        }
    }
    post = make_post(responses)
    findings, _p, _t = probe_mass_assignment(post, ("api/users",))
    assert findings == []


def test_safe_role_echoed_back_as_server_controlled_value():
    # We inject role="admin"; the server ignores it and echoes its own role="user".
    responses = {
        "api/users": {
            "baseline": (201, {}, _json({"id": 1, "role": "user"})),
            "injected": (201, {}, _json({"id": 2, "role": "user"})),
        }
    }
    post = make_post(responses)
    findings, _p, _t = probe_mass_assignment(post, ("api/users",))
    assert findings == []


# --------------------------------------------------------------------------
# (5) cap / truncation
# --------------------------------------------------------------------------

def test_cap_truncates_before_an_unpaired_write():
    # 3 endpoints, cap=3: ep1 does baseline+injected (2), ep2 does baseline (3) then must
    # stop before its injected POST -> truncated, no half-paired extra write.
    responses = {p: None for p in ("api/a", "api/b", "api/c")}
    post = make_post(responses)
    findings, probed, truncated = probe_mass_assignment(post, ("api/a", "api/b", "api/c"), cap=3)
    assert findings == []
    assert probed == 3
    assert truncated is True
