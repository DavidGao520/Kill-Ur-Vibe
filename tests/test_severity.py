"""Unit tests for the deterministic severity rule table (D9)."""

from __future__ import annotations

import pytest

from kuv.severity import (
    FindingType,
    NeedsOperatorSeverity,
    Severity,
    priority_for,
    severity_for,
)


def test_unauth_write_is_critical():
    assert severity_for(FindingType.UNAUTH_WRITE) is Severity.CRITICAL


def test_service_role_exposed_is_critical():
    assert severity_for(FindingType.SERVICE_ROLE_EXPOSED) is Severity.CRITICAL


def test_unauth_read_is_conditional_on_pii():
    assert severity_for(FindingType.UNAUTH_READ_SENSITIVE, contains_pii_or_secrets=True) is Severity.CRITICAL
    assert severity_for(FindingType.UNAUTH_READ_SENSITIVE) is Severity.HIGH


def test_off_allowlist_secret_is_high():
    assert severity_for(FindingType.OFF_ALLOWLIST_SECRET) is Severity.HIGH


def test_transport_posture_is_medium():
    assert severity_for(FindingType.WEAK_TRANSPORT_OR_CORS) is Severity.MEDIUM
    assert severity_for(FindingType.OAUTH_CONFIG_GAP) is Severity.MEDIUM


def test_accepts_string_finding_type():
    assert severity_for("unauth_write") is Severity.CRITICAL


def test_unknown_type_surfaces_to_operator():
    with pytest.raises(NeedsOperatorSeverity):
        severity_for("some_novel_finding_the_llm_dreamt_up")


def test_severity_is_stable_across_calls():
    # Determinism is the whole point — same input, same output, every time.
    assert severity_for(FindingType.UNAUTH_WRITE) is severity_for("unauth_write")


def test_priority_buckets():
    assert priority_for(Severity.CRITICAL) == "Today"
    assert priority_for(Severity.HIGH) == "24-48h"
    assert priority_for(Severity.MEDIUM) == "This week"


# --- Task 1: the opened vocabulary (common authz-bug classes) ---

def test_idor_is_high_or_critical_on_pii():
    assert severity_for(FindingType.IDOR) is Severity.HIGH
    assert severity_for(FindingType.IDOR, contains_pii_or_secrets=True) is Severity.CRITICAL


def test_privilege_escalation_is_critical():
    assert severity_for(FindingType.PRIVILEGE_ESCALATION) is Severity.CRITICAL


def test_mass_assignment_is_high():
    assert severity_for(FindingType.MASS_ASSIGNMENT) is Severity.HIGH


def test_jwt_forgeable_is_critical():
    assert severity_for(FindingType.JWT_FORGEABLE) is Severity.CRITICAL


def test_ssrf_is_high():
    assert severity_for(FindingType.SSRF) is Severity.HIGH


def test_open_redirect_is_low():
    assert severity_for(FindingType.OPEN_REDIRECT) is Severity.LOW


def test_new_types_accept_string_form():
    assert severity_for("privilege_escalation") is Severity.CRITICAL
    assert severity_for("idor", contains_pii_or_secrets=True) is Severity.CRITICAL


# --- Task 2: the NEEDS_OPERATOR escape-hatch sentinel ---

def test_needs_operator_severity_and_priority():
    assert Severity.NEEDS_OPERATOR.value == "Needs operator triage"
    assert priority_for(Severity.NEEDS_OPERATOR) == "Operator triage"


def test_missing_static_rule_degrades_to_operator_not_keyerror(monkeypatch):
    # Defensive: a known enum member with no static rule (e.g. a conditional type
    # mistakenly narrowed out of the branch) must degrade to NeedsOperatorSeverity,
    # never a bare KeyError that crashes report assembly.
    from kuv.severity import rules
    trimmed = dict(rules._STATIC)
    del trimmed[FindingType.SSRF]
    monkeypatch.setattr(rules, "_STATIC", trimmed)
    with pytest.raises(NeedsOperatorSeverity):
        severity_for(FindingType.SSRF)
