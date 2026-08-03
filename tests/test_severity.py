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
