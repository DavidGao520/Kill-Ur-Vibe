"""Unit tests for the authorization scope model + loader."""

from __future__ import annotations

from datetime import date

import pytest

from kuv.gate import ActionClass, Scope, ScopeError, load_scope_file

_VALID = {
    "engagement_id": "acme-2026",
    "authorized_by": "operator@example.com",
    "targets": ["app.example.com", "*.example.com"],
    "expires_at": "2026-12-31",
    "allowed_actions": ["account_create", "object_put"],
    "exclude": ["billing.example.com"],
}


def test_from_dict_parses_all_fields():
    scope = Scope.from_dict(_VALID)
    assert scope.engagement_id == "acme-2026"
    assert scope.expires_at == date(2026, 12, 31)
    assert ActionClass.ACCOUNT_CREATE in scope.allowed_actions
    assert scope.exclude == ("billing.example.com",)


@pytest.mark.parametrize("missing", ["engagement_id", "authorized_by", "targets", "expires_at"])
def test_missing_required_field_fails_fast(missing):
    data = {k: v for k, v in _VALID.items() if k != missing}
    with pytest.raises(ScopeError):
        Scope.from_dict(data)


def test_empty_targets_rejected():
    with pytest.raises(ScopeError):
        Scope.from_dict({**_VALID, "targets": []})


def test_unknown_action_class_rejected():
    with pytest.raises(ScopeError):
        Scope.from_dict({**_VALID, "allowed_actions": ["delete_everything"]})


def test_bad_date_rejected():
    with pytest.raises(ScopeError):
        Scope.from_dict({**_VALID, "expires_at": "not-a-date"})


def test_host_matching_exact_and_wildcard():
    scope = Scope.from_dict(_VALID)
    assert scope.host_in_scope("app.example.com") is True     # exact target
    assert scope.host_in_scope("dashboard.example.com") is True        # *.example.com subdomain
    assert scope.host_in_scope("example.com") is True           # *.example.com apex
    assert scope.host_in_scope("evil.com") is False         # off scope
    assert scope.host_in_scope("billing.example.com") is False  # excluded


def test_load_scope_file_roundtrip(tmp_path):
    import yaml

    path = tmp_path / "scope.yaml"
    path.write_text(yaml.safe_dump(_VALID), encoding="utf-8")
    scope = load_scope_file(str(path))
    assert scope.engagement_id == "acme-2026"


def test_load_non_mapping_rejected(tmp_path):
    path = tmp_path / "bad.yaml"
    path.write_text("- just\n- a\n- list\n", encoding="utf-8")
    with pytest.raises(ScopeError):
        load_scope_file(str(path))
