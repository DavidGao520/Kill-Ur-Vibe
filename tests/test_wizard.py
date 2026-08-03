"""Tests for the interactive wizard's pure helpers (no key, no network, no LLM)."""

from __future__ import annotations

from datetime import date

import pytest

from kuv.gate import ActionClass
from kuv.wizard import build_scope, parse_target


def test_parse_bare_domain():
    url, host, apex = parse_target("myapp.com")
    assert url == "https://myapp.com" and host == "myapp.com" and apex == "myapp.com"


def test_parse_full_url_with_subdomain():
    url, host, apex = parse_target("https://app.example.com/dashboard?x=1")
    assert host == "app.example.com" and apex == "example.com"


def test_parse_deep_subdomain_takes_last_two_labels():
    _, host, apex = parse_target("http://a.b.example.co")
    assert host == "a.b.example.co" and apex == "example.co"


def test_parse_rejects_junk():
    with pytest.raises(ValueError):
        parse_target("   ")


def test_build_scope_is_readonly_and_authorized():
    scope = build_scope("app.example.com", "example.com", "me@example.com")
    assert scope.targets == ("app.example.com", "example.com", "*.example.com")
    assert scope.allowed_actions == frozenset()          # read-only
    assert ActionClass.ACCOUNT_CREATE not in scope.allowed_actions
    assert scope.is_fixture is False
    assert scope.authorization_asserted is True
    assert scope.expires_at > date.today()
    # scope enforcement still works off this
    assert scope.host_in_scope("api.example.com") is True
    assert scope.host_in_scope("evil.com") is False
