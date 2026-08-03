"""Egress engine tests — two of the three safety acceptance gates live here:
scope refusal and write blocking."""

from __future__ import annotations

from datetime import date

from kuv.egress import Classification, Decision, EgressEngine, EgressRequest
from kuv.gate import ActionClass, Scope

_NOW = date(2026, 7, 31)


def _scope(**overrides) -> Scope:
    base = dict(
        engagement_id="acme-2026",
        authorized_by="operator@example.com",
        targets=("app.example.com", "*.example.com"),
        expires_at=date(2026, 12, 31),
        allowed_actions=frozenset({ActionClass.ACCOUNT_CREATE}),
        exclude=("billing.example.com",),
        is_fixture=False,
        authorization_asserted=True,
    )
    base.update(overrides)
    return Scope(**base)


def _engine(scope: Scope | None = None):
    events: list[dict] = []
    engine = EgressEngine(scope or _scope(), now=lambda: _NOW, audit=events.append)
    return engine, events


def _get(url):
    return EgressRequest("GET", url)


def _post(url, action=ActionClass.ACCOUNT_CREATE):
    return EgressRequest("POST", url, action_class=action)


# --- scope refusal --------------------------------------------------------

def test_passive_read_in_scope_allowed():
    engine, _ = _engine()
    v = engine.evaluate(_get("https://app.example.com/app.js"))
    assert v.decision is Decision.ALLOW
    assert v.classification is Classification.PASSIVE


def test_off_scope_host_refused():
    engine, _ = _engine()
    assert engine.evaluate(_get("https://evil.com/x")).decision is Decision.REFUSE


def test_excluded_host_refused():
    engine, _ = _engine()
    assert engine.evaluate(_get("https://billing.example.com/x")).decision is Decision.REFUSE


def test_expired_engagement_refuses_even_passive():
    engine, _ = _engine(_scope(expires_at=date(2026, 1, 1)))
    assert engine.evaluate(_get("https://app.example.com/x")).decision is Decision.REFUSE


def test_missing_host_refused():
    engine, _ = _engine()
    assert engine.evaluate(_get("not-a-url")).decision is Decision.REFUSE


# --- write blocking -------------------------------------------------------

def test_write_without_authorization_assertion_refused():
    engine, _ = _engine(_scope(authorization_asserted=False))
    assert engine.evaluate(_post("https://app.example.com/api/users")).decision is Decision.REFUSE


def test_write_of_unlisted_action_refused():
    engine, _ = _engine(_scope(allowed_actions=frozenset()))
    assert engine.evaluate(_post("https://app.example.com/api/users")).decision is Decision.REFUSE


def test_write_without_action_class_refused():
    engine, _ = _engine()
    req = EgressRequest("POST", "https://app.example.com/api/users")  # no action_class
    assert engine.evaluate(req).decision is Decision.REFUSE


def test_first_live_write_needs_confirmation_then_allows():
    engine, _ = _engine()
    first = engine.evaluate(_post("https://app.example.com/api/users"))
    assert first.decision is Decision.CONFIRM
    engine.confirm(ActionClass.ACCOUNT_CREATE)
    second = engine.evaluate(_post("https://app.example.com/api/users"))
    assert second.decision is Decision.ALLOW


def test_fixture_write_runs_unattended():
    engine, _ = _engine(_scope(is_fixture=True))
    v = engine.evaluate(_post("https://app.example.com/api/users"))
    assert v.decision is Decision.ALLOW
    assert v.classification is Classification.ACTIVE_WRITE


# --- redirect hop + audit -------------------------------------------------

def test_redirect_hop_off_scope_is_refused():
    # Each hop is judged independently; a redirect off-scope is refused, not followed.
    engine, _ = _engine()
    assert engine.evaluate(_get("https://app.example.com/go")).decision is Decision.ALLOW
    assert engine.evaluate(_get("https://tracker.evil.com/collect")).decision is Decision.REFUSE


def test_every_evaluate_emits_one_audit_event():
    engine, events = _engine()
    engine.evaluate(_get("https://app.example.com/a"))
    engine.evaluate(_get("https://evil.com/b"))
    assert len(events) == 2
    assert events[0]["decision"] == "allow"
    assert events[1]["decision"] == "refuse"
    assert events[1]["host"] == "evil.com"
