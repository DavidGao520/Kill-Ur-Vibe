"""Tests for the per-run budget and its enforcement in the egress engine (T9)."""

from __future__ import annotations

from datetime import date

from kuv.egress import Decision, EgressEngine, EgressRequest, RunBudget
from kuv.gate import ActionClass, Scope

_NOW = date(2026, 7, 31)


class _Clock:
    def __init__(self, t: float = 0.0):
        self.t = t

    def __call__(self) -> float:
        return self.t


def test_request_cap_refuses_after_limit():
    b = RunBudget(max_requests=3, clock=_Clock())
    assert b.charge() is None
    assert b.charge() is None
    assert b.charge() is None
    assert b.charge() is not None  # 4th over the cap
    assert b.requests_used == 3


def test_wall_clock_cap():
    clock = _Clock(0.0)
    b = RunBudget(max_requests=1000, max_wall_seconds=10.0, clock=clock)
    assert b.charge() is None  # starts the clock at t=0
    clock.t = 11.0
    assert "wall-clock" in (b.charge() or "")


def test_write_cap_leaves_reads_available():
    b = RunBudget(max_requests=100, max_writes=1, clock=_Clock())
    assert b.charge(is_write=True) is None
    assert b.charge(is_write=True) is not None  # second write blocked
    assert b.charge(is_write=False) is None      # reads still fine


def _scope() -> Scope:
    return Scope(
        engagement_id="acme",
        authorized_by="d",
        targets=("app.example.com",),
        expires_at=date(2026, 12, 31),
        authorization_asserted=True,
    )


def test_engine_refuses_over_budget_request():
    engine = EgressEngine(_scope(), now=lambda: _NOW, budget=RunBudget(max_requests=2, clock=_Clock()), ip_resolver=lambda h: ["93.184.216.34"])
    get = EgressRequest("GET", "https://app.example.com/a")
    assert engine.evaluate(get).decision is Decision.ALLOW
    assert engine.evaluate(get).decision is Decision.ALLOW
    over = engine.evaluate(get)
    assert over.decision is Decision.REFUSE
    assert "budget exhausted" in over.reason


def test_no_budget_means_no_cap():
    engine = EgressEngine(_scope(), now=lambda: _NOW, ip_resolver=lambda h: ["93.184.216.34"])  # budget=None
    get = EgressRequest("GET", "https://app.example.com/a")
    for _ in range(50):
        assert engine.evaluate(get).decision is Decision.ALLOW
