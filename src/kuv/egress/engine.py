"""The egress policy engine: the single point every request is judged at.

Stateless per request except for the operator-confirmed write classes. Re-evaluate
EVERY redirect hop — a redirect off-scope is refused, not followed
(DESIGN-active-cli.md §Authorization Gate, Codex #1/#2/#4).
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date
from enum import Enum
from typing import Callable
from urllib.parse import urlparse

from kuv.gate.scope import ActionClass, Scope

from .budget import RunBudget

_READ_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})


class Classification(str, Enum):
    PASSIVE = "passive"            # GET/HEAD/OPTIONS read of an in-scope host
    ACTIVE_WRITE = "active_write"  # any state-changing method


class Decision(str, Enum):
    ALLOW = "allow"
    CONFIRM = "confirm"            # first live write of a class — operator must confirm
    REFUSE = "refuse"


@dataclass(frozen=True)
class EgressRequest:
    method: str
    url: str
    action_class: ActionClass | None = None   # required for active writes


@dataclass(frozen=True)
class EgressVerdict:
    decision: Decision
    classification: Classification
    reason: str
    host: str


DateFn = Callable[[], date]
AuditSink = Callable[[dict], None]


def _noop_audit(_event: dict) -> None:
    pass


class EgressEngine:
    def __init__(
        self,
        scope: Scope,
        *,
        now: DateFn,
        audit: AuditSink = _noop_audit,
        budget: RunBudget | None = None,
    ) -> None:
        self._scope = scope
        self._now = now
        self._audit = audit
        self._budget = budget
        self._confirmed: set[ActionClass] = set()

    def confirm(self, action_class: ActionClass) -> None:
        """Record operator confirmation for the first live write of a class."""
        self._confirmed.add(action_class)

    def in_scope(self, host: str) -> bool:
        """Side-effect-free scope membership check (no budget charge, no audit) — for
        pre-filtering candidate hosts (e.g. which discovered URLs are worth gating)."""
        host = (host or "").lower()
        return bool(host) and self._now() <= self._scope.expires_at and self._scope.host_in_scope(host)

    def check_host(self, host: str, *, kind: str = "dns") -> tuple[bool, str]:
        """Gate a non-HTTP egress (a DNS lookup, a full-bundle scan fetch): scope +
        budget + audit, in the same engine so nothing reaches the network ungated."""
        host = (host or "").lower()

        def audit(decision: str, reason: str) -> tuple[bool, str]:
            self._audit({"kind": kind, "host": host, "classification": kind,
                         "decision": decision, "reason": reason})
            return (decision == "allow", reason)

        if self._budget is not None:
            over = self._budget.charge(is_write=False)
            if over is not None:
                return audit("refuse", over)
        if not host:
            return audit("refuse", "missing host")
        if self._now() > self._scope.expires_at:
            return audit("refuse", f"engagement {self._scope.engagement_id} expired")
        if not self._scope.host_in_scope(host):
            return audit("refuse", f"{host} is out of authorized scope")
        return audit("allow", f"{kind} of in-scope host")

    def evaluate(self, request: EgressRequest) -> EgressVerdict:
        classification = (
            Classification.PASSIVE
            if request.method.upper() in _READ_METHODS
            else Classification.ACTIVE_WRITE
        )
        host = (urlparse(request.url).hostname or "").lower()
        verdict = self._decide(request, classification, host)
        self._audit(
            {
                "method": request.method.upper(),
                "url": request.url,
                "host": host,
                "classification": classification.value,
                "decision": verdict.decision.value,
                "reason": verdict.reason,
                "action_class": request.action_class.value if request.action_class else None,
            }
        )
        return verdict

    def _decide(
        self, request: EgressRequest, classification: Classification, host: str
    ) -> EgressVerdict:
        def verdict(decision: Decision, reason: str) -> EgressVerdict:
            return EgressVerdict(decision, classification, reason, host)

        # Budget is the outermost gate: every request charges it, so the cap bounds
        # ALL agent activity (recon churn included), not just writes.
        if self._budget is not None:
            over = self._budget.charge(classification is Classification.ACTIVE_WRITE)
            if over is not None:
                return verdict(Decision.REFUSE, over)

        if not host:
            return verdict(Decision.REFUSE, "unparseable or missing host")
        if self._now() > self._scope.expires_at:
            return verdict(
                Decision.REFUSE,
                f"engagement {self._scope.engagement_id} expired {self._scope.expires_at}",
            )
        if not self._scope.host_in_scope(host):
            return verdict(Decision.REFUSE, f"{host} is out of authorized scope")

        if classification is Classification.PASSIVE:
            return verdict(Decision.ALLOW, "passive read of in-scope host")

        # --- active write ---
        if not self._scope.authorization_asserted:
            return verdict(Decision.REFUSE, "active write requires an authorization assertion")
        action = request.action_class
        if action is None:
            return verdict(Decision.REFUSE, "active write requires an action_class")
        if action not in self._scope.allowed_actions:
            return verdict(Decision.REFUSE, f"action {action.value} not in allowed_actions")
        if self._scope.is_fixture:
            return verdict(Decision.ALLOW, "write to fixture target")
        if action in self._confirmed:
            return verdict(Decision.ALLOW, f"write {action.value} confirmed for this run")
        return verdict(
            Decision.CONFIRM, f"first live write of {action.value} needs operator confirmation"
        )
