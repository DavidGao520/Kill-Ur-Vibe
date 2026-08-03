"""The authorization scope: what a single run is allowed to touch.

A malformed scope must fail fast at load — the tool never runs on a scope it
could not fully parse.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date, datetime
from enum import Enum


class ActionClass(str, Enum):
    """Write action classes, gated individually — blast radius differs per class."""

    ACCOUNT_CREATE = "account_create"
    OBJECT_PUT = "object_put"
    WEBSOCKET_SAVE = "websocket_save"
    AUTH_CHANGE = "auth_change"
    INVITE_FLOW = "invite_flow"


class ScopeError(ValueError):
    """Malformed scope — fail fast, never run on a bad scope."""


def _parse_date(value: object) -> date:
    if isinstance(value, datetime):
        return value.date()
    if isinstance(value, date):
        return value
    if isinstance(value, str):
        try:
            return date.fromisoformat(value)
        except ValueError as exc:
            raise ScopeError(f"bad expires_at: {value!r}") from exc
    raise ScopeError(f"bad expires_at type: {type(value).__name__}")


def _parse_action(value: object) -> ActionClass:
    try:
        return ActionClass(value)
    except ValueError as exc:
        raise ScopeError(f"unknown action class: {value!r}") from exc


def _host_matches(host: str, pattern: str) -> bool:
    pattern = pattern.lower().strip()
    if pattern.startswith("*."):
        base = pattern[2:]
        return host == base or host.endswith("." + base)
    return host == pattern


@dataclass(frozen=True)
class Scope:
    engagement_id: str
    authorized_by: str
    targets: tuple[str, ...]                       # hosts; "*.x.com" allows subdomains
    expires_at: date
    allowed_actions: frozenset[ActionClass] = frozenset()
    exclude: tuple[str, ...] = ()
    is_fixture: bool = False                       # fixtures run writes unattended
    authorization_asserted: bool = False           # the per-run "I am authorized" flag

    @staticmethod
    def from_dict(data: dict) -> "Scope":
        try:
            targets = tuple(data["targets"])
            engagement_id = str(data["engagement_id"])
            authorized_by = str(data["authorized_by"])
            expires_raw = data["expires_at"]
        except KeyError as exc:
            raise ScopeError(f"missing required scope field: {exc}") from exc
        except TypeError as exc:
            raise ScopeError(f"scope must be a mapping: {exc}") from exc
        if not targets:
            raise ScopeError("scope.targets must be non-empty")
        return Scope(
            engagement_id=engagement_id,
            authorized_by=authorized_by,
            targets=targets,
            expires_at=_parse_date(expires_raw),
            allowed_actions=frozenset(_parse_action(a) for a in data.get("allowed_actions", [])),
            exclude=tuple(data.get("exclude", [])),
            is_fixture=bool(data.get("is_fixture", False)),
            authorization_asserted=bool(data.get("authorization_asserted", False)),
        )

    def host_in_scope(self, host: str) -> bool:
        """True if `host` is allowed (matches a target and no exclude)."""
        host = host.lower()
        if any(_host_matches(host, e) for e in self.exclude):
            return False
        return any(_host_matches(host, t) for t in self.targets)


def load_scope_file(path: str) -> Scope:
    """Load and validate a scope YAML file, failing fast on any malformation."""
    import yaml  # declared dependency; imported lazily so the core stays stdlib-only

    with open(path, encoding="utf-8") as handle:
        data = yaml.safe_load(handle)
    if not isinstance(data, dict):
        raise ScopeError("scope file must be a YAML mapping")
    return Scope.from_dict(data)
