"""Detect an API that mass-assigns client-supplied privileged fields it should ignore.

The classic vibe-coded flaw is ``db.insert(req.body)`` / ``new User(req.body)`` — the
handler shovels the *entire* request body into the record instead of allow-listing the
few fields a client is allowed to set. When it does, a caller can smuggle in
``role="admin"``, ``is_admin=true``, ``credits=999999`` or ``plan="enterprise"`` on an
ordinary create/update and have the server store them. This probe looks for evidence of the
flaw the only way a single identity can — POST a benign synthetic object, then POST it again
with a fixed catalog of privileged fields injected, and see whether the response **echoes an
injected field back with the value we injected** that the baseline did NOT already return.
An echo is a *necessary* signal, not proof of storage: it cannot, from one identity, tell a
stored-and-unintended field (the real vuln) apart from one that was merely reflected back or
one that is legitimately client-settable. See HONEST LIMITATIONS below.

This is a WRITE probe. Safety / blast-radius properties (why it is legitimate to run
against a third party's production, and how the damage is bounded):

* **Pure and I/O-free.** This module does NO network, disk, or shell. Every request goes
  through the INJECTED ``post`` callable (gated egress), exactly like
  ``probe_webhook_sig(post, …)`` / ``run_templated_checks(fetch, …)``.
* **Side effect on the target: it creates (at most) two synthetic records per endpoint** —
  one benign baseline, one carrying the injected fields. Both use synthetic marker names
  (``name``/``title`` = ``"kuvprobe"``) and NON-EXISTENT owner ids (``owner_id``/``user_id``
  = ``"0"``), so the injected write cannot attach to or mutate a real user's data.
* **Bounded by ``cap``.** At most ``cap`` POSTs total across all endpoints (two per
  endpoint), so the number of synthetic rows created is hard-capped.
* **Differential, to kill false positives.** A field is flagged only if the injected
  response echoes it with the injected value AND the baseline response (which never
  carried that field) did NOT already return the same value. That suppresses the case
  where the server *always* sets the field itself (a server default), and the case where
  the server echoes the field back with its own value (e.g. ``role`` → ``"user"``).
* **Zero false positives from SPA catch-alls.** A vibe-coded SPA answers ``200`` + its
  HTML shell for any path; an HTML-document body is REJECTED. A 2xx generic
  acknowledgement with no object echo (``{"ok": true}``) matches nothing and is not a
  finding. Only a JSON body that echoes an injected field with the injected value counts.
* **Value-free evidence.** Evidence carries the status and the injected field *names*
  only — never response values, PII, or fetched content. The injected values are our own
  synthetic constants, not the target's data.

HONEST LIMITATIONS — an echo is single-identity evidence, and single-identity evidence is
two-sided (both a false-negative and a false-positive vector):

* **False NEGATIVE (no echo).** This detects only the case where the API **echoes** the
  accepted field back in its create/update response. An endpoint that *silently* accepts and
  stores a privileged field without echoing it is reported as clean here, not as vulnerable.
* **False POSITIVE (echo without storage).** Symmetrically, an echo does NOT prove the
  server *persisted* the field. A confirmation/echo create endpoint that reflects the posted
  body back for acknowledgement — without storing the privileged fields — produces the exact
  same differential (the baseline body carries no ``role``; the injected body echoes
  ``role="admin"``) and is flagged even though nothing was stored. The differential kills
  server-default and server-controlled echoes, but from one identity it cannot separate
  "stored" from "merely reflected".
* **False POSITIVE (stored but legitimately client-settable).** Some catalog fields are
  frequently *meant* to be chosen by the client and stored — most notably ``plan`` /
  ``subscription_tier`` on a signup/subscription create endpoint (the client picks a plan,
  the server stores + echoes it, and billing is enforced separately), and to a lesser degree
  ``owner_id`` / ``user_id``. A benign server that stores and echoes the client's chosen
  ``plan="enterprise"`` yields a ``mass_assignment`` finding. Because this module assigns no
  severity or confidence (finding_type only) and the catalog is spec-fixed, that benign case
  cannot be suppressed inside the module or downstream: a ``mass_assignment`` finding on
  ``plan`` / ``subscription_tier`` / ``owner_id`` / ``user_id`` REQUIRES a human to confirm
  the field is not intentionally client-settable before it is treated as a defect.

The sound disambiguation for BOTH false-positive vectors is the SAME two-identity read-back
that resolves the false negative — create the record carrying the injected field as one
identity, then read it back as a second identity. That proves the field was persisted AND is
visible cross-identity, which neither a reflect-without-store endpoint nor a per-client
legitimate field would satisfy. It is a future Wave-2b capability this probe does not attempt.

The module never imports :mod:`kuv.severity` and never decides a severity — it emits a
plain ``finding_type`` string (``"privilege_escalation"`` or ``"mass_assignment"``); the
deterministic severity table maps it downstream.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Callable, Optional

# --------------------------------------------------------------------------
# result row  (field names are mapped 1:1 to session.record_finding)
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class MassAssignmentFinding:
    finding_type: str
    title: str
    location: str
    evidence: str
    recommendation: str
    plain_impact: str
    contains_pii_or_secrets: bool = False


# --------------------------------------------------------------------------
# candidate create/update collections (the caller normally passes discovered
# POST-able endpoints; this is a conservative default for standalone use)
# --------------------------------------------------------------------------

DEFAULT_ENDPOINTS: tuple[str, ...] = (
    "api/users",
    "api/user",
    "api/register",
    "api/signup",
    "api/account",
    "api/profile",
    "api/profiles",
    "api/members",
)

# --------------------------------------------------------------------------
# the injected privileged-field catalog + how each is matched in a response
# --------------------------------------------------------------------------

_PRIVILEGE = True  # role / admin / permission fields  -> "privilege_escalation"
_MASS = False      # everything else                    -> "mass_assignment"


@dataclass(frozen=True)
class _Field:
    name: str
    is_privilege: bool
    kind: str          # "bool" | "str" | "num" | "list_admin"
    expected: Any      # the injected value (for str/num); ignored for bool/list_admin

    def matches(self, v: Any) -> bool:
        """True iff a response value ``v`` equals the value we injected for this field.

        Type-strict on purpose: a JSON bool must be a real ``True`` (not ``1``), a number
        must be numeric-and-not-bool, a string must match exactly. This keeps matching
        deterministic and avoids ``1 == True`` style false positives.
        """
        if self.kind == "bool":
            return isinstance(v, bool) and v is True
        if self.kind == "str":
            return isinstance(v, str) and v == self.expected
        if self.kind == "num":
            return isinstance(v, (int, float)) and not isinstance(v, bool) and v == self.expected
        if self.kind == "list_admin":
            return isinstance(v, list) and any(isinstance(x, str) and x == "admin" for x in v)
        return False


# Fixed catalog. Privilege/role fields first, then the broader mass-assignment set.
_CATALOG: tuple[_Field, ...] = (
    _Field("role", _PRIVILEGE, "str", "admin"),
    _Field("is_admin", _PRIVILEGE, "bool", True),
    _Field("isAdmin", _PRIVILEGE, "bool", True),
    _Field("admin", _PRIVILEGE, "bool", True),
    _Field("is_superuser", _PRIVILEGE, "bool", True),
    _Field("permissions", _PRIVILEGE, "list_admin", None),
    _Field("credits", _MASS, "num", 999999),
    _Field("balance", _MASS, "num", 999999),
    _Field("is_verified", _MASS, "bool", True),
    _Field("email_verified", _MASS, "bool", True),
    _Field("verified", _MASS, "bool", True),
    _Field("plan", _MASS, "str", "enterprise"),
    _Field("subscription_tier", _MASS, "str", "enterprise"),
    _Field("owner_id", _MASS, "str", "0"),
    _Field("user_id", _MASS, "str", "0"),
)

# The synthetic marker written into the benign fields of every probe object.
_MARKER = "kuvprobe"

# Baseline body: benign synthetic fields ONLY (no injected privileged fields).
_BASELINE_OBJ: dict = {"name": _MARKER, "title": _MARKER}

# Injected body: the same benign object plus every privileged field from the catalog.
_INJECTED_OBJ: dict = dict(_BASELINE_OBJ)
for _f in _CATALOG:
    if _f.kind == "bool":
        _INJECTED_OBJ[_f.name] = True
    elif _f.kind == "list_admin":
        _INJECTED_OBJ[_f.name] = ["admin"]
    else:
        _INJECTED_OBJ[_f.name] = _f.expected

# Deterministic, byte-stable serialization (mirrors webhook_sig.PROBE_BODY).
BASELINE_BODY: str = json.dumps(_BASELINE_OBJ, sort_keys=True, separators=(",", ":"))
INJECTED_BODY: str = json.dumps(_INJECTED_OBJ, sort_keys=True, separators=(",", ":"))
PROBE_HEADERS: dict = {"content-type": "application/json"}

# --------------------------------------------------------------------------
# matchers / helpers
# --------------------------------------------------------------------------

_MAX_DEPTH = 6  # bound recursion over the response object


def _looks_html(body: str) -> bool:
    """A body starting with an HTML doctype/`<html>`, or an early `<head>`, is an SPA
    shell — a real create/update endpoint returns JSON or an empty body, never a page."""
    head = (body or "")[:600].lstrip().lower()
    return head.startswith("<!doctype html") or head.startswith("<html") or "<head" in head[:200]


def _parse_json(body: Any) -> Optional[Any]:
    """Return the parsed JSON of ``body`` (dict/list/scalar), or ``None`` if the body is
    an HTML document or is not valid JSON. Never raises."""
    if isinstance(body, (bytes, bytearray)):
        try:
            body = body.decode("utf-8", "replace")
        except Exception:
            return None
    text = body or ""
    if _looks_html(text):
        return None
    try:
        return json.loads(text)
    except (ValueError, TypeError):
        return None


def _collect_pairs(obj: Any, out: Optional[list], depth: int = 0) -> list:
    """Recursively collect every ``(key, value)`` pair from dicts nested in ``obj``.

    Naive handlers return the created row either at the top level or wrapped
    (``{"user": {...}}`` / ``{"data": {...}}``), so we walk the whole structure. Bounded
    by ``_MAX_DEPTH``."""
    if out is None:
        out = []
    if depth > _MAX_DEPTH:
        return out
    if isinstance(obj, dict):
        for k, v in obj.items():
            out.append((k, v))
            _collect_pairs(v, out, depth + 1)
    elif isinstance(obj, list):
        for item in obj:
            _collect_pairs(item, out, depth + 1)
    return out


def _field_present_with_injected_value(field: _Field, pairs: list) -> bool:
    """True iff some ``(key, value)`` in ``pairs`` has ``key == field.name`` (exact) and a
    value equal to what we injected."""
    return any(k == field.name and field.matches(v) for k, v in pairs)


def _accepted_fields(status: Any, body: Any, baseline_obj: Optional[Any]) -> list[_Field]:
    """Return the catalog fields the injected response **echoes** with the injected value.

    A field qualifies iff: the injected response is a 2xx JSON body (not HTML) that echoes
    the field with the injected value, AND the baseline response (which never carried that
    field) did NOT already return the same value (server default / server-controlled echo).
    An echo is a *necessary* signal, not proof of storage — see the module HONEST LIMITATIONS
    (reflect-without-store, and legitimately client-settable fields such as plan).
    """
    try:
        code = int(status)
    except (TypeError, ValueError):
        return []
    if not (200 <= code < 300):
        return []
    obj = _parse_json(body)
    if obj is None:
        return []
    resp_pairs = _collect_pairs(obj, None)
    base_pairs = _collect_pairs(baseline_obj, None) if baseline_obj is not None else []

    accepted: list[_Field] = []
    for field in _CATALOG:
        if not _field_present_with_injected_value(field, resp_pairs):
            continue
        # Differential: if the baseline already returned this value, it is a server
        # default / server-controlled — NOT attacker-controlled. Do not flag.
        if baseline_obj is not None and _field_present_with_injected_value(field, base_pairs):
            continue
        accepted.append(field)
    return accepted


# --------------------------------------------------------------------------
# finding copy (two variants: privilege escalation vs. general mass assignment)
# --------------------------------------------------------------------------

_PRIV_TITLE = "API mass-assigns client-supplied privilege fields (privilege escalation)"
_PRIV_RECOMMENDATION = (
    "Never pass the raw request body into your data layer (db.insert(req.body) / new "
    "User(req.body)). Allow-list exactly the fields a client may set and drop everything "
    "else; set role, admin, superuser and permission fields ONLY from server-side logic, "
    "never from client input."
)
_PRIV_PLAIN_IMPACT = (
    "When creating or updating an object, a user can grant themselves elevated privileges "
    "just by adding an extra field to the request — for example setting their own role to "
    "admin or turning on a superuser flag. That is a direct path to taking over "
    "administrative control of the app."
)

_MASS_TITLE = "API mass-assigns client-supplied fields it should control server-side"
_MASS_RECOMMENDATION = (
    "Allow-list the fields a client is permitted to set and ignore the rest; never spread "
    "the whole request body into the record. Fields like balance, credits, verified "
    "status, plan/tier and record ownership must be set server-side only, never accepted "
    "from client input. Triage note: an echo shows the field was reflected, not necessarily "
    "persisted; and plan / subscription_tier / owner_id / user_id are sometimes intentionally "
    "client-settable. Confirm the field is genuinely stored and not meant to be client-set "
    "(ideally via a two-identity read-back) before treating this as a defect."
)
_MASS_PLAIN_IMPACT = (
    "A user can set fields the server is supposed to control just by adding them to the "
    "request — for example giving themselves a huge balance or credit count, marking their "
    "account verified, upgrading to a paid plan for free, or reassigning who owns a record."
)


def _make_finding(path: str, status: Any, fields: list[_Field], privilege: bool) -> MassAssignmentFinding:
    names = ", ".join(sorted({f.name for f in fields}))
    if privilege:
        finding_type, title = "privilege_escalation", _PRIV_TITLE
        recommendation, plain_impact = _PRIV_RECOMMENDATION, _PRIV_PLAIN_IMPACT
    else:
        finding_type, title = "mass_assignment", _MASS_TITLE
        recommendation, plain_impact = _MASS_RECOMMENDATION, _MASS_PLAIN_IMPACT
    return MassAssignmentFinding(
        finding_type=finding_type,
        title=title,
        location=f"POST /{path}",
        # value-free: status + injected field NAMES only (never the echoed values).
        evidence=(
            f"POST /{path} → {status}; JSON response echoed injected field(s) [{names}] "
            "with the injected value (not HTML; distinct from the benign baseline response)"
        ),
        recommendation=recommendation,
        plain_impact=plain_impact,
        contains_pii_or_secrets=False,
    )


# --------------------------------------------------------------------------
# entry point
# --------------------------------------------------------------------------


def probe_mass_assignment(
    post: Callable[[str, str, dict], Optional[tuple]],
    endpoints: tuple[str, ...],
    cap: int = 12,
) -> tuple[list[MassAssignmentFinding], int, bool]:
    """POST a benign object then an injected object to each endpoint; flag echoed fields.

    ``post(path, body, headers)`` returns ``(status, headers, body)`` or ``None``
    (refused/blocked/error); the caller sends it through the gated egress. Each endpoint
    costs up to two POSTs (baseline, then injected), and at most ``cap`` POSTs are made in
    total. For each endpoint we emit at most one ``privilege_escalation`` finding (if any
    role/admin/permission field was accepted) and at most one ``mass_assignment`` finding
    (if any other privileged field was accepted). Returns ``(findings, probed, truncated)``.
    """
    out: list[MassAssignmentFinding] = []
    probed = 0
    truncated = False

    for path in endpoints:
        # Need budget for the baseline POST.
        if probed >= cap:
            truncated = True
            break

        baseline_obj: Optional[Any] = None
        base_res = post(path, BASELINE_BODY, PROBE_HEADERS)
        probed += 1
        if base_res is not None:
            _b_status, _b_headers, b_body = base_res
            baseline_obj = _parse_json(b_body)  # None if HTML / non-JSON

        # Need budget for the injected POST; if not, stop before creating an unpaired write.
        if probed >= cap:
            truncated = True
            break

        inj_res = post(path, INJECTED_BODY, PROBE_HEADERS)
        probed += 1
        if inj_res is None:
            continue
        status, _headers, body = inj_res

        accepted = _accepted_fields(status, body, baseline_obj)
        if not accepted:
            continue

        priv = [f for f in accepted if f.is_privilege]
        mass = [f for f in accepted if not f.is_privilege]
        if priv:
            out.append(_make_finding(path, status, priv, privilege=True))
        if mass:
            out.append(_make_finding(path, status, mass, privilege=False))

    return out, probed, truncated
