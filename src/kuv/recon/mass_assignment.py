"""Detect an API that mass-assigns and PERSISTS client-supplied fields it should control.

The classic vibe-coded flaw is ``db.insert(req.body)`` / ``new User(req.body)`` — the
handler shovels the *entire* request body into the record instead of allow-listing the
few fields a client is allowed to set. When it does, a caller can smuggle in
``role="admin"``, ``is_admin=true``, ``credits=999999`` or ``plan="enterprise"`` on an
ordinary create/update and have the server **store** them.

An *echo* alone does not prove that flaw. The single commonest schemaless / NoSQL shape is
an echo-create — ``res.json({...req.body, id})`` — which reflects the posted body straight
back for acknowledgement while storing nothing extra. From one request that endpoint is
indistinguishable from a real mass-assignment: the baseline body carries no ``role``, the
injected body echoes ``role="admin"``, and a probe that stops at the echo fires a false
positive. **Echo is reflection, not storage.** This probe therefore crosses a second,
independent hop before it emits anything:

  1. POST a benign synthetic baseline object, then POST the same object with the fixed
     privileged-field catalog injected; compute the differential — an injected field
     echoed back with the injected value that the baseline did NOT already return (this
     kills server-default and server-controlled-echo cases).
  2. Parse the created record's id out of the injected response and issue a SECOND,
     INDEPENDENT ``GET <endpoint>/<id>``. A differential field qualifies as a finding ONLY
     if the read-back record still carries it with the injected value. No id, a read-back
     that is refused / 4xx / non-JSON, or the field absent on read-back -> the field is
     treated as reflected-not-stored and produces NOTHING.

Three tiers, and this probe only ever reaches the middle one:

  * echo but storage UNPROVEN  -> emit nothing.
  * storage PROVEN via read-back -> one ``mass_assignment`` finding (severity HIGH is
    assigned downstream by the fixed table, never here), carrying an explicit hedge that a
    stored field is not proven to *govern* authorization.
  * storage AND authorization-impact proven -> ``privilege_escalation`` (CRITICAL). Proving
    that a stored ``role``/``admin`` field is actually honored needs a two-identity scan and
    is OUT OF SCOPE for this single-identity probe. **This probe therefore NEVER emits
    ``privilege_escalation``** — a persisted ``role="admin"`` is reported as
    ``mass_assignment`` with the not-proven-to-govern-authorization hedge.

This is a WRITE probe. Safety / blast-radius properties (why it is legitimate to run
against a third party's production, and how the damage is bounded):

* **Pure and I/O-free.** This module does NO network, disk, or shell. Every request goes
  through the INJECTED ``request`` callable (gated egress), exactly like
  ``probe_webhook_sig(post, …)`` / ``run_templated_checks(fetch, …)``.
* **Side effect on the target: it creates (at most) two synthetic records per endpoint** —
  one benign baseline, one carrying the injected fields. Both use synthetic marker names
  (``name``/``title`` = ``"kuvprobe"``) and NON-EXISTENT owner ids (``owner_id``/``user_id``
  = ``"0"``), so the injected write cannot attach to or mutate a real user's data. These
  ``kuvprobe`` rows PERSIST on the target — kuv performs no DELETE, so the operator must
  purge them. The read-back GET is a read and creates nothing.
* **Bounded by ``cap``.** ``cap`` bounds the number of POSTs (writes) across all endpoints
  (two per endpoint), so the number of synthetic rows created is hard-capped. The read-back
  GET issued only for a differential endpoint is a read and is not charged against ``cap``.
* **Differential, to kill false positives.** A field is considered only if the injected
  response echoes it with the injected value AND the baseline response (which never carried
  that field) did NOT already return the same value. That suppresses the case where the
  server *always* sets the field itself (a server default) and the case where the server
  echoes the field back with its own value (e.g. ``role`` → ``"user"``).
* **Read-back, to kill the echo-without-storage false positive.** A differential field is
  emitted only if a second, independent ``GET <endpoint>/<id>`` shows the field persisted
  with the injected value. An echo-create that reflects the body without storing it
  produces the differential but fails the read-back, so it emits nothing.
* **Zero false positives from SPA catch-alls.** A vibe-coded SPA answers ``200`` + its
  HTML shell for any path; an HTML-document body is REJECTED at every hop. A 2xx generic
  acknowledgement with no object echo (``{"ok": true}``) matches nothing and is not a
  finding.
* **Value-free evidence.** Evidence carries the status and the injected field *names*
  only — never response values, the target's record id, PII, or fetched content. The
  injected values are our own synthetic constants, not the target's data.

HONEST LIMITATION that survives the read-back: proving a field is *stored and cross-visible*
is not the same as proving it *governs* authorization or billing. A benign server may store
and echo a client-chosen ``plan="enterprise"`` (billing enforced separately) or persist a
``role`` string an authorization layer never consults. So a ``mass_assignment`` finding here
means "the server accepted, persisted, and re-served a field a client should not be able to
set" — it does NOT assert privilege escalation. That last hop (does the stored field change
what the account can DO, proven across two identities) is a future Wave-2b capability this
probe does not attempt, which is exactly why it never emits ``privilege_escalation``.

The module never imports :mod:`kuv.severity` and never decides a severity — it emits a
plain ``finding_type`` string (always ``"mass_assignment"`` now); the deterministic
severity table maps it to HIGH downstream.
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


@dataclass(frozen=True)
class _Field:
    name: str
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


# Fixed catalog. role/admin/permission fields are included, but — unlike earlier revisions
# of this probe — they no longer route to a separate privilege_escalation finding: a stored
# role/admin field is reported as mass_assignment with the not-proven-to-govern-authz hedge.
_CATALOG: tuple[_Field, ...] = (
    _Field("role", "str", "admin"),
    _Field("is_admin", "bool", True),
    _Field("isAdmin", "bool", True),
    _Field("admin", "bool", True),
    _Field("is_superuser", "bool", True),
    _Field("permissions", "list_admin", None),
    _Field("credits", "num", 999999),
    _Field("balance", "num", 999999),
    _Field("is_verified", "bool", True),
    _Field("email_verified", "bool", True),
    _Field("verified", "bool", True),
    _Field("plan", "str", "enterprise"),
    _Field("subscription_tier", "str", "enterprise"),
    _Field("owner_id", "str", "0"),
    _Field("user_id", "str", "0"),
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
# Content-type the caller's `request` wrapper should send for the POST hops. The callable
# signature is request(method, path, body); headers are the wrapper's concern, not ours.
PROBE_HEADERS: dict = {"content-type": "application/json"}

# Keys under which a created record's id is commonly returned (top-level or nested).
_ID_KEYS: tuple[str, ...] = ("id", "_id", "uuid", "guid", "pk")
_ID_WRAPPERS: tuple[str, ...] = ("data", "object")

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


def _id_str(v: Any) -> Optional[str]:
    """Coerce a candidate id value to a non-empty string, or ``None`` if it is not a
    plain scalar id (bool/None/container are rejected)."""
    if isinstance(v, bool):
        return None
    if isinstance(v, str):
        return v or None
    if isinstance(v, int):
        return str(v)
    return None


def _extract_id(obj: Any) -> Optional[str]:
    """Pull a created record's id out of the injected response for the read-back GET.

    Looks for ``id`` / ``_id`` / ``uuid`` / ``guid`` / ``pk`` at the top level first, then
    the same keys nested one level under ``data`` / ``object`` (``data.id`` / ``object.id``,
    the common wrapped shapes). Returns the id as a string, or ``None`` if none is present.
    """
    if not isinstance(obj, dict):
        return None
    for k in _ID_KEYS:
        if k in obj:
            s = _id_str(obj[k])
            if s is not None:
                return s
    for wrapper in _ID_WRAPPERS:
        inner = obj.get(wrapper)
        if isinstance(inner, dict):
            for k in _ID_KEYS:
                if k in inner:
                    s = _id_str(inner[k])
                    if s is not None:
                        return s
    return None


def _field_present_with_injected_value(field: _Field, pairs: list) -> bool:
    """True iff some ``(key, value)`` in ``pairs`` has ``key == field.name`` (exact) and a
    value equal to what we injected."""
    return any(k == field.name and field.matches(v) for k, v in pairs)


def _differential_fields(status: Any, inj_obj: Any, baseline_obj: Optional[Any]) -> list[_Field]:
    """Return the catalog fields the injected response **echoes** with the injected value.

    A field qualifies iff: the injected response is a 2xx JSON body (already parsed into
    ``inj_obj``, ``None`` for HTML/non-JSON) that echoes the field with the injected value,
    AND the baseline response (which never carried that field) did NOT already return the
    same value (server default / server-controlled echo). This is a *necessary* signal, not
    proof of storage — the caller must confirm each field via the independent read-back.
    """
    try:
        code = int(status)
    except (TypeError, ValueError):
        return []
    if not (200 <= code < 300):
        return []
    if inj_obj is None:
        return []
    resp_pairs = _collect_pairs(inj_obj, None)
    base_pairs = _collect_pairs(baseline_obj, None) if baseline_obj is not None else []

    accepted: list[_Field] = []
    for field in _CATALOG:
        if not _field_present_with_injected_value(field, resp_pairs):
            continue
        # Differential: if the baseline already returned this value, it is a server
        # default / server-controlled — NOT attacker-controlled. Do not consider.
        if baseline_obj is not None and _field_present_with_injected_value(field, base_pairs):
            continue
        accepted.append(field)
    return accepted


# --------------------------------------------------------------------------
# finding copy  (single variant: mass assignment, storage proven via read-back)
# --------------------------------------------------------------------------

_MASS_TITLE = "API mass-assigns and stores client-supplied fields it should control server-side"
_MASS_RECOMMENDATION = (
    "Allow-list the fields a client is permitted to set and ignore the rest; never spread "
    "the whole request body into the record. Fields like role/admin flags, balance, credits, "
    "verified status, plan/tier and record ownership must be set server-side only, never "
    "accepted from client input. Triage note: this probe confirmed the field was PERSISTED "
    "via an independent read-back (not merely reflected in the create response), but it did "
    "NOT prove the stored field actually governs authorization or billing — a persisted role "
    "string may or may not be honored by the authorization layer, so confirm the field's real "
    "effect (ideally via a two-identity scan) before treating it as privilege escalation. "
    "Cleanup: this probe created synthetic 'kuvprobe' rows via POST that persist on the "
    "target; kuv performs no DELETE, so purge them manually."
)
_MASS_PLAIN_IMPACT = (
    "A user can set fields the server is supposed to control just by adding them to the "
    "request — for example giving themselves a huge balance or credit count, marking their "
    "account verified, upgrading to a paid plan for free, reassigning who owns a record, or "
    "setting a role/admin flag. This probe read the record back from an independent request "
    "and confirmed the injected field was actually stored, not just reflected — but it did "
    "not prove the stored field grants elevated privileges (it may be persisted yet ignored "
    "by the authorization layer). Note: the probe left synthetic 'kuvprobe' records behind "
    "that should be purged."
)


def _make_finding(path: str, status: Any, fields: list[_Field]) -> MassAssignmentFinding:
    names = ", ".join(sorted({f.name for f in fields}))
    return MassAssignmentFinding(
        finding_type="mass_assignment",
        title=_MASS_TITLE,
        location=f"POST /{path}",
        # value-free: status + injected field NAMES only (never the echoed values, and never
        # the target's record id — the read-back path uses an <id> placeholder here).
        evidence=(
            f"POST /{path} → {status}; JSON response echoed injected field(s) [{names}] with "
            "the injected value (not HTML; distinct from the benign baseline), and an "
            f"independent GET /{path}/<id> read-back confirmed [{names}] persisted with the "
            "injected value. Persistence is proven; whether the field governs authorization "
            "is NOT. Synthetic 'kuvprobe' rows were created via POST and are not auto-deleted."
        ),
        recommendation=_MASS_RECOMMENDATION,
        plain_impact=_MASS_PLAIN_IMPACT,
        contains_pii_or_secrets=False,
    )


# --------------------------------------------------------------------------
# entry point
# --------------------------------------------------------------------------


def probe_mass_assignment(
    request: Callable[[str, str, Optional[str]], Optional[tuple]],
    endpoints: tuple[str, ...],
    cap: int = 12,
) -> tuple[list[MassAssignmentFinding], int, bool]:
    """POST a benign then an injected object to each endpoint, then read the record back to
    prove the injected fields were actually stored (not merely echoed).

    ``request(method, path, body)`` returns ``(status, headers, body)`` or ``None``
    (refused/blocked/error); the caller sends it through the gated egress. ``method`` is
    ``"POST"`` (``body`` is the JSON string) or ``"GET"`` (``body`` is ``None``). Per
    endpoint: POST baseline, POST injected, compute the differential, then — only if the
    differential is non-empty — parse the created id from the injected response and issue an
    independent ``GET <endpoint>/<id>``; a differential field is emitted only if that
    read-back still carries it with the injected value.

    ``cap`` bounds the number of POSTs (writes) across all endpoints (two per endpoint); the
    read-back GET is a read and is not charged against it. For each endpoint at most one
    ``mass_assignment`` finding is emitted (this probe never emits ``privilege_escalation``).
    Returns ``(findings, probed, truncated)`` where ``probed`` counts POSTs made.
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
        base_res = request("POST", path, BASELINE_BODY)
        probed += 1
        if base_res is not None:
            _b_status, _b_headers, b_body = base_res
            baseline_obj = _parse_json(b_body)  # None if HTML / non-JSON

        # Need budget for the injected POST; if not, stop before creating an unpaired write.
        if probed >= cap:
            truncated = True
            break

        inj_res = request("POST", path, INJECTED_BODY)
        probed += 1
        if inj_res is None:
            continue
        status, _headers, body = inj_res

        inj_obj = _parse_json(body)  # None if HTML / non-JSON
        accepted = _differential_fields(status, inj_obj, baseline_obj)
        if not accepted:
            # No echoed differential at all -> nothing to try to prove.
            continue

        # --- second hop: prove STORAGE with an independent read-back GET ------------------
        obj_id = _extract_id(inj_obj)
        if obj_id is None:
            # Cannot locate the created record -> storage unproven -> emit nothing.
            continue

        read_res = request("GET", f"{str(path).rstrip('/')}/{obj_id}", None)
        if read_res is None:
            continue  # read-back refused/blocked/error -> storage unproven
        r_status, _r_headers, r_body = read_res
        try:
            r_code = int(r_status)
        except (TypeError, ValueError):
            continue
        if not (200 <= r_code < 300):
            continue  # 4xx/5xx read-back -> record not retrievable -> storage unproven
        read_obj = _parse_json(r_body)  # None if HTML / non-JSON
        if read_obj is None:
            continue
        read_pairs = _collect_pairs(read_obj, None)

        # A differential field qualifies ONLY if it survives in the read-back record.
        persisted = [f for f in accepted if _field_present_with_injected_value(f, read_pairs)]
        if not persisted:
            # Echoed but not stored (the res.json({...req.body, id}) reflect-only shape).
            continue

        out.append(_make_finding(path, status, persisted))

    return out, probed, truncated
