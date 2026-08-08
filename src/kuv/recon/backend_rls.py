"""Detect a BaaS backend (Supabase / Firebase / PocketBase / Appwrite) whose data
API returns rows **without authentication** — missing or mis-set Row-Level Security.
This is the single most common vibe-coded vulnerability: the app ships with a public
anon key and the developer never wrote an RLS policy, so `select * from users` works
for the whole internet.

SAFETY properties (this module is a pure analyzer, exactly like ``run_templated_checks``):

* **Pure & I/O-free.** No network, no disk, no shell. Every request is performed by
  the INJECTED ``fetch`` callable passed as the first argument; the caller (who knows
  the base URL and applies a row ``limit``) resolves each bare resource name to a
  base-appropriate URL (Supabase ``/rest/v1/<name>?select=*&limit=2`` or a Firebase
  ``<name>.json``). This module only decides *what* to ask about and *how to read* the
  answer.
* **One request per candidate, bounded by a cap.** At most ``cap`` fetches total.
* **Reads only, never mutates.** Pure GETs. It reads real rows, so the evidence it
  emits carries only status codes, row COUNTS, and field KEY NAMES — never a single
  row VALUE, secret, or PII datum.
* **Zero false positives.** A vibe-coded SPA answers ``200`` + its HTML shell for any
  path, so a finding REQUIRES a positive JSON-data signature and REJECTS an HTML
  document body, an empty array, a JSON ``null``, a JSON error object, and any
  non-JSON body. RLS-closed / auth-required responses (``401``/``403``, PostgREST
  ``{"code","message",...}``, Firebase ``{"error":"Permission denied"}``) yield nothing.

``finding_type`` is the PLAIN STRING ``"unauth_read_sensitive"`` (an existing type —
this module invents nothing). It NEVER imports ``kuv.severity`` and NEVER decides a
severity; ``contains_pii_or_secrets`` is a deterministic key-name flag, not a rating.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Callable, Optional

# --------------------------------------------------------------------------
# result row  (the session layer maps these field names to record_finding)
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class BackendReadRow:
    finding_type: str
    title: str
    location: str
    evidence: str
    recommendation: str
    plain_impact: str
    contains_pii_or_secrets: bool = False


# --------------------------------------------------------------------------
# curated candidate resources
# --------------------------------------------------------------------------

# Table / collection names vibe-coders routinely leave world-readable. Bare names:
# the injected ``fetch`` maps each to the base-appropriate URL + row limit.
DEFAULT_TABLES: tuple[str, ...] = (
    "users",
    "profiles",
    "accounts",
    "customers",
    "orders",
    "messages",
    "posts",
    "todos",
    "notes",
    "subscriptions",
    "waitlist",
    "emails",
    "contacts",
    "leads",
    "payments",
)

# Fixed strings — this module states WHAT was found; the severity table rates it.
_TITLE = "Backend data is readable without authentication (Row-Level Security not enforced)"
_RECOMMENDATION = (
    "Enable Row-Level Security on every table and write explicit per-row access "
    "policies (Supabase: ALTER TABLE ... ENABLE ROW LEVEL SECURITY + policies; "
    "Firebase/PocketBase/Appwrite: lock the database rules / collection permissions "
    "so unauthenticated reads are denied). Never rely on the anon/public key as a "
    "gate — it is shipped in the client and is public by definition."
)
_PLAIN_IMPACT = (
    "Anyone on the internet can read the rows in this table straight from your "
    "backend API without logging in — no password, no account. If it holds user "
    "records, that is a data breach waiting to be scraped."
)

# --------------------------------------------------------------------------
# deterministic response reading  (zero-false-positive discipline)
# --------------------------------------------------------------------------

# Bound the work of key extraction on a large / hostile response body.
_MAX_ROWS_SCANNED = 25
_MAX_KEYS = 40
_MAX_KEYS_IN_EVIDENCE = 12

# Key NAMES (not values) that mark a table as holding PII / secrets. Substring match
# on the lowercased key, so "user_email", "phone_number", "full_name", "access_token",
# "password_hash", "client_secret", "api_key" all trip their signature.
_PII_KEY_SIGNATURES: tuple[str, ...] = (
    "email",
    "phone",
    "name",
    "address",
    "token",
    "password",
    "passwd",
    "ssn",
    "api_key",
    "apikey",
    "secret",
)

# PostgREST / Firebase error-object key set. A successful Supabase read is ALWAYS a
# JSON array, so any top-level object from that shape is an error; Firebase signals a
# closed node with ``{"error": "Permission denied"}``.
_ERROR_KEY_SET = frozenset({"code", "details", "hint", "message", "error"})


def _as_text(body: Any) -> str:
    if isinstance(body, str):
        return body
    if isinstance(body, (bytes, bytearray)):
        try:
            return bytes(body).decode("utf-8", "replace")
        except Exception:  # pragma: no cover - defensive
            return ""
    return "" if body is None else str(body)


def _looks_html(body: str) -> bool:
    """An HTML document shell (SPA catch-all) — never a JSON data response."""
    head = (body or "")[:600].lstrip().lower()
    return head.startswith("<!doctype html") or head.startswith("<html") or "<head" in head[:200]


def _is_error_object(obj: dict) -> bool:
    """True for a PostgREST / Firebase auth-or-error object (a CLOSED signal)."""
    low = {str(k).lower() for k in obj.keys()}
    if not low:
        return False
    if "error" in low:  # Firebase "Permission denied", generic error envelope
        return True
    if low <= _ERROR_KEY_SET:  # a pure error shape ({"code","message",...})
        return True
    if "message" in low and "code" in low:  # PostgREST error carries both
        return True
    return False


def _collect_keys(records: list) -> list[str]:
    """Ordered, de-duplicated field key NAMES across up to _MAX_ROWS_SCANNED objects."""
    keys: list[str] = []
    seen: set[str] = set()
    for rec in records[:_MAX_ROWS_SCANNED]:
        if not isinstance(rec, dict):
            continue
        for k in rec.keys():
            ks = str(k)
            if ks not in seen:
                seen.add(ks)
                keys.append(ks)
                if len(keys) >= _MAX_KEYS:
                    return keys
    return keys


def _read_open_data(parsed: Any) -> Optional[tuple[str, int, list[str]]]:
    """Return ``(shape_label, row_count, field_keys)`` iff ``parsed`` is a positive
    unauthenticated-read signature, else ``None`` (closed / error / not data).

    Positive shapes:
      * a non-empty JSON ARRAY containing >=1 object (Supabase / PostgREST rows), or
      * a non-empty JSON OBJECT that is not an error object and carries >=1
        dict-valued member — the Firebase RTDB push-id -> record map. Field keys are
        read from the RECORDS only, never from the object's own top-level keys.

    A bare object with NO dict-valued member is deliberately rejected. Such a body is
    either a generic success/wrapper envelope (``{"data":[],"status":"ok"}``,
    ``{"success":false,"message":"nope"}``) — a false positive — or a scalar-valued
    index map (``{"alice_smith":1,"bob_jones":2}`` from a vibe-coded Firebase
    ``/usernames`` node) whose top-level keys ARE identifier data. Emitting those keys
    would leak values into evidence, so this shape yields nothing rather than a finding.
    """
    if isinstance(parsed, list):
        if not parsed:
            return None  # [] — RLS-closed empty result
        dict_items = [x for x in parsed if isinstance(x, dict)]
        if not dict_items:
            return None  # array of scalars — not a table read
        return ("JSON array", len(parsed), _collect_keys(dict_items))

    if isinstance(parsed, dict):
        if not parsed:
            return None  # {} — empty node
        if _is_error_object(parsed):
            return None  # 401/403 body, PostgREST error, Firebase permission denied
        # Require the push-id -> record shape: at least one dict-valued member. Keys are
        # gathered from those records only, so top-level ids/index keys never leak into
        # evidence. A scalar-valued map or a wrapper/status envelope has no dict member
        # and is rejected here (no false positive, no key-as-value leak).
        dict_values = [v for v in parsed.values() if isinstance(v, dict)]
        if not dict_values:
            return None
        return ("JSON object", len(dict_values), _collect_keys(dict_values))

    return None  # null / bool / number / string — not tabular data


def _pii_keys(keys: list[str]) -> list[str]:
    hits: list[str] = []
    for k in keys:
        kl = k.lower()
        if any(sig in kl for sig in _PII_KEY_SIGNATURES):
            hits.append(k)
    return hits


# --------------------------------------------------------------------------
# entry point
# --------------------------------------------------------------------------


def probe_backend_rls(
    fetch: Callable[[str], Optional[tuple]],
    candidates: tuple[str, ...] = DEFAULT_TABLES,
    cap: int = 30,
) -> tuple[list[BackendReadRow], int, bool]:
    """Probe each candidate resource for an unauthenticated (RLS-open) read.

    ``fetch(candidate)`` returns ``(status, headers, body)`` or ``None`` (refused /
    error). Exactly one fetch per candidate; at most ``cap`` fetches total. Returns
    ``(rows, probed_count, truncated)`` where each row is one table readable without
    auth. Evidence carries status, row COUNT, and field KEY NAMES only — never values.
    """
    out: list[BackendReadRow] = []
    probed = 0
    truncated = False

    for candidate in candidates:
        if probed >= cap:
            truncated = True
            break

        res = fetch(candidate)
        probed += 1
        if res is None:
            continue

        try:
            status, headers, body = res
        except (TypeError, ValueError):  # pragma: no cover - defensive on a bad fetch
            continue

        if status != 200:
            continue  # 401/403/404/... — auth required or absent, not open

        text = _as_text(body)
        if _looks_html(text):
            continue  # SPA HTML shell — the classic false positive we refuse

        try:
            parsed = json.loads(text)
        except (ValueError, TypeError):
            continue  # non-JSON body — not a data API response

        read = _read_open_data(parsed)
        if read is None:
            continue

        shape, row_count, keys = read
        pii = _pii_keys(keys)
        sample = sorted(set(keys))[:_MAX_KEYS_IN_EVIDENCE]
        keys_str = ", ".join(sample)
        out.append(
            BackendReadRow(
                finding_type="unauth_read_sensitive",
                title=_TITLE,
                location=candidate,
                evidence=(
                    f"GET {candidate} -> {status}, {shape}, {row_count} rows, "
                    f"keys: [{keys_str}]"
                ),
                recommendation=_RECOMMENDATION,
                plain_impact=_PLAIN_IMPACT,
                contains_pii_or_secrets=bool(pii),
            )
        )

    return out, probed, truncated
