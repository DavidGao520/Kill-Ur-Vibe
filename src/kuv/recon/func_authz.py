"""Detect BROKEN FUNCTION-LEVEL AUTHORIZATION (BFLA) — the *unauthenticated* slice.

A privileged/admin FUNCTION route (list every user, read global settings, export
data, tail logs) is supposed to be reachable only by a logged-in operator. A
vibe-coded app that gates the *page* in the client but forgets to gate the *API*
will happily hand the privileged payload to anyone who requests the route with no
session at all. This probe proves exactly that failure the only sound way — one
plain GET, no auth — and only flags a route when BOTH conditions hold: the route's
NAME denotes a privileged/admin function AND the response is a privileged DATA body
(a non-empty collection of records, or a config/settings/internal object).

Scope note: this covers the UNAUTHENTICATED case only (no session ⇒ privileged
data). The full BFLA case — a *normal authenticated* user calling an admin route —
needs a two-identity differential scan (a future Wave-2b capability) and is out of
scope here. Distinct from object-level IDOR/BOLA (reading another owner's object by
id) and from static exposed-file checks (:mod:`kuv.recon.templated`).

Safety / blast-radius properties (why this is legitimate to run against a third
party's production):

* **Pure and I/O-free.** No network, disk, or shell. Every request goes through the
  INJECTED ``fetch`` callable (gated egress), exactly like ``run_templated_checks``
  and ``probe_webhook_sig``.
* **GET only — read, non-mutating.** A GET reads; it never writes, deletes, or
  changes state on the target. No fuzzing, no brute-force.
* **Bounded by ``cap``.** At most ``cap`` GETs total; each route is probed once
  (deduplicated), and routes whose NAME is not privileged are never fetched at all.
* **Value-free evidence.** Evidence carries the route, status, response SHAPE and
  record/key COUNT only — never a fetched value, record, secret, or PII.
* **Zero false positives.** A vibe-coded SPA answers ``200`` + its HTML shell for
  ANY path, so an HTML-document body is REJECTED. So are 401/403/404, a 3xx / HTML
  login redirect, an empty list/object, an error/status envelope, and any public
  non-privileged endpoint. A finding requires a POSITIVE privileged-data signal on a
  privileged-NAMED route.

The module never imports :mod:`kuv.severity` and never decides a severity — it emits
a plain ``finding_type`` string; the deterministic severity table maps it downstream.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Callable, Optional

# --------------------------------------------------------------------------
# result row  (field names are mapped 1:1 to session.record_finding)
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class FuncAuthzFinding:
    finding_type: str
    title: str
    location: str
    evidence: str
    recommendation: str
    plain_impact: str
    contains_pii_or_secrets: bool = False


# --------------------------------------------------------------------------
# default catalog of privileged/admin FUNCTION routes (the search space)
# --------------------------------------------------------------------------

DEFAULT_PRIVILEGED_ROUTES: tuple[str, ...] = (
    "api/admin",
    "api/admin/users",
    "admin/api",
    "api/internal",
    "api/users",
    "api/all-users",
    "api/config",
    "api/settings",
    "api/settings/global",
    "api/export",
    "api/logs",
    "api/metrics",
    "api/accounts",
    "api/tenants",
    "api/organizations",
)

# --------------------------------------------------------------------------
# name gating: which route NAMES denote a privileged/admin function
# --------------------------------------------------------------------------

# Whole path-segment tokens that mark a route as a privileged/admin FUNCTION. A
# match on ANY segment qualifies the route. Kept to admin/internal/config/settings/
# export/logs/metrics/directory-listing tokens so plainly public routes (blog, about,
# health, products, …) never qualify. Deliberately excludes generic words like
# "events"/"stats" that are commonly public feeds.
_PRIV_TOKENS: frozenset[str] = frozenset(
    {
        # admin / operator surface
        "admin", "admins", "administrator", "administrators",
        "superadmin", "superuser", "sysadmin", "root",
        "internal", "system", "backend", "management", "manage",
        # configuration surface
        "config", "configuration", "configs", "settings", "setting",
        "global", "env", "environment",
        # data-egress / operations surface
        "export", "exports", "dump", "backup",
        "logs", "log", "audit",
        "metrics", "telemetry",
        # multi-record directory / tenancy surface
        "accounts", "tenants", "tenant",
        "organizations", "organization", "orgs", "org",
        "users", "all-users", "allusers", "members", "customers",
    }
)

# The subset of route names for which a config/settings/internal OBJECT body (not a
# record collection) is an accepted privileged signal. A named config/settings/
# internal/system route handing back a substantive object with no auth is the leak.
_CONFIG_ROUTE_TOKENS: frozenset[str] = frozenset(
    {
        "config", "configuration", "configs", "settings", "setting",
        "global", "env", "environment", "internal", "system",
    }
)


def _segments(path: str) -> tuple[str, ...]:
    return tuple(s for s in (path or "").lower().strip("/").split("/") if s)


def _is_privileged_route(path: str) -> bool:
    """True iff the route NAME denotes a privileged/admin function (any segment is a
    privileged token, or an ``admin``-prefixed segment). Purely lexical."""
    for seg in _segments(path):
        if seg in _PRIV_TOKENS or seg.startswith("admin"):
            return True
    return False


def _is_config_route(path: str) -> bool:
    return any(seg in _CONFIG_ROUTE_TOKENS for seg in _segments(path))


# --------------------------------------------------------------------------
# body classification (value-free: shape / count / key NAMES only)
# --------------------------------------------------------------------------

# Keys whose value is commonly the record array in a wrapped collection response.
_LIST_KEYS: tuple[str, ...] = (
    "data", "results", "items", "records", "rows", "docs", "edges", "nodes",
    "users", "accounts", "members", "tenants", "organizations", "orgs",
    "logs", "entries", "list", "payload",
)

# An object whose keys are ALL in this set is an error/status envelope, not data.
_ENVELOPE_KEYS: frozenset[str] = frozenset(
    {
        "error", "errors", "message", "messages", "detail", "details",
        "code", "status", "statuscode", "success", "ok", "reason",
    }
)

# A key NAME (identifier only — never a value) that hints an object is a real
# config/infra dump rather than a couple of public UI flags.
_CONFIGISH: tuple[str, ...] = (
    "secret", "key", "token", "password", "passwd", "credential", "dsn",
    "database", "db_", "_db", "url", "host", "port", "smtp", "aws", "s3",
    "bucket", "stripe", "apikey", "api_key", "private", "cert", "jwt",
    "oauth", "client", "webhook", "internal", "feature", "flag", "cors",
    "origin", "allow", "white", "admin", "mongo", "redis", "postgres",
    "mysql", "sentry", "supabase", "firebase", "endpoint", "region",
)

# Above this size we do not fully parse; an oversized ARRAY is still flagged as a
# collection by its opening bracket (an oversized object is skipped — safer).
_PARSE_CAP = 2_000_000

# Cross-site-script-inclusion / anti-CSRF prefixes some APIs prepend to JSON.
_XSSI_PREFIXES: tuple[str, ...] = (")]}'", ")]}',", "while(1);", "for(;;);", "&&&START&&&")


def _ctype(headers: dict) -> str:
    for k, v in (headers or {}).items():
        if str(k).lower() == "content-type":
            return str(v).lower()
    return ""


def _looks_html(body: str) -> bool:
    """A body opening with an HTML doctype/``<html>`` (or an early ``<head>``) is an
    SPA shell or a login page — never a privileged API payload."""
    head = (body or "")[:600].lstrip().lower()
    return head.startswith("<!doctype html") or head.startswith("<html") or "<head" in head[:200]


def _strip_xssi(body: str) -> str:
    b = (body or "").lstrip()
    for pref in _XSSI_PREFIXES:
        if b.startswith(pref):
            return b[len(pref):].lstrip()
    return b


def _first_dict(seq) -> Optional[dict]:
    return next((x for x in seq if isinstance(x, dict)), None) if isinstance(seq, list) else None


def _is_envelope(obj: dict) -> bool:
    keys = {str(k).lower() for k in obj.keys()}
    return bool(keys) and keys.issubset(_ENVELOPE_KEYS)


def _configish(obj: dict) -> bool:
    for k in obj.keys():
        low = str(k).lower()
        if any(tok in low for tok in _CONFIGISH):
            return True
    return False


def _classify_ndjson(body: str, max_lines: int = 200) -> Optional[tuple]:
    """NDJSON / JSON-lines bulk dumps: a collection when >=2 object lines parse."""
    dicts = 0
    for line in body.splitlines()[:max_lines]:
        line = line.strip()
        if not line:
            continue
        try:
            o = json.loads(line)
        except Exception:  # noqa: BLE001
            continue
        if isinstance(o, dict):
            dicts += 1
    if dicts >= 2:
        return ("records", "ndjson", dicts)
    return None


def _privileged_body(path: str, status: int, headers: dict, body: str) -> Optional[tuple]:
    """Return ``(kind, shape, count)`` iff the response is a PRIVILEGED data body, else
    ``None``. ``kind`` is ``"records"`` (a non-empty collection of records) or
    ``"config"`` (a substantive config/settings/internal object on a config-named
    route). Requires exactly ``200`` + a JSON/data body that is not an HTML shell.
    """
    try:
        code = int(status)
    except (TypeError, ValueError):
        return None
    if code != 200:
        return None
    if _looks_html(body):
        return None

    text = _strip_xssi(body)
    ct = _ctype(headers)
    if not ("json" in ct or text[:1] in ("{", "[")):
        return None  # not a JSON/data body (e.g. Prometheus text, a login page fragment)

    # Oversized: flag an array collection by its bracket; skip oversized objects.
    if len(text) > _PARSE_CAP:
        if text[:1] == "[":
            return ("records", "array", None)
        return None

    try:
        obj = json.loads(text)
    except Exception:  # noqa: BLE001
        return _classify_ndjson(text)

    # --- Branch A: a non-empty COLLECTION of records (any privileged route) ---
    if isinstance(obj, list):
        if obj and _first_dict(obj) is not None:
            return ("records", "array", len(obj))
        return None  # empty list, or a list of scalars → reject
    if isinstance(obj, dict):
        for k in _LIST_KEYS:
            v = obj.get(k)
            if isinstance(v, list) and v and _first_dict(v) is not None:
                return ("records", f"object.{k}[]", len(v))
        # Elasticsearch-style hits.hits[]
        hits = obj.get("hits")
        if isinstance(hits, dict):
            inner = hits.get("hits")
            if isinstance(inner, list) and inner and _first_dict(inner) is not None:
                return ("records", "object.hits.hits[]", len(inner))

        # --- Branch B: a config/settings/internal OBJECT (config-named route only) ---
        if _is_config_route(path) and not _is_envelope(obj):
            n = len(obj)
            if n >= 3 and (_configish(obj) or n >= 8):
                return ("config", "object", n)

    return None


# --------------------------------------------------------------------------
# entry point
# --------------------------------------------------------------------------

_TITLE = "An admin/privileged function is reachable with no authentication"
_RECOMMENDATION = (
    "Enforce authentication AND an authorization (role/admin) check on this route on "
    "the SERVER, for every privileged API endpoint — not just on the page or menu that "
    "links to it. Return 401/403 to any request without a valid privileged session, and "
    "verify the caller's role before returning any data. Hiding the admin UI in the "
    "client is not access control."
)
_PLAIN_IMPACT = (
    "An admin-only feature — such as listing every user, reading global settings, or "
    "exporting data — answers anyone on the internet without logging in. A stranger can "
    "pull privileged data or controls that should be limited to your staff, just by "
    "visiting the URL."
)


def probe_func_authz(
    fetch: Callable[[str], Optional[tuple]],
    routes: Optional[tuple[str, ...]] = None,
    cap: int = 20,
) -> tuple[list[FuncAuthzFinding], int, bool]:
    """GET each privileged-NAMED route with no auth; flag any that returns privileged data.

    ``fetch(path)`` returns ``(status, headers, body)`` or ``None`` (refused/blocked/
    error); the caller sends it through the gated egress. GET only — read, safe,
    non-mutating. ``routes`` are discovered privileged routes; when None/empty the
    default catalog is used. Routes whose NAME is not privileged are skipped WITHOUT a
    request. At most ``cap`` GETs total. Returns ``(findings, probed_count, truncated)``.
    """
    candidates = routes if routes else DEFAULT_PRIVILEGED_ROUTES
    out: list[FuncAuthzFinding] = []
    probed = 0
    truncated = False
    seen: set[str] = set()

    for raw in candidates:
        canon = (raw or "").strip().lstrip("/")
        if not canon:
            continue
        key = canon.lower().rstrip("/")
        if key in seen:
            continue  # deduplicate identical routes (no double-count, no wasted budget)
        seen.add(key)
        if not _is_privileged_route(canon):
            continue  # NAME is not privileged → not in scope for this probe; no request
        if probed >= cap:
            truncated = True
            return out, probed, truncated

        res = fetch(canon)
        probed += 1
        if res is None:
            continue
        status, headers, body = res
        verdict = _privileged_body(canon, status, headers, body)
        if verdict is None:
            continue
        kind, shape, count = verdict
        descr = "record collection" if kind == "records" else "config object"
        count_str = "unknown" if count is None else str(count)
        out.append(
            FuncAuthzFinding(
                finding_type="broken_function_auth",
                title=_TITLE,
                location=f"GET /{canon}",
                # value-free: route, status, shape, count only — never a fetched value.
                evidence=(
                    f"GET /{canon} → {status}, shape={shape}, count={count_str}, "
                    f"{len(body or '')} bytes; privileged route name + unauthenticated "
                    f"{descr}, response is not HTML"
                ),
                recommendation=_RECOMMENDATION,
                plain_impact=_PLAIN_IMPACT,
                contains_pii_or_secrets=False,
            )
        )
    return out, probed, truncated
