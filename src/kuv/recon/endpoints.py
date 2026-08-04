"""Deterministic API-endpoint classification for the unauthenticated-probe sweep.

`paths.py` finds every `/path` on a host; this module decides which of those are
data/API routes worth an unauthenticated GET, and — given a response — whether the
body looks like an exposed DATA collection (an array of records, a wrapped list, an
Elasticsearch `hits.hits`, an NDJSON dump). It NEVER returns field values, only
shape / count / field-name IDENTIFIERS: the point is to flag "this endpoint hands
back records with no auth", not to exfiltrate them. Pure over already-fetched bytes;
the gated GETs live in the session.

Why deterministic: the recall hole was that unauthenticated probing of each
discovered endpoint was left to per-request LLM discretion, so a single unguarded
sibling (e.g. a `/v1/search` that ignores the auth the REST routes enforce) could be
silently skipped. Sweeping every API endpoint in code closes that.
"""

from __future__ import annotations

import json
import re

# A data/API route worth an unauthenticated probe: versioned, /api, /graphql, /rest.
_API_PREFIX = re.compile(r"^/(?:v\d+|api|graphql|rest)(?:/|$)", re.I)
# The prefix words themselves — never a "resource" name (so /v1 doesn't yield "v1").
_PREFIX_WORD = re.compile(r"^(?:v\d+|api|graphql|rest)$", re.I)

# A search/query verb anywhere in the path — these need query params to leak, so the
# sweep probes generic variants (?q=…, ?index=<resource>) rather than a bare GET.
_SEARCH_SEG = re.compile(r"(?:^|/)(?:search|query|find|lookup|autocomplete|suggest)(?:/|$)", re.I)

# Keys whose value is commonly the record array in a wrapped response.
_LIST_KEYS = ("data", "results", "items", "hits", "records", "rows", "docs", "edges", "nodes")

_RESOURCE = re.compile(r"[A-Za-z][A-Za-z0-9_-]{1,40}$")

# A real field NAME identifier. Deliberately strict (no `@`, `.`, `-`, no leading
# digit, ≤40 chars) so that data-in-the-KEY-position — a map keyed by emails/UUIDs,
# `{"alice@corp.com": …}` — is DROPPED rather than surfaced as a "field name". This
# is the anti-value-leak guard: we return identifiers, not payload.
_IDENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,39}$")

# Cross-site-script-inclusion / anti-CSRF prefixes some APIs prepend to JSON.
_XSSI = re.compile(r"^(?:\)\]\}',?|while\s*\(1\);?|for\s*\(;;\);?|&&&START&&&)\s*")

# Above this size we don't fully parse (memory/latency) — but we still FLAG the body
# by its opening bracket rather than silently dropping it. A huge unauth body is more
# suspicious, not less; truncate-then-parse-fail would hide exactly the biggest leaks.
_PARSE_CAP = 5_000_000


def is_api_path(path: str) -> bool:
    """True if `path` is a data/API route (versioned / api / graphql / rest)."""
    return bool(_API_PREFIX.match(path or ""))


def is_search_path(path: str) -> bool:
    """True if `path` contains a search/query verb (needs param variants to leak)."""
    return bool(_SEARCH_SEG.search(path or ""))


def resource_name(path: str) -> str | None:
    """The REST resource name of an API path (`/v1/contacts` → `contacts`), or None
    for search verbs, trailing ids, the bare prefix (`/v1` → None), or non-API paths.
    Used to derive generic `?index=<resource>` search variants from what was actually
    discovered — never a hardcoded value."""
    if not is_api_path(path) or is_search_path(path):
        return None
    seg = (path or "").rstrip("/").rsplit("/", 1)[-1]
    if not _RESOURCE.fullmatch(seg) or _PREFIX_WORD.fullmatch(seg):
        return None
    return seg.lower()


def _safe_keys(rec: dict) -> tuple[str, ...]:
    """Record field NAMES that are plain identifiers only — drops any key that is
    itself data (an email/UUID/URL used as a map key) so values never leak out."""
    return tuple(k for k in sorted(str(x) for x in rec.keys()) if _IDENT.fullmatch(k))[:20]


def _first_dict(seq) -> dict | None:
    return next((x for x in seq if isinstance(x, dict)), None) if isinstance(seq, list) else None


def _classify_obj(obj) -> dict:
    """Classify an already-parsed JSON value."""
    none = {"data_shaped": False, "shape": None, "count": None, "keys": ()}
    if isinstance(obj, list):
        rec = _first_dict(obj)
        if rec and len(obj) > 0:
            return {"data_shaped": True, "shape": "array", "count": len(obj), "keys": _safe_keys(rec)}
        return none
    if isinstance(obj, dict):
        for k in _LIST_KEYS:
            v = obj.get(k)
            if isinstance(v, list) and v:
                rec = _first_dict(v)
                if rec:
                    return {"data_shaped": True, "shape": f"object.{k}[]", "count": len(v), "keys": _safe_keys(rec)}
            if k == "hits" and isinstance(v, dict):            # Elasticsearch: hits.hits[]
                inner = v.get("hits")
                rec = _first_dict(inner)
                if rec:
                    return {"data_shaped": True, "shape": "object.hits.hits[]", "count": len(inner), "keys": _safe_keys(rec)}
        if len(obj) >= 4:                                       # single fat record — weaker signal
            return {"data_shaped": True, "shape": "object", "count": 1, "keys": _safe_keys(obj)}
    return none


def _classify_ndjson(body: str, max_lines: int = 200) -> dict:
    """NDJSON / JSON-lines bulk dumps (the standard ES/export leak format) are not a
    single JSON doc — classify them by parsing the first lines."""
    none = {"data_shaped": False, "shape": None, "count": None, "keys": ()}
    dicts = []
    for line in body.splitlines()[:max_lines]:
        line = line.strip()
        if not line:
            continue
        try:
            o = json.loads(line)
        except Exception:  # noqa: BLE001
            continue
        if isinstance(o, dict):
            dicts.append(o)
    if len(dicts) >= 2:
        return {"data_shaped": True, "shape": "ndjson", "count": len(dicts), "keys": _safe_keys(dicts[0])}
    return none


def classify_json_body(status: int, content_type: str, text: str, parse_cap: int = _PARSE_CAP) -> dict:
    """Classify whether a response body looks like a DATA payload.

    Returns ``{"data_shaped", "shape", "count", "keys"}`` — shape is one of
    ``"array"`` / ``"object.<key>[]"`` / ``"object.hits.hits[]"`` / ``"ndjson"`` /
    ``"object"`` / ``None``; ``keys`` are record field-name identifiers only (never
    values). Non-2xx, non-JSON, or scalar/error bodies classify as not data-shaped. A
    body larger than ``parse_cap`` is FLAGGED by its opening bracket (``count`` /
    ``keys`` unknown) rather than silently dropped.
    """
    none = {"data_shaped": False, "shape": None, "count": None, "keys": ()}
    body = _XSSI.sub("", (text or "").lstrip())
    ct = (content_type or "").lower()
    if not (200 <= int(status) < 300) or not ("json" in ct or body[:1] in ("{", "[")):
        return none
    if len(body) > parse_cap:
        # Too big to fully parse — flag, don't drop. An array is a collection (→ exposed);
        # a giant object is data-shaped but the weaker single-object signal.
        return {"data_shaped": True, "shape": "array" if body[:1] == "[" else "object",
                "count": None, "keys": (), "large": True}
    try:
        obj = json.loads(body)
    except Exception:  # noqa: BLE001 — try NDJSON, then give up
        return _classify_ndjson(body)
    return _classify_obj(obj)


def is_exposed(status: int, classified: dict) -> bool:
    """True when a response is an unauthenticated DATA COLLECTION (2xx + a record
    list / ndjson / oversized array). A single fat object is deliberately excluded —
    too many benign config/status endpoints look like that; the collection shapes are
    the high-signal leak (records handed out with no auth). ``count is None`` (an
    oversized body flagged but not counted) still qualifies."""
    shape = classified.get("shape")
    if not (200 <= int(status) < 300 and classified.get("data_shaped")):
        return False
    if shape in (None, "object"):
        return False
    count = classified.get("count")
    return count is None or count > 0
