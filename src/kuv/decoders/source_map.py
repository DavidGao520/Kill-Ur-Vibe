"""Source-map exposure decoder: is a JS file's sibling `*.js.map` served?

An exposed source map hands an attacker the app's original, un-minified source
(often with comments, internal routes, and dev-only branches). The check is
deterministic: GET the sibling `.map` and confirm the body is a real source map
.

The network hop MUST go through the egress policy engine in production, so this
decoder does not fetch on its own — the caller injects a `fetch` callable. Tests
pass a fake; production passes the gated fetch.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Callable

# (status_code, body_text) — a body the caller already decoded to text.
FetchResult = tuple[int, str]
Fetch = Callable[[str], FetchResult]


@dataclass(frozen=True)
class SourceMapResult:
    map_url: str
    exposed: bool
    status: int | None
    reason: str


def source_map_url_for(js_url: str) -> str:
    """The conventional sibling source-map URL for a JS asset."""
    return js_url + ".map"


def _looks_like_source_map(body: str) -> bool:
    try:
        doc = json.loads(body)
    except (ValueError, TypeError):
        return False
    if not isinstance(doc, dict):
        return False
    # Source Map v3 spec: `version` (3) and a `mappings` string are required.
    return doc.get("version") == 3 and isinstance(doc.get("mappings"), str)


def check_source_map_exposed(js_url: str, fetch: Fetch) -> SourceMapResult:
    """GET `js_url`'s sibling `.map` via `fetch` and confirm it is exposed.

    `fetch(url) -> (status, body)` must be the egress-engine-mediated fetch in
    production; the decoder itself performs no network I/O.
    """
    map_url = source_map_url_for(js_url)
    status, body = fetch(map_url)
    if status != 200:
        return SourceMapResult(map_url, False, status, f"status {status}")
    if not _looks_like_source_map(body):
        return SourceMapResult(map_url, False, status, "200 but not a valid source map")
    return SourceMapResult(map_url, True, status, "200 + valid source map")
