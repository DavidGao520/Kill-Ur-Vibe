"""Fidelity scoring: a produced findings list vs. a ground-truth set.

The finding-identity key is ``(finding_type, location)``, compared
case-insensitively. ``score`` returns precision, recall, and the matched /
missed / extra breakdowns. Produced (and truth) items may be plain dicts or
objects exposing ``.finding_type`` / ``.location`` (e.g. kuv.report.Finding).
"""

from __future__ import annotations

from typing import Any


def _field(item: Any, name: str) -> Any:
    """Read ``name`` from a dict or an attribute-bearing object."""
    if isinstance(item, dict):
        return item.get(name)
    return getattr(item, name, None)


def _text(value: Any) -> str:
    """Canonicalize a key field: unwrap enum values, strip, lowercase."""
    value = getattr(value, "value", value)  # FindingType(...) -> "unauth_write"
    return str(value).strip().lower()


def _key(item: Any) -> tuple[str, str]:
    """The case-insensitive finding-identity key."""
    return (_text(_field(item, "finding_type")), _text(_field(item, "location")))


def _as_dict(item: Any) -> dict[str, str]:
    """Render an item back to a readable {finding_type, location} dict."""
    ft = _field(item, "finding_type")
    ft = getattr(ft, "value", ft)
    return {"finding_type": str(ft), "location": str(_field(item, "location"))}


def score(produced: Any, truth: Any) -> dict:
    """Score ``produced`` findings against ``truth`` on the identity key.

    Returns a dict with:
      * ``precision`` -- matched / produced (unique keys); 1.0 if none produced
      * ``recall``    -- matched / truth (unique keys); 1.0 if truth is empty
      * ``matched``   -- ground-truth findings that were produced
      * ``missed``    -- ground-truth findings that were not produced
      * ``extra``     -- produced findings absent from ground truth
    """
    produced = list(produced)
    truth = list(truth)

    truth_keys = {_key(t) for t in truth}
    produced_keys = {_key(p) for p in produced}
    matched_keys = produced_keys & truth_keys

    matched = [_as_dict(t) for t in truth if _key(t) in produced_keys]
    missed = [_as_dict(t) for t in truth if _key(t) not in produced_keys]

    extra: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for p in produced:
        k = _key(p)
        if k not in truth_keys and k not in seen:
            seen.add(k)
            extra.append(_as_dict(p))

    precision = len(matched_keys) / len(produced_keys) if produced_keys else 1.0
    recall = len(matched_keys) / len(truth_keys) if truth_keys else 1.0

    return {
        "precision": precision,
        "recall": recall,
        "matched": matched,
        "missed": missed,
        "extra": extra,
    }
