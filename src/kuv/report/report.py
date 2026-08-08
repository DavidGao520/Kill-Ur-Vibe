"""Assemble the report: deterministic structure, redacted, exec brief from the LLM."""

from __future__ import annotations

from collections import Counter
from typing import Iterable, Sequence

from kuv.severity import Severity

from .findings import Finding
from .redaction import redact_pii, redact_secrets

# Report ordering: most severe first (matches the hand PDF the tool reproduces).
_SEVERITY_RANK: dict[Severity, int] = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
    Severity.NEEDS_OPERATOR: 5,   # novel / unrated — sorts after everything rated
}


def _type_str(finding_type) -> str:
    """The finding_type as a string, whether it's a FindingType enum or a raw
    (novel, escape-hatch) str — `.value` would AttributeError on a str."""
    return getattr(finding_type, "value", finding_type)


def _counts_line(findings: Sequence[Finding]) -> str:
    counts = Counter(f.severity() for f in findings)
    parts = [
        f"{counts[sev]} {sev.value}"
        for sev in sorted(counts, key=lambda s: _SEVERITY_RANK[s])
    ]
    return " · ".join(parts) if parts else "no findings"


def coverage_note_from_audit(audit) -> str:
    """Deterministic coverage-shortfall note (model-independent, derived from the audit —
    NOT the LLM). If any request was refused because the run budget was exhausted, the scan
    did NOT finish: some hosts/probes were never run. Returned as a one-line banner so a
    partial scan is never presented as complete; empty string when coverage was not bounded.
    """
    n = sum(
        1
        for a in (audit or [])
        if a.get("decision") == "refuse" and "budget exhausted" in str(a.get("reason", "")).lower()
    )
    if not n:
        return ""
    return (
        f"Coverage incomplete — the run hit its request budget and {n} request(s) were refused. "
        f"Some hosts or probes were not fully assessed; raise the budget (KUV_MAX_REQUESTS) and "
        f"re-run for full coverage."
    )


def assemble_report(
    findings: Sequence[Finding],
    *,
    exec_brief: str,
    target: str,
    secrets: Iterable[str] = (),
    coverage_note: str = "",
) -> str:
    """Render the assessment report as markdown.

    `exec_brief` is the only LLM-authored prose; everything else (severity counts,
    ordering, the prioritized table) is deterministic. `coverage_note` (from
    `coverage_note_from_audit`) surfaces a budget-truncated scan. The whole output is
    scrubbed of `secrets` as the final step.
    """
    ordered = sorted(
        findings, key=lambda f: (_SEVERITY_RANK[f.severity()], _type_str(f.finding_type))
    )

    lines: list[str] = [
        f"# Security Assessment — {target}",
        "",
        f"**Findings:** {_counts_line(ordered)}",
        "",
    ]
    if coverage_note.strip():
        lines += [f"> ⚠️ **{coverage_note.strip()}**", ""]
    lines += [
        "## Executive brief",
        "",
        exec_brief.strip(),
        "",
        "## Prioritized actions",
        "",
        "| Priority | Severity | Finding | Location |",
        "| --- | --- | --- | --- |",
    ]
    for finding in ordered:
        lines.append(
            f"| {finding.priority()} | {finding.severity().value} "
            f"| {finding.title} | {finding.location} |"
        )

    lines += ["", "## Findings"]
    for finding in ordered:
        lines += [
            "",
            f"### [{finding.severity().value}] {finding.title}",
            f"- **Type:** `{_type_str(finding.finding_type)}`",
            f"- **Location:** {finding.location}",
            f"- **Evidence:** {finding.evidence}",
        ]

    # Two-stage scrub: known secret values, then any email PII (guardrail #4).
    return redact_pii(redact_secrets("\n".join(lines), secrets))
