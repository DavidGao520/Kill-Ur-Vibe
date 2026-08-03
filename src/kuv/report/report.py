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
}


def _counts_line(findings: Sequence[Finding]) -> str:
    counts = Counter(f.severity() for f in findings)
    parts = [
        f"{counts[sev]} {sev.value}"
        for sev in sorted(counts, key=lambda s: _SEVERITY_RANK[s])
    ]
    return " · ".join(parts) if parts else "no findings"


def assemble_report(
    findings: Sequence[Finding],
    *,
    exec_brief: str,
    target: str,
    secrets: Iterable[str] = (),
) -> str:
    """Render the assessment report as markdown.

    `exec_brief` is the only LLM-authored prose; everything else (severity counts,
    ordering, the prioritized table) is deterministic. The whole output is scrubbed
    of `secrets` as the final step.
    """
    ordered = sorted(
        findings, key=lambda f: (_SEVERITY_RANK[f.severity()], f.finding_type.value)
    )

    lines: list[str] = [
        f"# Security Assessment — {target}",
        "",
        f"**Findings:** {_counts_line(ordered)}",
        "",
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
            f"- **Type:** `{finding.finding_type.value}`",
            f"- **Location:** {finding.location}",
            f"- **Evidence:** {finding.evidence}",
        ]

    # Two-stage scrub: known secret values, then any email PII (guardrail #4).
    return redact_pii(redact_secrets("\n".join(lines), secrets))
