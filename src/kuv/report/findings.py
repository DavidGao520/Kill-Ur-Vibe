"""A verified finding — its severity comes from the rule table, not the LLM."""

from __future__ import annotations

from dataclasses import dataclass

from kuv.severity import FindingType, Severity, priority_for, severity_for


@dataclass(frozen=True)
class Finding:
    finding_type: FindingType
    title: str
    location: str                       # URL / surface where it was proven
    evidence: str                       # human-readable; must not embed raw secrets
    contains_pii_or_secrets: bool = False   # feeds the one conditional severity rule
    # Optional richer structure for the polished report (falls back to `evidence`):
    evidence_rows: tuple[tuple[str, str], ...] = ()   # (probe, result) pairs
    recommendation: str = ""
    # Plain-language, jargon-free statement of the real-world harm — the first thing a
    # non-technical founder reads. Severity-calibrated; never dramatized.
    plain_impact: str = ""

    def severity(self) -> Severity:
        return severity_for(
            self.finding_type, contains_pii_or_secrets=self.contains_pii_or_secrets
        )

    def priority(self) -> str:
        return priority_for(self.severity())
