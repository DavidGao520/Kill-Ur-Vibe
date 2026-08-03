"""Deterministic severity & priority — assigned by a rule table, not the LLM.

Per the design notes §Severity & priority rules (D9). The LLM writes the
narrative around a severity the rules already fixed, so the same finding gets the
same severity across runs (required for the fidelity eval's precision/recall to be
stable, and for a re-scan to be comparable).
"""

from .rules import (
    FindingType,
    NeedsOperatorSeverity,
    Severity,
    priority_for,
    severity_for,
)

__all__ = [
    "FindingType",
    "NeedsOperatorSeverity",
    "Severity",
    "priority_for",
    "severity_for",
]
