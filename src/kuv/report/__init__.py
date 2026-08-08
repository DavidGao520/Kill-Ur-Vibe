"""Report generation — deterministic structure, LLM-authored prose only.

Per the design notes §Report Spec + §Severity. The report's structure,
severity counts, and prioritized ordering are deterministic (from the severity
rule table); the LLM only writes the executive-brief narrative. A final redaction
pass guarantees no secret VALUE ever reaches the output (the 3rd safety gate).
"""

from .findings import Finding
from .html import assemble_html_report
from .redaction import redact_pii, redact_secrets
from .report import assemble_report, coverage_note_from_audit

__all__ = [
    "Finding",
    "assemble_html_report",
    "assemble_report",
    "coverage_note_from_audit",
    "redact_pii",
    "redact_secrets",
]
