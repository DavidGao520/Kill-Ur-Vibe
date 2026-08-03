"""The deterministic severity rule table.

`severity_for` maps a finding TYPE (plus context for the one conditional rule) to
a fixed severity. A finding type not in the table raises ``NeedsOperatorSeverity``
— the LLM never invents a severity for an unrecognized type.
"""

from __future__ import annotations

from enum import Enum


class Severity(str, Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Info"


class FindingType(str, Enum):
    UNAUTH_WRITE = "unauth_write"                        # unauth write to prod data
    UNAUTH_READ_SENSITIVE = "unauth_read_sensitive"      # unauth read (PII-conditional)
    SERVICE_ROLE_EXPOSED = "service_role_exposed"        # service_role key in bundle
    OFF_ALLOWLIST_SECRET = "off_allowlist_secret"        # non-public secret leaked in JS
    ABUSABLE_PRESIGNED_UPLOAD = "abusable_presigned_upload"
    WEAK_TRANSPORT_OR_CORS = "weak_transport_or_cors"    # missing HSTS/CSP, ACAO:*
    OAUTH_CONFIG_GAP = "oauth_config_gap"                # missing state/PKCE


class NeedsOperatorSeverity(Exception):
    """Raised for a finding type with no rule — surface to the operator, don't guess."""

    def __init__(self, finding_type: object) -> None:
        super().__init__(
            f"no severity rule for finding type {finding_type!r}; surface to operator"
        )
        self.finding_type = finding_type


# Static finding-type -> severity map.
_STATIC: dict[FindingType, Severity] = {
    FindingType.UNAUTH_WRITE: Severity.CRITICAL,
    FindingType.SERVICE_ROLE_EXPOSED: Severity.CRITICAL,
    FindingType.OFF_ALLOWLIST_SECRET: Severity.HIGH,
    FindingType.ABUSABLE_PRESIGNED_UPLOAD: Severity.HIGH,
    FindingType.WEAK_TRANSPORT_OR_CORS: Severity.MEDIUM,
    FindingType.OAUTH_CONFIG_GAP: Severity.MEDIUM,
}

# Priority bucket = impact-over-effort ordering, keyed off the assigned severity.
_PRIORITY: dict[Severity, str] = {
    Severity.CRITICAL: "Today",
    Severity.HIGH: "24-48h",
    Severity.MEDIUM: "This week",
    Severity.LOW: "This week",
    Severity.INFO: "Backlog",
}


def severity_for(finding_type: FindingType | str, **context: object) -> Severity:
    """Return the fixed severity for `finding_type`.

    The only conditional rule: an unauthenticated read is Critical when it exposes
    PII/secrets, else High. Pass ``contains_pii_or_secrets=True`` in that case.
    """
    try:
        ft = FindingType(finding_type)
    except ValueError as exc:
        raise NeedsOperatorSeverity(finding_type) from exc

    if ft is FindingType.UNAUTH_READ_SENSITIVE:
        return Severity.CRITICAL if context.get("contains_pii_or_secrets") else Severity.HIGH
    return _STATIC[ft]


def priority_for(severity: Severity) -> str:
    """Map a severity to its remediation-priority bucket."""
    return _PRIORITY[severity]
