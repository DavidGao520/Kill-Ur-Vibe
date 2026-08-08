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
    # Escape-hatch sentinel: a genuinely novel finding class the rule table can't
    # rate. It is a FIXED value, never an LLM choice — the invariant "the LLM never
    # sets severity" holds. Surfaced to the operator, never silently dropped.
    NEEDS_OPERATOR = "Needs operator triage"


class FindingType(str, Enum):
    UNAUTH_WRITE = "unauth_write"                        # unauth write to prod data
    UNAUTH_READ_SENSITIVE = "unauth_read_sensitive"      # unauth read (PII-conditional)
    SERVICE_ROLE_EXPOSED = "service_role_exposed"        # service_role key in bundle
    OFF_ALLOWLIST_SECRET = "off_allowlist_secret"        # non-public secret leaked in JS
    ABUSABLE_PRESIGNED_UPLOAD = "abusable_presigned_upload"
    WEAK_TRANSPORT_OR_CORS = "weak_transport_or_cors"    # missing HSTS/CSP, ACAO:*
    OAUTH_CONFIG_GAP = "oauth_config_gap"                # missing state/PKCE
    INSECURE_TLS = "insecure_tls"                        # expired/self-signed/mismatch/obsolete
    SUBDOMAIN_TAKEOVER = "subdomain_takeover"            # dangling CNAME to a claimable service
    EMAIL_SPOOFING = "email_spoofing"                    # DMARC p=none / unset
    INFO_DISCLOSURE = "info_disclosure"                  # unauth NON-sensitive internals (status/health/version)
    IDOR = "idor"                                        # broken object-level authz (BOLA): read/write another owner's object by id
    PRIVILEGE_ESCALATION = "privilege_escalation"        # a normal user gains admin / other rights
    MASS_ASSIGNMENT = "mass_assignment"                  # client sets fields it shouldn't (non-privilege)
    JWT_FORGEABLE = "jwt_forgeable"                       # alg=none / weak secret / forged token accepted
    SSRF = "ssrf"                                         # server fetches an attacker-controlled URL
    OPEN_REDIRECT = "open_redirect"                       # redirect to an attacker URL (phishing aid)
    EXPOSED_SECRET_FILE = "exposed_secret_file"           # served .env / .git / backup / dump — source & secret disclosure
    EXPOSED_SERVICE_INTERFACE = "exposed_service_interface"  # unauth admin/ops/diagnostics panel (actuator/phpinfo/server-status)
    WEBHOOK_UNVERIFIED = "webhook_unverified"            # payment/webhook receiver accepts unsigned (forgeable) events
    VERBOSE_ERROR_DISCLOSURE = "verbose_error_disclosure"  # stack-trace / framework debug page (debug mode left on in prod)
    CREDENTIALED_CORS = "credentialed_cors"              # reflected Origin + ACAC:true — any site reads logged-in data
    USER_ENUMERATION = "user_enumeration"                # login/signup/reset reveals which emails have accounts
    BROKEN_FUNCTION_AUTH = "broken_function_auth"        # a privileged/admin function is reachable without auth (BFLA, unauth slice)


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
    # A broken cert on a production host (expired / self-signed / hostname-mismatch /
    # obsolete protocol) is an active MITM exposure, not cosmetic → High.
    FindingType.INSECURE_TLS: Severity.HIGH,
    # A claimable dangling subdomain lets an attacker serve content from your domain.
    FindingType.SUBDOMAIN_TAKEOVER: Severity.HIGH,
    # Unenforced DMARC lets anyone spoof your domain in email — real but indirect.
    FindingType.EMAIL_SPOOFING: Severity.MEDIUM,
    # An unauth endpoint leaking NON-sensitive internals (status/health/version/job names,
    # counts, timestamps) — recon value only, no data/PII/secret. The honest low bucket, so
    # the agent stops inflating such things into unauth_read_sensitive.
    FindingType.INFO_DISCLOSURE: Severity.LOW,
    # A normal user gaining admin/other rights is game-over authorization failure.
    FindingType.PRIVILEGE_ESCALATION: Severity.CRITICAL,
    # Client sets fields it shouldn't (a non-privilege field); if the field is a role/
    # privilege field, record privilege_escalation (Critical) instead.
    FindingType.MASS_ASSIGNMENT: Severity.HIGH,
    # The server accepts a forgeable token (alg=none / weak secret) → mint any identity.
    FindingType.JWT_FORGEABLE: Severity.CRITICAL,
    # Server can be steered to fetch attacker-controlled URLs (internal svc / cloud metadata).
    FindingType.SSRF: Severity.HIGH,
    # Open redirect: mostly a phishing aid on its own.
    FindingType.OPEN_REDIRECT: Severity.LOW,
    # A served .env / .git / backup / DB dump discloses source and (usually) live
    # secrets — High (treat every secret it contained as leaked).
    FindingType.EXPOSED_SECRET_FILE: Severity.HIGH,
    # An unauthenticated admin/ops/diagnostics interface (Spring actuator, phpinfo,
    # mod_status) leaks configuration/internals — Medium.
    FindingType.EXPOSED_SERVICE_INTERFACE: Severity.MEDIUM,
    # A webhook/payment receiver that accepts unsigned events lets anyone forge a
    # provider event (fake "payment succeeded", grant credits) — High.
    FindingType.WEBHOOK_UNVERIFIED: Severity.HIGH,
    # A stack-trace / framework debug page leaks source paths, versions, and internals —
    # a recon aid on its own, not direct data loss → Low (honest floor, not inflated).
    FindingType.VERBOSE_ERROR_DISCLOSURE: Severity.LOW,
    # Server reflects an arbitrary Origin AND sets Access-Control-Allow-Credentials: true,
    # so any website can make credentialed cross-origin reads of a logged-in user's data — High.
    FindingType.CREDENTIALED_CORS: Severity.HIGH,
    # An account-existence oracle (login/signup/reset reveals which emails are registered)
    # aids targeted phishing/credential-stuffing — real but indirect → Medium.
    FindingType.USER_ENUMERATION: Severity.MEDIUM,
    # A privileged/admin FUNCTION reachable with no auth (unauth BFLA) exposes admin data
    # or actions to anyone → High.
    FindingType.BROKEN_FUNCTION_AUTH: Severity.HIGH,
}

# Priority bucket = impact-over-effort ordering, keyed off the assigned severity.
_PRIORITY: dict[Severity, str] = {
    Severity.CRITICAL: "Today",
    Severity.HIGH: "24-48h",
    Severity.MEDIUM: "This week",
    Severity.LOW: "This week",
    Severity.INFO: "Backlog",
    Severity.NEEDS_OPERATOR: "Operator triage",
}


def severity_for(finding_type: FindingType | str, **context: object) -> Severity:
    """Return the fixed severity for `finding_type`.

    Two PII-conditional rules: a fully-unauthenticated read AND a cross-user (IDOR/BOLA)
    read are each High by default and Critical when they expose PII/secrets — pass
    ``contains_pii_or_secrets=True`` in that case. Every other known type is a fixed
    lookup. A type with no rule at all raises ``NeedsOperatorSeverity`` (never a
    bare KeyError), so the LLM never invents a severity for an unrecognized type.
    """
    try:
        ft = FindingType(finding_type)
    except ValueError as exc:
        raise NeedsOperatorSeverity(finding_type) from exc

    # Two PII-conditional types: a fully-unauth read, and a cross-user (IDOR/BOLA) read.
    # Both are High by default, Critical when they expose PII/secrets.
    if ft in (FindingType.UNAUTH_READ_SENSITIVE, FindingType.IDOR):
        return Severity.CRITICAL if context.get("contains_pii_or_secrets") else Severity.HIGH
    sev = _STATIC.get(ft)
    if sev is None:
        # A known enum member with no static rule (e.g. a conditional type mistakenly
        # narrowed out of the branch above) degrades to the operator sentinel, not KeyError.
        raise NeedsOperatorSeverity(finding_type)
    return sev


def priority_for(severity: Severity) -> str:
    """Map a severity to its remediation-priority bucket."""
    return _PRIORITY[severity]
