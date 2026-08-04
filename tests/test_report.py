"""Report assembly + redaction tests. Redaction is the 3rd safety acceptance gate."""

from __future__ import annotations

from kuv.report import Finding, assemble_report, redact_pii, redact_secrets
from kuv.severity import FindingType


def _findings():
    return [
        Finding(
            FindingType.WEAK_TRANSPORT_OR_CORS,
            "Missing HSTS header",
            "https://ideas.example.com",
            "no Strict-Transport-Security on the main document",
        ),
        Finding(
            FindingType.UNAUTH_WRITE,
            "Unauthenticated websocket save",
            "wss://ideas.example.com/socket",
            "created a record with no auth token",
        ),
    ]


def test_report_orders_critical_before_medium():
    md = assemble_report(_findings(), exec_brief="brief", target="ideas.example.com")
    assert md.index("Unauthenticated websocket save") < md.index("Missing HSTS header")


def test_report_counts_and_severity_from_rules():
    md = assemble_report(_findings(), exec_brief="brief", target="ideas.example.com")
    assert "1 Critical · 1 Medium" in md
    assert "[Critical] Unauthenticated websocket save" in md


def test_exec_brief_is_included():
    md = assemble_report(_findings(), exec_brief="The site leaks writes.", target="t")
    assert "The site leaks writes." in md


# --- safety gate 3: redaction --------------------------------------------

def test_redact_secrets_masks_value_and_keeps_length():
    out = redact_secrets("token=sk_live_ABC123", ["sk_live_ABC123"])
    assert "sk_live_ABC123" not in out
    assert "len=14" in out


def test_report_never_emits_a_secret_value():
    secret = "sk_live_DEADBEEFdeadbeef00"
    finding = Finding(
        FindingType.OFF_ALLOWLIST_SECRET,
        "Leaked Stripe secret key",
        "https://ideas.example.com/app.js",
        f"found {secret} in the bundle",  # simulate a slip-through in evidence
    )
    md = assemble_report([finding], exec_brief="x", target="t", secrets=[secret])
    assert secret not in md
    assert "«redacted" in md


def test_longer_secret_masked_whole_when_overlapping():
    short, long = "abc123", "abc123def456"
    out = redact_secrets("k=abc123def456", [short, long])
    # The full key is masked; no dangling 'def456' tail from a short-first pass.
    assert "def456" not in out


def test_redact_pii_masks_emails():
    out = redact_pii("contact: a.n.d.y.j@gmail.com and jane.doe@corp.co.uk")
    assert "@gmail.com" not in out and "@corp.co.uk" not in out
    assert out.count("«email redacted»") == 2


def test_report_never_emits_an_email_from_evidence():
    # An exposed record quoted verbatim by the agent must not leak the real email.
    finding = Finding(
        FindingType.UNAUTH_READ_SENSITIVE,
        "Unauth search exposes contacts",
        "GET /v1/search",
        'returned {"name":"Real Person","email":"real.person@gmail.com"}',
        contains_pii_or_secrets=True,
    )
    md = assemble_report([finding], exec_brief="x", target="t")
    assert "real.person@gmail.com" not in md
    assert "«email redacted»" in md


def test_novel_string_type_renders_as_needs_operator():
    """The escape hatch: a novel class recorded as a raw string renders as
    'Needs operator triage' and preserves the proposed type for the operator."""
    from kuv.severity import Severity

    f = Finding(
        finding_type="graphql_batching_dos",  # not in the enum
        title="Novel: query batching amplification",
        location="POST /graphql",
        evidence="10 aliased mutations in one request all executed",
        plain_impact="An attacker could multiply one request into many to overload the server.",
    )
    assert f.severity() is Severity.NEEDS_OPERATOR
    out = assemble_report([f], exec_brief="x", target="example.com")
    assert "Needs operator triage" in out
    assert "graphql_batching_dos" in out  # the proposed type is preserved
