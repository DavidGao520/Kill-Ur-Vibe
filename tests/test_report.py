"""Report assembly + redaction tests. Redaction is the 3rd safety acceptance gate."""

from __future__ import annotations

from kuv.report import Finding, assemble_report, redact_pii, redact_secrets
from kuv.severity import FindingType


def _findings():
    return [
        Finding(
            FindingType.WEAK_TRANSPORT_OR_CORS,
            "Missing HSTS header",
            "https://app.example.com",
            "no Strict-Transport-Security on the main document",
        ),
        Finding(
            FindingType.UNAUTH_WRITE,
            "Unauthenticated websocket save",
            "wss://app.example.com/socket",
            "created record 42 with no auth token",
        ),
    ]


def test_report_orders_critical_before_medium():
    md = assemble_report(_findings(), exec_brief="brief", target="app.example.com")
    assert md.index("Unauthenticated websocket save") < md.index("Missing HSTS header")


def test_report_counts_and_severity_from_rules():
    md = assemble_report(_findings(), exec_brief="brief", target="app.example.com")
    assert "1 Critical · 1 Medium" in md
    assert "[Critical] Unauthenticated websocket save" in md


def test_exec_brief_is_included():
    md = assemble_report(_findings(), exec_brief="The site leaks writes.", target="t")
    assert "The site leaks writes." in md


# --- safety gate 3: redaction --------------------------------------------

def test_redact_secrets_masks_value_and_keeps_length():
    out = redact_secrets("token=sk_" "live_ABC123", ["sk_" "live_ABC123"])
    assert "sk_" "live_ABC123" not in out
    assert "len=14" in out


def test_report_never_emits_a_secret_value():
    secret = "sk_" "live_DEADBEEFdeadbeef00"
    finding = Finding(
        FindingType.OFF_ALLOWLIST_SECRET,
        "Leaked Stripe secret key",
        "https://app.example.com/app.js",
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
