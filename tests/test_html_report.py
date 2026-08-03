"""Tests for the polished HTML report generator."""

from __future__ import annotations

from kuv.report import Finding, assemble_html_report
from kuv.severity import FindingType


def _findings():
    return [
        Finding(
            FindingType.WEAK_TRANSPORT_OR_CORS,
            "Permissive CORS + dev-mode CSP",
            "GET /",
            "ACAO: * on every response",
            recommendation="Use an origin allowlist; drop dev origins.",
        ),
        Finding(
            FindingType.UNAUTH_READ_SENSITIVE,
            "Unauth search exposes contacts",
            "GET /v1/search",
            "evidence blob",
            contains_pii_or_secrets=True,
            evidence_rows=(("GET /v1/search?q=a", "200, real emails: real.person@gmail.com"),),
            recommendation="Add the missing auth check.",
        ),
    ]


def _html():
    return assemble_html_report(
        _findings(),
        target="app.example.com",
        exec_brief="One Critical and one Medium.",
        decision_needed="Fix the /v1/search auth gap.",
        prepared_for="Acme",
        date_str="2026-07-31",
    )


def test_html_has_cover_and_sections():
    html = _html()
    assert "<!DOCTYPE html>" in html
    assert "Security Review" in html          # cover title
    assert "Executive Brief" in html
    assert "Finding Matrix" in html
    assert "Decision needed" in html


def test_html_orders_critical_first_and_ids_findings():
    html = _html()
    # Critical (contains PII) must appear before the Medium.
    assert html.index("C-01") < html.index("M-01")


def test_html_redacts_pii_in_evidence():
    html = _html()
    assert "real.person@gmail.com" not in html
    assert "«email redacted»" in html


def test_header_never_emits_an_email():
    # Even the operator's own email passed as prepared_for must be redacted.
    html = assemble_html_report(
        _findings(), target="t", exec_brief="x", prepared_for="operator@example.com", date_str="2026-08-03"
    )
    assert "operator@example.com" not in html


def test_html_renders_evidence_rows_as_table():
    html = _html()
    assert "<th>Probe</th>" in html
    assert "Recommended fix" in html


def test_markdown_brief_is_rendered_not_literal():
    md = "## Assessment Summary\n\n**Scope:** unauth recon on `www.example.com`.\n\n- one\n- two"
    html = assemble_html_report(
        _findings(), target="t", exec_brief=md, prepared_for="Acme", date_str="2026-08-02"
    )
    assert "<h4 class=\"md-h\">Assessment Summary</h4>" in html
    assert "<strong>Scope:</strong>" in html
    assert "<code>www.example.com</code>" in html
    assert "<li>one</li>" in html
    assert "## Assessment" not in html and "**Scope" not in html  # no literal markdown


def test_markdown_table_renders_as_html_table_not_pipes():
    md = (
        "Proven findings:\n\n"
        "| # | Finding | Severity |\n"
        "| --- | --- | --- |\n"
        "| 1 | Unauth search | Critical |\n"
        "| 2 | Wildcard CORS | Medium |\n"
    )
    html = assemble_html_report(
        _findings(), target="t", exec_brief=md, prepared_for="Acme", date_str="2026-08-03"
    )
    body = html.split("Executive Brief", 1)[1]
    assert "<th>Finding</th>" in body                      # header cell rendered
    assert "<td>Unauth search</td>" in body                # body cell rendered
    assert "| # | Finding" not in body                     # no raw pipe row leaked
    assert "| --- |" not in body                           # separator row consumed


def test_decision_needed_is_derived_from_top_finding_when_absent():
    # Caller omits decision_needed -> it defaults to the top (most severe) fix.
    html = assemble_html_report(
        _findings(), target="t", exec_brief="x", prepared_for="Acme", date_str="2026-08-03"
    )
    assert "Decision needed" in html
    assert "Add the missing auth check" in html            # from the Critical's recommendation


def test_no_decision_callout_when_only_low_severity():
    low = [Finding(FindingType.OAUTH_CONFIG_GAP, "Missing state param", "GET /oauth", "no state")]
    html = assemble_html_report(low, target="t", exec_brief="x", date_str="2026-08-03")
    assert "Decision needed" not in html                   # Medium/Low alone -> no forced callout


def test_cover_core_result_is_short_not_the_whole_brief():
    long_brief = "## Summary\n\nUNIQUEBRIEFTOKEN " + ("detail " * 80)
    html = assemble_html_report(
        _findings(), target="t", exec_brief=long_brief, prepared_for="Acme", date_str="2026-08-02"
    )
    cover_core = html.split('<p class="core">')[1].split("</p>")[0]
    assert "UNIQUEBRIEFTOKEN" not in cover_core       # cover is NOT the full dump
    assert "Top finding:" in cover_core                # derived short line
    assert "UNIQUEBRIEFTOKEN" in html                  # full brief still in the body
