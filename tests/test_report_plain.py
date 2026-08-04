"""Tests for the plain-language report layer: glossary, type titles, severity, impact."""

from __future__ import annotations

from kuv.report import Finding, assemble_html_report
from kuv.report.plain import (
    SEVERITY_PLAIN,
    TYPE_TITLES,
    Glosser,
    severity_plain,
    type_title,
)
from kuv.severity import FindingType, Severity


# ---- glossary ----

def test_glosser_explains_term_on_first_use_only():
    g = Glosser()
    out1 = g.gloss("The IDOR lets anyone read data.")
    assert "IDOR (" in out1                          # glossed on first use
    out2 = g.gloss("A second IDOR reference here.")
    assert "IDOR (" not in out2                       # not glossed again (same report)


def test_glosser_skips_code_spans():
    g = Glosser()
    out = g.gloss("The `CORS` header and CORS policy.")
    # the backtick-quoted CORS is untouched; the prose CORS gets the gloss
    assert "`CORS`" in out
    assert "CORS (" in out


def test_glosser_longest_term_wins_no_double_gloss():
    g = Glosser()
    out = g.gloss("An abusable pre-signed PUT was found.")
    assert "pre-signed PUT (" in out
    assert out.count("(") == 1                        # PUT alone did not also gloss


def test_glosser_respects_author_existing_explanation():
    g = Glosser()
    out = g.gloss("IDOR (their own explanation) is here.")
    assert out == "IDOR (their own explanation) is here."   # not double-explained


def test_glosser_glosses_prose_after_a_stray_backtick():
    # A prose segment beginning with an unbalanced backtick must NOT be treated as code.
    g = Glosser()
    out = g.gloss("`CORS and CSP are misconfigured")   # leading stray backtick
    assert "CORS (" in out and "CSP (" in out           # both still glossed


def test_glosser_version_tag_does_not_suppress_later_gloss():
    # "OAuth (v2)" is a version tag, not an explanation — a later OAuth must still gloss.
    g = Glosser()
    first = g.gloss("Use OAuth (v2) on the callback.")
    assert "OAuth (the log-in" not in first             # this occurrence left alone
    later = g.gloss("The OAuth flow is missing a state check.")
    assert "OAuth (the log-in" in later                 # not poisoned report-wide


def test_type_titles_cover_every_finding_type():
    for ft in FindingType:
        assert ft in TYPE_TITLES and TYPE_TITLES[ft]
        assert type_title(ft) == TYPE_TITLES[ft]


def test_severity_plain_covers_every_severity():
    for sev in Severity:
        assert sev in SEVERITY_PLAIN and severity_plain(sev)


def test_info_disclosure_is_low_not_high():
    from kuv.severity import severity_for
    # a non-sensitive status/ops endpoint gets the honest Low bucket, not an inflated High
    assert severity_for(FindingType.INFO_DISCLOSURE) is Severity.LOW
    assert type_title(FindingType.INFO_DISCLOSURE)          # has a human title


# ---- report integration ----

def _finding(sev_type=FindingType.UNAUTH_READ_SENSITIVE, **kw):
    defaults = dict(
        finding_type=sev_type, title="Unauth search exposes contacts",
        location="GET /v1/search", evidence="200 with data",
        contains_pii_or_secrets=True,
        recommendation="Add the missing CORS restriction and auth check.",
        plain_impact="Anyone can pull your users' names and emails with no login.",
    )
    defaults.update(kw)
    return Finding(**defaults)


def _html(findings):
    return assemble_html_report(
        findings, target="app.example.com", exec_brief="An IDOR was found on search.",
        prepared_for="Acme", date_str="2026-08-03",
    )


def test_report_renders_plain_impact_first():
    html = _html([_finding()])
    assert "What could go wrong:" in html
    assert "names and emails with no login" in html   # (apostrophe is HTML-escaped)


def test_report_renders_plain_severity_line():
    html = _html([_finding()])
    assert "fix today" in html                        # Critical plain-severity sentence


def test_report_glosses_exec_brief_term():
    html = _html([_finding()])
    assert "IDOR (" in html                            # exec brief term auto-glossed


def test_glossing_never_leaks_a_secret_split_by_a_term():
    # Regression: the glosser splices "(gloss)" into words; a secret/email that contains a
    # glossary-term substring (oauth, csp, ...) must still be redacted, not leaked.
    secret = "tokAB-oauth-9f3a2b1c"                    # 'oauth' is a glossary term
    f = _finding(
        recommendation=f"Rotate the leaked key {secret} and email ceo@mail-oauth-prod.com.",
    )
    html = assemble_html_report(
        [f], target="app.example.com",
        exec_brief=f"The key {secret} appears in the bundle; contact csp@corp.example.com.",
        prepared_for="Acme", date_str="2026-08-03", secrets=(secret,),
    )
    assert secret not in html                           # secret value must not render
    assert "ceo@mail-oauth-prod.com" not in html        # email must not render
    assert "csp@corp.example.com" not in html
    assert "redacted" in html                           # redaction markers present


def test_report_never_shows_raw_finding_type_token():
    html = _html([_finding(sev_type=FindingType.WEAK_TRANSPORT_OR_CORS, title="")])
    assert "weak_transport_or_cors" not in html        # internal token never rendered
    assert "missing standard browser security protections" in html   # human title fallback
