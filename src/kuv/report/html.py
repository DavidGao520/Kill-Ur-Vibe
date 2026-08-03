"""Polished HTML report — matches the reference Acme PDF design.

Cover (dark navy + teal/blue accents, severity tiles) → Executive brief (decision
callout, stat tiles, severity bar chart, prioritized action table) → Finding matrix
→ per-finding cards (severity badge + Evidence table + Recommended fix). Self-
contained and print-friendly (Cmd-P → Save as PDF). All text is PII/secret-scrubbed.
"""

from __future__ import annotations

import html
import re
from collections import Counter
from typing import Iterable, Sequence

from kuv.severity import Severity

from .findings import Finding
from .redaction import redact_pii, redact_secrets

_SEV_ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]
_SEV_CLASS = {
    Severity.CRITICAL: "crit",
    Severity.HIGH: "high",
    Severity.MEDIUM: "med",
    Severity.LOW: "low",
    Severity.INFO: "low",
}
_SEV_PREFIX = {
    Severity.CRITICAL: "C",
    Severity.HIGH: "H",
    Severity.MEDIUM: "M",
    Severity.LOW: "L",
    Severity.INFO: "I",
}

_CSS = """
:root{
  --navy:#0b1c30; --navy2:#12293f; --teal:#16a0a0; --blue:#34509b;
  --ink:#2b2f36; --muted:#8a8f98; --rule:#e3e6ea; --zebra:#f7f8fa;
  --crit:#a11d1d; --high:#d05a5a; --med:#e0a52a; --low:#3f6fd0; --callout:#e9f6f6;
}
*{box-sizing:border-box}
body{margin:0;background:#5b6472;font-family:-apple-system,"Helvetica Neue",Helvetica,Arial,sans-serif;
  color:var(--ink);-webkit-print-color-adjust:exact;print-color-adjust:exact}
.page{background:#fff;width:820px;margin:22px auto;padding:52px 60px;position:relative;min-height:1040px}
.cover{background:var(--navy);color:#fff;padding:0;overflow:hidden}
.cover .topbar{height:12px;background:var(--teal);width:86%}
.cover .rightcol{position:absolute;top:0;right:0;width:88px;height:100%;background:var(--blue)}
.cover .rightcol:before{content:"";position:absolute;left:-6px;top:0;width:6px;height:100%;background:var(--teal)}
.cover .inner{padding:0 60px}
.cover h1{font-size:44px;line-height:1.08;font-weight:600;margin:300px 0 14px;letter-spacing:-.5px}
.cover .sub{color:#a9c3d6;font-size:19px;margin-bottom:54px}
.cover .lbl{font-weight:700;font-size:15px;margin:0 0 8px}
.cover .core{color:#c7d6e2;font-size:15px;line-height:1.55;max-width:520px;margin:0 0 26px}
.cover .tiles{display:flex;gap:14px;margin-bottom:90px}
.cover .tile{background:var(--navy2);border-radius:6px;padding:18px 22px;min-width:130px;display:flex;align-items:baseline;gap:10px}
.cover .tile b{font-size:34px;font-weight:600}
.cover .tile span{color:#c7d6e2;font-size:14px}
.cover .band{background:#0f2740;padding:40px 60px 70px;margin-top:40px}
.cover .band b{display:block;font-weight:700;margin-bottom:8px}
.cover .band div{color:#b9cad8;font-size:14px;line-height:1.7}
.cover .conf{position:absolute;right:14px;bottom:26px;color:#cdd8ff;font-size:13px}
.hdr{display:flex;justify-content:space-between;font-size:12.5px;color:#334;border-bottom:1px solid var(--rule);
  padding-bottom:10px;margin-bottom:30px}
.hdr .r{color:var(--blue)}
h2.section{font-size:30px;font-weight:400;color:#16202b;margin:0 0 18px}
p{font-size:14.5px;line-height:1.55;margin:0 0 14px}
.callout{background:var(--callout);border-left:4px solid var(--teal);padding:16px 18px;border-radius:3px;
  font-size:15px;line-height:1.5;margin:18px 0 26px}
.stats{display:flex;gap:16px;margin:20px 0 30px}
.stat{border:1px solid var(--rule);border-radius:4px;padding:14px 16px;flex:1;display:flex;gap:12px;align-items:flex-start}
.stat b{font-size:30px;font-weight:600;line-height:1}
.stat .m{font-size:14px}
.stat .m .t{font-weight:600}
.stat .m .d{color:var(--muted);font-size:12.5px;line-height:1.35}
.crit{color:var(--crit)} .high{color:var(--high)} .med{color:var(--med)} .low{color:var(--low)}
.chart{margin:6px 0 26px}
.chart .cap{font-size:16px;margin-bottom:4px}
.chart .note{color:var(--muted);font-size:12.5px;margin-bottom:14px}
.bar{display:flex;align-items:center;gap:10px;margin:7px 0;font-size:13px}
.bar .bl{width:92px;color:#333}
.bar .track{flex:1;background:#eef0f3;height:15px;border-radius:2px;overflow:hidden}
.bar .fill{height:100%}
.bar .fill.crit{background:var(--crit)} .bar .fill.high{background:var(--high)}
.bar .fill.med{background:var(--med)} .bar .fill.low{background:var(--low)}
.bar .cn{width:22px;text-align:right;color:#333}
table{border-collapse:collapse;width:100%;font-size:13px;margin:6px 0 20px}
th{background:var(--navy);color:#fff;text-align:left;font-weight:600;padding:9px 12px;font-size:12.5px}
td{padding:9px 12px;border-bottom:1px solid var(--rule);vertical-align:top}
tbody tr:nth-child(even){background:var(--zebra)}
.finding{border:1px solid #e5e7ea;border-radius:4px;padding:16px 18px;margin:16px 0}
.fhead{display:flex;gap:14px;align-items:flex-start;margin-bottom:4px}
.badge{color:#fff;font-weight:700;font-size:11px;letter-spacing:.5px;padding:3px 9px;border-radius:2px;white-space:nowrap;margin-top:2px}
.badge.crit{background:var(--crit)} .badge.high{background:var(--high)} .badge.med{background:var(--med)} .badge.low{background:var(--low)}
.fhead .ft{font-weight:700;font-size:15px}
.fhead .fl{color:var(--muted);font-size:12.5px;margin-top:3px}
.finding h4{font-size:14px;font-weight:600;margin:14px 0 6px;color:#16202b}
.evi-block{background:var(--zebra);border:1px solid var(--rule);border-radius:3px;padding:12px 14px;
  font-size:12.5px;line-height:1.5;white-space:pre-wrap}
.ftr{position:absolute;left:60px;right:60px;bottom:26px;display:flex;justify-content:space-between;
  font-size:11.5px;color:var(--muted);border-top:1px solid var(--rule);padding-top:10px}
.pos{color:var(--muted);font-size:12.5px;line-height:1.5;margin-top:8px}
.executive{font-size:14.5px;line-height:1.58;color:#33383f}
.executive p{margin:0 0 12px}
.md-h{font-size:14px;font-weight:700;color:#16202b;letter-spacing:.2px;margin:18px 0 6px}
.executive ul{margin:6px 0 14px;padding-left:20px}
.executive li{margin:4px 0;font-size:14px;line-height:1.5}
code{background:#eef0f3;color:#324;padding:1px 5px;border-radius:3px;
  font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:12.5px}
@media print{
  body{background:#fff}
  .page{width:auto;margin:0;min-height:auto;padding:40px 46px;page-break-after:always}
  .cover{min-height:100vh}
}
"""


def _scrub(text: object, secrets: Iterable[str]) -> str:
    return redact_pii(redact_secrets(str(text), secrets))


def _e(text: object, secrets: Iterable[str]) -> str:
    return html.escape(_scrub(text, secrets))


_BOLD = re.compile(r"\*\*(.+?)\*\*")
_CODE = re.compile(r"`([^`]+)`")


def _inline(escaped: str) -> str:
    """Apply inline markdown (**bold**, `code`) to already-HTML-escaped text."""
    return _CODE.sub(r"<code>\1</code>", _BOLD.sub(r"<strong>\1</strong>", escaped))


def _md(text: object, secrets: Iterable[str]) -> str:
    """Render the agent's markdown subset (headings, bullets, bold, code, paragraphs)
    to clean HTML — so a summary is formatted, not dumped as literal `##`/`**`."""
    scrubbed = _scrub(text, secrets)
    out: list[str] = []
    para: list[str] = []
    items: list[str] = []

    def flush_para() -> None:
        if para:
            out.append("<p>" + _inline(html.escape(" ".join(para))) + "</p>")
            para.clear()

    def flush_items() -> None:
        if items:
            out.append("<ul>" + "".join(f"<li>{_inline(html.escape(i))}</li>" for i in items) + "</ul>")
            items.clear()

    for raw in scrubbed.split("\n"):
        line = raw.strip()
        if not line:
            flush_para(); flush_items(); continue
        heading = re.match(r"^(#{1,6})\s+(.*)$", line)
        if heading:
            flush_para(); flush_items()
            out.append(f'<h4 class="md-h">{_inline(html.escape(heading.group(2)))}</h4>')
        elif line[:2] in ("- ", "* "):
            flush_para()
            items.append(line[2:].strip())
        else:
            flush_items()
            para.append(line)
    flush_para(); flush_items()
    return "\n".join(out)


def _first_sentence(text: str, limit: int = 220) -> str:
    """A short, markdown-free lead for the cover's core result."""
    flat = re.sub(r"[*`#>|]", "", str(text)).replace("\n", " ")
    flat = re.sub(r"\s+", " ", flat).strip()
    cut = flat.find(". ")
    lead = flat if cut == -1 else flat[: cut + 1]
    return (lead[:limit].rstrip() + "…") if len(lead) > limit else lead


def _hdr(target: str, prepared_for: str, date_str: str) -> str:
    right = " - ".join(x for x in [f"Prepared for {prepared_for}" if prepared_for else "", date_str] if x)
    # redact_pii here too: no email (even the operator's) should appear unredacted.
    return f'<div class="hdr"><div>{html.escape(target)} Security Review</div><div class="r">{html.escape(redact_pii(right))}</div></div>'


def _ftr(page: int) -> str:
    return (
        '<div class="ftr"><div>Confidential security assessment — sensitive values '
        f'intentionally redacted</div><div>Page {page}</div></div>'
    )


def assemble_html_report(
    findings: Sequence[Finding],
    *,
    target: str,
    exec_brief: str,
    decision_needed: str = "",
    prepared_for: str = "",
    date_str: str = "",
    subtitle: str = "Executive security report",
    core_result: str = "",
    secrets: Iterable[str] = (),
) -> str:
    secrets = tuple(secrets)
    ordered = sorted(findings, key=lambda f: (_SEV_ORDER.index(f.severity()), f.finding_type.value))
    counts = Counter(f.severity() for f in ordered)

    # deterministic IDs per severity (C-01, H-01, M-01, ...)
    seen: dict[str, int] = {}
    fid: dict[int, str] = {}
    for f in ordered:
        pre = _SEV_PREFIX[f.severity()]
        seen[pre] = seen.get(pre, 0) + 1
        fid[id(f)] = f"{pre}-{seen[pre]:02d}"

    # A short cover line — derived from the findings, never the whole summary dump.
    if not core_result:
        if ordered:
            parts = ", ".join(f"{counts[s]} {s.value}" for s in _SEV_ORDER if counts.get(s))
            core_result = f"{parts}. Top finding: {ordered[0].title}."
        else:
            core_result = "No verified findings within the authorized scope."

    # ---- cover ----
    cover_tiles = "".join(
        f'<div class="tile"><b>{counts[s]}</b><span>{s.value}</span></div>'
        for s in _SEV_ORDER if counts.get(s)
    )
    cover = f"""
<section class="page cover">
  <div class="topbar"></div>
  <div class="rightcol"></div>
  <div class="inner">
    <h1>{html.escape(target)}<br>Security Review</h1>
    <div class="sub">{html.escape(subtitle)}</div>
    <p class="lbl">Core result</p>
    <p class="core">{_e(core_result, secrets)}</p>
    <div class="tiles">{cover_tiles}</div>
  </div>
  <div class="band">
    <b>Prepared</b>
    <div>{html.escape(date_str)}<br>Authorized assessment{('  ·  ' + html.escape(redact_pii(prepared_for))) if prepared_for else ''}<br>No secret values included in this report</div>
  </div>
  <div class="conf">Confidential</div>
</section>"""

    # ---- exec brief ----
    max_c = max([counts.get(s, 0) for s in _SEV_ORDER] + [1])
    bars = ""
    for label, sev in [("Critical", Severity.CRITICAL), ("High", Severity.HIGH),
                       ("Medium", Severity.MEDIUM), ("Low / Info", Severity.LOW)]:
        n = counts.get(sev, 0)
        pct = int(round(100 * n / max_c))
        bars += (f'<div class="bar"><div class="bl">{label}</div>'
                 f'<div class="track"><div class="fill {_SEV_CLASS[sev]}" style="width:{pct}%"></div></div>'
                 f'<div class="cn">{n}</div></div>')

    exec_tiles = "".join(
        f'<div class="stat"><b class="{_SEV_CLASS[s]}">{counts[s]}</b>'
        f'<div class="m"><div class="t">{s.value}</div><div class="d">{s.value.lower()}-severity findings</div></div></div>'
        for s in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM] if counts.get(s)
    )

    action_rows = "".join(
        f"<tr><td>{_e(f.priority(), secrets)}</td><td>{_e(f.severity().value, secrets)}</td>"
        f"<td>{_e(f.title, secrets)}</td><td>{_e(f.location, secrets)}</td></tr>"
        for f in ordered
    )
    callout = f'<div class="callout"><b>Decision needed:</b> {_e(decision_needed, secrets)}</div>' if decision_needed else ""

    exec_page = f"""
<section class="page">
  {_hdr(target, prepared_for, date_str)}
  <h2 class="section">Executive Brief</h2>
  <div class="executive">{_md(exec_brief, secrets)}</div>
  {callout}
  <div class="stats">{exec_tiles}</div>
  <div class="chart"><div class="cap">Verified issue count by severity</div>
    <div class="note">Severity assigned by the deterministic rule table, not the model.</div>
    {bars}
  </div>
  <table><thead><tr><th>Priority</th><th>Severity</th><th>Action</th><th>Location</th></tr></thead>
    <tbody>{action_rows}</tbody></table>
  {_ftr(2)}
</section>"""

    # ---- finding matrix ----
    matrix_rows = "".join(
        f"<tr><td>{fid[id(f)]}</td><td>{_e(f.severity().value, secrets)}</td>"
        f"<td>{_e(f.title, secrets)}</td><td>{_e(f.location, secrets)}</td></tr>"
        for f in ordered
    )
    matrix_page = f"""
<section class="page">
  {_hdr(target, prepared_for, date_str)}
  <h2 class="section">Finding Matrix</h2>
  <table><thead><tr><th>ID</th><th>Severity</th><th>Finding</th><th>Location</th></tr></thead>
    <tbody>{matrix_rows}</tbody></table>
  {_ftr(3)}
</section>"""

    # ---- per-finding cards ----
    cards = ""
    for f in ordered:
        cls = _SEV_CLASS[f.severity()]
        if f.evidence_rows:
            rows = "".join(
                f"<tr><td>{_e(p, secrets)}</td><td>{_e(r, secrets)}</td></tr>" for p, r in f.evidence_rows
            )
            evidence = (f'<table><thead><tr><th>Probe</th><th>Result</th></tr></thead>'
                        f'<tbody>{rows}</tbody></table>')
        else:
            evidence = f'<div class="evi-block">{_e(f.evidence, secrets)}</div>'
        fix = f'<h4>Recommended fix</h4><p>{_e(f.recommendation, secrets)}</p>' if f.recommendation else ""
        cards += f"""
  <div class="finding">
    <div class="fhead"><span class="badge {cls}">{f.severity().value.upper()}</span>
      <div><div class="ft">{fid[id(f)]} — {_e(f.title, secrets)}</div>
      <div class="fl">{_e(f.location, secrets)}</div></div></div>
    <h4>Evidence</h4>
    {evidence}
    {fix}
  </div>"""

    findings_page = f"""
<section class="page">
  {_hdr(target, prepared_for, date_str)}
  <h2 class="section">Findings</h2>
  {cards}
  {_ftr(4)}
</section>"""

    return (
        f"<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\">"
        f"<title>{html.escape(target)} Security Review</title><style>{_CSS}</style></head>"
        f"<body>{cover}{exec_page}{matrix_page}{findings_page}</body></html>"
    )
