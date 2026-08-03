#!/usr/bin/env python3
"""Interactive wizard — the simplest way to run kuv.

    kuv

Prompts for the Anthropic key (hidden input, held in memory only — never written to
disk), the target URL, and an explicit authorization confirmation; runs a READ-ONLY
assessment; and drops a PDF report on the Desktop.
"""

from __future__ import annotations

import asyncio
import getpass
import os
import shutil
import subprocess
import sys
from datetime import date, timedelta
from urllib.parse import urlparse

from kuv.agent.spine import run_assessment
from kuv.egress import RunBudget
from kuv.gate import ActionClass, Scope
from kuv.report import assemble_html_report

# The synthetic-write classes the opt-in tier enables (never destructive; each still
# gated per-class, tagged synthetic records only). These EXACTLY match what the
# ENABLE-WRITES prompt discloses — INVITE_FLOW is deliberately excluded (sending an
# invite emails a third party, a side effect the opt-in prompt does not disclose).
WRITE_TIER_ACTIONS = frozenset({
    ActionClass.ACCOUNT_CREATE,
    ActionClass.OBJECT_PUT,
    ActionClass.WEBSOCKET_SAVE,
})

BANNER = r"""
  _  _____ _     _       _   _ ____    _   _ ___ ____  _____
 | |/ /_ _| |   | |     | | | |  _ \  | | | |_ _| __ )| ____|
 | ' / | || |   | |     | | | | |_) | | | | || ||  _ \|  _|
 | . \ | || |___| |___  | |_| |  _ <  | |_| || || |_) | |___
 |_|\_\___|_____|_____|  \___/|_| \_\  \___/|___|____/|_____|

 Security assessment for AI-built web apps  ·  authorized targets only
"""


def parse_target(raw: str) -> tuple[str, str, str]:
    """(normalized_url, host, apex) from user input like 'myapp.com' or a full URL."""
    raw = raw.strip()
    if "://" not in raw:
        raw = "https://" + raw
    host = (urlparse(raw).hostname or "").lower()
    if not host:
        raise ValueError("could not parse a hostname from that input")
    labels = host.split(".")
    apex = ".".join(labels[-2:]) if len(labels) >= 2 else host
    return raw, host, apex


def build_scope(host: str, apex: str, authorized_by: str, allow_writes: bool = False) -> Scope:
    """A one-year scope for an interactively-authorized target. Read-only by default;
    `allow_writes` opts into the gated synthetic-write classes (still per-class gated)."""
    return Scope(
        engagement_id=host,
        authorized_by=authorized_by,
        targets=(host, apex, f"*.{apex}"),
        expires_at=date.today() + timedelta(days=365),
        allowed_actions=WRITE_TIER_ACTIONS if allow_writes else frozenset(),
        is_fixture=False,
        authorization_asserted=True,       # set only after the operator confirms below
    )


def _find_browser() -> str | None:
    for path in (
        "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
        "/Applications/Chromium.app/Contents/MacOS/Chromium",
        "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
        "/Applications/Brave Browser.app/Contents/MacOS/Brave Browser",
    ):
        if os.path.exists(path):
            return path
    for name in ("google-chrome", "google-chrome-stable", "chromium", "chromium-browser", "microsoft-edge"):
        found = shutil.which(name)
        if found:
            return found
    return None


def html_to_pdf(html_path: str, pdf_path: str) -> bool:
    """Render HTML → PDF. Tries Playwright, then a headless Chrome/Edge. False if neither."""
    html_url = "file://" + os.path.abspath(html_path)
    try:
        from playwright.sync_api import sync_playwright

        with sync_playwright() as pw:
            browser = pw.chromium.launch()
            page = browser.new_page()
            page.goto(html_url)
            page.pdf(path=pdf_path, format="A4", print_background=True)
            browser.close()
        return os.path.exists(pdf_path)
    except Exception:  # noqa: BLE001 — playwright/chromium absent → try system browser
        pass

    browser = _find_browser()
    if browser:
        try:
            subprocess.run(
                [browser, "--headless=new", "--disable-gpu", "--no-pdf-header-footer",
                 f"--print-to-pdf={os.path.abspath(pdf_path)}", html_url],
                check=True, capture_output=True, timeout=90,
            )
            return os.path.exists(pdf_path)
        except Exception:  # noqa: BLE001
            pass
    return False


def _ask(prompt: str) -> str:
    try:
        return input(prompt).strip()
    except (EOFError, KeyboardInterrupt):
        print("\nCancelled.")
        raise SystemExit(1)


def main() -> int:
    print(BANNER)

    # 1) Auth — your Claude subscription (claude.ai login) or a pay-per-token API key.
    print("How do you want to pay for the model?")
    print("  [1] Claude subscription — use your claude.ai login (Pro/Max), no API fees")
    print("  [2] Anthropic API key — pay per token")
    use_subscription = (_ask("Choose [1/2] (default 1): ") or "1").strip() != "2"
    if use_subscription:
        os.environ.pop("ANTHROPIC_API_KEY", None)   # unset so the SDK uses your claude.ai login
        print("→ Using your claude.ai login (be logged in via Claude Code / `claude` first).")
    else:
        key = getpass.getpass("Paste your Anthropic API key (input hidden, never saved): ").strip()
        if not key:
            print("No key provided.")
            return 1
        os.environ["ANTHROPIC_API_KEY"] = key

    # 2) Model. (Independent of auth. Access to a model depends on your plan/API org.)
    models = {
        "1": "claude-sonnet-5",
        "2": "claude-opus-5",
        "3": "claude-fable-5",
        "4": "claude-haiku-4-5-20251001",
    }
    print("\nWhich model?")
    print("  [1] Sonnet 5   — fast + capable (default)")
    print("  [2] Opus 5     — most capable, best at subtle authz bugs (more $ / quota)")
    print("  [3] Fable 5")
    print("  [4] Haiku 4.5  — cheapest / fastest")
    model = os.environ.get("KUV_MODEL") or models.get((_ask("Choose [1-4] (default 1): ") or "1").strip(), "claude-sonnet-5")

    # 3) Target URL.
    try:
        url, host, apex = parse_target(_ask("\nWhich site do you want to check? (URL): "))
    except ValueError as exc:
        print(f"  {exc}")
        return 1

    # 4) Authorization confirmation — the load-bearing gate. This is the ONE consent
    #    that gates the whole run (read AND write); it must stay mandatory.
    print(
        f"\n⚠  kuv will actively security-test  {host}  (and *.{apex}).\n"
        f"   It sends real requests and — with write probes ON by default — may CREATE\n"
        f"   clearly-tagged synthetic records (never destructive; you can switch to read-only\n"
        f"   in the next step).\n"
        f"   Only proceed if you OWN this site or have written permission to test AND change it."
    )
    if _ask("   Type 'yes' to confirm you are authorized: ").lower() != "yes":
        print("Not confirmed — nothing was run.")
        return 1

    # 4b) Synthetic-WRITE tier — ON by default (breadth + depth: reproduces the
    #     open-registration / public-upload / websocket read-write finding classes by
    #     CREATING clearly-tagged synthetic records). Never destructive; each class still
    #     per-gated by the egress engine; fires only after the authorization above. Opt OUT
    #     with 'READ-ONLY'. INVITE_FLOW stays excluded (it would email a third party).
    print(
        "\n   Synthetic WRITE probes are ON (self-registration, file-upload, websocket-save):\n"
        "   they CREATE clearly-tagged synthetic records to prove write paths — never\n"
        "   destructive — but a write can trigger real side effects (a welcome email, a\n"
        "   webhook, a Stripe customer)."
    )
    allow_writes = _ask("   Press Enter to keep writes ON, or type 'READ-ONLY' to disable: ").strip().upper() != "READ-ONLY"
    print("   → " + ("Synthetic writes ON (tagged records only; each still per-class gated)."
                     if allow_writes else "Read-only — no writes will be made."))

    who = _ask("   Your name or email (for the report header, optional): ") or "operator"
    scope = build_scope(host, apex, who, allow_writes=allow_writes)
    confirm_actions = WRITE_TIER_ACTIONS if allow_writes else frozenset()
    budget = RunBudget(max_requests=100, max_wall_seconds=600.0)

    pay = "your Claude subscription (no API fees)" if use_subscription else "your Anthropic key (≤ $2)"
    mode = "read-only" if not allow_writes else "read + synthetic writes"
    print(f"\nAssessing {url} … ({mode}; a few minutes; {model}; {pay}; capped at "
          f"{budget.max_requests} calls / {int(budget.max_wall_seconds // 60)} min)")
    result = asyncio.run(run_assessment(
        scope, url, now=date.today, budget=budget, model=model, confirm_actions=confirm_actions
    ))

    # 5) Report → PDF on the Desktop.
    html = assemble_html_report(
        result.findings,
        target=host,
        exec_brief=result.final_text or "(no summary produced)",
        prepared_for=scope.engagement_id,
        date_str=date.today().isoformat(),
    )
    desktop = os.path.expanduser("~/Desktop")
    stem = os.path.join(desktop, f"kuv-report-{host}-{date.today().isoformat()}")
    html_path = stem + ".html"
    with open(html_path, "w", encoding="utf-8") as handle:
        handle.write(html)

    pdf_path = stem + ".pdf"
    made_pdf = html_to_pdf(html_path, pdf_path)

    crit = sum(1 for f in result.findings if f.severity().value == "Critical")
    print("\n" + "─" * 56)
    print(f"Done. {len(result.findings)} finding(s){f' · {crit} Critical' if crit else ''}.")
    if use_subscription:
        print("Billed to your Claude subscription (no API charge).")
    elif result.cost_usd is not None:
        print(f"Cost: ${result.cost_usd:.2f}")
    if made_pdf:
        print(f"PDF report on your Desktop: {pdf_path}")
        os.remove(html_path)
    else:
        print(f"Report on your Desktop: {html_path}")
        print("  (No Chrome/Chromium found for PDF — open the HTML and Cmd-P → Save as PDF,")
        print("   or `pip install playwright && playwright install chromium` for automatic PDF.)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
