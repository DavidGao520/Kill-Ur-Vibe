#!/usr/bin/env python3
"""Run an assessment against an AUTHORIZED target defined by a scope YAML.

    python assess.py <target-url> <scope.yaml>

The scope decides what is in bounds; the egress engine enforces it in code. The run
is READ-ONLY unless the scope's `allowed_actions` permits writes (and on a live
target the first write of each class still needs operator confirmation). Requires
ANTHROPIC_API_KEY (env or a gitignored .env).

Tunables via env: KUV_MODEL, KUV_MAX_REQUESTS, KUV_MAX_WALL.
"""

from __future__ import annotations

import asyncio
import os
import sys
from datetime import date

sys.path.insert(0, "src")

from urllib.parse import urlparse  # noqa: E402

from kuv.agent.spine import run_assessment  # noqa: E402
from kuv.egress import RunBudget  # noqa: E402
from kuv.gate import load_scope_file  # noqa: E402
from kuv.report import assemble_html_report, assemble_report  # noqa: E402


def _load_dotenv(path: str = ".env") -> None:
    if not os.path.exists(path):
        return
    with open(path, encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, val = line.partition("=")
            os.environ.setdefault(key.strip(), val.strip().strip('"').strip("'"))


def main(argv: list[str]) -> int:
    _load_dotenv()
    if len(argv) < 3:
        print("usage: python assess.py <target-url> <scope.yaml>")
        return 2
    target, scope_path = argv[1], argv[2]
    if not os.environ.get("ANTHROPIC_API_KEY"):
        print("Set ANTHROPIC_API_KEY (env var or a .env file).")
        return 2

    scope = load_scope_file(scope_path)
    budget = RunBudget(
        max_requests=int(os.environ.get("KUV_MAX_REQUESTS", "100")),
        max_wall_seconds=float(os.environ.get("KUV_MAX_WALL", "300")),
    )
    model = os.environ.get("KUV_MODEL", "claude-sonnet-5")
    max_turns = int(os.environ.get("KUV_MAX_TURNS", "40"))
    max_usd = float(os.environ.get("KUV_MAX_USD", "2.0"))

    print(f"Assessing {target}  (engagement {scope.engagement_id}, "
          f"{'READ-ONLY' if not scope.allowed_actions else 'writes: ' + ','.join(a.value for a in scope.allowed_actions)}; "
          f"caps: {budget.max_requests} calls / {max_turns} turns / ${max_usd})")
    result = asyncio.run(run_assessment(
        scope, target, now=date.today, model=model, budget=budget,
        max_turns=max_turns, max_budget_usd=max_usd,
    ))

    report = assemble_report(
        result.findings,
        exec_brief=result.final_text or "(agent produced no summary)",
        target=target,
    )
    print("\n" + report)

    # Polished HTML report (print-to-PDF friendly), written to runs/ (gitignored).
    host = urlparse(target).hostname or target.replace("/", "_")
    html = assemble_html_report(
        result.findings,
        target=host,
        exec_brief=result.final_text or "(agent produced no summary)",
        prepared_for=scope.engagement_id,  # audit label, not the operator's email
        date_str=date.today().isoformat(),
    )
    os.makedirs("runs", exist_ok=True)
    html_path = os.path.join("runs", f"{host}-{date.today().isoformat()}.html")
    with open(html_path, "w", encoding="utf-8") as handle:
        handle.write(html)

    refused = sum(1 for a in result.audit if a["decision"] == "refuse")
    print("\n" + "=" * 60)
    print(f"FINDINGS: {len(result.findings)}")
    print(f"EGRESS: {len(result.audit)} gated requests, {refused} refused (off-scope / budget / write-blocked)")
    print(f"BUDGET: {result.budget.requests_used}/{result.budget.max_requests} tool-calls, "
          f"{result.budget.elapsed:.0f}s")
    if result.cost_usd is not None:
        print(f"COST: ${result.cost_usd:.4f} (model {model})")
    print(f"HTML REPORT: {html_path}  (open in a browser, Cmd-P → Save as PDF)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
