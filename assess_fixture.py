#!/usr/bin/env python3
"""The Assignment (end-to-end): run the agent against the LOCAL fixture, score
fidelity against ground truth, and print the report.

Requires `ANTHROPIC_API_KEY` in the environment (rotate the one you exposed first)
and `pip install -e '.[dev]'` / claude-agent-sdk installed. Touches only localhost.

    python assess_fixture.py
"""

from __future__ import annotations

import asyncio
import os
import subprocess
import sys
import time
import urllib.request
from datetime import date

sys.path.insert(0, "src")

from eval.fidelity import score  # noqa: E402
from eval.ground_truth import GROUND_TRUTH  # noqa: E402
from kuv.agent.spine import run_assessment  # noqa: E402
from kuv.egress import RunBudget  # noqa: E402
from kuv.gate import ActionClass, Scope  # noqa: E402
from kuv.report import assemble_report  # noqa: E402

FIXTURE_URL = "http://127.0.0.1:8779"
MODEL = os.environ.get("KUV_MODEL", "claude-sonnet-5")


def _load_dotenv(path: str = ".env") -> None:
    """Load KEY=VALUE lines from a gitignored .env into the environment.

    The value is never printed or logged. This lets the operator place their own
    key in .env (created by them) without exporting it into a shared shell.
    """
    if not os.path.exists(path):
        return
    with open(path, encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, val = line.partition("=")
            os.environ.setdefault(key.strip(), val.strip().strip('"').strip("'"))


def _wait_health(timeout_s: int = 10) -> bool:
    for _ in range(timeout_s * 10):
        try:
            with urllib.request.urlopen(FIXTURE_URL + "/health", timeout=1) as resp:
                if resp.status == 200:
                    return True
        except Exception:  # noqa: BLE001 — server still coming up
            time.sleep(0.1)
    return False


def _fixture_scope() -> Scope:
    # is_fixture=True -> writes run unattended (no operator confirm needed).
    return Scope(
        engagement_id="fixture-assignment",
        authorized_by="local-test",
        targets=("127.0.0.1",),
        expires_at=date(2027, 1, 1),
        allowed_actions=frozenset(ActionClass),
        is_fixture=True,
        authorization_asserted=True,
    )


def main() -> int:
    _load_dotenv()
    if not os.environ.get("ANTHROPIC_API_KEY"):
        print("Set ANTHROPIC_API_KEY (env var or a .env file with ANTHROPIC_API_KEY=...).")
        return 2

    server = subprocess.Popen(
        [sys.executable, "fixtures/vuln_app/server.py"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        if not _wait_health():
            print("fixture server did not become healthy on :8779")
            return 1

        # A tight budget for a tiny fixture — bounds the recon path-guessing churn.
        budget = RunBudget(max_requests=80, max_wall_seconds=300.0)
        result = asyncio.run(
            run_assessment(_fixture_scope(), FIXTURE_URL, now=date.today, model=MODEL, budget=budget)
        )

        report = assemble_report(
            result.findings,
            exec_brief=result.final_text or "(agent produced no summary)",
            target=FIXTURE_URL,
        )
        fidelity = score(result.findings, GROUND_TRUTH)

        print(report)
        print("\n" + "=" * 60)
        print(f"FIDELITY vs ground truth: precision={fidelity['precision']:.2f} "
              f"recall={fidelity['recall']:.2f}")
        if fidelity["missed"]:
            print("  missed:", fidelity["missed"])
        if fidelity["extra"]:
            print("  extra :", fidelity["extra"])
        print(f"EGRESS AUDIT: {len(result.audit)} gated requests")
        print(f"BUDGET: {result.budget.requests_used}/{result.budget.max_requests} tool-calls, "
              f"{result.budget.elapsed:.0f}s")
        crit = any(f.severity().value == "Critical" for f in result.findings)
        print(f"ASSIGNMENT: {'PASS — reproduced a Critical' if crit else 'no Critical reproduced'}")
        return 0
    finally:
        server.terminate()
        try:
            server.wait(timeout=5)
        except subprocess.TimeoutExpired:
            server.kill()


if __name__ == "__main__":
    raise SystemExit(main())
