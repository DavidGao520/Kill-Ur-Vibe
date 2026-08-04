#!/usr/bin/env python3
"""Generalization suite (operator-run; costs API budget — NOT a CI gate).

Runs the full agent against every fixture in `eval.ground_truth.FIXTURES` and reports
per-fixture precision/recall plus the headline number: RECALL ON THE HELD-OUT FIXTURES —
did the agent find the bug in apps whose specific endpoints it has never seen (IDOR,
privilege-escalation, unauth websocket), using only the method + taxonomy? This replaces
the old self-referential "any Critical" gate.

    ANTHROPIC_API_KEY=... python eval/suite.py

Touches only localhost. Each fixture is a synthetic, in-memory app; restart resets it.
"""

from __future__ import annotations

import asyncio
import os
import socket
import subprocess
import sys
import time
import urllib.request
from datetime import date

sys.path.insert(0, "src")

from eval.fidelity import score  # noqa: E402
from eval.ground_truth import FIXTURES  # noqa: E402
from kuv.agent.spine import run_assessment  # noqa: E402
from kuv.egress import RunBudget  # noqa: E402
from kuv.gate import ActionClass, Scope  # noqa: E402

MODEL = os.environ.get("KUV_MODEL", "claude-sonnet-5")


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


def _wait_http(port: int, timeout_s: int = 10) -> bool:
    for _ in range(timeout_s * 20):
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{port}/health", timeout=1) as resp:
                if resp.status == 200:
                    return True
        except Exception:  # noqa: BLE001
            time.sleep(0.05)
    return False


def _wait_tcp(port: int, timeout_s: int = 10) -> bool:
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                return True
        except OSError:
            time.sleep(0.05)
    return False


def _fixture_scope(name: str) -> Scope:
    # is_fixture=True → writes run unattended; all action classes allowed so the agent
    # can exercise whatever the fixture needs (account_create, websocket_save, ...).
    return Scope(
        engagement_id=f"suite-{name}",
        authorized_by="local-test",
        targets=("127.0.0.1",),
        expires_at=date(2027, 1, 1),
        allowed_actions=frozenset(ActionClass),
        is_fixture=True,
        authorization_asserted=True,
    )


def _run_one(fx: dict) -> dict:
    proc = subprocess.Popen(
        [sys.executable, fx["module"]],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    try:
        ready = _wait_http(fx["port"]) if fx["health"] == "http" else _wait_tcp(fx["port"])
        if not ready:
            return {"name": fx["name"], "error": f"did not become ready on :{fx['port']}"}
        budget = RunBudget(max_requests=120, max_wall_seconds=400.0)
        result = asyncio.run(run_assessment(
            _fixture_scope(fx["name"]), fx["url"], now=date.today, model=MODEL,
            budget=budget, task=fx.get("task"),
        ))
        fidelity = score(result.findings, fx["ground_truth"])
        produced_types = {getattr(f.finding_type, "value", f.finding_type) for f in result.findings}
        allowed_io = sum(1 for a in result.audit if a.get("decision") == "allow")
        held_out_hit = None
        if fx["held_out"]:
            # Credit requires BOTH the accepted class AND real gated I/O to the target — a
            # finding recorded with zero allowed requests is not proof (fabrication guard).
            # (Limitation: this checks the run made real requests, not that THIS finding's
            # specific request fired. Full per-finding evidence-token binding is future work.)
            class_present = bool(produced_types & set(fx["accept_types"]))
            held_out_hit = class_present and allowed_io > 0
        return {
            "name": fx["name"],
            "held_out": fx["held_out"],
            "autonomous": fx.get("autonomous", True),
            "precision": fidelity["precision"],
            "recall": fidelity["recall"],
            "missed": fidelity["missed"],
            "produced_types": sorted(produced_types),
            "allowed_io": allowed_io,
            "held_out_hit": held_out_hit,
        }
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()


def main() -> int:
    _load_dotenv()
    if not os.environ.get("ANTHROPIC_API_KEY"):
        print("Set ANTHROPIC_API_KEY (env var or a .env file). This suite runs the live agent.")
        return 2

    rows = [_run_one(fx) for fx in FIXTURES]

    print("\n" + "=" * 74)
    print(f"{'FIXTURE':<16} {'HELD-OUT':<9} {'AUTO':<5} {'PREC':<6} {'RECALL':<7} {'RESULT'}")
    print("-" * 74)
    for r in rows:
        if r.get("error"):
            print(f"{r['name']:<16} ERROR: {r['error']}")
            continue
        held = "yes" if r["held_out"] else "no"
        auto = "yes" if r["autonomous"] else "no"
        res = ""
        if r["held_out"]:
            res = ("✓ " + ",".join(r["produced_types"])) if r["held_out_hit"] else "✗ MISSED"
        print(f"{r['name']:<16} {held:<9} {auto:<5} {r['precision']:<6.2f} {r['recall']:<7.2f} {res}")

    print("-" * 74)
    ok_rows = [r for r in rows if not r.get("error")]
    autonomous_ho = [r for r in ok_rows if r["held_out"] and r["autonomous"]]
    reachability_ho = [r for r in ok_rows if r["held_out"] and not r["autonomous"]]

    # Headline = recall on AUTONOMOUS held-out fixtures (the agent had to DISCOVER the bug),
    # gated ALSO by a precision floor so a shotgun run that reports every type can't fake it.
    PRECISION_FLOOR = 0.5
    if autonomous_ho:
        hits = sum(1 for r in autonomous_ho if r["held_out_hit"])
        total = len(autonomous_ho)
        ho_recall = hits / total
        mean_prec = sum(r["precision"] for r in autonomous_ho) / total
        prec_ok = mean_prec >= PRECISION_FLOOR
        passed = ho_recall == 1.0 and prec_ok
        note = "" if prec_ok else f"  (precision {mean_prec:.2f} < {PRECISION_FLOOR} floor — shotgun?)"
        verdict = "PASS" if passed else f"FAIL{note}"
        print(f"GENERALIZATION (autonomous held-out): recall {ho_recall:.2f} ({hits}/{total}), "
              f"mean precision {mean_prec:.2f} — {verdict}")
        print("  Held-out = the METHOD is taught (Phase 3), but this app's endpoints/payloads")
        print("  are unseen. Credit needs the class + real gated I/O to the target.")
    else:
        print("No autonomous held-out fixtures configured.")

    # Reachability fixtures (task-hinted, e.g. ws_app) are reported SEPARATELY — they test
    # tool+pipeline reachability, not autonomous discovery, so they never inflate the headline.
    for r in reachability_ho:
        print(f"TOOL REACHABILITY ({r['name']}, task-guided): "
              f"{'✓ found' if r['held_out_hit'] else '✗ MISSED'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
