"""The agent spine: assemble the SDK options and run one assessment.

The keystone is enforced two ways: (1) the only tools the agent has are our
egress-gated ones — no bash, no built-in network; (2) a PreToolUse hook denies, in
code, any tool call whose name is not on our allowlist, regardless of SDK version
or permission-mode semantics. The egress engine inside each tool is the scope gate.

NOTE: the exact ClaudeAgentOptions/HookMatcher surface is validated on first run
against the installed claude-agent-sdk version; adjust here if the SDK differs.
"""

from __future__ import annotations

from dataclasses import dataclass

import httpx
from claude_agent_sdk import ClaudeAgentOptions, HookMatcher, query

from kuv.egress import EgressEngine, RunBudget
from kuv.gate import Scope
from kuv.report import Finding

from .methodology import METHODOLOGY_SYSTEM_PROMPT, task_prompt
from .session import AssessmentSession
from .tools import TOOL_NAMES, build_network_server

# The operator's BYO key; capable default, overridable per run.
DEFAULT_MODEL = "claude-sonnet-5"
# Hard loop/cost bounds at the SDK layer (the other half of T9 — the egress RunBudget
# only caps tool-calls, so the LLM turn loop can run away past it without these).
DEFAULT_MAX_TURNS = 40
DEFAULT_MAX_BUDGET_USD = 2.0

_ALLOWED = frozenset(TOOL_NAMES)
_DISALLOWED_BUILTINS = [
    "Bash", "WebFetch", "WebSearch", "Read", "Write", "Edit", "NotebookEdit", "Glob", "Grep", "Task",
]


async def _gate_hook(input_data, tool_use_id, context):
    """Code-level closure: allow only our tools, deny everything else."""
    name = input_data.get("tool_name", "")
    if name in _ALLOWED:
        return {"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "allow"}}
    return {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": (
                f"{name!r} is not an authorized tool for this assessment; "
                f"only egress-mediated kuv tools are permitted"
            ),
        }
    }


@dataclass
class AssessmentResult:
    findings: list[Finding]
    audit: list[dict]
    final_text: str
    budget: RunBudget
    cost_usd: float | None = None
    usage: object | None = None


async def run_assessment(
    scope: Scope,
    target: str,
    *,
    now,
    model: str = DEFAULT_MODEL,
    budget: RunBudget | None = None,
    max_turns: int = DEFAULT_MAX_TURNS,
    max_budget_usd: float = DEFAULT_MAX_BUDGET_USD,
) -> AssessmentResult:
    """Run one autonomous assessment of `target` under `scope`.

    Runaway is bounded on two layers: the egress `budget` caps tool-calls / wall-clock
    / writes, and `max_turns` + `max_budget_usd` hard-cap the LLM loop and its spend at
    the SDK layer (so it cannot burn turns/tokens after the tool budget is exhausted).
    """
    audit: list[dict] = []
    budget = budget or RunBudget()
    engine = EgressEngine(scope, now=now, audit=audit.append, budget=budget)
    async with httpx.AsyncClient(follow_redirects=False, timeout=15.0) as client:
        session = AssessmentSession(engine, client)
        server = build_network_server(session)
        options = ClaudeAgentOptions(
            model=model,
            system_prompt=METHODOLOGY_SYSTEM_PROMPT,
            mcp_servers={"kuvnet": server},
            allowed_tools=list(TOOL_NAMES),
            disallowed_tools=list(_DISALLOWED_BUILTINS),
            hooks={"PreToolUse": [HookMatcher(matcher="*", hooks=[_gate_hook])]},
            max_turns=max_turns,
            max_budget_usd=max_budget_usd,
        )
        final_text = ""
        cost_usd: float | None = None
        usage: object | None = None
        async for message in query(prompt=task_prompt(target), options=options):
            result = getattr(message, "result", None)
            if isinstance(result, str):
                final_text = result
            cost = getattr(message, "total_cost_usd", None)
            if cost is not None:
                cost_usd = cost
            used = getattr(message, "usage", None)
            if used is not None:
                usage = used
    return AssessmentResult(session.findings, audit, final_text, budget, cost_usd, usage)
