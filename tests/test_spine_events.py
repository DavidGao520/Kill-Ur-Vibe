"""run_assessment streams structured events to on_event (for VibeCheck's live terminal)."""

from __future__ import annotations

import asyncio
from datetime import date

import kuv.agent.spine as spine
from claude_agent_sdk import AssistantMessage, ResultMessage, TextBlock, ToolUseBlock
from kuv.gate import Scope


def _scope():
    return Scope(engagement_id="t", authorized_by="t", targets=("127.0.0.1",),
                 expires_at=date(2027, 1, 1), allowed_actions=frozenset(),
                 is_fixture=True, authorization_asserted=True)


def test_run_assessment_emits_events(monkeypatch):
    async def fake_query(*, prompt, options):
        yield AssistantMessage(
            content=[TextBlock(text="Looking at the site."),
                     ToolUseBlock(id="1", name="mcp__kuvnet__http_get",
                                  input={"url": "http://127.0.0.1/"})],
            model="m", parent_tool_use_id=None, error=None, usage=None,
            message_id="x", stop_reason=None, session_id="s", uuid="u")
        yield ResultMessage(
            subtype="success", duration_ms=1, duration_api_ms=1, is_error=False, num_turns=1,
            session_id="s", stop_reason="end_turn", total_cost_usd=0.0, usage=None, result="done",
            structured_output=None, model_usage=None, permission_denials=[], deferred_tool_use=None,
            errors=[], api_error_status=None, uuid="u2", terminal_reason=None)

    monkeypatch.setattr(spine, "query", fake_query)
    events = []
    asyncio.run(spine.run_assessment(_scope(), "http://127.0.0.1/", now=date.today,
                                     on_event=events.append))
    types = [e["type"] for e in events]
    assert "status" in types and "narration" in types and "tool" in types and "done" in types
    tool = next(e for e in events if e["type"] == "tool")
    assert tool["name"] == "http_get"
    narr = next(e for e in events if e["type"] == "narration")
    assert "Looking at the site" in narr["text"]
