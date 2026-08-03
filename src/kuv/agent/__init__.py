"""The agent spine — the Claude Agent SDK harness.

Kept deliberately import-light: `session` (the SDK-free tool core, unit-testable
without the SDK) is separate from `spine`/`tools` (which import the SDK + httpx).
Import `kuv.agent.spine` explicitly to run an assessment.
"""
