"""Kill-Ur-Vibe — authorized active security-assessment CLI for AI-built web apps.

Thin core =
  agent (Claude Agent SDK, Anthropic-only) that reaches the target ONLY through
  a single egress policy engine, plus deterministic decoders, a deterministic
  severity rule table, and a report generator.

This package is an authorized-assessment tool: every network action is scope-
gated in code, writes are synthetic and gated per action class, and it never
runs against a target without an explicit authorization assertion. See the
§Authorization Gate section of the design doc.
"""

__version__ = "0.0.1"
