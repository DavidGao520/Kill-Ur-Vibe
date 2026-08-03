"""Thin Claude Agent SDK wrappers around the SDK-free AssessmentSession core.

These are the ONLY tools the agent gets — no bash, no built-in network. Each
delegates to the session, which gates every request through the egress engine.
"""

from __future__ import annotations

import json

from claude_agent_sdk import create_sdk_mcp_server, tool

from kuv.gate import ActionClass
from kuv.severity import FindingType

from .session import AssessmentSession, parse_evidence_rows

_ACTIONS = ", ".join(a.value for a in ActionClass)
_TYPES = ", ".join(f.value for f in FindingType)

SERVER_NAME = "kuvnet"
TOOL_NAMES = (
    "mcp__kuvnet__http_get",
    "mcp__kuvnet__http_write",
    "mcp__kuvnet__record_finding",
    "mcp__kuvnet__decode_jwt_role",
    "mcp__kuvnet__classify_secret",
    "mcp__kuvnet__check_source_map",
    "mcp__kuvnet__scan_js",
    "mcp__kuvnet__enumerate_subdomains",
    "mcp__kuvnet__check_email_auth",
)


def _ok(obj) -> dict:
    return {"content": [{"type": "text", "text": json.dumps(obj)}]}


def _err(message: str) -> dict:
    return {"content": [{"type": "text", "text": message}], "is_error": True}


def _wrap(result: dict) -> dict:
    if result.get("ok") is False:
        return _err(result.get("error", "error"))
    return _ok(result)


def build_network_server(session: AssessmentSession):
    """Build the in-process MCP server exposing the six gated tools."""

    @tool("http_get", "HTTP GET an in-scope URL (passive read). Returns status, headers, body.", {"url": str})
    async def http_get(args):
        return _wrap(await session.http_request("GET", args["url"]))

    @tool(
        "http_write",
        f"Synthetic HTTP write (POST/PUT/PATCH/DELETE) to an in-scope URL. "
        f"action_class must be one of: {_ACTIONS}.",
        {"url": str, "method": str, "body": str, "action_class": str},
    )
    async def http_write(args):
        try:
            action = ActionClass(args["action_class"])
        except ValueError:
            return _err(f"unknown action_class {args['action_class']!r}; one of: {_ACTIONS}")
        return _wrap(await session.http_request(args["method"], args["url"], args.get("body"), action))

    @tool(
        "record_finding",
        f"Record a PROVEN finding. finding_type must be one of: {_TYPES}. Severity is "
        f"assigned deterministically by the tool, not by you. `evidence` is a one-line "
        f"summary; `evidence_json` is a JSON array of [probe, result] pairs (the exact "
        f"requests you sent and the responses that proved it); `recommendation` is the fix.",
        {
            "finding_type": str,
            "title": str,
            "location": str,
            "evidence": str,
            "contains_pii_or_secrets": bool,
            "recommendation": str,
            "evidence_json": str,
        },
    )
    async def record_finding(args):
        return _wrap(
            session.record_finding(
                args["finding_type"],
                args["title"],
                args["location"],
                args["evidence"],
                bool(args.get("contains_pii_or_secrets", False)),
                args.get("recommendation", ""),
                parse_evidence_rows(args.get("evidence_json", "")),
            )
        )

    @tool("decode_jwt_role", "Deterministically decode a JWT and return its Supabase role.", {"token": str})
    async def decode_jwt_role_tool(args):
        return _ok(session.decode_jwt(args["token"]))

    @tool("classify_secret", "Public-by-design vs candidate real leak for a flagged token.", {"token": str})
    async def classify_secret_tool(args):
        return _ok(session.classify_secret(args["token"]))

    @tool("check_source_map", "Is a JS file's sibling .map exposed? (gated GET).", {"js_url": str})
    async def check_source_map_tool(args):
        return _wrap(await session.check_source_map(args["js_url"]))

    @tool(
        "scan_js",
        "Fetch a JS/asset URL in full and scan it for secrets (AWS/Stripe/OpenAI/"
        "Google/Slack/GitHub keys, JWTs, private keys, DB URIs). Returns type/count/"
        "length only — the bundle never enters your context. Use on every shipped bundle.",
        {"url": str},
    )
    async def scan_js_tool(args):
        return _wrap(await session.scan_js(args["url"]))

    @tool(
        "enumerate_subdomains",
        "Enumerate common subdomains under an in-scope apex domain (e.g. 'example.com') via "
        "DNS, flagging dangling CNAMEs that are subdomain-takeover candidates. Use this "
        "FIRST to map the wider attack surface, then probe each live host.",
        {"apex": str},
    )
    async def enumerate_subdomains_tool(args):
        return _wrap(await session.enumerate_subdomains(args["apex"]))

    @tool(
        "check_email_auth",
        "Check an in-scope apex domain's SPF + DMARC posture (DMARC p=none/unset means "
        "email spoofing is possible).",
        {"apex": str},
    )
    async def check_email_auth_tool(args):
        return _wrap(session.check_email_auth(args["apex"]))

    return create_sdk_mcp_server(
        SERVER_NAME,
        "0.1.0",
        tools=[
            http_get,
            http_write,
            record_finding,
            decode_jwt_role_tool,
            classify_secret_tool,
            check_source_map_tool,
            scan_js_tool,
            enumerate_subdomains_tool,
            check_email_auth_tool,
        ],
    )
