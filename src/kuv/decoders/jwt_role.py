"""JWT role decoder: base64url-decode a JWT payload and read the `role` claim.

Supabase issues both the public `anon` key and the all-powerful `service_role`
key as `eyJ`-prefixed JWTs that look identical to a regex. The distinction lives
in the base64url-encoded payload's `role` claim, so this is deterministic code,
not an LLM judgement.
"""

from __future__ import annotations

import base64
import binascii
import json
from dataclasses import dataclass
from enum import Enum


class JwtRole(str, Enum):
    SERVICE_ROLE = "service_role"    # bypasses RLS → world-writable DB (Critical)
    AUTHENTICATED = "authenticated"  # scoped to a signed-in user
    ANON = "anon"                    # expected public client key (informational)
    UNKNOWN = "unknown"              # decoded, but no recognized `role` claim
    INVALID = "invalid"              # not a decodable 3-segment JWT


@dataclass(frozen=True)
class JwtRoleResult:
    role: JwtRole
    is_finding: bool          # True only for SERVICE_ROLE (a real exposure)
    raw_role: str | None      # the exact `role` claim string, if present


def _b64url_decode(segment: str) -> bytes:
    # JWT segments are base64url without padding; restore it before decoding.
    padding = "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode(segment + padding)


def decode_jwt_role(token: str) -> JwtRoleResult:
    """Decode `token`'s payload and classify its Supabase `role` claim.

    Never raises on malformed input — returns ``JwtRole.INVALID`` instead, so a
    junk match in a minified bundle is a non-finding rather than a crash.
    """
    parts = token.strip().split(".")
    if len(parts) != 3:
        return JwtRoleResult(JwtRole.INVALID, False, None)
    try:
        payload = json.loads(_b64url_decode(parts[1]))
    except (binascii.Error, ValueError, UnicodeDecodeError):
        return JwtRoleResult(JwtRole.INVALID, False, None)
    if not isinstance(payload, dict):
        return JwtRoleResult(JwtRole.INVALID, False, None)

    raw = payload.get("role")
    if not isinstance(raw, str):
        return JwtRoleResult(JwtRole.UNKNOWN, False, None)
    if raw == "service_role":
        return JwtRoleResult(JwtRole.SERVICE_ROLE, True, raw)
    if raw == "authenticated":
        return JwtRoleResult(JwtRole.AUTHENTICATED, False, raw)
    if raw == "anon":
        return JwtRoleResult(JwtRole.ANON, False, raw)
    return JwtRoleResult(JwtRole.UNKNOWN, False, raw)
