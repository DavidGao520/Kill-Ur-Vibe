"""Deterministic decoders — the one place the LLM is NOT trusted.

Per the design notes §Deterministic decoders. These are small, pure(ish)
functions whose output feeds the deterministic severity rules — never the LLM's
guess. An LLM cannot reliably base64-decode a `service_role` JWT in minified JS,
and getting the anon-vs-service_role call wrong is the difference between "your
DB is world-writable" (Critical) and "expected public key".
"""

from .jwt_role import JwtRole, JwtRoleResult, decode_jwt_role
from .public_prefix import PUBLIC_PREFIXES, PublicPrefixResult, classify_secret_prefix
from .source_map import (
    Fetch,
    FetchResult,
    SourceMapResult,
    check_source_map_exposed,
    source_map_url_for,
)

__all__ = [
    "JwtRole",
    "JwtRoleResult",
    "decode_jwt_role",
    "PUBLIC_PREFIXES",
    "PublicPrefixResult",
    "classify_secret_prefix",
    "Fetch",
    "FetchResult",
    "SourceMapResult",
    "check_source_map_exposed",
    "source_map_url_for",
]
