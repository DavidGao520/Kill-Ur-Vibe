"""Regex secret scanner over already-fetched text — the TruffleHog-lite.

High-signal, low-false-positive detectors for the secret classes that actually
leak in shipped JS. Results carry type + count + max length ONLY — never the value
(guardrail #4). This complements `kuv.decoders.classify_secret` (which classifies a
single handed token) by DISCOVERING tokens across a whole bundle.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

# (label, pattern). Patterns use non-capturing groups so findall returns strings.
_DETECTORS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("aws_access_key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("stripe_secret_key", re.compile(r"\b(?:sk|rk)_(?:live|test)_[0-9A-Za-z]{16,}\b")),
    ("openai_key", re.compile(r"\bsk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20,}\b")),
    ("anthropic_key", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}\b")),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("slack_token", re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b")),
    ("github_token", re.compile(r"\bgh[posru]_[0-9A-Za-z]{36,}\b")),
    ("supabase_secret", re.compile(r"\bsb_secret_[A-Za-z0-9_-]{20,}\b")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{5,}\b")),
    ("private_key_block", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |PGP |DSA )?PRIVATE KEY-----")),
    ("gcp_service_account", re.compile(r'"type"\s*:\s*"service_account"')),
    ("db_uri_with_credentials", re.compile(r"\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis)://[^:@\s/]+:[^@\s/]+@")),
)


@dataclass(frozen=True)
class SecretHit:
    detector: str
    count: int
    max_len: int   # length only — never the value


def scan_secrets(text: str) -> list[SecretHit]:
    """Scan `text` and return one SecretHit per detector that matched."""
    hits: list[SecretHit] = []
    for label, pattern in _DETECTORS:
        matches = pattern.findall(text)
        if matches:
            hits.append(SecretHit(label, len(matches), max(len(m) for m in matches)))
    return hits
