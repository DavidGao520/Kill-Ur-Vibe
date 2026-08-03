"""Redaction — a security tool must never be the thing that leaks the secret.

The final report is scrubbed of every secret VALUE the run collected; only
presence/type/length survive.
"""

from __future__ import annotations

import re
from typing import Iterable

# Redact longest-first so a secret that contains a shorter secret as a substring
# is masked whole, not left with a dangling tail.
def redact_secrets(text: str, secrets: Iterable[str]) -> str:
    out = text
    for secret in sorted((s for s in secrets if s), key=len, reverse=True):
        out = out.replace(secret, f"«redacted len={len(secret)}»")
    return out


# Email addresses are the high-value PII that leaks into evidence when the agent
# quotes an exposed record verbatim. Guardrail #4: record presence, never the value.
_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")


def redact_pii(text: str) -> str:
    """Mask email addresses (a report must never carry real PII values)."""
    return _EMAIL_RE.sub("«email redacted»", text)
