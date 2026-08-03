"""Ground-truth finding set for the local fixture.

Each entry carries only the finding-identity key — finding_type + location —
which is what the fidelity eval scores against. The local fixture has EXACTLY
two known-true findings.
"""

from __future__ import annotations

GROUND_TRUTH: list[dict[str, str]] = [
    {"finding_type": "unauth_write", "location": "POST /api/ideas"},
    {"finding_type": "unauth_read_sensitive", "location": "GET /api/ideas"},
]
