"""Egress policy engine — the KEYSTONE.

Every outbound request from the agent routes through this single mediation point:
scope check + passive/active classification + per-action write rule + audit — all
enforced in code at call time, never by prompt. The agent has no raw network path.
"""

from .budget import RunBudget
from .engine import (
    Classification,
    Decision,
    EgressEngine,
    EgressRequest,
    EgressVerdict,
)

__all__ = [
    "Classification",
    "Decision",
    "EgressEngine",
    "EgressRequest",
    "EgressVerdict",
    "RunBudget",
]
