"""Local scanners that operate on already-fetched bytes (no new target egress).

Per the design notes §Dependencies (thin core). `scan_secrets` is the
TruffleHog-lite: it finds high-signal secrets in a bundle the agent already
fetched and reports type/count/length only — never the value.
"""

from .secrets import SecretHit, scan_secrets

__all__ = ["SecretHit", "scan_secrets"]
