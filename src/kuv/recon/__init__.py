"""DNS recon — subdomain enumeration, dangling-CNAME (takeover) detection, and
email auth (DMARC/SPF). Closes the biggest breadth gap vs a full hand assessment.

The resolver is injected (a `(name, rrtype) -> list[str]` callable) so the logic is
unit-testable without real DNS; `dnspython_resolver` is the production default.
"""

from .dns import (
    SUBDOMAIN_WORDLIST,
    HostResult,
    dnspython_resolver,
    email_auth,
    enumerate_subdomains,
    is_takeover,
    takeover_suffix,
)

__all__ = [
    "SUBDOMAIN_WORDLIST",
    "HostResult",
    "dnspython_resolver",
    "email_auth",
    "enumerate_subdomains",
    "is_takeover",
    "takeover_suffix",
]
