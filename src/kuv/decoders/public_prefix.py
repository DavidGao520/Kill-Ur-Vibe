"""Public-prefix allowlist: is a flagged token public-by-design or a real leak?

Secret scanners flag any high-entropy string, but many tokens are meant to ship
in a client bundle (Stripe publishable keys, GA measurement IDs, Supabase
publishable keys). This deterministic allowlist suppresses those so the report
does not cry wolf; anything OFF the list is escalated as a candidate real leak
.

The result deliberately carries NO secret material — only whether it is public,
which known prefix matched, and the length. Redaction discipline: a decoder for a
security tool must never be the thing that leaks the secret.
"""

from __future__ import annotations

from dataclasses import dataclass

# Prefixes that are PUBLIC by construction — safe to appear in client code.
# Conservative on purpose: only include prefixes whose public/secret status is
# unambiguous. Format-ambiguous keys (e.g. Algolia search-vs-admin) are NOT here;
# they belong to a separate "needs confirmation" path, not a silent allowlist.
PUBLIC_PREFIXES: tuple[str, ...] = (
    "pk_live_",         # Stripe publishable (live)
    "pk_test_",         # Stripe publishable (test)
    "pk_",              # Clerk publishable (never overlaps the secret `sk_`)
    "sb_publishable_",  # Supabase publishable
    "phc_",             # PostHog project (public) key
    "G-",               # GA4 measurement ID
    "UA-",              # Universal Analytics ID
    "GTM-",             # Google Tag Manager container ID
)


@dataclass(frozen=True)
class PublicPrefixResult:
    is_public: bool
    matched_prefix: str | None
    length: int


def classify_secret_prefix(secret: str) -> PublicPrefixResult:
    """Classify a scanner-flagged token as public-by-design or a candidate leak."""
    s = secret.strip()
    for prefix in PUBLIC_PREFIXES:
        if s.startswith(prefix):
            return PublicPrefixResult(True, prefix, len(s))
    return PublicPrefixResult(False, None, len(s))
