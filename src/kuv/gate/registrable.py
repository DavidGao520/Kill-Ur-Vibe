"""Registrable-domain (eTLD+1) computation, backed by the Public Suffix List.

Used to widen a scan's authorization scope from the single host the operator
typed to the whole registrable domain they own — the apex (needed for email-auth
DNS: SPF/DMARC/DKIM live on the registrable domain, never on a `www.`/`app.`
host) and its subdomains (where the real product / API surface lives) — WITHOUT
ever crossing into a multi-tenant hosting suffix.

Why the PSL and not `host.split('.')[-2:]`: last-2-labels is wrong two ways that
each *authorize scanning hosts the operator never meant to touch*:

  * It over-scopes on multi-label public suffixes: ``app.foo.co.uk`` → ``co.uk``,
    so ``*.co.uk`` would authorize the entire UK commercial namespace.
  * It cannot see *private* suffixes: ``myapp.vercel.app`` would collapse to
    ``vercel.app``, so ``*.vercel.app`` would authorize scanning every other
    tenant's app on Vercel.

``tldextract`` with the PSL *private* section included gets both right
(``app.foo.co.uk → foo.co.uk``; ``myapp.vercel.app → myapp.vercel.app``). We pin
it to its bundled offline snapshot (``suffix_list_urls=()``) so the boundary is
deterministic and never depends on a runtime network fetch that could fail open;
freshening the list is a dependency bump, a deliberate act.
"""

from __future__ import annotations

# Lazily constructed so importing this module (hot on the CLI path) never builds
# the suffix trie or reads the snapshot until a registrable domain is first asked
# for. Offline (no network) + PSL private section = multi-tenant-safe.
_EXTRACT = None


def _extractor():
    global _EXTRACT
    if _EXTRACT is None:
        import tldextract

        _EXTRACT = tldextract.TLDExtract(
            suffix_list_urls=(),  # never fetch — deterministic bundled snapshot
            cache_dir=None,  # no cache dir to write (read-only FS safe)
            include_psl_private_domains=True,  # vercel.app etc. count as suffixes
        )
    return _EXTRACT


def registrable_domain(host: str) -> str | None:
    """The registrable domain (eTLD+1) of ``host``, or ``None`` if undeterminable.

    Returns ``None`` — the fail-closed signal that callers MUST read as "do not
    widen, keep an exact-host scope" — when ``host`` is an IP literal, a bare
    public suffix (``co.uk``), a single label (``localhost``), or otherwise has
    no registrable part.
    """
    if not host:
        return None
    host = host.strip().strip(".").lower()
    if not host:
        return None
    result = _extractor()(host)
    # Build from the stable (domain, suffix) parts rather than the deprecated
    # `registered_domain` property, so this is correct across tldextract versions.
    if result.domain and result.suffix:
        return f"{result.domain}.{result.suffix}"
    return None
