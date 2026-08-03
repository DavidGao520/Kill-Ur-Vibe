"""DNS recon primitives. Pure logic over an injected resolver."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Callable

# resolver(name, rrtype) -> list[str]; rrtype in {"A", "CNAME", "TXT"}. Empty on miss.
Resolver = Callable[[str, str], list]

# Common subdomains probed under an authorized apex (small, high-signal list).
SUBDOMAIN_WORDLIST: tuple[str, ...] = (
    "www", "app", "api", "dev", "staging", "test", "beta", "demo", "internal", "gateway",
    "metrics", "shop", "media", "blog", "docs", "portal", "dashboard", "careers", "vpn",
    "admin", "mail", "cdn", "assets", "status", "support", "auth", "login", "git",
)

# CNAME suffixes that are takeover-prone when the target no longer resolves/serves.
TAKEOVER_SUFFIXES: tuple[str, ...] = (
    ".herokuapp.com", ".herokudns.com", ".onrender.com", ".github.io",
    ".s3.amazonaws.com", ".cloudfront.net", ".vercel.app", ".netlify.app",
    ".fastly.net", ".azurewebsites.net", ".ghost.io", ".pantheonsite.io",
    ".readthedocs.io", ".bitbucket.io", ".surge.sh", ".fly.dev",
)


# Specific body fingerprints of a deleted/unclaimed app behind a takeover-prone CNAME.
TAKEOVER_FINGERPRINTS: dict[str, tuple[str, ...]] = {
    "onrender.com": ("x-render-routing: no-server", "not found"),
    "herokuapp.com": ("no such app", "no-such-app.html"),
    "github.io": ("there isn't a github pages site here",),
    "s3.amazonaws.com": ("nosuchbucket", "the specified bucket does not exist"),
    "fastly.net": ("fastly error: unknown domain",),
    "vercel.app": ("the deployment could not be found", "deployment_not_found"),
    "netlify.app": ("not found - request id",),
    "ghost.io": ("domain error",),
    "surge.sh": ("project not found",),
}

# HTTP statuses that, on a takeover-prone CNAME, indicate the upstream app is gone.
_TAKEOVER_STATUSES = frozenset({404, 410, 502, 503})


def takeover_suffix(cname: str | None) -> str | None:
    """The takeover-prone service suffix a CNAME points at, if any."""
    if not cname:
        return None
    target = cname.rstrip(".").lower()
    for suffix in TAKEOVER_SUFFIXES:
        if target.endswith(suffix):
            return suffix.lstrip(".")
    return None


def is_takeover(suffix: str, status: int | None, body: str) -> bool:
    """True if the HTTP response looks like a dangling upstream (deleted app)."""
    if any(fp in body.lower() for fp in TAKEOVER_FINGERPRINTS.get(suffix, ())):
        return True
    return status in _TAKEOVER_STATUSES


@dataclass(frozen=True)
class HostResult:
    name: str
    a: tuple[str, ...]
    cname: str | None
    dangling: bool                 # CNAME to a takeover-prone service, no A record
    takeover_service: str | None


def _classify(a: tuple[str, ...], cname: str | None) -> tuple[bool, str | None]:
    if cname:
        target = cname.rstrip(".")
        suffix = next((s for s in TAKEOVER_SUFFIXES if target.endswith(s)), None)
        if suffix and not a:
            return True, suffix.lstrip(".")
    return False, None


def enumerate_subdomains(
    apex: str, resolve: Resolver, wordlist: tuple[str, ...] = SUBDOMAIN_WORDLIST
) -> list[HostResult]:
    """Resolve each `<sub>.<apex>` and return the ones that exist, flagging dangling
    CNAMEs (subdomain-takeover candidates)."""
    results: list[HostResult] = []
    for sub in wordlist:
        name = f"{sub}.{apex}"
        a = tuple(resolve(name, "A"))
        cnames = resolve(name, "CNAME")
        cname = cnames[0].rstrip(".") if cnames else None
        if not a and not cname:
            continue  # does not exist
        dangling, service = _classify(a, cname)
        results.append(HostResult(name, a, cname, dangling, service))
    return results


def email_auth(apex: str, resolve: Resolver) -> dict:
    """SPF + DMARC posture for `apex` from its TXT records."""
    spf = [t for t in resolve(apex, "TXT") if t.lower().startswith("v=spf1")]
    dmarc = [t for t in resolve(f"_dmarc.{apex}", "TXT") if t.lower().startswith("v=dmarc1")]
    policy = None
    if dmarc:
        match = re.search(r"\bp=(\w+)", dmarc[0])
        policy = match.group(1) if match else None
    return {
        "spf_present": bool(spf),
        "dmarc_present": bool(dmarc),
        "dmarc_policy": policy,           # None / "none" / "quarantine" / "reject"
        "dmarc_enforced": policy in ("quarantine", "reject"),
    }


def dnspython_resolver(name: str, rrtype: str) -> list[str]:
    """Production resolver. Returns [] on any failure (NXDOMAIN, timeout, no dnspython)."""
    try:
        import dns.resolver  # lazy: only needed at run time
    except ImportError:
        return []
    try:
        answers = dns.resolver.resolve(name, rrtype, lifetime=5.0)
    except Exception:  # noqa: BLE001 — NXDOMAIN / NoAnswer / timeout all mean "no record"
        return []
    if rrtype == "TXT":
        out = []
        for record in answers:
            parts = getattr(record, "strings", None)
            if parts:
                out.append("".join(p.decode() if isinstance(p, bytes) else p for p in parts))
            else:
                out.append(record.to_text().strip('"'))
        return out
    return [record.to_text() for record in answers]
