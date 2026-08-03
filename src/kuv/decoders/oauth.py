"""Deterministic OAuth authorize-URL analysis — is the redirect flow CSRF-safe?

An LLM eyeballing a Google/Microsoft authorize URL will miss a absent `state` or
`code_challenge` in a wall of query params. This decoder parses the URL and reports
the exact controls present/absent, so the `oauth_config_gap` finding rests on facts,
not a guess (mirrors the reference M-01: "OAuth missing state and hosted-domain
signals"). Pure — no I/O; the agent passes an authorize URL it already fetched.
"""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import parse_qs, urlparse

# authorize-endpoint host -> provider name. Matched as a suffix so tenant subdomains
# (e.g. login.microsoftonline.com/<tenant>) and regional hosts still classify.
_PROVIDERS: tuple[tuple[str, str], ...] = (
    ("accounts.google.com", "google"),
    ("login.microsoftonline.com", "microsoft"),
    ("login.live.com", "microsoft"),
    ("github.com", "github"),
    ("facebook.com", "facebook"),
    ("appleid.apple.com", "apple"),
    ("slack.com", "slack"),
    ("auth0.com", "auth0"),
    ("okta.com", "okta"),
    ("linkedin.com", "linkedin"),
)

# Path fragments that mark an OAuth/OIDC authorize endpoint on an unknown host
# (self-hosted IdPs, Auth0/Okta custom domains).
_AUTHORIZE_PATHS: tuple[str, ...] = ("/authorize", "/oauth/authorize", "/o/oauth2", "/connect/authorize")


@dataclass(frozen=True)
class OAuthConfig:
    is_oauth: bool
    provider: str | None
    response_type: str | None
    has_state: bool
    has_pkce: bool                 # code_challenge present
    has_nonce: bool
    hosted_domain: str | None      # Google `hd` — restricts to a Workspace domain
    redirect_host: str | None
    scopes: tuple[str, ...]
    gaps: tuple[str, ...]          # human-readable missing controls (empty = clean)


def _provider_for(host: str, path: str) -> str | None:
    host = host.lower()
    for suffix, name in _PROVIDERS:
        if host == suffix or host.endswith("." + suffix):
            return name
    if any(frag in path.lower() for frag in _AUTHORIZE_PATHS):
        return "custom"
    return None


def analyze_oauth_url(url: str) -> OAuthConfig:
    """Parse an OAuth authorize URL and report which CSRF/interception controls it
    carries. `is_oauth=False` if the URL is not an authorize endpoint."""
    parsed = urlparse((url or "").strip())
    host = (parsed.hostname or "")
    provider = _provider_for(host, parsed.path)
    if not provider:
        return OAuthConfig(False, None, None, False, False, False, None, None, (), ())

    q = parse_qs(parsed.query, keep_blank_values=True)

    def first(key: str) -> str | None:
        vals = q.get(key)
        return vals[0] if vals else None

    response_type = first("response_type")
    has_state = bool(first("state"))
    has_pkce = bool(first("code_challenge"))     # a blank code_challenge= is NOT PKCE
    has_nonce = bool(first("nonce"))
    hosted_domain = first("hd")
    redirect_raw = first("redirect_uri") or first("redirectUrl") or first("redirect_url")
    redirect_host = (urlparse(redirect_raw).hostname if redirect_raw else None)
    scope_raw = first("scope") or ""
    scopes = tuple(s for s in scope_raw.replace("+", " ").split() if s)

    rt = (response_type or "").lower()
    gaps: list[str] = []
    if not has_state:
        gaps.append("missing `state` parameter — no CSRF protection on the callback")
    if "code" in rt and not has_pkce:
        gaps.append("no PKCE (`code_challenge`) — authorization-code interception risk")
    if ("id_token" in rt or "openid" in scope_raw.lower()) and not has_nonce:
        gaps.append("missing `nonce` — OIDC id_token replay risk")
    if provider == "google" and not hosted_domain:
        gaps.append("no `hd` parameter — any Google account is accepted, not just a workspace")

    return OAuthConfig(
        True, provider, response_type, has_state, has_pkce, has_nonce,
        hosted_domain, redirect_host, scopes, tuple(gaps),
    )
