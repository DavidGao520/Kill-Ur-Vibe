"""Detect an account-existence oracle: an endpoint that reveals whether an
email/username is registered.

A signup / login / password-reset flow becomes an **enumeration oracle** when its
response differs depending on whether the identifier already has an account —
``{"available": false}`` from a live email-availability check, ``"That email is
already registered"`` on signup, or ``"No account found with that email"`` on login
while a registered email would instead say "wrong password". An attacker feeds a list
of emails through such an endpoint and learns exactly which of your users exist — a
ready-made target list for phishing, credential-stuffing, and password-spray, plus a
privacy leak (that a specific person uses your app).

Safety / blast-radius properties (the whole reason this is legitimate to run):

* **Pure and I/O-free.** This module does NO network, disk, or shell. Every request
  goes through the INJECTED ``request`` callable (gated egress), exactly like
  ``run_templated_checks(fetch, …)`` in :mod:`kuv.recon.templated`.
* **SYNTHETIC identifiers only — never real/guessed users.** Every probe uses a
  ``kuv-probe-<n>@example.com`` identifier. ``example.com`` is an RFC-2606 reserved
  domain that cannot receive mail, so a password-reset probe emails NO real user, and a
  login probe for a non-existent address can lock NO real account. The probe never
  sprays a guessed or real email.
* **Read-only, non-mutating queries.** Availability checks are GET/POST *lookups*.
  Login is probed with a synthetic (non-existent) email + a dummy password: it fails
  authentication, creates nothing, and — the account not existing — locks nothing.
  Forgot-password is probed with the synthetic email only.
* **No account creation.** Registration/create endpoints are deliberately NOT probed —
  the probe only touches availability-check and login/forgot-password shaped paths, so
  it can never bring a new account into existence.
* **Bounded by ``cap``.** At most ``cap`` requests total across all candidates; a
  candidate uses one request (login/forgot) or at most two (an availability check tried
  GET-then-POST). ``truncated`` reports if the cap cut the sweep short.
* **Zero false positives.** A vibe-coded SPA answers ``200`` + its HTML shell for any
  path, so an HTML-document body is REJECTED. A candidate is only flagged on a POSITIVE
  disclosure signal (a boolean existence/availability flag in JSON, a message that
  states the identifier's registration status, or a login/forgot response that
  explicitly discloses the account does not exist). The **safe** non-disclosing pattern
  — a uniform "if an account exists we've sent you an email" and a generic "invalid
  email or password" — is explicitly NOT flagged.

The module never imports :mod:`kuv.severity` and never decides a severity — it emits a
plain ``finding_type`` string; the deterministic severity table maps it downstream.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Callable, Optional
from urllib.parse import quote

# --------------------------------------------------------------------------
# result row  (field names are mapped 1:1 to session.record_finding)
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class UserEnumFinding:
    finding_type: str
    title: str
    location: str
    evidence: str
    recommendation: str
    plain_impact: str
    contains_pii_or_secrets: bool = False


# --------------------------------------------------------------------------
# candidate paths (the search space)
# --------------------------------------------------------------------------

DEFAULT_ENDPOINTS: tuple[str, ...] = (
    # availability / existence oracles (preferred, read-safe signal)
    "api/auth/check-email",
    "api/check-email",
    "api/email-exists",
    "api/users/exists",
    "api/user/exists",
    "api/auth/exists",
    "api/username-available",
    "api/check-username",
    "api/account/exists",
    "auth/check-email",
    # login / forgot-password (secondary, disclosure-differential signal)
    "api/auth/login",
    "api/login",
    "api/auth/forgot-password",
    "api/forgot-password",
    "api/password/forgot",
)

# --------------------------------------------------------------------------
# the synthetic, NON-EXISTENT probe identifiers
# --------------------------------------------------------------------------

# example.com is RFC-2606 reserved (cannot receive mail); the identifier is obviously
# synthetic, does not exist on the target, and is never a real/guessed user.
_SYNTHETIC_DOMAIN = "example.com"
_DUMMY_PASSWORD = "kuv-probe-not-a-real-password-000"


def _synthetic_email(n: int) -> str:
    return f"kuv-probe-{n}@{_SYNTHETIC_DOMAIN}"


def _synthetic_username(n: int) -> str:
    return f"kuv-probe-{n}"


# --------------------------------------------------------------------------
# path classification
# --------------------------------------------------------------------------

# Availability/existence-check paths: their whole purpose is to answer "is this taken?".
_AVAIL_HINTS: tuple[str, ...] = (
    "check-email",
    "check_email",
    "checkemail",
    "email-exists",
    "email_exists",
    "emailexists",
    "email-available",
    "email_available",
    "check-username",
    "check_username",
    "username-available",
    "username_available",
    "username-exists",
    "username_exists",
    "user-exists",
    "users/exists",
    "user/exists",
    "account-exists",
    "account/exists",
    "auth/exists",
    "is-registered",
    "is_registered",
    "is-taken",
    "is-available",
    "isavailable",
    "validate-email",
    "validate_email",
    "exists",
    "available",
    "taken",
)

# Login / password-reset paths: probe with a synthetic (non-existent) email and see if
# the response discloses that the account does not exist. Registration/create endpoints
# are intentionally absent — probing them could create an account.
_AUTH_HINTS: tuple[str, ...] = (
    "forgot-password",
    "forgot_password",
    "forgotpassword",
    "password/forgot",
    "reset-password",
    "reset_password",
    "password/reset",
    "password-reset",
    "forgot",
    "login",
    "log-in",
    "signin",
    "sign-in",
    "sign_in",
    "authenticate",
    "sessions",
    "session",
)


def _classify(path: str) -> Optional[str]:
    """Return "avail", "auth", or None (a path we will NOT probe). Availability intent
    is checked first (more specific). Anything else is left untouched — the probe never
    fires at arbitrary routes, which keeps the blast radius tight."""
    low = (path or "").lower()
    if any(h in low for h in _AVAIL_HINTS):
        return "avail"
    if any(h in low for h in _AUTH_HINTS):
        return "auth"
    return None


# --------------------------------------------------------------------------
# matchers
# --------------------------------------------------------------------------

# A JSON boolean existence/availability flag: "available"/"exists"/"taken"/"registered"/
# "inUse"/"found" (optionally prefixed, e.g. "emailExists") with a true/false value.
_BOOL_EXISTENCE_KEY = re.compile(
    r'"[a-z_]*(?:available|exists|taken|registered|in_?use|found)"\s*:\s*(?:true|false)',
    re.IGNORECASE,
)

# Message text that states the identifier's registration status (an oracle by content).
_DISCLOSE_MARKERS: tuple[str, ...] = (
    "already registered",
    "already taken",
    "already in use",
    "already exists",
    "email is available",
    "username is available",
    "is available",
    "not available",
    "user not found",
    "no account",
    "no user",
    "not registered",
    "does not exist",
    "doesn't exist",
    "email not found",
    "account not found",
    "email not recognized",
    "unknown email",
    "no matching account",
)

# The SAFE, non-disclosing pattern (uniform reset response) — must NEVER be flagged.
_SAFE_MARKERS: tuple[str, ...] = (
    "if the account exists",
    "if an account exists",
    "if that account exists",
    "if a matching account",
    "if there is an account",
    "if you have an account",
    "if the email exists",
    "if an email exists",
    "if that email",
    "if this email",
    "we've sent",
    "we have sent",
    "you will receive",
    "you'll receive",
    "check your email",
    "check your inbox",
    "reset link has been sent",
    "reset email",
    "email has been sent",
)

# Generic credential failures that lump email+password together — they disclose nothing
# about which identifier exists, so they are the SAFE login behavior.
_GENERIC_AUTH_FAIL: tuple[str, ...] = (
    "invalid email or password",
    "invalid username or password",
    "invalid credentials",
    "incorrect email or password",
    "incorrect username or password",
    "wrong email or password",
    "login failed",
    "authentication failed",
    "invalid login",
)


def _looks_html(body: str) -> bool:
    """A body starting with an HTML doctype/`<html>`, or an early `<head>`, is an SPA
    shell — a real availability/login API returns JSON, never a page."""
    head = (body or "")[:600].lstrip().lower()
    return head.startswith("<!doctype html") or head.startswith("<html") or "<head" in head[:200]


def _coerce_status(status) -> Optional[int]:
    try:
        return int(status)
    except (TypeError, ValueError):
        return None


def _has_safe_nondisclosure(low: str) -> bool:
    return any(m in low for m in _SAFE_MARKERS)


def _availability_signal(body: str) -> Optional[str]:
    """A short signal label if an availability endpoint discloses existence, else None.

    Requires a POSITIVE indicator: a boolean existence/availability flag in JSON, or a
    message that states the identifier's registration status. The uniform "if an account
    exists…" wording is treated as SAFE and yields None.
    """
    low = (body or "").lower()
    if _has_safe_nondisclosure(low):
        return None
    if _BOOL_EXISTENCE_KEY.search(body or ""):
        return "existence oracle: boolean availability/existence flag in JSON response"
    if any(m in low for m in _DISCLOSE_MARKERS):
        return "existence oracle: response message states whether the identifier is registered"
    return None


def _auth_signal(body: str) -> Optional[str]:
    """A short signal label if a login/forgot endpoint discloses that the synthetic
    (non-existent) account does not exist, else None.

    The SAFE uniform reset response and a generic "invalid email or password" both yield
    None — only an explicit account-non-existence disclosure is a finding.
    """
    low = (body or "").lower()
    if _has_safe_nondisclosure(low):
        return None
    if any(m in low for m in _GENERIC_AUTH_FAIL):
        return None
    if any(m in low for m in _DISCLOSE_MARKERS):
        return "existence oracle: login/forgot response discloses the account does not exist"
    return None


# --------------------------------------------------------------------------
# request builders
# --------------------------------------------------------------------------


def _avail_attempts(path: str, email: str, username: str) -> tuple[tuple[str, str, Optional[str]], ...]:
    """(method, path, body) attempts for an availability endpoint: GET (query) first —
    read-safe and preferred — then POST (JSON) as a fallback if GET is unusable. Both
    carry the synthetic email AND username so whichever field the endpoint keys on is
    present."""
    q = f"email={quote(email)}&username={quote(username)}"
    get_path = path + ("&" if "?" in path else "?") + q
    body = json.dumps({"email": email, "username": username}, separators=(",", ":"))
    return (("GET", get_path, None), ("POST", path, body))


def _auth_attempts(path: str, email: str, username: str) -> tuple[tuple[str, str, Optional[str]], ...]:
    """One POST attempt for a login/forgot endpoint with the synthetic identifier. A
    forgot/reset path gets the email only (no password); a login path gets a dummy
    password too. Nothing here creates an account or emails a real user."""
    low = (path or "").lower()
    if any(h in low for h in ("forgot", "reset")):
        body = json.dumps({"email": email}, separators=(",", ":"))
    else:
        body = json.dumps(
            {"email": email, "username": username, "password": _DUMMY_PASSWORD},
            separators=(",", ":"),
        )
    return (("POST", path, body),)


# --------------------------------------------------------------------------
# entry point
# --------------------------------------------------------------------------

_TITLE = "An endpoint reveals whether an email/username is registered (user enumeration)"
_RECOMMENDATION = (
    "Make account-existence responses uniform: return the same message, status, and "
    "timing whether or not the identifier is registered. For login, use a single "
    "'invalid email or password' error; for password reset, always answer 'if an "
    "account exists, we've sent a link'; remove or authenticate any dedicated "
    "email-/username-availability endpoint (or, if one is truly needed for signup UX, "
    "put it behind strict rate limiting and CAPTCHA)."
)
_PLAIN_IMPACT = (
    "Your login, password-reset, or signup form tells anyone whether a given email or "
    "username already has an account. An attacker can feed in a list of emails and learn "
    "exactly which of your users are registered — a ready-made target list for phishing, "
    "credential-stuffing, and password-spray attacks, and a privacy leak that reveals a "
    "specific person uses your app."
)


def probe_user_enum(
    request: Callable[[str, str, Optional[str]], Optional[tuple]],
    endpoints: tuple[str, ...] = DEFAULT_ENDPOINTS,
    cap: int = 16,
) -> tuple[list[UserEnumFinding], int, bool]:
    """Probe availability-check and login/forgot endpoints for an existence oracle.

    ``request(path, method, body)`` returns ``(status, headers, body)`` or ``None``
    (refused/blocked/error); ``method`` is "GET" or "POST"; the caller gates and sends
    it. Every probe uses a SYNTHETIC ``kuv-probe-<n>@example.com`` identifier — never a
    real or guessed user. At most ``cap`` requests total. Returns
    ``(findings, probed_count, truncated)``.
    """
    out: list[UserEnumFinding] = []
    probed = 0
    truncated = False
    n = 0

    for path in endpoints:
        category = _classify(path)
        if category is None:
            continue  # not an availability/login-shaped path — never probe arbitrary routes
        n += 1
        email = _synthetic_email(n)
        username = _synthetic_username(n)
        if category == "avail":
            attempts = _avail_attempts(path, email, username)
        else:
            attempts = _auth_attempts(path, email, username)

        for method, req_path, body in attempts:
            if probed >= cap:
                truncated = True
                return out, probed, truncated
            res = request(req_path, method, body)
            probed += 1
            if res is None:
                continue  # gate refused / error for this verb — try the next attempt
            status, _headers, resp_body = res
            code = _coerce_status(status)
            if code in (404, 405):
                continue  # no route / wrong method — try the next attempt
            if _looks_html(resp_body):
                continue  # SPA HTML shell for this verb — try the next attempt
            # A real, non-HTML API answer for this verb: evaluate and stop probing this
            # endpoint (matched or not — we have the endpoint's definitive behavior).
            signal = _availability_signal(resp_body) if category == "avail" else _auth_signal(resp_body)
            if signal is not None:
                out.append(
                    UserEnumFinding(
                        finding_type="user_enumeration",
                        title=_TITLE,
                        location=f"{method} /{path}",
                        # value-free: verb, path, status, byte count, and which signal
                        # fired — never the response body, keys, or any user value.
                        evidence=(
                            f"{method} /{path} → {status}, {len(resp_body or '')} bytes; "
                            f"{signal}; probed with a synthetic example.com identifier "
                            "(no real user touched)"
                        ),
                        recommendation=_RECOMMENDATION,
                        plain_impact=_PLAIN_IMPACT,
                        contains_pii_or_secrets=False,
                    )
                )
            break

    return out, probed, truncated
