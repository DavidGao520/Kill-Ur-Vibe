"""Detect RESPONSE-REFLECTED SSRF: a URL-taking parameter whose server-side fetch of
that URL is echoed back in the response, proving the server will fetch arbitrary /
internal URLs on our behalf.

The sound, out-of-band-free way to prove SSRF is a **canary reflection**: hand the
parameter a benign EXTERNAL URL with stable, well-known content (``http://example.com/``,
whose page contains the marker ``Example Domain``) and see whether the response contains
that FETCHED marker. If it does, the server dereferenced a URL we chose and streamed the
result back — that is response-reflected SSRF. Merely echoing the URL *string* we sent is
NOT a fetch, so the matcher requires the fetched-content marker, never the URL itself.

Blind SSRF (the server fetches but does not reflect) is deliberately **out of scope**:
proving it needs an out-of-band callback collaborator (a server the target calls that we
observe) which KUV does not have yet. This probe only asserts the reflected case.

Safety / blast-radius properties (why this is legitimate to run against a third party's
production):

* **Pure and I/O-free.** This module does NO network, disk, or shell. Every request goes
  through the INJECTED ``request`` callable (gated egress), exactly like
  ``run_templated_checks(fetch, …)`` in :mod:`kuv.recon.templated` and
  ``probe_webhook_sig(post, …)`` in :mod:`kuv.recon.webhook_sig`.
* **WRITE-like side effect, tightly bounded.** The test makes the target server issue
  OUTBOUND requests to URLs *we* choose. Those URLs are only (a) a benign external canary
  (``http://example.com/`` — a reserved IANA documentation host that returns a static
  page) and (b) well-known internal probe addresses (``169.254.169.254`` cloud metadata,
  ``localhost``) used ONLY for a status/shape differential. No attacker-controlled payload,
  no writes to the target, no fetch of a URL an attacker would benefit from us reflecting.
* **Value-free evidence.** Evidence reports only that the external canary marker was
  reflected, plus an optional coarse status differential (e.g. external 200 vs internal
  500). It NEVER contains any byte of fetched internal / cloud-metadata content, no
  headers, no body — only the fact that a differential existed.
* **Bounded by ``cap``.** At most ``cap`` requests total across all sinks; each sink costs
  one canary request (plus, only after a canary hit, up to two corroboration requests),
  and a confirmed sink short-circuits the rest.
* **Zero false positives.** The SPA catch-all answers ``200`` + its own HTML shell for any
  path and parameter, so we require the DISTINCTIVE fetched content of the canary page —
  BOTH the marker ``Example Domain`` and the stable phrase ``illustrative examples`` from
  that exact IANA documentation page — neither of which a real app's shell contains.
  A non-2xx is REJECTED. A body that merely contains the URL we sent (input echo, not a
  fetch) contains neither phrase and is REJECTED. Note we deliberately do NOT blanket-reject
  an HTML-document body the way the file-exposure probes do: a genuine reflected fetch of
  ``example.com`` IS an HTML document, so a blanket HTML reject would be a FALSE NEGATIVE
  that silently disables this probe. The two-phrase requirement is the stronger positive
  signal that defeats the SPA shell in its place (the shell carries neither phrase).

The module never imports :mod:`kuv.severity` and never decides a severity — it emits a
plain ``finding_type`` string (``"ssrf"``); the deterministic severity table maps it
downstream.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Optional

# --------------------------------------------------------------------------
# result row  (field names are mapped 1:1 to session.record_finding)
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class SsrfFinding:
    finding_type: str
    title: str
    location: str
    evidence: str
    recommendation: str
    plain_impact: str
    contains_pii_or_secrets: bool = False


# --------------------------------------------------------------------------
# the search space: default URL-parameter-name catalog
# --------------------------------------------------------------------------

# Common parameter names that take a URL the server then dereferences. When the caller
# passes no explicit sinks we probe the site root ("") with each of these param names.
DEFAULT_PARAM_NAMES: tuple[str, ...] = (
    "url",
    "uri",
    "link",
    "src",
    "image",
    "imageUrl",
    "avatar",
    "avatar_url",
    "webhook",
    "callback",
    "callback_url",
    "target",
    "dest",
    "redirect",
    "redirect_uri",
    "feed",
    "rss",
    "import",
    "fetch",
    "remote",
    "source",
    "endpoint",
)

# --------------------------------------------------------------------------
# canary + corroboration targets
# --------------------------------------------------------------------------

# A benign external URL with stable, well-known content. example.com is an IANA-reserved
# documentation domain that serves a static page containing "Example Domain". If the
# server fetches this and reflects it, it will fetch arbitrary external URLs.
_EXTERNAL_CANARY_URL = "http://example.com/"

# The markers that prove the FETCHED page content (not our input URL) came back. We require
# BOTH stable phrases from example.com's static page so that neither the app's own SPA shell
# nor a coincidental "Example Domain" in a page title can satisfy the matcher.
_CANARY_MARKER = "Example Domain"
_CANARY_PHRASE2 = "illustrative examples"

# Well-known internal targets. Used ONLY for a coarse status/shape differential as
# corroboration — their fetched BODIES are never inspected or reflected into evidence.
_INTERNAL_TARGETS: tuple[str, ...] = (
    "http://169.254.169.254/",  # cloud instance-metadata service
    "http://localhost/",        # loopback
)


# --------------------------------------------------------------------------
# matchers
# --------------------------------------------------------------------------


def _status_int(status: object) -> Optional[int]:
    try:
        return int(status)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return None


def _reflects_canary(status: object, body: str) -> bool:
    """True iff the response PROVES the server fetched the external canary and reflected
    its content: a 2xx status whose body carries the DISTINCTIVE fetched-page content of
    ``example.com`` — both ``Example Domain`` and ``illustrative examples``.

    Those phrases live on the fetched page, NOT in the URL string we sent, so an endpoint
    that merely echoes our input parameter does not match. Requiring BOTH phrases (rather
    than blanket-rejecting HTML) is what defeats the SPA catch-all shell: the shell answers
    ``200`` for any input but contains neither phrase. A genuine reflected fetch — whether
    returned as raw HTML or wrapped in JSON — carries both.
    """
    code = _status_int(status)
    if code is None or not (200 <= code < 300):
        return False
    low = (body or "").lower()
    return _CANARY_MARKER.lower() in low and _CANARY_PHRASE2.lower() in low


def _shape_key(status: object, body: str) -> tuple:
    """A coarse, VALUE-FREE fingerprint of a response used only for the external-vs-internal
    differential: the status code and a bucketed body length. Never includes body content."""
    code = _status_int(status)
    n = len(body or "")
    # bucket length so tiny wording differences don't create spurious differentials
    bucket = 0 if n == 0 else 1 if n < 64 else 2 if n < 1024 else 3
    return (code, bucket)


# --------------------------------------------------------------------------
# copy
# --------------------------------------------------------------------------

_TITLE = "Server-side request forgery: a URL parameter makes the server fetch arbitrary URLs"
_RECOMMENDATION = (
    "Do not let user input choose what the server fetches. Validate the URL against a "
    "strict allow-list of permitted hosts/schemes, reject internal and link-local targets "
    "(127.0.0.0/8, 169.254.0.0/16, 10/8, 172.16/12, 192.168/16, ::1, metadata endpoints), "
    "resolve the host and re-check the resolved IP before connecting to defeat DNS "
    "rebinding, disable redirects to internal targets, and never reflect the fetched body "
    "back to the caller."
)
_PLAIN_IMPACT = (
    "One of your endpoints takes a web address as input and the server itself goes and "
    "fetches it. An attacker can point it at your internal network or your cloud provider's "
    "metadata service to read things that are only reachable from inside — credentials, "
    "internal admin pages, other services — even though those are not exposed to the "
    "public internet."
)


# --------------------------------------------------------------------------
# entry point
# --------------------------------------------------------------------------


def probe_ssrf(
    request: Callable[[str, str, str, str], Optional[tuple]],
    sinks: Optional[tuple[tuple[str, str], ...]] = None,
    cap: int = 12,
) -> tuple[list[SsrfFinding], int, bool]:
    """Probe each (path, param) sink for response-reflected SSRF via an external canary.

    ``request(path, method, param, url_value)`` issues a gated request to ``path`` with the
    query/body parameter ``param`` set to ``url_value`` and returns ``(status, headers,
    body)`` or ``None`` (refused / blocked / error). The caller owns method/gating; this
    module uses ``"GET"``.

    ``sinks`` is candidate ``(path, param)`` pairs. If ``None``/empty, the default catalog
    is used against the site root: ``("", name)`` for each name in :data:`DEFAULT_PARAM_NAMES`.

    For each sink we send the benign external canary. If its FETCHED marker is reflected,
    it is a finding; we then optionally send the well-known internal targets and record a
    coarse status differential as corroboration (never their content). At most ``cap``
    requests total. Returns ``(findings, probed_count, truncated)``.
    """
    if not sinks:
        sinks = tuple(("", name) for name in DEFAULT_PARAM_NAMES)

    out: list[SsrfFinding] = []
    probed = 0
    truncated = False
    seen: set[tuple[str, str]] = set()

    for path, param in sinks:
        key = (path, param)
        if key in seen:
            continue
        seen.add(key)

        if probed >= cap:
            return out, probed, True

        res = request(path, "GET", param, _EXTERNAL_CANARY_URL)
        probed += 1
        if res is None:
            continue
        status, _headers, body = res
        if not _reflects_canary(status, body):
            continue

        # --- confirmed external reflection: this sink fetches URLs we choose ---
        ext_shape = _shape_key(status, body)

        # Corroboration: does an internal target respond DIFFERENTLY from the external one?
        # We inspect only the coarse shape (status + length bucket), never the body content.
        differential = False
        for internal_url in _INTERNAL_TARGETS:
            if probed >= cap:
                truncated = True
                break
            ires = request(path, "GET", param, internal_url)
            probed += 1
            if ires is None:
                continue
            istatus, _ih, ibody = ires
            if _shape_key(istatus, ibody) != ext_shape:
                differential = True
                # do NOT break early on nothing else to learn beyond "a differential exists"

        loc_param = param or "(body)"
        location = f"GET /{path}?{loc_param}=" if path else f"GET / ({loc_param})"
        corrob = (
            "; internal-target status/shape differed from external (corroborated)"
            if differential
            else ""
        )
        out.append(
            SsrfFinding(
                finding_type="ssrf",  # REUSE existing type; module never sets severity
                title=_TITLE,
                location=location,
                # value-free: names + the FACT of reflection / differential only. No fetched
                # content, no internal/metadata bytes, no URL values beyond the param name.
                evidence=(
                    f"param '{loc_param}' at /{path or ''}: server fetched the external "
                    f"canary and reflected its page marker (status {status}, non-HTML body)"
                    + corrob
                ),
                recommendation=_RECOMMENDATION,
                plain_impact=_PLAIN_IMPACT,
                contains_pii_or_secrets=False,
            )
        )
        # One confirmed reflected-SSRF sink is a definitive finding; stop to bound work and
        # avoid hammering the target with more outbound-inducing requests.
        return out, probed, truncated

    return out, probed, truncated
