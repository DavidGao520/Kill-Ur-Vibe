"""Detect verbose error / debug pages that leak framework internals (nuclei-lite).

The caller has already discovered a handful of live endpoint paths. This probe
appends a single **malformed query string** to each and asks the injected
``fetch`` to GET it once, hoping to trip an *unhandled* error. A finding is
raised only when the response body carries a **real framework traceback / debug
page** (debug mode left on in production).

SAFETY properties (this module is a pure analyzer):

* **Pure / I/O-free**: no network, no disk, no shell. Every request happens
  through the injected ``fetch`` callable — exactly like ``run_templated_checks``.
* **Non-mutating**: one **GET** per endpoint with a malformed query. GET is the
  only method; nothing is written, no state is changed on the target.
* **Bounded**: at most one request per endpoint, and never more than ``cap``
  requests total. Findings are de-duplicated to one per framework so a target
  that leaks the same debug page on ten routes yields one finding, not ten.
* **False-positive resistant** (a strong bias, not a blanket guarantee): a
  vibe-coded SPA answers ``200`` + its HTML shell for *any* path, and branded
  404/500 pages abound. Every matcher therefore requires a **stack-trace-shaped
  signature** — a real traceback header, a managed/V8 stack *frame*, or a
  source-frame line paired with an exception-summary line — rather than a loose
  set of vocabulary tokens that a docs or marketing page could scatter through
  its prose. The known-negatives that are proven rejected in the tests are the
  four generic ones (SPA shell, branded 404/500, JSON ``{"error": ...}`` body,
  marketing page) plus a .NET concept page and a page that merely cites a
  ``/node_modules/`` path. This is a deliberate bias against false positives, not
  a proof that *no* benign body can ever match; the signatures are tuned to the
  concrete shapes real debug pages emit.

  NOTE on the HTML rule: ``templated.py`` rejects any HTML-document body because
  the files it hunts (.env, .git/config, openapi.json) are *never* legitimately
  HTML. Here the discipline is deliberately different — a Werkzeug/Flask, Django
  DEBUG, or Rails debug page **is** a full HTML document — so we cannot blanket
  reject HTML without going blind to the two most common leaks. The resistance
  instead comes from the *specificity* of the signatures: a plain
  ``<!doctype html>`` SPA shell or marketing page matches **none** of them
  (proven by the HTML-catch-all test).

Evidence is value-free: framework label, matched signature NAME, status code,
and byte count only — never the leaked source paths, locals, or secrets that a
debug page may contain.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Callable, Iterable, Optional

# --------------------------------------------------------------------------
# result row (field names are mapped 1:1 to record_finding by the session layer)
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class ErrorLeak:
    finding_type: str
    title: str
    location: str
    evidence: str
    recommendation: str
    plain_impact: str
    contains_pii_or_secrets: bool = False


# --------------------------------------------------------------------------
# signature helpers
# --------------------------------------------------------------------------

# A Python traceback source-frame line: `File "/app/views.py", line 42, in handler`.
_PY_SRC_LINE = re.compile(r'\.py", line \d+')
_PY_SRC_LINE_IN = re.compile(r'\.py", line \d+, in ')
# A Python exception-summary line: `KeyError: 7`, `app.MyError: ...`, `ValueError`.
# Anchored to a line start so it matches a real trailer, not prose like
# "catching an Exception". Requires a class name that ends the way Python
# exception types do.
_PY_EXC_LINE = re.compile(
    r"(?m)^\s*(?:[A-Za-z_][\w.]*\.)?[A-Z]\w*"
    r"(?:Error|Exception|Warning|Interrupt|Exit|Iteration)\b"
)
# A Java stack frame rooted in a real package: `at com.example.Foo(Foo.java:42)`.
_JAVA_FRAME = re.compile(r"at\s+(?:com|org|net|io|java|javax)\.\w")
# A Symfony component namespace: `Symfony\Component\HttpKernel\...`.
_SYMFONY_NS = re.compile(r"Symfony\\Component\\")
# A .NET managed stack frame: `at MyApp.Controllers.HomeController.Index(`.
# Requires the `at ` to immediately introduce a dotted managed method call,
# so prose mentioning "System.Collections" or "read a StackTrace" cannot fire.
_DOTNET_FRAME = re.compile(r"at\s+[A-Za-z_][\w.]*\.[A-Za-z_]\w*\s*\(")
# A V8 stack frame whose file lives under node_modules, WITH a `:line:col`
# location: `at fn (/srv/node_modules/pg/lib/connection.js:280:10)`. The `at `
# and the node_modules path must sit on the same frame line, so a directory
# listing or README that merely names a node_modules path cannot fire.
_NODE_MODULES_FRAME = re.compile(r"at\s+[^\n]*?/node_modules/[^\s)]*:\d+:\d+")


def _malformed(endpoint: str) -> str:
    """Append a malformed query designed to trip unhandled parsing/type errors.

    Encodes ``'"<>`` plus a bad-type numeric param. Purely additive to the URL —
    a GET with this query neither mutates nor authenticates against anything.
    """
    sep = "&" if "?" in endpoint else "?"
    return f"{endpoint}{sep}id=%27%22%3C%3E&page=notanumber"


def _detect_trace(body: Optional[str]) -> Optional[tuple[str, str]]:
    """Return ``(framework_label, signature_name)`` for a real debug page, else None.

    Each branch demands a multi-token signature. Token *names* — not the matched
    values — are what get returned, so the caller can build value-free evidence.
    """
    if not body:
        return None
    b = body
    low = b.lower()

    # Werkzeug / Flask traceback or interactive debugger.
    if "Traceback (most recent call last)" in b and (
        "werkzeug" in low or _PY_SRC_LINE.search(b)
    ):
        return ("werkzeug/flask", "traceback+werkzeug_or_pysrc")

    # Django technical 500 page (DEBUG=True).
    if "Django Version" in b and "Request Method:" in b:
        return ("django-debug", "django_version+request_method")

    # Rails verbose exception page.
    if "Action Controller: Exception caught" in b:
        return ("rails", "action_controller_exception")
    if "ActionView::" in b and "app/" in b:
        return ("rails", "actionview+app_path")

    # Symfony component stack trace.
    if _SYMFONY_NS.search(b) and "Stack Trace" in b:
        return ("symfony", "symfony_namespace+stack_trace")

    # Node / Express V8 stack trace.
    if "at Object.<anonymous>" in b:
        return ("node/express", "at_object_anonymous")
    if _NODE_MODULES_FRAME.search(b):
        return ("node/express", "node_modules_v8_frame")

    # Java / JVM stack trace.
    if ".java:" in b and _JAVA_FRAME.search(b):
        return ("java", "java_frame+package_prefix")

    # .NET exception with a managed stack trace. Requires an actual managed
    # frame (`at Namespace.Method(`), not merely the tokens System./Exception/
    # StackTrace scattered through a docs or marketing page.
    if "System." in b and "Exception" in b and _DOTNET_FRAME.search(b):
        return (".net", "system+exception+managed_frame")

    # Generic Python traceback (any WSGI framework, no vendor branding).
    # Requires a source-frame line AND an exception-summary line, so a bare
    # tutorial snippet showing only `File "x.py", line N, in f` does not fire.
    if _PY_SRC_LINE_IN.search(b) and _PY_EXC_LINE.search(b):
        return ("python", "py_source_frame+exception_line")

    return None


# --------------------------------------------------------------------------
# entry
# --------------------------------------------------------------------------

_FINDING_TYPE = "verbose_error_disclosure"
_TITLE = "Error pages leak internal code details (stack traces)"
_RECOMMENDATION = (
    "Turn off debug/verbose errors in production (DEBUG=false, RAILS_ENV=production, "
    "ASPNETCORE_ENVIRONMENT=Production, NODE_ENV=production). Return a generic error "
    "page to users and log the full trace server-side only."
)
_PLAIN_IMPACT = (
    "When something breaks, your site shows visitors the raw error — file paths, "
    "framework versions, and snippets of your own source code. Attackers read these "
    "pages to learn exactly how your app is built and where to attack next."
)


def probe_error_leak(
    fetch: Callable[[str], Optional[tuple]],
    endpoints: Iterable[str],
    cap: int = 20,
) -> tuple[list[ErrorLeak], int, bool]:
    """Probe each endpoint once with a malformed query; report real debug leaks.

    ``fetch(path_with_malformed_query)`` returns ``(status, headers, body)`` or
    ``None`` (refused/error). At most ``cap`` GETs total. Findings are collapsed
    to one per framework. Returns ``(leaks, probed_count, truncated)``.
    """
    out: list[ErrorLeak] = []
    probed = 0
    truncated = False
    seen: set[str] = set()

    for endpoint in endpoints:
        if probed >= cap:
            truncated = True
            return out, probed, truncated

        path = _malformed(endpoint)
        res = fetch(path)
        probed += 1
        if res is None:
            continue

        status, _headers, body = res
        hit = _detect_trace(body)
        if hit is None:
            continue

        framework, signature = hit
        if framework in seen:
            continue
        seen.add(framework)

        out.append(
            ErrorLeak(
                finding_type=_FINDING_TYPE,
                title=_TITLE,
                location=endpoint,
                evidence=(
                    f"GET {path} -> {status}; framework={framework}; "
                    f"matched={signature}; {len(body or '')} bytes"
                ),
                recommendation=_RECOMMENDATION,
                plain_impact=_PLAIN_IMPACT,
            )
        )

    return out, probed, truncated
