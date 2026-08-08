"""Tests for the verbose-error / debug-page probe (kuv.recon.error_leak).

No network: every ``fetch`` here is a hand-built fake returning
``(status, headers, body)`` tuples (or ``None`` for refused).
"""

from __future__ import annotations

from kuv.recon.error_leak import _detect_trace, _malformed, probe_error_leak

# --------------------------------------------------------------------------
# realistic bodies
# --------------------------------------------------------------------------

# Werkzeug/Flask AND Django pages are full HTML documents — the probe must catch
# them even though they start with <!doctype html>.
WERKZEUG = (
    "<!DOCTYPE html><html><head><title>ValueError // Werkzeug Debugger</title></head>"
    "<body><h1>ValueError</h1>"
    "Traceback (most recent call last):\n"
    '  File "/srv/app/views.py", line 42, in index\n'
    "    return render(request)\n"
    "werkzeug.exceptions.InternalServerError\n"
    "</body></html>"
)
DJANGO = (
    "<!DOCTYPE html><html><head><title>ValueError at /api/user</title></head><body>"
    "<h1>ValueError at /api/user</h1>"
    "<table><tr><th>Request Method:</th><td>GET</td></tr>"
    "<tr><th>Django Version:</th><td>4.2.1</td></tr></table>"
    "</body></html>"
)
RAILS = (
    "Action Controller: Exception caught\n"
    "ActionView::Template::Error (undefined method `name')\n"
    "app/views/users/show.html.erb:3\n"
)
SYMFONY = (
    "NotFoundHttpException\n"
    "Symfony\\Component\\HttpKernel\\Exception\\NotFoundHttpException\n"
    "Stack Trace\n"
    "#0 /var/www/vendor/symfony/http-kernel/HttpKernel.php(203)\n"
)
NODE_ANON = (
    "TypeError: Cannot read properties of undefined (reading 'id')\n"
    "    at Object.<anonymous> (/app/server.js:10:5)\n"
    "    at Module._compile (node:internal/modules/cjs/loader:1254:14)\n"
)
NODE_MODULES = (
    "Error: connect ECONNREFUSED\n"
    "    at TCPConnectWrap.afterConnect (/app/node_modules/pg/lib/connection.js:280:10)\n"
)
JAVA = (
    "java.lang.NullPointerException\n"
    "\tat com.example.app.UserService.get(UserService.java:42)\n"
    "\tat org.springframework.web.servlet.DispatcherServlet.doService(DispatcherServlet.java:1006)\n"
)
DOTNET = (
    "System.NullReferenceException: Object reference not set to an instance of an object.\n"
    "   at MyApp.Controllers.HomeController.Index()\n"
    "StackTrace:\n   at System.Web.Mvc.ActionMethodDispatcher.Execute()\n"
)
GENERIC_PY = (
    "Internal Server Error\n"
    '  File "/app/handlers/user.py", line 88, in get_user\n'
    "    return db[user_id]\n"
    "KeyError: 7\n"
)

# --- benign / must-not-fire ---
SPA_SHELL = (
    "<!doctype html><html><head><title>My App</title></head>"
    "<body><div id=\"root\"></div><script src=\"/bundle.js\"></script></body></html>"
)
BRANDED_404 = (
    "<!DOCTYPE html><html><body><h1>404 - Page Not Found</h1>"
    "<p>Sorry, we couldn't find that page. Head back home.</p></body></html>"
)
JSON_ERROR = '{"error":"Invalid id parameter","status":400}'
MARKETING = (
    "<!DOCTYPE html><html><body><h1>Welcome to Acme</h1>"
    "<p>We build software for org. teams. Contact hello@acme.com.</p></body></html>"
)
# A .NET docs/marketing page: scatters System., Exception, and StackTrace through
# prose but contains no managed `at Namespace.Method(` stack frame.
DOTNET_DOCS = (
    "<!DOCTYPE html><html><head><title>Exception handling in .NET</title></head>"
    "<body><h1>Exception handling</h1>"
    "<p>Learn about System.Collections, how to catch an Exception, and how to "
    "read the StackTrace property to diagnose failures in production.</p>"
    "</body></html>"
)
# A rendered README / directory listing that names a node_modules path but has
# no V8 frame (`at fn (path:line:col)`).
NODE_MODULES_DOC = (
    "<!DOCTYPE html><html><body><h1>Project layout</h1>"
    "<p>Dependencies are installed at /node_modules/pg and imported via "
    "require('pg'). Run the linter at build time.</p></body></html>"
)
# A Python tutorial snippet showing one source-frame line with no runtime
# traceback header and no exception-summary line.
PY_TUTORIAL = (
    "<!DOCTYPE html><html><body><h1>Reading a traceback</h1>"
    '<pre>A frame looks like: File "app.py", line 5, in main</pre>'
    "<p>Each frame names a source file and a line number.</p></body></html>"
)
# THE REVIEWER'S FALSE POSITIVE, reproduced: a 200 text/html docs / tutorial
# page that renders a full EXAMPLE Python traceback in its prose — the header
# line AND a `.py", line 42` source frame AND an exception-summary line. Under
# the old body-only matcher this tripped `verbose_error_disclosure`; with the
# status gate a 200 must yield nothing.
PY_DOCS_TRACEBACK = (
    "<!DOCTYPE html><html><head><title>How to read a Python traceback</title></head>"
    "<body><h1>Reading a traceback</h1>"
    "<p>When your program raises an unhandled exception, Python prints something "
    "like this:</p>"
    "<pre>Traceback (most recent call last):\n"
    '  File "example.py", line 42, in main\n'
    "    result = compute(value)\n"
    "ValueError: invalid literal for int()</pre>"
    "<p>The final line is the exception type and message. Read frames bottom-up."
    "</p></body></html>"
)

# --- malicious / must-fire ---
# A genuine 500 whose body is a real Flask/Werkzeug traceback WITHOUT any
# interactive-debugger console markers, so it exercises the error-status branch
# (a) rather than the debugger branch (b).
FLASK_500_TRACEBACK = (
    "Traceback (most recent call last):\n"
    '  File "/srv/app/views.py", line 42, in index\n'
    "    return render(request)\n"
    "ValueError: could not render template\n"
)
# A live Werkzeug interactive-debugger console served behind a 200 — the pin
# form and __debugger__ resource loader make this a code-execution surface, a
# real exposure that must fire on ANY status.
WERKZEUG_DEBUGGER_CONSOLE = (
    "<!DOCTYPE html><html><head><title>ValueError // Werkzeug Debugger</title>"
    '<script src="?__debugger__=yes&amp;cmd=resource&amp;f=debugger.js"></script>'
    "</head><body><div class=\"traceback\"><h1>ValueError</h1>"
    "<p>The debugger caught an exception in your WSGI application.</p>"
    '<form class="console-mode"><input type="hidden" name="pin" id="pin_input">'
    "</form></div></body></html>"
)


# --------------------------------------------------------------------------
# matcher-level: every framework signature fires; benign bodies do not
# --------------------------------------------------------------------------


# A rendered traceback is only a leak when the response is itself an error, so
# the framework matchers are exercised at an error status (500).


def test_detect_werkzeug():
    assert _detect_trace(500, WERKZEUG)[0] == "werkzeug/flask"


def test_detect_django():
    assert _detect_trace(500, DJANGO)[0] == "django-debug"


def test_detect_rails():
    assert _detect_trace(500, RAILS)[0] == "rails"


def test_detect_symfony():
    assert _detect_trace(500, SYMFONY)[0] == "symfony"


def test_detect_node_anonymous():
    assert _detect_trace(500, NODE_ANON)[0] == "node/express"


def test_detect_node_modules():
    assert _detect_trace(500, NODE_MODULES)[0] == "node/express"


def test_detect_java():
    assert _detect_trace(500, JAVA)[0] == "java"


def test_detect_dotnet():
    assert _detect_trace(500, DOTNET)[0] == ".net"


def test_detect_generic_python():
    # No "Traceback (most recent call last)" header -> falls through to the
    # generic Python source-frame branch, not the Werkzeug branch.
    assert _detect_trace(500, GENERIC_PY)[0] == "python"


# The benign bodies must match NO signature even at an error status (a branded
# 500 page is still status 500) -> the resistance is signature specificity.


def test_spa_shell_is_not_a_trace():
    assert _detect_trace(500, SPA_SHELL) is None


def test_branded_404_is_not_a_trace():
    assert _detect_trace(404, BRANDED_404) is None


def test_json_error_message_only_is_not_a_trace():
    assert _detect_trace(400, JSON_ERROR) is None


def test_marketing_page_is_not_a_trace():
    assert _detect_trace(500, MARKETING) is None


def test_dotnet_docs_page_is_not_a_trace():
    # System. + Exception + StackTrace as loose vocabulary, but no managed frame.
    assert _detect_trace(500, DOTNET_DOCS) is None


def test_node_modules_reference_is_not_a_trace():
    # ' at ' and '/node_modules/' co-occur, but there is no `:line:col` V8 frame.
    assert _detect_trace(500, NODE_MODULES_DOC) is None


def test_python_tutorial_snippet_is_not_a_trace():
    # A source-frame line with no exception-summary line is not a real traceback.
    assert _detect_trace(500, PY_TUTORIAL) is None


# --------------------------------------------------------------------------
# THE FIX: status gate. A 200 docs page with an EXAMPLE traceback is EMPTY;
# a 500 traceback and a 200 interactive-debugger console both still fire.
# --------------------------------------------------------------------------


def test_docs_page_example_traceback_at_200_is_empty():
    # THE REVIEWER'S FALSE POSITIVE, now zero: a 200 text/html docs page that
    # renders a full example traceback (header + `.py", line 42` frame +
    # exception line) in prose must NOT be a finding.
    assert _detect_trace(200, PY_DOCS_TRACEBACK) is None


def test_same_docs_body_at_500_would_fire():
    # Proves the ONLY thing that changed for this body is the status: the exact
    # same bytes are empty at 200 (above) but a genuine leak at an error status.
    assert _detect_trace(200, PY_DOCS_TRACEBACK) is None
    assert _detect_trace(500, PY_DOCS_TRACEBACK) is not None


def test_real_500_traceback_still_fires():
    # MUST-FIRE (branch a): a real Flask/Werkzeug traceback at a 500, with no
    # interactive-debugger markers, is a genuine verbose-error leak.
    assert _detect_trace(500, FLASK_500_TRACEBACK)[0] == "werkzeug/flask"


def test_interactive_debugger_console_fires_on_any_status():
    # MUST-FIRE (branch b): the live Werkzeug debugger console is a code-exec
    # surface. It renders behind a 200, so it fires regardless of status.
    assert _detect_trace(200, WERKZEUG_DEBUGGER_CONSOLE)[0] == "werkzeug/flask"
    assert _detect_trace(500, WERKZEUG_DEBUGGER_CONSOLE)[0] == "werkzeug/flask"
    # ...even on a 200 that a vibe-coded SPA would otherwise return.
    assert (
        _detect_trace(200, WERKZEUG_DEBUGGER_CONSOLE)[1]
        == "interactive_debugger_console"
    )


def test_empty_and_none_bodies():
    assert _detect_trace(500, "") is None
    assert _detect_trace(500, None) is None
    assert _detect_trace(None, "") is None


def test_malformed_query_appends_correctly():
    assert "?" in _malformed("/search")
    # existing query string -> append with &, keep a single leading ?
    out = _malformed("/search?q=1")
    assert out.startswith("/search?q=1&")
    assert out.count("?") == 1


# --------------------------------------------------------------------------
# runner-level: single-request-per-endpoint, dedupe, cap
# --------------------------------------------------------------------------


def test_positive_yields_exactly_one_finding():
    def fetch(path):
        return (500, {"content-type": "text/html"}, WERKZEUG)

    leaks, probed, truncated = probe_error_leak(fetch, ["/api/user"])
    assert len(leaks) == 1
    assert leaks[0].finding_type == "verbose_error_disclosure"
    assert leaks[0].location == "/api/user"
    assert leaks[0].contains_pii_or_secrets is False
    # evidence is value-free: no leaked source path from the body
    assert "/srv/app/views.py" not in leaks[0].evidence
    assert "werkzeug/flask" in leaks[0].evidence
    assert probed == 1
    assert truncated is False


def test_clean_site_yields_nothing():
    endpoints = ["/", "/about", "/api/user", "/login"]

    def fetch(path):
        return (404, {"content-type": "text/html"}, BRANDED_404)

    leaks, probed, truncated = probe_error_leak(fetch, endpoints)
    assert leaks == []
    assert probed == len(endpoints)
    assert truncated is False


def test_spa_catchall_yields_nothing():
    # A vibe-coded SPA returns 200 + its HTML shell for every path, malformed or not.
    def fetch(path):
        return (200, {"content-type": "text/html"}, SPA_SHELL)

    leaks, probed, truncated = probe_error_leak(fetch, ["/", "/x", "/api/thing"])
    assert leaks == []
    assert probed == 3


def test_json_error_only_yields_nothing():
    def fetch(path):
        return (400, {"content-type": "application/json"}, JSON_ERROR)

    leaks, _probed, _trunc = probe_error_leak(fetch, ["/api/user"])
    assert leaks == []


def test_refused_fetch_is_skipped():
    def fetch(path):
        return None

    leaks, probed, truncated = probe_error_leak(fetch, ["/a", "/b"])
    assert leaks == []
    assert probed == 2


def test_dedupes_one_finding_per_framework():
    # Same framework leaks on many routes -> a single finding.
    def fetch(path):
        return (500, {}, WERKZEUG)

    leaks, probed, _trunc = probe_error_leak(fetch, ["/a", "/b", "/c", "/d"])
    assert len(leaks) == 1
    assert probed == 4


def test_cap_bounds_total_requests():
    def fetch(path):
        return (404, {}, BRANDED_404)

    endpoints = [f"/e{i}" for i in range(50)]
    leaks, probed, truncated = probe_error_leak(fetch, endpoints, cap=5)
    assert probed == 5
    assert truncated is True
    assert leaks == []


def test_docs_page_example_traceback_at_200_yields_nothing():
    # End-to-end version of the reviewer's false positive: a 200 text/html docs
    # page rendering an example traceback produces NO findings.
    def fetch(path):
        return (200, {"content-type": "text/html"}, PY_DOCS_TRACEBACK)

    leaks, probed, truncated = probe_error_leak(fetch, ["/docs/errors", "/blog/tb"])
    assert leaks == []
    assert probed == 2
    assert truncated is False


def test_interactive_debugger_console_at_200_yields_a_finding():
    # A 200 that serves the live Werkzeug debugger console IS a live exposure.
    def fetch(path):
        return (200, {"content-type": "text/html"}, WERKZEUG_DEBUGGER_CONSOLE)

    leaks, probed, _trunc = probe_error_leak(fetch, ["/api/user"])
    assert len(leaks) == 1
    assert leaks[0].finding_type == "verbose_error_disclosure"
    assert "werkzeug/flask" in leaks[0].evidence
    # evidence stays value-free: no leaked pin / source path from the console body
    assert "pin_input" not in leaks[0].evidence
    assert probed == 1
