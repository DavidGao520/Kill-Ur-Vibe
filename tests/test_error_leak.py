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


# --------------------------------------------------------------------------
# matcher-level: every framework signature fires; benign bodies do not
# --------------------------------------------------------------------------


def test_detect_werkzeug():
    assert _detect_trace(WERKZEUG)[0] == "werkzeug/flask"


def test_detect_django():
    assert _detect_trace(DJANGO)[0] == "django-debug"


def test_detect_rails():
    assert _detect_trace(RAILS)[0] == "rails"


def test_detect_symfony():
    assert _detect_trace(SYMFONY)[0] == "symfony"


def test_detect_node_anonymous():
    assert _detect_trace(NODE_ANON)[0] == "node/express"


def test_detect_node_modules():
    assert _detect_trace(NODE_MODULES)[0] == "node/express"


def test_detect_java():
    assert _detect_trace(JAVA)[0] == "java"


def test_detect_dotnet():
    assert _detect_trace(DOTNET)[0] == ".net"


def test_detect_generic_python():
    # No "Traceback (most recent call last)" header -> falls through to the
    # generic Python source-frame branch, not the Werkzeug branch.
    assert _detect_trace(GENERIC_PY)[0] == "python"


def test_spa_shell_is_not_a_trace():
    assert _detect_trace(SPA_SHELL) is None


def test_branded_404_is_not_a_trace():
    assert _detect_trace(BRANDED_404) is None


def test_json_error_message_only_is_not_a_trace():
    assert _detect_trace(JSON_ERROR) is None


def test_marketing_page_is_not_a_trace():
    assert _detect_trace(MARKETING) is None


def test_dotnet_docs_page_is_not_a_trace():
    # System. + Exception + StackTrace as loose vocabulary, but no managed frame.
    assert _detect_trace(DOTNET_DOCS) is None


def test_node_modules_reference_is_not_a_trace():
    # ' at ' and '/node_modules/' co-occur, but there is no `:line:col` V8 frame.
    assert _detect_trace(NODE_MODULES_DOC) is None


def test_python_tutorial_snippet_is_not_a_trace():
    # A source-frame line with no exception-summary line is not a real traceback.
    assert _detect_trace(PY_TUTORIAL) is None


def test_empty_and_none_bodies():
    assert _detect_trace("") is None
    assert _detect_trace(None) is None


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
