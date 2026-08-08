"""Unit tests for the response-reflected SSRF probe.

No network: every request callable is a hand-built fake returning (status, headers, body)
tuples or None. We prove: (1) a reflected external-canary marker => exactly one "ssrf"
finding; (2) a benign endpoint that never fetches => none; (3) an SPA HTML catch-all =>
none; (4) an endpoint that merely ECHOES the URL string we sent (no fetch) => none —
the SAFE case that must not be flagged; plus cap / evidence-hygiene guarantees.
"""

from __future__ import annotations

from kuv.recon.ssrf_probe import (
    DEFAULT_PARAM_NAMES,
    _CANARY_MARKER,
    _CANARY_PHRASE2,
    _EXTERNAL_CANARY_URL,
    probe_ssrf,
)

# The static page example.com serves; BOTH distinctive phrases live INSIDE this fetched
# content. Note it is itself an HTML document — a genuine reflected fetch of example.com is
# HTML, and the probe intentionally flags it (it is NOT the app's own shell).
_EXAMPLE_PAGE = (
    "<html><head><title>Example Domain</title></head><body>"
    "<h1>Example Domain</h1><p>This domain is for use in illustrative examples.</p>"
    "</body></html>"
)
# A vibe-coded SPA shell returned for literally any path/param.
_SPA_SHELL = '<!doctype html><html><head><title>My App</title></head><body><div id="root"></div></body></html>'


def _sink() -> tuple[tuple[str, str], ...]:
    return (("proxy", "url"),)


def test_reflected_canary_yields_one_ssrf_finding():
    # A server-side fetcher: it dereferences whatever url= points at and reflects the body.
    def request(path, method, param, url_value):
        if url_value == _EXTERNAL_CANARY_URL:
            # server actually fetched example.com and streamed the page back
            return (200, {"content-type": "text/html"}, _EXAMPLE_PAGE)
        # an internal target: reachable but different (corroboration differential)
        return (500, {}, "upstream connect error")

    findings, probed, truncated = probe_ssrf(request, sinks=_sink(), cap=12)

    assert len(findings) == 1
    f = findings[0]
    assert f.finding_type == "ssrf"
    assert f.contains_pii_or_secrets is False
    assert "url" in f.location
    assert probed >= 1
    # corroboration recorded because internal (500) differed from external (200)
    assert "corroborated" in f.evidence


def test_reflection_without_internal_differential_still_flags():
    # Reflects the canary but internal targets look identical to external => still a
    # finding (reflection alone is sufficient), just without the corroboration note.
    def request(path, method, param, url_value):
        return (200, {"content-type": "text/html"}, _EXAMPLE_PAGE)

    findings, probed, truncated = probe_ssrf(request, sinks=_sink(), cap=12)
    assert len(findings) == 1 and findings[0].finding_type == "ssrf"
    assert "corroborated" not in findings[0].evidence


def test_benign_endpoint_yields_nothing():
    # A normal endpoint that ignores the param entirely and returns its own JSON.
    def request(path, method, param, url_value):
        return (200, {"content-type": "application/json"}, '{"ok":true,"items":[]}')

    findings, probed, truncated = probe_ssrf(request, sinks=_sink(), cap=12)
    assert findings == []


def test_html_catch_all_yields_nothing():
    # SPA returns its own HTML shell for any path/param — it contains NEITHER canary phrase,
    # so it is rejected. This is the core false-positive the two-phrase discriminator kills.
    def request(path, method, param, url_value):
        return (200, {"content-type": "text/html"}, _SPA_SHELL)

    findings, probed, truncated = probe_ssrf(request, sinks=_sink(), cap=12)
    assert findings == []


def test_shell_with_only_the_marker_is_rejected():
    # A shell whose <title> happens to say "Example Domain" carries the marker but NOT the
    # second fetched phrase ("illustrative examples"), so it is rejected — a single
    # coincidental marker never suffices.
    shell = "<!doctype html><html><head><title>Example Domain dashboard</title></head><body></body></html>"

    def request(path, method, param, url_value):
        return (200, {}, shell)

    findings, _, _ = probe_ssrf(request, sinks=_sink(), cap=12)
    assert findings == []


def test_json_wrapped_reflection_is_flagged():
    # A URL-preview/unfurl proxy that returns the FETCHED page's fields wrapped in JSON
    # (not an HTML document) is still a reflected fetch — both phrases present => finding.
    def request(path, method, param, url_value):
        if url_value == _EXTERNAL_CANARY_URL:
            body = '{"title":"Example Domain","description":"This domain is for use in illustrative examples."}'
            return (200, {"content-type": "application/json"}, body)
        return None

    findings, _, _ = probe_ssrf(request, sinks=_sink(), cap=12)
    assert len(findings) == 1 and findings[0].finding_type == "ssrf"


def test_url_echo_is_not_a_fetch():
    # SAFE case: the endpoint echoes back the URL STRING we sent (input reflection) but did
    # NOT fetch it — the fetched-content marker is absent. Must NOT be flagged.
    def request(path, method, param, url_value):
        body = '{"error":"could not process url","input":"%s"}' % url_value
        return (200, {"content-type": "application/json"}, body)

    findings, probed, truncated = probe_ssrf(request, sinks=_sink(), cap=12)
    assert findings == []


def test_non_2xx_reflection_is_rejected():
    # Marker present but status is an error — reject (not a successful fetch reflection).
    def request(path, method, param, url_value):
        return (403, {}, "blocked: " + _EXAMPLE_PAGE)

    findings, _, _ = probe_ssrf(request, sinks=_sink(), cap=12)
    assert findings == []


def test_none_response_is_skipped():
    # request refused/blocked by the gate => None => no crash, no finding.
    def request(path, method, param, url_value):
        return None

    findings, probed, truncated = probe_ssrf(request, sinks=_sink(), cap=12)
    assert findings == [] and probed == 1


def test_default_param_catalog_used_when_no_sinks():
    seen_params = []

    def request(path, method, param, url_value):
        seen_params.append(param)
        return (404, {}, "not found")

    findings, probed, truncated = probe_ssrf(request, sinks=None, cap=100)
    assert findings == []
    # every default param name got probed against the root path
    assert set(seen_params) == set(DEFAULT_PARAM_NAMES)


def test_cap_bounds_requests_and_sets_truncated():
    calls = {"n": 0}

    def request(path, method, param, url_value):
        calls["n"] += 1
        return (404, {}, "nope")

    findings, probed, truncated = probe_ssrf(request, sinks=None, cap=3)
    assert probed == 3
    assert calls["n"] == 3
    assert truncated is True


def test_evidence_is_value_free_no_fetched_content():
    # Evidence must NOT contain fetched body content, internal-target bytes, or the URL we
    # sent — only names + the fact of reflection.
    def request(path, method, param, url_value):
        if url_value == _EXTERNAL_CANARY_URL:
            return (200, {}, _EXAMPLE_PAGE)
        # internal metadata target returns a juicy secret we must never surface
        return (200, {}, "iam-role: AKIA-SUPER-SECRET-CREDENTIAL")

    findings, _, _ = probe_ssrf(request, sinks=_sink(), cap=12)
    assert len(findings) == 1
    blob = findings[0].evidence + findings[0].location
    assert "AKIA-SUPER-SECRET-CREDENTIAL" not in blob
    assert "illustrative examples" not in blob  # no fetched external body either
    assert _EXTERNAL_CANARY_URL not in blob      # not even the URL string we sent
    # the marker string itself is generic wording; assert we didn't dump the raw page
    assert "<h1>" not in blob


def test_finding_type_is_exactly_ssrf():
    def request(path, method, param, url_value):
        return (200, {}, _EXAMPLE_PAGE)

    findings, _, _ = probe_ssrf(request, sinks=_sink(), cap=12)
    assert [f.finding_type for f in findings] == ["ssrf"]


def test_marker_constant_sanity():
    # guard against an accidental marker edit that would silently disable the probe
    assert _CANARY_MARKER.lower() in _EXAMPLE_PAGE.lower()
    assert _CANARY_PHRASE2.lower() in _EXAMPLE_PAGE.lower()
