"""Tests for the mass-assignment write probe.

No network: every case drives ``probe_mass_assignment`` with a hand-built fake ``request``
callable that returns ``(status, headers, body)`` tuples (or ``None``). The callable's
signature is ``request(method, path, body)`` where ``method`` is ``"POST"`` (``body`` is the
JSON string) or ``"GET"`` (``body`` is ``None``).

The probe crosses TWO hops before it emits: an echoed differential on the injected POST, then
an independent ``GET <endpoint>/<id>`` read-back that must still carry the injected field.
That read-back is what separates a genuine mass-assignment (stored) from the commonest false
positive — an echo-create (``res.json({...req.body, id})``) that reflects the body without
storing it. finding_type is ALWAYS ``mass_assignment``; ``privilege_escalation`` is never
emitted (proving a stored role is honored needs a two-identity scan, out of scope here).
"""

from __future__ import annotations

import inspect
import json

import kuv.recon.mass_assignment as mass_assignment_module
from kuv.recon.mass_assignment import (
    BASELINE_BODY,
    INJECTED_BODY,
    MassAssignmentFinding,
    probe_mass_assignment,
)

_HTML_SHELL = "<!doctype html><html><head><title>App</title></head><body>root</body></html>"


def make_request(responses: dict):
    """Build a fake ``request(method, path, body)``.

    ``responses`` maps an endpoint path -> ``{"baseline": r, "injected": r, "readback": r}``
    where each ``r`` is a ``(status, headers, body)`` tuple or ``None`` (or the key omitted,
    which also yields ``None``). POSTs are routed to ``"baseline"`` vs ``"injected"`` by
    whether the body carries the injected ``role`` field. A GET's path is the read-back
    ``<endpoint>/<id>``; the ``/<id>`` tail is stripped to find the endpoint's ``readback``.
    """
    calls: list[tuple] = []

    def request(method, path, body):
        m = (method or "").upper()
        if m == "GET":
            calls.append(("GET", path))
            base = path.rsplit("/", 1)[0]  # strip the /<id> tail
            spec = responses.get(base)
            if spec is None:
                return None
            return spec.get("readback")
        # POST
        parsed = json.loads(body)
        phase = "injected" if "role" in parsed else "baseline"
        calls.append(("POST", path, phase))
        spec = responses.get(path)
        if spec is None:
            return None
        return spec.get(phase)

    request.calls = calls  # type: ignore[attr-defined]
    return request


def _json(obj) -> str:
    return json.dumps(obj)


# --------------------------------------------------------------------------
# sanity: the injected body actually carries the whole catalog
# --------------------------------------------------------------------------

def test_bodies_are_shaped_as_expected():
    base = json.loads(BASELINE_BODY)
    inj = json.loads(INJECTED_BODY)
    assert base == {"name": "kuvprobe", "title": "kuvprobe"}
    # baseline carries NO privileged fields; injected carries role + the rest.
    assert "role" not in base
    for key in ("role", "is_admin", "isAdmin", "admin", "is_superuser", "permissions",
                "credits", "balance", "is_verified", "email_verified", "verified",
                "plan", "subscription_tier", "owner_id", "user_id"):
        assert key in inj
    assert inj["credits"] == 999999 and inj["permissions"] == ["admin"]


# --------------------------------------------------------------------------
# (1) MALICIOUS — read-back confirms the injected field was PERSISTED -> fires
# --------------------------------------------------------------------------

def test_positive_readback_confirms_persisted_is_mass_assignment():
    # The create endpoint stores req.body: the injected role="admin" is echoed on create AND
    # still present when the record is read back from an independent GET -> genuine finding.
    responses = {
        "api/items": {
            "baseline": (201, {}, _json({"id": "obj-BASE-001", "name": "kuvprobe", "role": "user"})),
            "injected": (201, {}, _json({"id": "obj-INJ-777", "name": "kuvprobe", "role": "admin"})),
            "readback": (200, {}, _json({"id": "obj-INJ-777", "name": "kuvprobe", "role": "admin"})),
        }
    }
    request = make_request(responses)
    findings, probed, truncated = probe_mass_assignment(request, ("api/items",))

    assert len(findings) == 1
    assert isinstance(findings[0], MassAssignmentFinding)
    assert findings[0].finding_type == "mass_assignment"
    assert findings[0].location == "POST /api/items"
    assert "role" in findings[0].evidence
    assert findings[0].contains_pii_or_secrets is False
    # value-free: neither the injected value nor the target's record id leaks into evidence
    assert "admin" not in findings[0].evidence
    assert "obj-INJ-777" not in findings[0].evidence
    # the read-back GET was actually issued against <endpoint>/<id>, and only 2 POSTs happened
    assert probed == 2 and truncated is False
    assert ("GET", "api/items/obj-INJ-777") in request.calls
    assert ("POST", "api/items", "baseline") in request.calls
    assert ("POST", "api/items", "injected") in request.calls


def test_positive_persisted_role_is_mass_assignment_never_privilege_escalation():
    # A persisted role="admin" is exactly the shape that used to become privilege_escalation.
    # It must now be mass_assignment ONLY — privilege_escalation requires a two-identity scan.
    responses = {
        "api/users": {
            "baseline": (201, {}, _json({"id": 1, "role": "user"})),
            "injected": (201, {}, _json({"id": 2, "role": "admin"})),
            "readback": (200, {}, _json({"id": 2, "role": "admin"})),
        }
    }
    request = make_request(responses)
    findings, _p, _t = probe_mass_assignment(request, ("api/users",))
    assert len(findings) == 1
    assert findings[0].finding_type == "mass_assignment"
    assert all(f.finding_type != "privilege_escalation" for f in findings)


def test_positive_nested_wrapped_object_with_readback():
    # naive handlers wrap the created row: {"data": {"user": {...}}}; id is nested at data.id.
    responses = {
        "api/register": {
            "baseline": (201, {}, _json({"data": {"id": "b", "user": {"isAdmin": False}}})),
            "injected": (201, {}, _json({"data": {"id": "wrap-9", "user": {"isAdmin": True}}})),
            "readback": (200, {}, _json({"data": {"id": "wrap-9", "user": {"isAdmin": True}}})),
        }
    }
    request = make_request(responses)
    findings, _p, _t = probe_mass_assignment(request, ("api/register",))
    assert len(findings) == 1
    assert findings[0].finding_type == "mass_assignment"
    assert "isAdmin" in findings[0].evidence
    assert ("GET", "api/register/wrap-9") in request.calls


def test_positive_multiple_persisted_fields_yield_one_finding():
    # role + credits both persist; the probe emits exactly ONE mass_assignment listing both.
    responses = {
        "api/users": {
            "baseline": (201, {}, _json({"id": 1, "role": "user", "credits": 0})),
            "injected": (201, {}, _json({"id": 2, "role": "admin", "credits": 999999})),
            "readback": (200, {}, _json({"id": 2, "role": "admin", "credits": 999999})),
        }
    }
    request = make_request(responses)
    findings, _p, _t = probe_mass_assignment(request, ("api/users",))
    assert len(findings) == 1
    assert findings[0].finding_type == "mass_assignment"
    assert "role" in findings[0].evidence and "credits" in findings[0].evidence
    # value-free even with the numeric field
    assert "999999" not in findings[0].evidence


def test_positive_baseline_refused_but_readback_confirms():
    # baseline POST refused (None) -> no differential-suppression data, but the injected field
    # is still echoed and the independent read-back proves it was stored -> fires.
    responses = {
        "api/items": {
            "baseline": None,
            "injected": (201, {}, _json({"id": "x9", "role": "admin"})),
            "readback": (200, {}, _json({"id": "x9", "role": "admin"})),
        }
    }
    request = make_request(responses)
    findings, probed, _t = probe_mass_assignment(request, ("api/items",))
    assert len(findings) == 1
    assert findings[0].finding_type == "mass_assignment"
    assert probed == 2


# --------------------------------------------------------------------------
# (2) BENIGN echo-create — reflected but NOT stored -> MUST be EMPTY
# --------------------------------------------------------------------------

def test_negative_echo_create_reflects_but_readback_omits_injected_field_is_empty():
    # THE reviewer's false positive: res.json({...req.body, id}) echoes role="admin" (and
    # credits) straight back on create, but the INDEPENDENT read-back returns the stored
    # record WITHOUT those fields -> reflected, not stored -> ZERO findings.
    responses = {
        "api/items": {
            "baseline": (201, {}, _json({"id": "b1", "name": "kuvprobe"})),
            "injected": (201, {}, _json({"id": "i1", "name": "kuvprobe", "role": "admin", "credits": 999999})),
            "readback": (200, {}, _json({"id": "i1", "name": "kuvprobe"})),
        }
    }
    request = make_request(responses)
    findings, probed, truncated = probe_mass_assignment(request, ("api/items",))
    assert findings == []
    assert probed == 2 and truncated is False
    # the read-back WAS attempted (the probe crossed the second hop) but disproved storage
    assert ("GET", "api/items/i1") in request.calls


def test_negative_echo_create_no_id_cannot_read_back_is_empty():
    # echo-create that returns no id at all -> the probe cannot locate the record to read
    # back -> storage unproven -> emit nothing (and no GET is issued).
    responses = {
        "api/items": {
            "baseline": (201, {}, _json({"name": "kuvprobe"})),
            "injected": (201, {}, _json({"name": "kuvprobe", "role": "admin"})),
            "readback": (200, {}, _json({"name": "kuvprobe", "role": "admin"})),
        }
    }
    request = make_request(responses)
    findings, _p, _t = probe_mass_assignment(request, ("api/items",))
    assert findings == []
    assert not any(c[0] == "GET" for c in request.calls)


def test_negative_readback_refused_is_empty():
    # differential present + id parsed, but the read-back GET is refused/blocked (None).
    responses = {
        "api/items": {
            "baseline": (201, {}, _json({"id": "b", "name": "kuvprobe"})),
            "injected": (201, {}, _json({"id": "z1", "role": "admin"})),
            "readback": None,
        }
    }
    request = make_request(responses)
    findings, _p, _t = probe_mass_assignment(request, ("api/items",))
    assert findings == []
    assert ("GET", "api/items/z1") in request.calls


def test_negative_readback_4xx_is_empty():
    # read-back returns 404 (record not retrievable / not stored) -> emit nothing.
    responses = {
        "api/items": {
            "baseline": (201, {}, _json({"id": "b", "name": "kuvprobe"})),
            "injected": (201, {}, _json({"id": "z2", "role": "admin"})),
            "readback": (404, {}, _json({"error": "not found"})),
        }
    }
    request = make_request(responses)
    findings, _p, _t = probe_mass_assignment(request, ("api/items",))
    assert findings == []


def test_negative_readback_html_shell_is_empty():
    # read-back answers the SPA HTML shell (200 + <!doctype html>) -> rejected -> empty.
    responses = {
        "api/items": {
            "baseline": (201, {}, _json({"id": "b", "name": "kuvprobe"})),
            "injected": (201, {}, _json({"id": "z3", "role": "admin"})),
            "readback": (200, {"content-type": "text/html"}, _HTML_SHELL),
        }
    }
    request = make_request(responses)
    findings, _p, _t = probe_mass_assignment(request, ("api/items",))
    assert findings == []


# --------------------------------------------------------------------------
# (3) other known-NEGATIVE benign shapes (no differential -> no read-back)
# --------------------------------------------------------------------------

def test_negative_server_ignores_injected_fields():
    responses = {
        "api/users": {
            "baseline": (201, {}, _json({"id": 1, "name": "kuvprobe", "role": "user", "credits": 0})),
            # server dropped every injected field; row is unchanged shape
            "injected": (201, {}, _json({"id": 2, "name": "kuvprobe", "role": "user", "credits": 0})),
        }
    }
    request = make_request(responses)
    findings, probed, truncated = probe_mass_assignment(request, ("api/users",))
    assert findings == []
    assert probed == 2 and truncated is False
    assert not any(c[0] == "GET" for c in request.calls)


def test_negative_generic_ack_with_no_object_echo():
    responses = {
        "api/users": {
            "baseline": (200, {}, _json({"ok": True})),
            "injected": (200, {}, _json({"ok": True, "message": "created"})),
        }
    }
    request = make_request(responses)
    findings, _p, _t = probe_mass_assignment(request, ("api/users",))
    assert findings == []


def test_negative_4xx_rejection():
    responses = {
        "api/users": {
            "baseline": (201, {}, _json({"id": 1, "name": "kuvprobe"})),
            "injected": (400, {}, _json({"error": "unknown field: role", "role": "admin"})),
        }
    }
    request = make_request(responses)
    findings, _p, _t = probe_mass_assignment(request, ("api/users",))
    # 4xx -> rejected, even though the error body happens to echo the field name
    assert findings == []


def test_negative_request_returns_none_everywhere():
    request = make_request({})  # every path -> None
    findings, probed, truncated = probe_mass_assignment(request, ("api/users", "api/account"))
    assert findings == []
    assert probed == 4 and truncated is False


def test_html_catch_all_is_not_flagged():
    responses = {
        "api/users": {
            "baseline": (200, {"content-type": "text/html"}, _HTML_SHELL),
            "injected": (200, {"content-type": "text/html"}, _HTML_SHELL),
        }
    }
    request = make_request(responses)
    findings, probed, _t = probe_mass_assignment(request, ("api/users",))
    assert findings == []
    assert probed == 2


def test_safe_server_default_true_is_suppressed():
    # The server ALWAYS sets is_verified=true on new records (its own default). The injected
    # value matches, but the baseline proves it is server-controlled -> no differential.
    responses = {
        "api/users": {
            "baseline": (201, {}, _json({"id": 1, "name": "kuvprobe", "is_verified": True})),
            "injected": (201, {}, _json({"id": 2, "name": "kuvprobe", "is_verified": True})),
        }
    }
    request = make_request(responses)
    findings, _p, _t = probe_mass_assignment(request, ("api/users",))
    assert findings == []
    assert not any(c[0] == "GET" for c in request.calls)


def test_safe_role_echoed_back_as_server_controlled_value():
    # We inject role="admin"; the server ignores it and echoes its own role="user".
    responses = {
        "api/users": {
            "baseline": (201, {}, _json({"id": 1, "role": "user"})),
            "injected": (201, {}, _json({"id": 2, "role": "user"})),
        }
    }
    request = make_request(responses)
    findings, _p, _t = probe_mass_assignment(request, ("api/users",))
    assert findings == []


# --------------------------------------------------------------------------
# (4) privilege_escalation is NEVER emitted, anywhere
# --------------------------------------------------------------------------

def test_privilege_escalation_is_never_emitted_across_shapes():
    # drive several privilege-field shapes that all persist on read-back; every finding must
    # be mass_assignment, and privilege_escalation must appear nowhere in the output.
    shapes = [
        ("api/a", {"id": "a1", "is_admin": True}),
        ("api/b", {"id": "b1", "is_superuser": True}),
        ("api/c", {"id": "c1", "permissions": ["admin"]}),
        ("api/d", {"id": "d1", "role": "admin"}),
    ]
    total = []
    for path, stored in shapes:
        responses = {
            path: {
                "baseline": (201, {}, _json({"id": "base"})),
                "injected": (201, {}, _json(stored)),
                "readback": (200, {}, _json(stored)),
            }
        }
        request = make_request(responses)
        findings, _p, _t = probe_mass_assignment(request, (path,))
        assert len(findings) == 1
        total.extend(findings)
    assert all(f.finding_type == "mass_assignment" for f in total)
    assert not any(f.finding_type == "privilege_escalation" for f in total)


def test_emission_path_has_no_privilege_escalation_literal():
    # Structural guard: the sole emitter (_make_finding) hard-codes the mass_assignment
    # finding_type and never assigns privilege_escalation (the _PRIV_* path was deleted).
    src = inspect.getsource(mass_assignment_module._make_finding)
    assert 'finding_type="mass_assignment"' in src
    assert "privilege_escalation" not in src


# --------------------------------------------------------------------------
# (5) cap / truncation  (probed counts POSTs; the read-back GET is not charged)
# --------------------------------------------------------------------------

def test_cap_truncates_before_an_unpaired_write():
    # 3 endpoints, cap=3: ep1 does baseline+injected (2), ep2 does baseline (3) then must
    # stop before its injected POST -> truncated, no half-paired extra write.
    responses = {p: None for p in ("api/a", "api/b", "api/c")}
    request = make_request(responses)
    findings, probed, truncated = probe_mass_assignment(request, ("api/a", "api/b", "api/c"), cap=3)
    assert findings == []
    assert probed == 3
    assert truncated is True
