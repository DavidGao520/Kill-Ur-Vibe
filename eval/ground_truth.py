"""Ground-truth finding sets for the local fixtures.

`GROUND_TRUTH` is the original single-fixture set (kept for `assess_fixture.py`).
`FIXTURES` is the multi-fixture generalization suite. Be precise about what is "held
out": the methodology prompt DOES teach the technique for these bug classes (Phase 3
names IDOR, privilege-escalation, forgeable tokens, SSRF and how to probe them). What is
held out is the TARGET — the specific app, endpoints, and payloads, which the agent has
never seen. So this measures "given the method, can the agent find the bug in a NEW app",
not "can it invent a class it was never told about" (that is what the escape hatch +
its pipeline test cover).

Fields:
  held_out    — counts toward the generalization headline.
  autonomous  — the agent must DISCOVER the bug from recon (no task hint). A fixture with
                a `task` hint (ws_app) is spoon-fed, so it is held_out but NOT autonomous:
                it measures tool+pipeline reachability, reported separately, NOT folded
                into the autonomous-discovery generalization number.
  accept_types — the SET of finding_types that count as "found the bug" for a held-out
                fixture. Credit also requires real gated I/O to the target and a precision
                floor (see eval/suite.py), so a shotgun run cannot fake recall.
"""

from __future__ import annotations

# The original single-fixture ground truth — finding-identity keys (type + location).
GROUND_TRUTH: list[dict[str, str]] = [
    {"finding_type": "unauth_write", "location": "POST /api/ideas"},
    {"finding_type": "unauth_read_sensitive", "location": "GET /api/ideas"},
]

# The generalization suite. `accept_types` (held-out fixtures only) is the SET of
# finding_types that count as "found the bug" — the held-out gate scores on class
# presence, not exact location, because generalization means "found an IDOR", not
# "guessed the exact id in the path".
FIXTURES: list[dict] = [
    {
        "name": "vuln_app",
        "module": "fixtures/vuln_app/server.py",
        "url": "http://127.0.0.1:8779",
        "port": 8779,
        "health": "http",
        "held_out": False,
        "autonomous": True,
        "ground_truth": [
            {"finding_type": "unauth_write", "location": "POST /api/ideas"},
            {"finding_type": "unauth_read_sensitive", "location": "GET /api/ideas"},
        ],
    },
    {
        "name": "idor_app",
        "module": "fixtures/idor_app/server.py",
        "url": "http://127.0.0.1:8780",
        "port": 8780,
        "health": "http",
        "held_out": True,
        "autonomous": True,
        "accept_types": ["idor"],
        "ground_truth": [{"finding_type": "idor", "location": "GET /api/orders/{id}"}],
    },
    {
        "name": "massassign_app",
        "module": "fixtures/massassign_app/server.py",
        "url": "http://127.0.0.1:8781",
        "port": 8781,
        "health": "http",
        "held_out": True,
        "autonomous": True,
        # honoring role=admin is privilege escalation; an agent may file either class.
        "accept_types": ["privilege_escalation", "mass_assignment"],
        "ground_truth": [{"finding_type": "privilege_escalation", "location": "POST /api/signup"}],
    },
    {
        "name": "ws_app",
        "module": "fixtures/ws_app/server.py",
        "url": "ws://127.0.0.1:8782/",
        "port": 8782,
        "health": "tcp",
        "held_out": True,
        "autonomous": False,   # task-hinted (a pure-ws target has no HTTP surface for recon)
        # same trust failure over a different TRANSPORT — reaching it needs probe_websocket.
        # Spoon-fed via a `task`, so this measures TOOL+pipeline reachability (also CI-covered),
        # NOT autonomous discovery. The autonomous DISCOVER-the-bug set is idor_app + massassign_app.
        "accept_types": ["unauth_read_sensitive", "unauth_write"],
        "task": (
            "The target is a websocket endpoint at ws://127.0.0.1:8782/. Use "
            "probe_websocket with no token and an untrusted origin to test whether it "
            "accepts an anonymous client and returns/accepts records. Record each PROVEN "
            "finding with record_finding (location like 'WS /'). Then stop."
        ),
        "ground_truth": [{"finding_type": "unauth_read_sensitive", "location": "WS /"}],
    },
]
