# Kill-Ur-Vibe

[![CI](https://github.com/DavidGao520/Kill-Ur-Vibe/actions/workflows/ci.yml/badge.svg)](https://github.com/DavidGao520/Kill-Ur-Vibe/actions/workflows/ci.yml)

**A security assessment CLI for AI-built ("vibe-coded") web apps.**

You shipped an app with Lovable, v0, Cursor, Bolt, or Replit. The AI wrote a clean
happy path — and quietly skipped authorization. The bugs that actually hurt aren't
CVEs a scanner catches; they're **authorization-logic** holes:

- an endpoint that returns *everyone's* data with no login,
- open self-registration behind a cosmetic "invite only" gate,
- a pre-signed upload URL anyone can write to,
- a websocket that reads and writes production records without a token.

Kill-Ur-Vibe is an autonomous agent (bring your own Anthropic key) that probes an
app **you own or are authorized to assess**, reasons about *who the server trusts*,
proves the holes with real requests, and produces a consultant-grade report. Every
finding **leads with the plain-language harm** ("what could go wrong, and who's hurt")
so a non-technical founder gets it at a glance — while keeping the precise terms (each
explained on first use) and the exact evidence an engineer or AI needs to fix it.

> ⚠️ **Authorized targets only.** This is an active-assessment tool. Point it only at
> systems you own or have written permission to test. It is built to make unauthorized
> use hard — every request is scope-gated in code — but the authorization is your
> responsibility.

## Safety posture (non-negotiable, enforced in code)

- **Single egress policy engine** — the agent has *no* raw network. Every request
  (recon, probe, DNS, scan) is checked against the authorized scope at call time. An
  out-of-scope host or off-scope redirect is refused, not followed.
- **Writes are synthetic, gated, and consented.** The default run enables the
  synthetic-write classes (account-create / object-PUT / websocket-save) for depth — but
  only *after* a mandatory per-run authorization confirmation, and every write is gated
  *per action class*, creates clearly-tagged synthetic records, and is never destructive.
  Type `READ-ONLY` at the prompt to run purely read-only.
- **No secret or PII values in reports.** Findings record presence / type / count /
  length only; a redaction pass scrubs the output.
- **Bounded.** Hard caps on tool calls, wall-clock, and spend per run.
- **Deterministic where it matters.** Severity comes from a rule table, not the model;
  JWT-role / source-map / secret-prefix judgments come from deterministic decoders.

## Quick start

The fastest way — an interactive wizard:

```bash
pip install -e .
kuv
```

It asks for your Anthropic key (hidden input, never saved to disk), the site you want
to check, and an explicit **authorization confirmation** — then runs a read-only
assessment and drops a **PDF report on your Desktop**. For automatic PDF it uses a
headless Chrome if you have one, or `pip install '.[pdf]'` for a bundled renderer.

---

Prefer to drive it yourself? Install, test, and try the bundled **local vulnerable
fixture** (touches only localhost, reproduces a real authorization bug):

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -e '.[dev]'
pytest -q

export ANTHROPIC_API_KEY=sk-ant-...
python assess_fixture.py
```

Assess your **own** app via a scope file that defines what's in bounds:

```yaml
# scope/myapp.yaml  (gitignored)
engagement_id: myapp
authorized_by: you@example.com
targets: [ "app.example.com", "*.example.com" ]
expires_at: "2027-01-01"
allowed_actions: []        # read-only; add classes to permit synthetic writes
is_fixture: false
authorization_asserted: true
```

```bash
python assess.py https://app.example.com/ scope/myapp.yaml
```

It writes a polished HTML report to `runs/` (open it, Cmd-P → Save as PDF).

## What the agent can do

Fourteen gated tools: `http_get`, `http_write` (gated, per action class), `record_finding`,
`decode_jwt_role`, `classify_secret`, `check_source_map`, `scan_js` (full-bundle secret
scan), `enumerate_subdomains` (DNS + dangling-CNAME takeover detection), `check_email_auth`
(SPF / DMARC), `discover_paths` (route/endpoint discovery from the page + JS bundles, with an
optional path wordlist), `probe_websocket` (unauthenticated websocket read/write probe with a
values-free field summary), `check_http_posture` (deterministic CSP / cookie / CORS / HSTS
gap analysis), `analyze_oauth` (authorize-URL `state` / PKCE / `hd` analysis), and
`check_tls` (certificate validity / expiry / hostname / protocol).

The **synthetic-write tier** (self-registration, object-PUT, websocket-save) is ON by
default to prove write paths — clearly-tagged synthetic records, never destructive, still
per-class gated, and only after the per-run authorization confirmation. Type `READ-ONLY`
at the prompt to run purely read-only.

## Status

Thin core is built and unit-tested (159 tests): egress policy engine + authorization
scope, deterministic decoders + severity rules, the Claude Agent SDK harness, the secret
scanner, DNS recon, the websocket / HTTP-posture / OAuth / TLS probes, and the report
generator. **Deferred:** a headless browser for JS-heavy SPAs.

## Stack

Python 3.11+, Claude Agent SDK (Anthropic), `dnspython`, `httpx`. BYO Anthropic key.

## License

MIT
