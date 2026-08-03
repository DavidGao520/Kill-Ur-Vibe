# Kill-Ur-Vibe

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
proves the holes with real requests, and produces a consultant-grade report.

> ⚠️ **Authorized targets only.** This is an active-assessment tool. Point it only at
> systems you own or have written permission to test. It is built to make unauthorized
> use hard — every request is scope-gated in code — but the authorization is your
> responsibility.

## Safety posture (non-negotiable, enforced in code)

- **Single egress policy engine** — the agent has *no* raw network. Every request
  (recon, probe, DNS, scan) is checked against the authorized scope at call time. An
  out-of-scope host or off-scope redirect is refused, not followed.
- **Read-only by default.** Writes go through a gated tool, authorized *per action
  class* (account-create / object-PUT / websocket-save / …). The first write of each
  class against a live target needs operator confirmation; synthetic records only,
  never destructive.
- **No secret or PII values in reports.** Findings record presence / type / count /
  length only; a redaction pass scrubs the output.
- **Bounded.** Hard caps on tool calls, wall-clock, and spend per run.
- **Deterministic where it matters.** Severity comes from a rule table, not the model;
  JWT-role / source-map / secret-prefix judgments come from deterministic decoders.

## Quick start

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -e '.[dev]'
pytest -q
```

Try it end-to-end against the bundled **local vulnerable fixture** (touches only
localhost, reproduces a real authorization bug):

```bash
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

Nine gated tools: `http_get`, `http_write` (gated, per action class), `record_finding`,
`decode_jwt_role`, `classify_secret`, `check_source_map`, `scan_js` (full-bundle secret
scan), `enumerate_subdomains` (DNS + dangling-CNAME takeover detection), `check_email_auth`
(SPF / DMARC).

## Status

Thin core is built and unit-tested (94 tests): egress policy engine + authorization
scope, deterministic decoders + severity rules, the Claude Agent SDK harness, the secret
scanner, DNS recon, and the report generator. **Deferred:** TLS validation and a headless
browser for JS-heavy SPAs.

## Stack

Python 3.11+, Claude Agent SDK (Anthropic), `dnspython`, `httpx`. BYO Anthropic key.

## License

MIT
