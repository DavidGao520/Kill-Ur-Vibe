# vuln_app — intentionally-insecure test fixture

**This is deliberately-vulnerable test scaffolding. Do not ship it, deploy it, or
expose it to any network other than loopback.**

It exists only so Kill-Ur-Vibe's own test suite and fidelity eval can prove the
CLI reproduces two known findings against a controlled target on `127.0.0.1`.
There is no real user data here — the store is in-memory, seeded with two fake
records, and resets on every restart. Zero external dependencies: it uses the
Python standard-library `http.server` only.

## The deliberate vulnerabilities

The "vulnerabilities" are simply the intentional absence of authentication and
authorization:

- **`unauth_read_sensitive`** — `GET /api/ideas` returns records containing an
  `email` field (PII) with **no auth** required.
- **`unauth_write`** (the Critical to reproduce) — `POST /api/ideas` creates a
  record with **no auth** required.

## HTTP contract

Base URL: `http://127.0.0.1:8779`

| Method | Path         | Auth | Behavior |
|--------|--------------|------|----------|
| GET    | `/api/ideas` | none | `200` JSON list; each item `{id, title, email}`; `email` is PII |
| POST   | `/api/ideas` | none | `201` created from JSON body `{title}`; returns the new record |
| GET    | `/health`    | none | `200 {"status": "ok"}` |

## Run

```bash
python fixtures/vuln_app/server.py
```

The server binds to `127.0.0.1:8779` and prints a one-line "intentionally-insecure"
banner. Stop it with `Ctrl-C`.

### Quick manual check

```bash
curl -s http://127.0.0.1:8779/health
curl -s http://127.0.0.1:8779/api/ideas
curl -s -X POST http://127.0.0.1:8779/api/ideas \
  -H 'Content-Type: application/json' -d '{"title":"New idea"}'
```
