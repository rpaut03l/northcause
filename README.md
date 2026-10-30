# Northcause

**Find it. Fix it. Prove it.**

Northcause is an evidence-led AI operations assurance platform. This repository holds the **pilot MVP**: a single Cloudflare Worker that lets a team record an incident, upload evidence, build a timeline, get ranked hypotheses that cite the exact evidence lines, draft a remediation for human approval, and check post-fix evidence.

Status: **pilot**. It is not production-ready. See [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) for controls and known gaps.

## What works

| Area | Routes |
|---|---|
| Public site | `/`, `/product`, `/security`, `/docs`, `/pricing`, `/contact` (form, rate limited), `/healthz` |
| Auth | `/login`, `POST /logout`. Pilot accounts are created with `scripts/create-user.mjs`. |
| Demo sandbox | `POST /sandbox` → isolated tenant with synthetic sample data, deleted after 24 h |
| Incidents | `/app` (list), `/app/incidents/new`, `/app/incidents/:id` (detail), status update, admin delete |
| Evidence | `POST /app/incidents/:id/evidence`, `/app/evidence/:id` (line-numbered viewer), `/download`, delete |
| Timeline | Built from ISO-8601 timestamps in text and `timestamp`/`time`/`ts` fields in JSON |
| Investigation | `POST /app/incidents/:id/investigate`, `/app/investigations/:id` |
| Remediation | `POST /app/claims/:id/draft`, `POST /app/drafts/:id/decision` (admin + reason), `POST /app/drafts/:id/checks` |
| Report | `/app/incidents/:id/report.md` |
| Audit | `/app/audit` with hash-chain verification |
| Settings | `/app/settings` (external model opt-in, admin only) |
| Integrations | `/app/integrations` — GitHub Actions read-only adapter (**not connected** unless `GITHUB_TOKEN` is set); OpenTelemetry **not built** |

### Investigation providers

- **Local rule-based analysis** (`src/providers/local-rules.ts`) — not an AI model. Matches a fixed set of failure signatures (OOM kills, CrashLoopBackOff, GPU OOM, 5xx, timeouts, connection refused, 429/quotas, TLS, disk full, RAG retrieval, CI failures) and security/policy risks (prompt-injection text, leaked secrets, privileged containers, public exposure, `:latest` tags). Unmatched evidence returns **insufficient evidence**.
- **External model** (`src/providers/external-model.ts`) — any OpenAI-compatible chat completions endpoint, configured only by server-side secrets, used only when an admin opts in and the user confirms each run.
- Both pass through `src/providers/citations.ts`, which re-checks every citation against stored evidence and labels claims **supported**, **uncertain** or **unsupported**.

There is no execution path: Northcause never runs commands or changes customer systems.

## Architecture

```
Browser ──HTTPS──▶ Cloudflare Worker (Hono, server-rendered JSX, strict CSP, no client JS)
                     ├── D1  (tenants, users, sessions, incidents, evidence metadata, timeline,
                     │        investigations, claims, citations, drafts, approvals, checks, audit)
                     ├── R2  (redacted evidence text)
                     ├── optional ─▶ external model endpoint (opt-in, redacted input)
                     └── optional ─▶ GitHub REST API (GET only)
Cron (hourly) ──▶ retention sweep
```

Bindings and setup: [docs/DEPLOY.md](docs/DEPLOY.md).

## Quick start (local)

```bash
npm ci
npm run db:migrate:local
npm run dev        # http://127.0.0.1:8787 → "Try the sandbox"
```

## Checks

```bash
npm run typecheck
npm test           # vitest: auth, tenant isolation, CSRF, evidence validation, redaction,
                   # citations, providers, approvals, audit, retention, integrations, pages
npm run build      # wrangler deploy --dry-run
npm audit --omit=dev
```

## Layout

```
src/app.tsx              routes, middleware (headers, origin check, sessions, CSRF, errors)
src/services/            accounts, workflow (incidents → checks), report, sandbox, retention
src/lib/                 crypto, audit, rate limit, evidence validation, redaction, timeline
src/providers/           provider interface, local rules, external model, citation gate
src/integrations/        GitHub Actions read-only adapter
src/views/               JSX pages
migrations/              D1 schema
test/                    vitest suites (SQLite-backed D1 shim + in-memory R2)
docs/                    threat model, deployment
```
