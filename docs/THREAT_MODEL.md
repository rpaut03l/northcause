# Northcause pilot — threat model

Scope: the pilot web app and API (one Cloudflare Worker), D1 metadata, R2 evidence, optional external model endpoint, optional read-only GitHub Actions adapter. Status: pilot, not production-hardened. Last reviewed with the code in this branch.

## Assets

| Asset | Where | Why it matters |
|---|---|---|
| Customer evidence (logs, events, CI output) | R2, redacted text only | Can contain secrets, personal data, internal topology |
| Incident metadata, claims, approvals | D1 | Confidentiality between tenants; integrity of decisions |
| Audit trail | D1 `audit_events` | Accountability for approvals and data access |
| Session tokens, CSRF tokens | Cookie + D1 (SHA-256 of token) | Account takeover |
| Model API key, GitHub token | Worker secrets | Cost abuse, data exfiltration to provider account |

## Trust boundaries

1. Browser ↔ Worker (internet).
2. Worker ↔ D1 / R2 (Cloudflare bindings, trusted).
3. Worker ↔ external model endpoint (third party; only on opt-in).
4. Worker ↔ GitHub API (third party; read-only; only if a token is configured).
5. Evidence content and model output: **untrusted data** crossing into the app, even though they arrive through trusted channels.

## Threats and controls

| # | Threat | Control in code | Residual risk |
|---|---|---|---|
| T1 | Tenant B reads or changes tenant A's data by guessing IDs | Every query filters on `tenant_id` from the session (`src/services/workflow.ts`); IDs are 96-bit random; other-tenant IDs return 404. Tests: `test/auth-tenancy.test.ts`. | A future query that forgets the filter. Mitigation: code review checklist; consider D1 row-level helpers. |
| T2 | Malicious upload (binary, HTML, huge file, path traversal) | Extension + MIME allow-list, 2 MiB / 50k-line cap, NUL-byte and strict UTF-8 checks, JSON/NDJSON parse, 25 files per incident (`src/lib/evidence-validate.ts`). R2 keys built only from server IDs. Downloads are `text/plain` attachments with `nosniff`. | Large-but-valid files still consume CPU time for parsing; per-user upload rate limit (60/h). |
| T3 | Stored XSS via evidence, titles, model output | Server-side JSX escapes all text; CSP `script-src 'none'`; Markdown report escapes control characters. Tests: `test/evidence.test.ts`. | None known; CSP blocks script even if escaping regressed. |
| T4 | Prompt injection in evidence steers the model | Evidence fenced in `<evidence>` blocks, closing tags in data neutralised, system prompt states evidence is data; output parsed as JSON only; every citation re-verified against stored evidence; model citations must quote ≥ 12 characters of the cited line and may not cite injection-like lines; model `notes` are labelled unverified; no tools or actions available to the model. Injection-like lines are flagged to users as risks. | A model can still produce a wrong but cited hypothesis. Users see the cited lines and support label. |
| T5 | Model hallucinates causes or citations | `verifyClaims` drops citations whose evidence ID/line/excerpt do not match storage; uncited claims are "unsupported" with low confidence; no supported hypothesis ⇒ "insufficient evidence". Support is re-derived at read time, so deleting cited evidence turns a claim unsupported and blocks drafts from it. | Correct citation of an irrelevant line. Mitigation: human review before any draft is approved. |
| T6 | Secrets leak to the model provider or UI | Pattern redaction before storage (keys, tokens, JWTs, private keys, password assignments, URL credentials, emails, Luhn-valid card numbers), re-applied before model calls; external model off by default, admin opt-in + per-run consent. | Pattern redaction misses unknown formats (e.g. custom tokens, names, IPs). Documented to users. |
| T7 | Unauthorised or unattended remediation; weak "proof" | No execution path exists: drafts are text; approval only writes records; checks only read uploaded evidence. Admin role required to decide; reason required; single decision per draft. Checks count only post-fix evidence uploaded after the approval and need ≥ 3 non-empty lines, otherwise "inconclusive". | Users may still apply a bad change manually or upload unrepresentative post-fix evidence; report states checks are not guarantees. |
| T8 | ReDoS via regex on user data | Only server-defined regexes run on evidence, all with bounded quantifiers; lines are truncated to 4,000 characters before matching; model-supplied signals are stored as literals and matched with `includes`. A test runs crafted near-limit inputs under a time budget. | Low. |
| T9 | CSRF / cross-site actions (incl. login CSRF) | Per-session CSRF token on every workspace POST; every non-GET must carry a same-origin `Origin` or `Sec-Fetch-Site` header (requests with neither are refused); `SameSite=Strict` cookies. | Login/sandbox/contact rely on the header check rather than a token. |
| T10 | Session theft / fixation | `__Host-` cookie, HttpOnly, Secure, SameSite=Strict, 12 h TTL; only SHA-256 of the token stored; new token per login; logout deletes the session. | No idle timeout or device list yet. |
| T11 | Credential stuffing / brute force / lockout | PBKDF2-SHA256 (100k iterations, Workers max), constant-work check for unknown emails. Only failed attempts count: 10 per account+IP, 30 per IP, 100 per account per 15 min, so a third party cannot easily lock out a user. | No MFA/SSO yet. D1 fixed-window limiter is coarse; a distributed attacker can still exhaust the per-account cap. |
| T12 | Audit tampering | SQLite triggers reject UPDATE/DELETE on `audit_events`; per-tenant SHA-256 hash chain verified in the UI; `UNIQUE(tenant_id, prev_hash)` plus retry stops concurrent writers from forking the chain. Only the retention job may delete events of an expired sandbox. | Someone with direct D1 admin access can drop triggers; the chain then shows a break but cannot prove what changed. Ship events to external WORM storage before production. |
| T13 | Information leakage via errors/logs | Generic error pages with request ID; logs contain error class + short message only, never bodies, cookies, evidence or keys; provider errors not shown to users. | Third-party Worker logs retention depends on account settings. |
| T14 | Sandbox abuse (spam tenants, storage, jamming retention) | Sandbox off by default (`SANDBOX_ENABLED`); 5 sandboxes per IP per hour; 30 evidence files per sandbox (1,000 per pilot workspace); 24 h expiry; R2 deletes chunked to 1,000 keys and each tenant purged independently so one failure cannot stop the sweep. | Distributed abuse; add Turnstile before public launch. |
| T15 | Integration over-privilege / cross-tenant use of the shared token | GitHub adapter issues GET only; the operator token can be used only for repositories the operator allow-lists per workspace (`integrations` table); admin-only; never in sandboxes. UI shows "not connected" or "configured, unverified", never "connected". | Token scope is the operator's responsibility: use a fine-grained read-only token limited to pilot repos. Per-tenant tokens (GitHub App) needed before wider rollout. |
| T16 | Clickjacking / content sniffing | `frame-ancestors 'none'`, `X-Frame-Options: DENY`, `nosniff`, HSTS. | — |

## Retention and deletion

- Pilot evidence: deleted after `tenants.retention_days` (default 30) by the hourly cron; users and admins can delete evidence at any time; admins can delete whole incidents.
- Sandbox tenants: deleted completely (including audit events and R2 objects) after 24 h.
- Audit events for pilot tenants are kept (no evidence content inside).
- Contact messages are kept until deleted manually (no automatic purge yet).

## Known gaps before production

SSO/MFA, malware scanning of uploads, external immutable audit sink, per-tenant encryption keys, Turnstile on public forms, Workers Rate Limiting binding or Durable Objects for limits, contact message retention, DPA/sub-processor list for model providers, penetration test.
