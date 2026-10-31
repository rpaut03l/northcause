# NorthCause Python parallel implementation

A local-first Python/FastAPI implementation using the NorthCause white, navy, and cobalt visual direction.

## Local setup

Requires Python 3.11+.

```bash
cd python-platform
python3.11 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip setuptools wheel
python -m pip install -e ".[test]"
python -m pytest -q
python create_user.py admin@example.com
uvicorn app.main:app --reload --host 127.0.0.1 --port 8888
```

Open http://127.0.0.1:8888. SQLite/evidence files live under `var/`; set `NORTHCAUSE_DATA`, `NORTHCAUSE_DB`, and `NORTHCAUSE_EVIDENCE` to override. Local cookie is not Secure for HTTP; switch Secure on behind HTTPS before any deployment.

The public `/demo` route is a read-only tour with fictional records; it needs no account and does not connect to live systems. To run the focused web checks, install the test extra and use `python -m pytest` from this directory.

## Included local workflows

Public product/security/docs/pricing/contact pages, login/admin provisioning, incident create/list/detail, bounded UTF-8 text evidence uploads, simple secret redaction, rule-based investigation with exact evidence line references, human-reviewed remediation drafts, audit events, admin contact inbox/deletion, and paired exact-match replay checks attached to incidents.

The Reliability Replay accepts UTF-8 JSONL with one object per line and non-empty string fields `expected`, `baseline`, and `candidate`. It compares exact-match rates, requires the candidate to meet the user-supplied threshold and not regress against baseline, and records only aggregate metrics plus the source file SHA-256. The input payload is evaluated in memory and is not stored. Start with [`examples/replay-example.jsonl`](examples/replay-example.jsonl). This exact-match check is separate from the optional semantic judge API documented in [`../docs/live-integrations.md`](../docs/live-integrations.md); neither score alone is a production safety guarantee.

See [`../docs/northcause-product-blueprint.md`](../docs/northcause-product-blueprint.md) for the proposed product scope, integration sequence, data model, deployment direction, pricing hypotheses, and roadmap. Proposal items are marked separately from current pilot capabilities.

## NorthCause CLI and NorthCause AI CLI CLI tools

The package exposes `northcause` for deterministic local workflows and `northcause-ai` for explicitly enabled, BYO-model drafts. From this directory run `python -m pip install -e .`, then use `northcause --help` and `northcause-ai --help`. Full setup, examples, data handling, limitations, customer access flow, and the Cloud Shell hosting boundary are in [`../docs/cli-and-portal.md`](../docs/cli-and-portal.md).

The deterministic analyzer remains rule-based. This branch adds opt-in OTLP/HTTP JSON intake, signed GitHub push/deployment webhooks, optional customer-configured semantic judging, Ed25519 replay proof records, and an authenticated SOS intake. GitHub integration is read-only, semantic evaluation is disabled until explicitly configured, and remediation remains human-approved draft guidance. The SOS intake is not staffed and does not provide a response SLA or automatic containment. Tenant provisioning, billing, MFA/SSO, automatic customer-system changes, and managed production operations are not implemented. Do not use customer data until security review and deployment-specific storage/auth controls are complete.

## GitHub and Cloudflare preview

GitHub Actions runs the Python test suite for pull requests and builds a static Cloudflare Pages preview of the public pages, including the signup-request and Cloud Shell product pages. The preview is for visual review only; sign-in, access-request submission, incident creation, evidence uploads, and account actions require the local FastAPI server. The Cloud Shell page is a roadmap overview, not a hosted terminal.

To enable preview deployments, create a Cloudflare Pages project and add repository secret `CLOUDFLARE_API_TOKEN`, secret `CLOUDFLARE_ACCOUNT_ID`, and repository variable `CLOUDFLARE_PAGES_PROJECT`. Set `CLOUDFLARE_PAGES_PREVIEW` to `true` to enable PR deployments. The workflow builds the preview with `python scripts/build_cloudflare_preview.py` and deploys it to a branch-specific Pages URL. The Cloudflare step is skipped until enabled. Only public routes are deployed; the FastAPI integration API is not hosted by the static Pages artifact.

See [`../docs/live-integrations.md`](../docs/live-integrations.md) for API setup, environment variables, data boundaries, proof signing, SOS limitations, and Cloudflare preview configuration.

This keeps the local SQLite and file-based pilot out of Cloudflare. Do not treat the static preview as a hosted interactive service.
