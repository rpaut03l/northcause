# NorthCause

NorthCause helps teams investigate AI production incidents, connect them to relevant evidence, and verify a fix before release.

The local Python pilot now includes Reliability Replay: a small, deterministic paired check that compares candidate outputs with reviewed expected/baseline examples and holds regressions before release review. It is a first vertical slice, not an AI diagnosis engine or live telemetry integration.

The product direction, customer gap hypothesis, architecture, pricing assumptions, and delivery roadmap are documented in [`docs/northcause-product-blueprint.md`](docs/northcause-product-blueprint.md). This is a proposal and is not a description of shipped integrations.

NorthCause is a product of **Narmadya Innovations Pvt Ltd**. Visit the parent company at [narmadya.com](https://narmadya.com/).

Public brand, browser-tab, and social-sharing behavior—including the NorthCause.com canonical URL, WhatsApp share action, and 1200 × 630 preview image—is documented in [`docs/brand-and-sharing.md`](docs/brand-and-sharing.md).

This repository includes a standalone Python/FastAPI pilot under [`python-platform/`](python-platform/README.md). The public pages explain the workflow; the local workspace supports incident records, development/staging/production context, bounded text evidence uploads, deterministic evidence scanning, human-reviewed remediation drafts, and an audit view.

## Run locally

Requires Python 3.11 or later.

```bash
cd python-platform
python3.11 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip setuptools wheel
python -m pip install -e '.[test]'
python -m pytest -q
python create_user.py admin@example.com
uvicorn app.main:app --reload --host 127.0.0.1 --port 8888
```

Open `http://127.0.0.1:8888`. The `/demo` route is read-only and uses fictional records.

## GitHub and Cloudflare preview

GitHub Actions runs the Python tests for pull requests and builds a static Cloudflare Pages preview of the public pages. The preview is for visual review only. Sign-in, incident creation, evidence uploads, and account actions require the local FastAPI server.

To enable automatic Pages preview deployments, create a Cloudflare Pages project and add these repository settings:

- Secret `CLOUDFLARE_API_TOKEN`
- Secret `CLOUDFLARE_ACCOUNT_ID`
- Variable `CLOUDFLARE_PAGES_PROJECT` with the Pages project name
- Variable `CLOUDFLARE_PAGES_PREVIEW` set to `true`

The deployment job remains skipped until the preview variable is enabled. This keeps local SQLite and file-based pilot data out of Cloudflare.

## Pilot boundaries

- Analysis is deterministic local pattern matching, not an LLM diagnosis. Findings are hypotheses with source references.
- Evidence is stored locally in SQLite and local files. Common secret-like patterns are masked, but masking is not a complete secret detector.
- This pilot has account sign-in and per-account incident scoping, but no organization/tenant administration, SSO, MFA, or billing.
- This branch adds opt-in OTLP JSON ingestion, signed GitHub push/deployment webhooks, optional customer-configured semantic judging, Ed25519 replay proof records, and a user-authenticated SOS intake. See [`docs/live-integrations.md`](docs/live-integrations.md) for configuration and data boundaries.
- Remediation is a human-reviewed draft. NorthCause does not run commands or modify customer systems.
- SOS intake is not staffed, does not provide a response SLA, and does not perform automatic containment. The Cloudflare Pages artifact remains a static visual preview; it does not host FastAPI or the integration API. Do not deploy the Python service as a customer-facing interactive service or upload sensitive production data without a separate security and hosting review.

See [`python-platform/README.md`](python-platform/README.md) for setup and implementation details.
