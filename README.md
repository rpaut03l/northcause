# NorthCause

NorthCause helps teams investigate AI production incidents, connect them to relevant evidence, and verify a fix before release.

The local Python pilot now includes Reliability Replay: a small, deterministic paired check that compares candidate outputs with reviewed expected/baseline examples and holds regressions before release review. It is a first vertical slice, not an AI diagnosis engine or live telemetry integration.

NorthCause is a product of **Narmadaya Innovations Pvt Ltd**. Visit the parent company at [narmadaya.com](https://narmadaya.com/).

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
- It does not include live OpenTelemetry, cloud, Kubernetes, model-provider, or CI/CD connectors. Evidence is uploaded manually.
- Remediation is a human-reviewed draft. NorthCause does not run commands or modify customer systems.
- This configuration is for local evaluation. Do not deploy it as a customer-facing interactive service or upload sensitive production data without a separate security and hosting review.

See [`python-platform/README.md`](python-platform/README.md) for setup and implementation details.
