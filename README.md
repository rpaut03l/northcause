# NorthCause

NorthCause helps teams investigate AI production incidents, connect them to relevant evidence, and verify a fix before release.

This repository adds a standalone Python/FastAPI pilot under [`python-platform/`](python-platform/README.md), alongside the existing repository history. The public pages explain the workflow; the local workspace supports incident records, development/staging/production context, bounded text evidence uploads, deterministic evidence scanning, human-reviewed remediation drafts, and an audit view.

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

## Pilot boundaries

- Analysis is deterministic local pattern matching, not an LLM diagnosis. Findings are hypotheses with source references.
- Evidence is stored locally in SQLite and local files. Common secret-like patterns are masked, but masking is not a complete secret detector.
- This pilot has account sign-in and per-account incident scoping, but no organization/tenant administration, SSO, MFA, or billing.
- It does not include live OpenTelemetry, cloud, Kubernetes, GitHub Actions, model-provider, or CI/CD connectors. Evidence is uploaded manually.
- Remediation is a human-reviewed draft. NorthCause does not run commands or modify customer systems.
- This configuration is for local evaluation. Do not deploy it as a customer-facing service or upload sensitive production data without a separate security and deployment review.

See [`python-platform/README.md`](python-platform/README.md) for setup and implementation details.
