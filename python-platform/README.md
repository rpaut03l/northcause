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

Public product/security/docs/pricing/contact pages, login/admin provisioning, incident create/list/detail, bounded UTF-8 text evidence uploads, simple secret redaction, rule-based investigation with exact evidence line references, human-reviewed remediation drafts, audit events, admin contact inbox/deletion.

The analyser is deterministic rules, not an LLM. No external model call, GitHub integration, OpenTelemetry ingestion, automatic production changes, tenant provisioning UI, billing, or MFA/SSO is implemented in this parallel slice. Do not use customer data until security review and deployment-specific storage/auth controls are complete.

## Cloudflare direction

Cloudflare now supports Python Workers and FastAPI via `workers` ASGI integration. Port SQLite/file persistence to D1/R2 bindings, replace local session/storage implementations with binding-backed services, add `python_workers` compatibility flag, and run via `uv run pywrangler dev`. Do not deploy this local SQLite configuration directly.
