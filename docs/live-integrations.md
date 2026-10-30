# NorthCause live integration pilot

Status: working integration foundations for the local FastAPI pilot. These connectors are not enabled on the static Cloudflare Pages preview.

## OpenTelemetry OTLP/HTTP JSON

Set a high-entropy bearer token in the FastAPI runtime, then configure an OpenTelemetry Collector or SDK exporter to send OTLP JSON to `POST /api/otel/v1/traces`.

```bash
export NORTHCAUSE_OTEL_INGEST_TOKEN="replace-with-a-long-random-secret"
```

The endpoint accepts OTLP JSON batches up to 2 MiB and 1,000 spans. It stores span/trace IDs, service/environment, timestamps, duration, status, and a small allowlist of attributes. Prompt, completion, request/response body, message, and content attributes are discarded. Filter sensitive attributes in the collector too. The endpoint currently uses one deployment-wide token. Set `NORTHCAUSE_INTEGRATION_OWNER_EMAIL` to the single account allowed to view these integration signals; this pilot does not support multiple customer workspaces or per-tenant tokens.

## GitHub push and deployment webhooks

Create a GitHub repository webhook targeting `https://<your-api-host>/api/integrations/github/webhook`, select a long random secret, and enable `push` plus `deployment_status` events. Configure that exact secret in the FastAPI runtime:

```bash
export NORTHCAUSE_GITHUB_WEBHOOK_SECRET="replace-with-a-long-random-secret"
```

GitHub's `X-Hub-Signature-256` is verified before metadata is accepted. NorthCause stores delivery ID, event, repository, ref, commit SHAs, environment, and deployment state. Payloads are not retained; delivery IDs are idempotent. This is read-only correlation. It does not create commits, branches, or pull requests.

Set `NORTHCAUSE_GITHUB_REPOSITORY=owner/repository` to expose matching change metadata in an incident's previous-24-hour signals view. Each incident also shows spans matched on service, environment, and time window. These are contextual correlations, not causal conclusions.

## Semantic evaluation

The endpoint `POST /api/evaluations/semantic` requires an authenticated NorthCause session and accepts up to 20 cases (each with `criteria`, `expected`, and `candidate`). It is disabled until the operator deliberately configures an OpenAI-compatible chat-completions endpoint and API key:

```bash
export NORTHCAUSE_SEMANTIC_JUDGE_URL="https://your-approved-provider.example/v1/chat/completions"
export NORTHCAUSE_SEMANTIC_JUDGE_API_KEY="your-provider-key"
export NORTHCAUSE_SEMANTIC_JUDGE_MODEL="your-approved-model"
```

Evaluation text is sent to the configured endpoint for scoring. NorthCause stores only aggregate counts and scores, not case text. The provider may retain requests under its own terms. HTTPS is required except for local development endpoints. A model judge is a heuristic; use reviewed examples and independent safety checks, not a single model score, as a release gate.

## Signed proof records

Every paired exact-match replay now produces a canonical JSON proof with the replay summary, source file SHA-256, previous ledger hash, and Ed25519 signature. The raw JSONL evaluation cases are not included. A local key is created under `NORTHCAUSE_DATA` with owner-only file permissions. Back it up securely for local use. Production must set a durable Ed25519 private key in `NORTHCAUSE_PROOF_PRIVATE_KEY` (PEM, with newlines) before startup; production intentionally refuses to create an ephemeral key.

Authenticated report export: `GET /api/proofs/{proof_id}`. Signature verification: `GET /api/proofs/{proof_id}/verify`. Verification establishes the integrity of the record against its embedded public key. Independently pin the public-key fingerprint through a trusted deployment channel if you need to establish signer identity.

## SOS intake and remediation boundary

`POST /api/sos` requires a signed-in user and creates a high/critical incident with a redacted summary. The incident page can create a deterministic, evidence-linked playbook draft for supported findings; a reviewer must approve or reject it. This pilot does not create a GitHub PR or change customer code or infrastructure. SOS intake does not offer staffed response, notifications, an SLA, or automatic kill switches. The webhook and intake APIs are not a substitute for a production response/on-call service.

## Local run

```bash
cd python-platform
python -m pip install -e '.[test]'
python -m pytest -q
uvicorn app.main:app --reload --host 127.0.0.1 --port 8888
```

## Cloudflare preview

The current Cloudflare Pages artifact is a **static visual preview** of public routes. It does not run FastAPI, SQLite, the OTLP receiver, semantic judge, webhook handler, proof signer, or SOS endpoint. For branch previews, configure GitHub repository variables `CLOUDFLARE_PAGES_PREVIEW=true` and `CLOUDFLARE_PAGES_PROJECT=<Pages project>` plus secrets `CLOUDFLARE_API_TOKEN` and `CLOUDFLARE_ACCOUNT_ID`. PR builds deploy to a `pr-<number>` Pages preview branch and do not target the production branch or a custom domain.

The preview job is intentionally skipped until those repository settings are present. The Pages project and credentials are account-specific and are not available in the source tree; the repository owner must add them in GitHub Settings. The running Python integration API needs a separate ASGI-capable host and database; static Pages cannot host this FastAPI service.
