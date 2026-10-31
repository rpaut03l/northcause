# NorthCause CLI, NorthCause AI CLI, and the customer portal

**Status:** early-access implementation foundation, not a production-hosted CLI service. Reviewed 31 October 2026.

NorthCause ships two command line entry points from one Python package:

| Name | Command | Default behavior | Uses an AI provider? |
|---|---|---|---|
| **NorthCause CLI** | `northcause` | Local, deterministic evidence and replay utilities; explicit OTLP push and health check | No |
| **NorthCause AI CLI** | `northcause-ai` | No request by default; drafts incident explanations, fix plans, or regression cases when explicitly enabled | Yes, BYO OpenAI-compatible endpoint |

Both tools are authored for the NorthCause product and share its evidence-first workflow. Names and commands are early-access working product names and can change before a public release.

## Install

Requires Python 3.11 or newer. From a checkout of this repository:

```bash
cd python-platform
python3.11 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e .
northcause --help
northcause-ai --help
```

The repository's regular test extra is separate: `python -m pip install -e ".[test]"`.

## NorthCause CLI command guide

### Create a local incident packet

```bash
northcause incident init \
  --title "RAG groundedness fell after prompt update" \
  --service answer-api --environment staging \
  --out incident.json
northcause incident add-evidence incident.json ./redacted-trace.json
northcause incident show incident.json
```

The manifest stores the evidence filename, byte length, and SHA-256 digest. It does not copy or upload the file. Keep the incident packet and referenced inputs in a controlled directory; do not attach customer evidence to a public issue or commit it to a repository.

### Fingerprint an evidence file

```bash
northcause evidence hash ./redacted-trace.json
```

NorthCause CLI reads at most 2 MiB for this command and prints a digest and size. A digest can show whether a file changed; it does not establish that the file is accurate or that a hypothesis is true.

### Run the deterministic paired replay

```bash
northcause replay run examples/replay-example.jsonl --threshold 90
```

Each non-empty JSONL record must have non-empty `expected`, `baseline`, and `candidate` strings. The tool compares exact strings after trimming whitespace, supports up to 1,000 cases, and emits counts, rates, gate, and input digest. Exit status is `0` for pass, `2` for hold, and `1` for invalid input or operational error. Exact match is a narrow regression signal; it is not a semantic quality, factuality, policy, privacy, or safety measurement.

### Check an API and send traces

```bash
export NORTHCAUSE_API_URL="https://api.example.com"
northcause doctor

export NORTHCAUSE_OTEL_INGEST_TOKEN="<token-from-your-operator>"
northcause otel send ./otlp-batch.json
```

`doctor` reads only `/healthz`. `otel send` posts a bounded JSON object containing `resourceSpans` to `/api/otel/v1/traces`. The token is read from the process environment and is never written to a NorthCause CLI config file. The current NorthCause pilot filters a narrow attribute allowlist and rejects prompt/completion/body content, but collector-side filtering is still recommended. Review data handling and your server configuration before sending production telemetry. This endpoint is a single configured pilot workspace; tenant-scoped connector credentials are not implemented.

### Verify a downloaded proof

```bash
northcause proof verify ./proof-record.json
```

NorthCause CLI calls the existing Ed25519 verification routine locally and reports validity, record hash, and key fingerprint. Keep the original signed file. A valid signature establishes integrity and signer-key possession for that record; it does not establish that the evidence is complete or a control framework requirement is satisfied.

## NorthCause AI CLI command guide

NorthCause AI CLI is optional. It is not the deterministic analyzer and does not claim causal certainty. It sends no model request unless both conditions are met:

1. The user supplies `--allow-evidence-egress` for that invocation.
2. An API base URL and key are available in the current process environment or flags.

Use HTTPS for remote endpoints. Plain HTTP is accepted only for localhost development. Keys are not written to project files or manifests.

```bash
export NORTHCAUSE_AI_BASE_URL="https://model-gateway.example.com/v1"
export NORTHCAUSE_AI_API_KEY="<your-key>"
export NORTHCAUSE_AI_MODEL="your-approved-model"

# Local-only readiness check; sends no request.
northcause-ai doctor

# Review the listed inputs and endpoint, then explicitly allow egress.
northcause-ai explain incident.json \
  --evidence ./redacted-trace.json \
  --allow-evidence-egress

northcause-ai draft-fix incident.json \
  --evidence ./redacted-trace.json \
  --allow-evidence-egress

northcause-ai eval-case incident.json \
  --evidence ./reviewed-failure.json \
  --allow-evidence-egress
```

The assistant sends only the supplied manifest and explicitly named evidence files, bounded to 48,000 characters total; individual inputs are bounded to 16,000 bytes. It applies basic pattern-based redaction for common key/token/password/secret formats, which can miss sensitive content. Review and redact files yourself. The model provider may retain request content under its own terms. For local inference, configure an OpenAI-compatible gateway on loopback and use its local URL; do not expose an unauthenticated local endpoint to an untrusted network.

The prompt treats evidence as untrusted data and asks for source references, counterevidence, missing signals, risks, tests, and rollback. This is defense-in-depth, not a guarantee against prompt injection or model mistakes. Output is always labeled draft-only. NorthCause AI CLI does not run shell commands, modify a repository, apply a change, approve a release, deploy, or contact an on-call responder.

## Environment variables

| Variable | Used by | Required for | Stored by CLI? |
|---|---|---|---|
| `NORTHCAUSE_API_URL` | NorthCause CLI | Optional default API origin; defaults to local `127.0.0.1:8888` | No |
| `NORTHCAUSE_OTEL_INGEST_TOKEN` | NorthCause CLI | Explicit OTLP push | No |
| `NORTHCAUSE_AI_BASE_URL` | NorthCause AI CLI | Optional OpenAI-compatible endpoint base | No |
| `NORTHCAUSE_AI_API_KEY` | NorthCause AI CLI | Optional model request | No |
| `NORTHCAUSE_AI_MODEL` | NorthCause AI CLI | Optional model name; defaults to `gpt-4o-mini` | No |

Environment variables are inherited by child processes. Use your organization's approved secret manager or shell mechanism and avoid shell history when setting credentials.

## Customer access and portal boundary

The customer sign-in is `/login`; the authenticated workspace starts at `/app`. Pilot accounts remain provisioned by an administrator. `/signup` is a **workspace-access request**, not password-based self-registration: it collects a name, work email, organization, and optional short message, then stores the request in the existing administrator contact inbox. It does not collect passwords, send verification email, create a user, or grant access. Repeated requests from the same email are suppressed for 15 minutes. The page links back to `/login` and lists `hello@narmadya.com` as the NorthCause contact and headquarters as Jabalpur, Madhya Pradesh, India.

The FastAPI app uses its existing SQLite pilot store for these requests. The public Cloudflare Pages artifact renders `/signup` as a visual preview and intercepts the form; it does **not** submit or persist the request. Do not enter real contact data in the static preview. The current implementation still does not provide self-service credentials, email verification, password reset, SSO/MFA, organization membership, billing, or user-managed API keys.

## Browser shell and paid-feature direction

`/cloud-shell` describes the planned browser workflow for `northcause` and `northcause-ai`, proposed Developer/Pro/Enterprise packaging, session profiles, usage estimates, and spend controls. The page is a product overview only: no web terminal, remote command execution, persistent shell volume, subscription, metering, or payment flow is deployed by this PR. Cloud Shell prices, entitlements, included usage, retention and idle limits remain unannounced and must be set after compute and support costs are validated.

The proposed first hosting shape is Cloudflare Workers as an authenticated session broker with Cloudflare Containers running a prebuilt Linux CLI image. Keep the container image portable and isolate it from the identity, billing, and evidence APIs so NorthCause can move the runtime to another provider later. This is an architecture direction, not a deployment. Before customer command execution, build and review per-user/container isolation, short-lived scoped credentials, network-egress policy, websocket authorization, resource quotas, idle shutdown, log redaction, persistence/deletion behavior, abuse controls, billing estimates/caps, and incident response. The `northcause-ai` command must retain its per-command `--allow-evidence-egress` guard even inside a hosted terminal.

## Cloudflare preview and deployment boundary

Cloudflare Pages serves the public site, product documentation, CLI product page, and clearly labeled visual previews of `/login`, `/signup`, and `/cloud-shell`. Static Pages does not run the Python FastAPI application, SQLite, evidence uploads, replay, authentication, signup requests, or a remote terminal. Its preview script intercepts every form and performs no authentication or data submission. Do not put passwords, tokens, customer data, or real workspace activity into the static preview.

When usage justifies moving the API, deploy the Python application on an HTTPS-capable host or container platform with durable database/object storage, managed secrets, backups, retention/deletion controls, tenant-scoped auth, rate limits, monitoring, and a reviewed data-residency design. Keep Cloudflare in front as the public edge if useful. Moving hosts will require migration and security work; it is not automatic just because the marketing site uses Cloudflare.

## Current feature boundary

| Available in this PR | Not delivered by this PR |
|---|---|
| Local incident packet and evidence fingerprints | Customer tenant management or multi-workspace credentials |
| Exact-match paired replay and local proof verification | Semantic guarantees or universal RCA |
| Health check and bounded OTLP push to existing pilot endpoint | General Git provider CLI, CI checks, or production change application |
| Optional BYO OpenAI-compatible NorthCause AI CLI drafts | NorthCause-hosted model, training on customer data, or staffed AI SOS |
| Sign-in and workspace-access request page with admin review | Self-service account/password creation, verification email, SSO/MFA |
| Cloud Shell product overview and commercial-plan concepts | Hosted shell runtime, subscription billing, metering, or spend enforcement |
| Static Cloudflare pages for the public overview and previews | Production Cloudflare authentication/API hosting or customer compute |

## Support and reporting

Before using production data, confirm the deployment's storage, backup, encryption, access, deletion, and retention controls with the operator. Report reproducible CLI issues through the repository issue tracker with synthetic examples only; never include tokens, prompts, customer traces, or unredacted logs.
