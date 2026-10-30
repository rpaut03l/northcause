# NorthCause product blueprint

Status: product proposal for discovery, not a description of shipped capability. Reviewed 31 October 2026.

## Position

Help teams investigate an AI production incident, connect it to the relevant evidence, and verify a candidate fix before release. Start with RAG groundedness regressions after prompt, model, retrieval-index, or deployment changes.

NorthCause is an evidence and release-assurance layer across existing tools. It should not claim universal early detection, autonomous root-cause certainty, or replacement of an observability stack.

## Customer gap and competitor boundary

Tracing, evaluation, security testing, incident response, and monitoring products are established categories. Datadog provides AI agent observability and investigation; Langfuse provides tracing, prompt management, evaluation, and an open-source path; Phoenix provides open-source AI observability and evaluation. NorthCause's hypothesis is that customers still manually preserve the links from incident evidence to reviewed regression cases and approved releases across vendor boundaries.

Sources to validate during discovery:

- NIST AI 800-4, deployed AI monitoring challenges: https://doi.org/10.6028/NIST.AI.800-4
- Grafana Labs Observability Survey 2025: https://grafana.com/observability-survey/2025/
- OpenTelemetry GenAI conventions: https://opentelemetry.io/docs/specs/semconv/registry/attributes/gen-ai/
- Langfuse pricing: https://langfuse.com/pricing
- LangSmith pricing: https://www.langchain.com/pricing
- Datadog Agent Observability: https://www.datadoghq.com/products/ai/agent-observability/
- Arize pricing and Phoenix: https://arize.com/pricing

Do not infer missing competitor features from absent website copy. Pricing, deployment, funding, and customer complaints require date-stamped vendor or primary-source verification.

## Product pillars

1. **Evidence-backed investigation.** Rank hypotheses; attach the exact trace, log, metric, change, or evaluation result; expose contradictory evidence and uncertainty; allow inconclusive outcomes.
2. **Incident-derived replay.** Convert reviewed production failures into versioned evaluation cases. Compare baseline and candidate on named, task-specific evaluators.
3. **Human-gated remediation.** Suggest a code/configuration change, run it in an isolated replay or canary, require a named approval, and preserve rollback instructions. Never mutate a customer production system by default.
4. **Proof record.** Preserve incident, evidence hashes, dataset/evaluator versions, results, reviewer, approval time, deployment reference, and export signature. A report supports assurance work; it does not itself certify compliance.
5. **Privacy and control.** Redact before persistence; keep prompt/body capture opt-in; support BYO model or local analysis; never train on customer content without a separate explicit agreement.
6. **Integrations.** Use OpenTelemetry as a portable telemetry input. Add GitHub/GitLab, Kubernetes, model registry, prompt, vector index, and evaluation adapters in response to pilot demand.

## Explicitly deferred

- 24/7 AI SOS hotline, emergency response SLA, and automatic kill switches until NorthCause has staffed operations and tested customer controls.
- Generic autonomous remediation, unattended production changes, and unsubstantiated “15-minute RCA” promises.
- Reimplementing all model evaluation, AI security, infrastructure monitoring, or governance products.
- Compliance certification or legal conclusions.

## User stories and success measures

- As an on-call engineer, I want the likely cause linked to source evidence, so I can verify the claim rather than trust a summary.
- As an AI engineer, I want a reviewed failure added to a repeatable dataset, so the next prompt or model change is tested against it.
- As a release owner, I want before/after results and a named reviewer, so a release decision is defensible.
- As a CISO, I want data-flow, retention, and access boundaries, so incident analysis does not silently export sensitive prompts.
- Pilot measures: time to assemble evidence, fraction of hypotheses with inspectable support, replay repeatability, useful regressions caught, false-positive rate, reviewer acceptance, and weekly active use.

## Data model

| Entity | Minimum fields |
|---|---|
| Tenant / Project | id, region, policy, retention, owner |
| Service | id, project_id, environment, deployment identifiers |
| Trace / Span | trace_id, parent_id, service, timestamps, semantic attributes, redaction state |
| Incident | id, service_id, impact, severity, start/end, status |
| Evidence | id, incident_id, source, reference, content hash, capture time, sensitivity labels |
| CauseHypothesis | incident_id, statement, confidence, evidence refs, counterevidence, status |
| Eval / EvalCase | dataset version, expected behavior, labels, source incident, reviewer |
| FixProposal | change ref, scope, risk, rollback, approver, state |
| Verification | candidate version, evaluator version, before/after metrics, gate result |
| ProofRecord | linked object versions, actor, timestamp, signature, export digest |
| Policy / Attack / CostEvent | future modules; policy decision, red-team run, per-request cost attribution |

## API and integration outline

```text
POST /v1/otlp/v1/traces
POST /v1/incidents
POST /v1/incidents/{incident_id}/evidence-refs
POST /v1/incidents/{incident_id}/hypotheses
POST /v1/incidents/{incident_id}/eval-cases
POST /v1/incidents/{incident_id}/replays
GET  /v1/replays/{replay_id}
POST /v1/fixes/{fix_id}/approval
POST /v1/fixes/{fix_id}/verification
GET  /v1/proofs/{proof_id}/export
```

Start with authenticated, tenant-scoped, read-only ingestion. Enforce request/body limits, content-type and schema validation, secret/PII handling, idempotency, rate limits, and explicit retention before accepting customer telemetry.

## Proposed architecture

- Python 3.11+ and FastAPI API/control plane.
- OpenTelemetry Collector for customer-side collection and redaction; do not make NorthCause a mandatory telemetry vendor.
- PostgreSQL for tenant, incident, policy, and workflow metadata.
- ClickHouse or a managed columnar store for high-volume spans after load testing. Keep object storage for opted-in evidence payloads with lifecycle controls.
- Redis plus a durable job queue for replay/report tasks; use idempotent workers.
- `pgvector` only for runbook/incident retrieval if pilot results show the need.
- Start as a modular monolith. Split ingestion and replay workers only when throughput or isolation requirements justify it.
- Deployment path: local Docker Compose, then Helm for customer VPC/on-prem pilots. Cloudflare Pages remains a static visual preview, not the interactive Python runtime.

## Pricing hypothesis

| Plan | Proposed list price | Concept |
|---|---:|---|
| Free / self-host | $0 | One project, bounded local replay, community support |
| Team | $299/month or ₹24,999/month | A few services, shared review, bounded replay usage |
| Business | $1,500/month or ₹1.25 lakh/month | More services, audit export, advanced retention and identity as delivered |
| Enterprise | Custom | Private deployment, support, residency, connector scope |
| SOS retainer | Future, test $2,000/month plus per incident | Only after staffing and SLA definition |
| Assurance exports | Future, test $500/month | Evidence mapping/export, not certification |

These are interview anchors, not active offers. BYO model keys and quotas help bound variable evaluator costs. Measure storage, compute, support, and model costs before making margin claims.

## 12-month delivery sequence

| Weeks | Goal |
|---|---|
| 1-2 | Customer interviews and one incident class |
| 3-4 | Threat model, redaction policy, data model |
| 5-6 | Python RAG example and OpenTelemetry instrumentation |
| 7-8 | OTLP ingestion prototype and version correlation |
| 9-10 | Reviewed dataset and evaluator versioning |
| 11-12 | Quality, latency, and error regression signals |
| 13-14 | Evidence timeline and change links |
| 15-16 | Ranked, source-linked hypotheses with inconclusive state |
| 17-18 | Incident-to-eval case creation |
| 19-20 | Paired replay and threshold hold |
| 21-22 | Git provider check integration, no production write access |
| 23-24 | Signed proof bundle prototype |
| 25-26 | Security and load review |
| 27-28 | First design partner pilot |
| 29-32 | Measure quality, false positives, adoption, and support costs |
| 33-36 | Add one requested adapter and role controls |
| 37-40 | Threat-test evidence injection and canary workflow |
| 41-44 | Pricing interviews and next partner pilots |
| 45-48 | Retention, residency, reliability hardening |
| 49-52 | Publish permissioned outcomes; choose next vertical based on usage |

## Legal and standards note

Regulatory mapping is time-sensitive and use-case-specific. As of 31 October 2026, EU high-risk dates are not universally 2 August 2026; the European Commission lists later deadlines for Annex III and regulated-product systems. India DPDP Rules have phased commencement. MAS issued AI risk-management guidelines in October 2026, with staged effective dates in 2027 and 2028. Obtain counsel for classification and obligations; build configurable evidence capture, not a legal-compliance guarantee.
