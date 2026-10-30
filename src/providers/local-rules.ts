import type {
  InvestigationInput,
  InvestigationProvider,
  ProviderClaim,
  ProviderCitation,
  ProviderResult,
} from './types';

/**
 * Local rule-based provider. It is NOT an AI model: it matches known failure signatures in
 * the uploaded evidence and cites the exact lines it matched. Used for development, demo and
 * for tenants who have not opted in to an external model.
 */
interface Rule {
  id: string;
  category: string;
  pattern: RegExp;
  statement: string;
  remediation: { title: string; steps: string[] };
}

const RULES: Rule[] = [
  {
    id: 'oom-kill',
    category: 'kubernetes',
    pattern: /\b(OOMKilled|out of memory|exit code 137|Killed process \d+)\b/i,
    statement: 'Containers were killed for exceeding memory limits (OOMKilled / exit 137).',
    remediation: {
      title: 'Right-size memory for the affected workload',
      steps: [
        'Compare the container memory limit with observed peak usage from the cited window.',
        'If a recent change raised memory use, consider rolling back that change first.',
        'Otherwise raise the limit or reduce in-process caching, then redeploy through your normal pipeline.',
        'Upload post-fix logs or events covering at least one full traffic peak.',
      ],
    },
  },
  {
    id: 'crashloop',
    category: 'kubernetes',
    pattern: /\b(CrashLoopBackOff|Back-off restarting failed container)\b/i,
    statement: 'Pods entered CrashLoopBackOff; the new revision fails during start-up.',
    remediation: {
      title: 'Restore a healthy revision and fix start-up',
      steps: [
        'Check the first error logged by the failing container after the cited deploy event.',
        'If the failure started with a release, roll back to the last healthy revision via your normal pipeline.',
        'Fix the start-up error (config, missing secret reference, migration order) and redeploy.',
        'Upload post-fix pod events showing stable restarts count.',
      ],
    },
  },
  {
    id: 'gpu-oom',
    category: 'gpu',
    pattern: /(CUDA out of memory|torch\.cuda\.OutOfMemoryError|CUBLAS_STATUS_ALLOC_FAILED|NVML[^\n]{0,200}(memory|Xid))/i,
    statement: 'GPU memory was exhausted during inference or training.',
    remediation: {
      title: 'Reduce GPU memory pressure',
      steps: [
        'Check batch size, max sequence length and KV-cache settings changed near the cited window.',
        'Lower batch size or max tokens, or move the model to a GPU with more memory.',
        'Confirm only one model process is pinned to the affected GPU.',
        'Upload post-fix inference logs covering a comparable load.',
      ],
    },
  },
  {
    id: 'http-5xx',
    category: 'application',
    pattern: /\b(HTTP\/\d(\.\d)? 5\d\d|status[=: ]{1,5}5\d\d|\b50[234] (Bad Gateway|Service Unavailable|Gateway Timeout))/i,
    statement: 'The service returned elevated 5xx responses.',
    remediation: {
      title: 'Stop the 5xx source',
      steps: [
        'Identify the first 5xx in the cited lines and the dependency or handler it came from.',
        'If it lines up with a deploy, roll back; otherwise fix or fail over the failing dependency.',
        'Upload post-fix access logs for the same routes.',
      ],
    },
  },
  {
    id: 'timeout',
    category: 'dependency',
    pattern: /\b(timed out|timeout exceeded|deadline exceeded|context deadline exceeded|ETIMEDOUT)\b/i,
    statement: 'Calls to a dependency timed out.',
    remediation: {
      title: 'Address dependency latency',
      steps: [
        'Find which dependency the cited timeouts point to and check its health in the same window.',
        'Review timeout and retry settings; avoid retry storms with backoff and jitter.',
        'Upload post-fix logs for the same call path.',
      ],
    },
  },
  {
    id: 'conn-refused',
    category: 'dependency',
    pattern: /\b(connection refused|ECONNREFUSED|no route to host|dial tcp [^\n]{0,200}connect: )/i,
    statement: 'A dependency refused connections or was unreachable.',
    remediation: {
      title: 'Restore connectivity to the dependency',
      steps: [
        'Confirm the target host and port from the cited lines and whether the dependency was running.',
        'Check recent network policy, security group or service discovery changes.',
        'Upload post-fix logs showing successful connections.',
      ],
    },
  },
  {
    id: 'rate-limit',
    category: 'llm-provider',
    pattern: /\b(429 Too Many Requests|status[=: ]{1,5}429|rate limit(ed)?|RateLimitError|quota exceeded)\b/i,
    statement: 'Requests were throttled by an upstream API or model provider (HTTP 429 / quota).',
    remediation: {
      title: 'Reduce or shape upstream request volume',
      steps: [
        'Check request volume and concurrency against the provider quota for the cited window.',
        'Add client-side rate limiting, backoff with jitter, and request queueing.',
        'Request a quota increase if sustained demand needs it.',
        'Upload post-fix logs showing no throttling at comparable load.',
      ],
    },
  },
  {
    id: 'tls-expired',
    category: 'security',
    pattern: /\b(certificate has expired|x509: certificate|CERT_HAS_EXPIRED|SSL certificate problem)\b/i,
    statement: 'TLS certificate validation failed (expired or untrusted certificate).',
    remediation: {
      title: 'Renew or correct the certificate',
      steps: [
        'Identify the endpoint and certificate from the cited lines.',
        'Renew or replace the certificate and confirm the full chain is served.',
        'Add expiry monitoring for this certificate.',
        'Upload post-fix logs showing successful TLS handshakes.',
      ],
    },
  },
  {
    id: 'disk-full',
    category: 'linux',
    pattern: /\b(No space left on device|ENOSPC|disk quota exceeded)\b/i,
    statement: 'A filesystem ran out of space.',
    remediation: {
      title: 'Free and protect disk space',
      steps: [
        'Identify the volume from the cited lines and what filled it (logs, temp files, model caches).',
        'Free space safely and add log rotation or cache limits.',
        'Upload post-fix logs or df output.',
      ],
    },
  },
  {
    id: 'rag-retrieval',
    category: 'rag',
    pattern: /\b(retrieved 0 (documents|chunks)|no documents (were )?retrieved|empty context|embedding dimension mismatch|index not found)\b/i,
    statement: 'The RAG pipeline returned no or invalid retrieval context.',
    remediation: {
      title: 'Restore retrieval quality',
      steps: [
        'Check whether the embedding model or index changed near the cited window (dimension or version mismatch).',
        'Re-index with the matching embedding model, or roll back the embedding change.',
        'Run your retrieval evaluation set and upload the results as post-fix evidence.',
      ],
    },
  },
  {
    id: 'ci-failure',
    category: 'ci-cd',
    pattern: /(##\[error\]|Process completed with exit code [1-9]|\b\d+ (tests? )?failed\b|FAILED \S{1,200}::)/i,
    statement: 'A CI/CD job failed (non-zero exit or failing tests).',
    remediation: {
      title: 'Fix the failing pipeline step',
      steps: [
        'Open the first failing step in the cited log lines.',
        'Reproduce locally with the same commit and dependency lockfile.',
        'Fix the cause; do not skip or quarantine the test without an owner and a date.',
        'Upload the post-fix CI log.',
      ],
    },
  },
];

const RISK_RULES: Array<{ category: string; pattern: RegExp; statement: string }> = [
  {
    category: 'prompt_injection',
    pattern: /ignore (all |any )?(previous|prior|above) (instructions|prompts?)|disregard (the )?(system|previous)|you are now (a|an|in) |<[ \t]{0,5}\/?[ \t]{0,5}system[ \t]{0,5}>/i,
    statement: 'Evidence contains text that looks like instructions to an AI system. It was treated as data only; review the source for prompt-injection attempts.',
  },
  {
    category: 'secret_exposure',
    pattern: /\[REDACTED:[a-z_]+\]/,
    statement: 'Secrets or sensitive values appeared in the uploaded evidence and were redacted. Rotate any real credentials that were logged.',
  },
  {
    category: 'policy_privileged_container',
    pattern: /\bprivileged:[ \t]{0,10}true\b|--privileged\b/i,
    statement: 'A privileged container configuration appears in the evidence.',
  },
  {
    category: 'policy_public_exposure',
    pattern: /\b0\.0\.0\.0\/0\b|allUsers|public-read|allow-unauthenticated/i,
    statement: 'Configuration in the evidence suggests public network or storage exposure.',
  },
  {
    category: 'policy_mutable_image_tag',
    pattern: /image:[ \t]{0,10}\S{1,300}?:latest\b/i,
    statement: 'A mutable ":latest" image tag is used, which weakens release traceability.',
  },
];

const MAX_CITATIONS = 5;

// Lines are truncated before matching so pathological inputs cannot blow up regex time.
export const MAX_MATCH_LINE = 4000;

function findLines(text: string, re: RegExp): Array<{ lineNo: number; line: string }> {
  const out: Array<{ lineNo: number; line: string }> = [];
  text.split(/\r?\n/).forEach((line, i) => {
    if (re.test(line.slice(0, MAX_MATCH_LINE))) out.push({ lineNo: i + 1, line });
  });
  return out;
}

export const localRulesProvider: InvestigationProvider = {
  id: 'local-rules',
  label: 'Local rule-based analysis (not an AI model)',
  external: false,

  async investigate(input: InvestigationInput): Promise<ProviderResult> {
    const incidentEvidence = input.evidence.filter((e) => e.phase === 'incident');
    const claims: ProviderClaim[] = [];

    // Earliest deploy event, used to correlate error onset with a change.
    const deploys = input.timeline.filter((t) => t.kind === 'deploy').sort((a, b) => a.occurredAt.localeCompare(b.occurredAt));

    const scored: Array<{ claim: ProviderClaim; score: number }> = [];
    for (const rule of RULES) {
      const citations: ProviderCitation[] = [];
      let hits = 0;
      for (const ev of incidentEvidence) {
        for (const m of findLines(ev.text, rule.pattern)) {
          hits++;
          if (citations.length < MAX_CITATIONS) citations.push({ evidenceId: ev.id, lineNo: m.lineNo });
        }
      }
      if (hits === 0) continue;

      let statement = rule.statement;
      let correlated = false;
      const firstHit = input.timeline
        .filter((t) => citations.some((c) => c.evidenceId === t.evidenceId && c.lineNo === t.lineNo))
        .sort((a, b) => a.occurredAt.localeCompare(b.occurredAt))[0];
      const priorDeploy = firstHit ? [...deploys].reverse().find((d) => d.occurredAt <= firstHit.occurredAt) : undefined;
      if (firstHit && priorDeploy) {
        const minutes = Math.round((Date.parse(firstHit.occurredAt) - Date.parse(priorDeploy.occurredAt)) / 60000);
        if (minutes <= 60) {
          correlated = true;
          statement += ` First seen ${minutes} min after a deploy/change event.`;
          citations.push({ evidenceId: priorDeploy.evidenceId, lineNo: priorDeploy.lineNo });
        }
      }

      const confidence: ProviderClaim['confidence'] = hits >= 3 && correlated ? 'high' : hits >= 2 ? 'medium' : 'low';
      scored.push({
        score: hits + (correlated ? 10 : 0),
        claim: {
          kind: 'hypothesis',
          category: rule.category,
          statement,
          confidence,
          citations,
          signalPatterns: [{ type: 'regex', value: rule.pattern.source }],
          remediation: rule.remediation,
        },
      });
    }
    scored.sort((a, b) => b.score - a.score);
    claims.push(...scored.map((s) => s.claim));

    for (const risk of RISK_RULES) {
      const citations: ProviderCitation[] = [];
      for (const ev of input.evidence) {
        for (const m of findLines(ev.text, risk.pattern)) {
          if (citations.length < MAX_CITATIONS) citations.push({ evidenceId: ev.id, lineNo: m.lineNo });
        }
      }
      if (citations.length) {
        claims.push({ kind: 'risk', category: risk.category, statement: risk.statement, confidence: 'medium', citations });
      }
    }

    const hypotheses = claims.filter((c) => c.kind === 'hypothesis');
    const insufficientEvidence = hypotheses.length === 0;
    const notes = insufficientEvidence
      ? 'Insufficient evidence: no known failure signature matched the uploaded incident evidence. Add logs from around the start time, deploy history, or metrics exports. Northcause does not guess at failures it cannot see.'
      : `${hypotheses.length} hypothesis(es) matched known failure signatures. Ranking uses match count and proximity to deploy events; it is not a probability.`;
    return { claims, insufficientEvidence, notes };
  },
};
