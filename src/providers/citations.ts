import { detectInjection } from '../lib/redact';
import type { ProviderClaim, ProviderEvidence, SignalPattern } from './types';

export interface VerifiedCitation {
  evidenceId: string;
  lineNo: number | null;
  excerpt: string;
}

export interface VerifiedClaim {
  kind: 'hypothesis' | 'risk';
  category: string;
  statement: string;
  confidence: 'high' | 'medium' | 'low';
  support: 'supported' | 'uncertain' | 'unsupported';
  citations: VerifiedCitation[];
  signalPatterns: SignalPattern[];
  remediation?: { title: string; steps: string[] };
}

const MAX_STATEMENT = 600;
const MAX_EXCERPT = 240;

function clean(s: unknown, max: number): string {
  return typeof s === 'string' ? s.replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/g, '').trim().slice(0, max) : '';
}

/**
 * Server-side gate applied to EVERY provider's output, local or external.
 * - A citation counts only if its evidence ID belongs to this incident and its line exists.
 * - The excerpt shown to users is re-read from the stored evidence, never taken from the model.
 * - If a model supplies an excerpt, it must appear in the cited line (or anywhere in the file
 *   when no line is given), otherwise the citation is dropped.
 * - Claims with no valid citation are labelled "unsupported" and their confidence forced to low.
 * - Claims with valid citations but low confidence are labelled "uncertain".
 */
export interface VerifyOptions {
  /**
   * For model output: each citation must carry an excerpt of at least MIN_MODEL_EXCERPT
   * characters copied from the cited line, and may not point at a line that looks like an
   * instruction to an AI (such a line is evidence of an injection attempt, not of a cause).
   */
  untrustedProvider?: boolean;
}

export const MIN_MODEL_EXCERPT = 12;

export function verifyClaims(claims: ProviderClaim[], evidence: ProviderEvidence[], opts: VerifyOptions = {}): VerifiedClaim[] {
  const byId = new Map(evidence.map((e) => [e.id, e.text.split(/\r?\n/)]));
  const flagged = new Map(evidence.map((e) => [e.id, new Set(detectInjection(e.text).lines)]));
  const out: VerifiedClaim[] = [];
  for (const c of claims.slice(0, 30)) {
    const statement = clean(c.statement, MAX_STATEMENT);
    if (!statement) continue;
    const citations: VerifiedCitation[] = [];
    const seen = new Set<string>();
    for (const cit of (Array.isArray(c.citations) ? c.citations : []).slice(0, 10)) {
      const lines = byId.get(String(cit?.evidenceId));
      if (!lines) continue; // unknown or other tenant's evidence ID: dropped
      let lineNo = Number.isInteger(cit.lineNo) ? (cit.lineNo as number) : null;
      const modelExcerpt = clean(cit.excerpt, 400);
      if (opts.untrustedProvider && modelExcerpt.length < MIN_MODEL_EXCERPT) continue;
      let excerpt: string;
      if (lineNo !== null) {
        if (lineNo < 1 || lineNo > lines.length) continue;
        const line = lines[lineNo - 1]!;
        if (modelExcerpt && !line.includes(modelExcerpt)) continue;
        excerpt = line;
      } else {
        if (!modelExcerpt) continue;
        const idx = lines.findIndex((l) => l.includes(modelExcerpt));
        if (idx < 0) continue;
        lineNo = idx + 1;
        excerpt = lines[idx]!;
      }
      if (opts.untrustedProvider && flagged.get(String(cit.evidenceId))?.has(lineNo)) continue;
      const key = `${cit.evidenceId}:${lineNo ?? excerpt}`;
      if (seen.has(key)) continue;
      seen.add(key);
      citations.push({ evidenceId: String(cit.evidenceId), lineNo, excerpt: excerpt.slice(0, MAX_EXCERPT) });
    }
    const confidence = (['high', 'medium', 'low'] as const).includes(c.confidence) ? c.confidence : 'low';
    const support: VerifiedClaim['support'] =
      citations.length === 0 ? 'unsupported' : confidence === 'low' ? 'uncertain' : 'supported';
    out.push({
      kind: c.kind === 'risk' ? 'risk' : 'hypothesis',
      category: clean(c.category, 60) || 'general',
      statement,
      confidence: support === 'unsupported' ? 'low' : confidence,
      support,
      citations,
      signalPatterns: (c.signalPatterns ?? [])
        .filter((p) => p && (p.type === 'regex' || p.type === 'literal') && typeof p.value === 'string')
        .slice(0, 5)
        .map((p) => ({ type: p.type, value: p.value.slice(0, 200) })),
      remediation: c.remediation
        ? {
            title: clean(c.remediation.title, 160) || 'Remediation draft',
            steps: (Array.isArray(c.remediation.steps) ? c.remediation.steps : [])
              .map((s) => clean(s, 400))
              .filter(Boolean)
              .slice(0, 10),
          }
        : undefined,
    });
  }
  return out;
}
