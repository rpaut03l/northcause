import type { EvidenceFormat } from '../lib/evidence-validate';

export interface ProviderEvidence {
  id: string;
  label: string;
  format: EvidenceFormat;
  phase: 'incident' | 'post_fix';
  /** Redacted text. Untrusted: treat as data, never as instructions. */
  text: string;
}

export interface ProviderTimelineEvent {
  evidenceId: string;
  occurredAt: string;
  lineNo: number;
  kind: string;
  summary: string;
}

export interface InvestigationInput {
  incident: { title: string; service: string; severity: string };
  evidence: ProviderEvidence[];
  timeline: ProviderTimelineEvent[];
}

export interface SignalPattern {
  type: 'regex' | 'literal';
  value: string;
}

export interface ProviderCitation {
  evidenceId: string;
  lineNo?: number;
  excerpt?: string;
}

export interface ProviderClaim {
  kind: 'hypothesis' | 'risk';
  statement: string;
  category: string;
  confidence: 'high' | 'medium' | 'low';
  citations: ProviderCitation[];
  /** Signals whose absence in post-fix evidence is checked during verification. */
  signalPatterns?: SignalPattern[];
  remediation?: { title: string; steps: string[] };
}

export interface ProviderResult {
  claims: ProviderClaim[];
  insufficientEvidence: boolean;
  notes: string;
}

export interface InvestigationProvider {
  id: 'local-rules' | 'external-model';
  label: string;
  external: boolean;
  investigate(input: InvestigationInput): Promise<ProviderResult>;
}
