import { audit } from '../lib/audit';
import { newId, nowIso, sha256Hex } from '../lib/crypto';
import { EvidenceError, MAX_EVIDENCE_PER_INCIDENT, validateEvidence, type EvidenceFormat } from '../lib/evidence-validate';
import { detectInjection, redact } from '../lib/redact';
import { parseTimeline } from '../lib/timeline';
import { verifyClaims } from '../providers/citations';
import type { InvestigationProvider, ProviderEvidence, SignalPattern } from '../providers/types';

// Every function takes tenantId from the authenticated session and filters on it.
// A record from another tenant is indistinguishable from a missing record (returns null).

export type Severity = 'sev1' | 'sev2' | 'sev3' | 'sev4';
export type IncidentStatus = 'open' | 'investigating' | 'mitigated' | 'resolved';
export const SEVERITIES: Severity[] = ['sev1', 'sev2', 'sev3', 'sev4'];
export const STATUSES: IncidentStatus[] = ['open', 'investigating', 'mitigated', 'resolved'];

export interface Incident {
  id: string;
  tenant_id: string;
  title: string;
  service: string;
  severity: Severity;
  status: IncidentStatus;
  summary: string;
  created_by: string;
  created_at: string;
  updated_at: string;
}

export interface EvidenceRow {
  id: string;
  incident_id: string;
  label: string;
  original_filename: string;
  format: EvidenceFormat;
  phase: 'incident' | 'post_fix';
  source: string;
  size_bytes: number;
  sha256: string;
  r2_key: string;
  line_count: number;
  secrets_redacted: number;
  injection_flags: number;
  uploaded_by: string;
  created_at: string;
}

export const MAX_EVIDENCE_PER_TENANT = 1000;
export const MAX_EVIDENCE_PER_SANDBOX = 30;
/** Minimum non-empty post-fix lines before a check may report pass. */
export const MIN_POST_FIX_LINES = 3;

export class NotFound extends Error {}
export class Forbidden extends Error {}
export class BadRequest extends Error {}

export async function createIncident(
  db: D1Database,
  tenantId: string,
  actor: string,
  input: { title: string; service: string; severity: string; summary: string },
): Promise<string> {
  const title = input.title.trim().slice(0, 160);
  const service = input.service.trim().slice(0, 80);
  if (!title) throw new BadRequest('Title is required.');
  if (!service) throw new BadRequest('Service is required.');
  if (!SEVERITIES.includes(input.severity as Severity)) throw new BadRequest('Invalid severity.');
  const id = newId('inc');
  const now = nowIso();
  await db
    .prepare(
      'INSERT INTO incidents (id, tenant_id, title, service, severity, status, summary, created_by, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
    )
    .bind(id, tenantId, title, service, input.severity, 'open', input.summary.trim().slice(0, 2000), actor, now, now)
    .run();
  await audit(db, { tenantId, actor, action: 'incident.create', target: id, metadata: { severity: input.severity } });
  return id;
}

export async function listIncidents(db: D1Database, tenantId: string): Promise<Incident[]> {
  return (await db.prepare('SELECT * FROM incidents WHERE tenant_id = ? ORDER BY created_at DESC LIMIT 200').bind(tenantId).all<Incident>()).results;
}

export async function getIncident(db: D1Database, tenantId: string, id: string): Promise<Incident | null> {
  return db.prepare('SELECT * FROM incidents WHERE tenant_id = ? AND id = ?').bind(tenantId, id).first<Incident>();
}

export async function updateIncidentStatus(db: D1Database, tenantId: string, actor: string, id: string, status: string): Promise<void> {
  if (!STATUSES.includes(status as IncidentStatus)) throw new BadRequest('Invalid status.');
  const r = await db
    .prepare('UPDATE incidents SET status = ?, updated_at = ? WHERE tenant_id = ? AND id = ?')
    .bind(status, nowIso(), tenantId, id)
    .run();
  if (!r.meta.changes) throw new NotFound();
  await audit(db, { tenantId, actor, action: 'incident.status', target: id, metadata: { status } });
}

export async function deleteIncident(db: D1Database, bucket: R2Bucket, tenantId: string, actor: string, id: string): Promise<void> {
  const inc = await getIncident(db, tenantId, id);
  if (!inc) throw new NotFound();
  const ev = await listEvidence(db, tenantId, id);
  if (ev.length) await bucket.delete(ev.map((e) => e.r2_key));
  await db.prepare('DELETE FROM incidents WHERE tenant_id = ? AND id = ?').bind(tenantId, id).run();
  await audit(db, { tenantId, actor, action: 'incident.delete', target: id, metadata: { evidence_deleted: ev.length } });
}

// ---------- Evidence ----------

export async function addEvidence(
  db: D1Database,
  bucket: R2Bucket,
  tenantId: string,
  actor: string,
  incidentId: string,
  file: { name: string; type: string; bytes: Uint8Array },
  meta: { label: string; phase: string; source: string },
): Promise<string> {
  const inc = await getIncident(db, tenantId, incidentId);
  if (!inc) throw new NotFound();
  const count = await db
    .prepare('SELECT COUNT(*) AS n FROM evidence WHERE tenant_id = ? AND incident_id = ?')
    .bind(tenantId, incidentId)
    .first<{ n: number }>();
  if ((count?.n ?? 0) >= MAX_EVIDENCE_PER_INCIDENT) throw new EvidenceError(`An incident can hold at most ${MAX_EVIDENCE_PER_INCIDENT} evidence files.`);
  const tenantTotal = await db
    .prepare('SELECT t.kind, (SELECT COUNT(*) FROM evidence e WHERE e.tenant_id = t.id) AS n FROM tenants t WHERE t.id = ?')
    .bind(tenantId)
    .first<{ kind: string; n: number }>();
  const tenantCap = tenantTotal?.kind === 'sandbox' ? MAX_EVIDENCE_PER_SANDBOX : MAX_EVIDENCE_PER_TENANT;
  if ((tenantTotal?.n ?? 0) >= tenantCap) throw new EvidenceError(`This workspace has reached its limit of ${tenantCap} evidence files. Delete old evidence first.`);
  const phase = meta.phase === 'post_fix' ? 'post_fix' : 'incident';

  const v = validateEvidence(file.name, file.type, file.bytes);
  const red = redact(v.text);
  const inj = detectInjection(red.text);
  const id = newId('ev');
  // Object key is built only from server-generated IDs, never from the user's filename.
  const r2Key = `tenants/${tenantId}/incidents/${incidentId}/${id}`;
  await bucket.put(r2Key, red.text, {
    httpMetadata: { contentType: 'text/plain; charset=utf-8' },
    customMetadata: { tenantId, incidentId, evidenceId: id },
  });
  const sha = await sha256Hex(file.bytes); // hash of the original upload, for chain of custody
  await db
    .prepare(
      `INSERT INTO evidence (id, tenant_id, incident_id, label, original_filename, format, phase, source, size_bytes, sha256, r2_key, line_count, secrets_redacted, injection_flags, uploaded_by, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    )
    .bind(
      id, tenantId, incidentId,
      (meta.label.trim() || v.safeFilename).slice(0, 120),
      v.safeFilename, v.format, phase, meta.source.slice(0, 40) || 'upload',
      file.bytes.byteLength, sha, r2Key, v.lineCount, red.count, inj.count, actor, nowIso(),
    )
    .run();

  const events = parseTimeline(red.text, v.format);
  if (events.length) {
    const stmt = db.prepare(
      'INSERT INTO timeline_events (id, tenant_id, incident_id, evidence_id, occurred_at, line_no, kind, summary) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
    );
    await db.batch(events.map((e) => stmt.bind(newId('tl'), tenantId, incidentId, id, e.occurredAt, e.lineNo, e.kind, e.summary)));
  }
  await audit(db, {
    tenantId, actor, action: 'evidence.upload', target: id,
    metadata: { incident: incidentId, bytes: file.bytes.byteLength, format: v.format, phase, redactions: red.count, injection_flags: inj.count, timeline_events: events.length },
  });
  return id;
}

export async function listEvidence(db: D1Database, tenantId: string, incidentId: string): Promise<EvidenceRow[]> {
  return (
    await db.prepare('SELECT * FROM evidence WHERE tenant_id = ? AND incident_id = ? ORDER BY created_at ASC').bind(tenantId, incidentId).all<EvidenceRow>()
  ).results;
}

export async function getEvidence(db: D1Database, tenantId: string, id: string): Promise<EvidenceRow | null> {
  return db.prepare('SELECT * FROM evidence WHERE tenant_id = ? AND id = ?').bind(tenantId, id).first<EvidenceRow>();
}

export async function readEvidenceText(bucket: R2Bucket, row: EvidenceRow): Promise<string> {
  const obj = await bucket.get(row.r2_key);
  return obj ? await obj.text() : '';
}

export async function deleteEvidence(db: D1Database, bucket: R2Bucket, tenantId: string, actor: string, id: string): Promise<void> {
  const row = await getEvidence(db, tenantId, id);
  if (!row) throw new NotFound();
  await bucket.delete(row.r2_key);
  await db.prepare('DELETE FROM evidence WHERE tenant_id = ? AND id = ?').bind(tenantId, id).run();
  await audit(db, { tenantId, actor, action: 'evidence.delete', target: id, metadata: { incident: row.incident_id } });
}

export interface TimelineRow {
  id: string;
  evidence_id: string;
  occurred_at: string;
  line_no: number;
  kind: string;
  summary: string;
}

export async function listTimeline(db: D1Database, tenantId: string, incidentId: string): Promise<TimelineRow[]> {
  return (
    await db
      .prepare('SELECT id, evidence_id, occurred_at, line_no, kind, summary FROM timeline_events WHERE tenant_id = ? AND incident_id = ? ORDER BY occurred_at ASC, line_no ASC LIMIT 1000')
      .bind(tenantId, incidentId)
      .all<TimelineRow>()
  ).results;
}

// ---------- Investigations ----------

export interface ClaimRow {
  id: string;
  investigation_id: string;
  kind: 'hypothesis' | 'risk';
  rank: number;
  category: string;
  statement: string;
  confidence: string;
  support: 'supported' | 'uncertain' | 'unsupported';
  signal_patterns: string;
}
export interface CitationRow {
  id: string;
  claim_id: string;
  evidence_id: string;
  line_no: number | null;
  excerpt: string;
}
export interface InvestigationRow {
  id: string;
  incident_id: string;
  provider: string;
  provider_label: string;
  external_model_used: number;
  status: 'complete' | 'insufficient_evidence' | 'failed';
  notes: string;
  created_by: string;
  created_at: string;
}

export async function runInvestigation(
  db: D1Database,
  bucket: R2Bucket,
  tenantId: string,
  actor: string,
  incidentId: string,
  provider: InvestigationProvider,
): Promise<string> {
  const inc = await getIncident(db, tenantId, incidentId);
  if (!inc) throw new NotFound();
  const evRows = await listEvidence(db, tenantId, incidentId);
  const evidence: ProviderEvidence[] = [];
  for (const row of evRows) {
    evidence.push({ id: row.id, label: row.label, format: row.format, phase: row.phase, text: await readEvidenceText(bucket, row) });
  }
  const timeline = (await listTimeline(db, tenantId, incidentId)).map((t) => ({
    evidenceId: t.evidence_id, occurredAt: t.occurred_at, lineNo: t.line_no, kind: t.kind, summary: t.summary,
  }));

  const invId = newId('inv');
  let status: InvestigationRow['status'] = 'complete';
  let notes = '';
  let verified: ReturnType<typeof verifyClaims> = [];

  if (!evidence.some((e) => e.phase === 'incident')) {
    status = 'insufficient_evidence';
    notes = 'Insufficient evidence: no incident evidence has been uploaded. Upload logs, events or CI output first.';
  } else {
    try {
      const result = await provider.investigate({
        incident: { title: inc.title, service: inc.service, severity: inc.severity },
        evidence,
        timeline,
      });
      verified = verifyClaims(result.claims, evidence, { untrustedProvider: provider.external });
      notes = provider.external && result.notes ? `Model notes (unverified, not evidence): ${result.notes}` : result.notes;
      const supported = verified.filter((c) => c.kind === 'hypothesis' && c.support !== 'unsupported');
      if (result.insufficientEvidence || supported.length === 0) {
        status = 'insufficient_evidence';
        if (!result.insufficientEvidence) notes = `${notes} No hypothesis had a citation that matched stored evidence, so the result is marked insufficient.`.trim();
      }
    } catch (err) {
      status = 'failed';
      // Safe message only; provider errors can contain upstream details.
      notes = 'The investigation provider failed. No findings were stored. Try again or use the local provider.';
      // Error class only: upstream messages can echo evidence or provider details.
      console.error('investigation_failed', { tenantId, incidentId, provider: provider.id, error: err instanceof Error ? err.name : 'unknown' });
    }
  }

  const stmts: D1PreparedStatement[] = [
    db
      .prepare('INSERT INTO investigations (id, tenant_id, incident_id, provider, provider_label, external_model_used, status, notes, created_by, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)')
      .bind(invId, tenantId, incidentId, provider.id, provider.label, provider.external ? 1 : 0, status, notes.slice(0, 2000), actor, nowIso()),
  ];
  let hRank = 0;
  let rRank = 0;
  for (const c of verified) {
    const claimId = newId('clm');
    const rank = c.kind === 'hypothesis' ? ++hRank : ++rRank;
    stmts.push(
      db
        .prepare('INSERT INTO claims (id, tenant_id, investigation_id, kind, rank, category, statement, confidence, support, signal_patterns) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)')
        .bind(claimId, tenantId, invId, c.kind, rank, c.category, c.statement, c.confidence, c.support, JSON.stringify({ patterns: c.signalPatterns, remediation: c.remediation ?? null })),
    );
    for (const cit of c.citations) {
      stmts.push(
        db
          .prepare('INSERT INTO claim_citations (id, tenant_id, claim_id, evidence_id, line_no, excerpt) VALUES (?, ?, ?, ?, ?, ?)')
          .bind(newId('cit'), tenantId, claimId, cit.evidenceId, cit.lineNo, cit.excerpt),
      );
    }
  }
  if (inc.status === 'open') {
    stmts.push(db.prepare("UPDATE incidents SET status = 'investigating', updated_at = ? WHERE tenant_id = ? AND id = ?").bind(nowIso(), tenantId, incidentId));
  }
  await db.batch(stmts);
  await audit(db, {
    tenantId, actor, action: 'investigation.run', target: invId,
    metadata: {
      incident: incidentId, provider: provider.id, external_model: provider.external, status,
      claims: verified.length, unsupported: verified.filter((c) => c.support === 'unsupported').length,
    },
  });
  return invId;
}

export async function listInvestigations(db: D1Database, tenantId: string, incidentId: string): Promise<InvestigationRow[]> {
  return (
    await db.prepare('SELECT * FROM investigations WHERE tenant_id = ? AND incident_id = ? ORDER BY created_at DESC').bind(tenantId, incidentId).all<InvestigationRow>()
  ).results;
}

export async function getInvestigationDetail(db: D1Database, tenantId: string, invId: string) {
  const inv = await db.prepare('SELECT * FROM investigations WHERE tenant_id = ? AND id = ?').bind(tenantId, invId).first<InvestigationRow>();
  if (!inv) return null;
  const claims = (
    await db.prepare('SELECT * FROM claims WHERE tenant_id = ? AND investigation_id = ? ORDER BY kind ASC, rank ASC').bind(tenantId, invId).all<ClaimRow>()
  ).results;
  const citations = claims.length
    ? (
        await db
          .prepare(`SELECT c.* FROM claim_citations c JOIN claims k ON k.id = c.claim_id WHERE c.tenant_id = ? AND k.investigation_id = ?`)
          .bind(tenantId, invId)
          .all<CitationRow>()
      ).results
    : [];
  // Support is re-derived from citations that still exist: if cited evidence was deleted,
  // the claim must no longer be shown as supported.
  const cited = new Set(citations.map((c) => c.claim_id));
  for (const c of claims) if (!cited.has(c.id)) c.support = 'unsupported';
  return { inv, claims, citations };
}

// ---------- Remediation drafts, approvals, checks ----------

export interface DraftRow {
  id: string;
  incident_id: string;
  investigation_id: string;
  claim_id: string;
  title: string;
  steps: string;
  checks: string;
  status: 'draft' | 'approved' | 'rejected';
  created_by: string;
  created_at: string;
}

interface CheckDef {
  name: string;
  pattern: SignalPattern;
}

export async function createDraft(db: D1Database, tenantId: string, actor: string, claimId: string): Promise<string> {
  const claim = await db
    .prepare(
      `SELECT k.*, i.incident_id FROM claims k JOIN investigations i ON i.id = k.investigation_id AND i.tenant_id = k.tenant_id
       WHERE k.tenant_id = ? AND k.id = ?`,
    )
    .bind(tenantId, claimId)
    .first<ClaimRow & { incident_id: string }>();
  if (!claim) throw new NotFound();
  if (claim.kind !== 'hypothesis') throw new BadRequest('Remediation drafts are created from hypotheses.');
  const live = await db
    .prepare('SELECT COUNT(*) AS n FROM claim_citations WHERE tenant_id = ? AND claim_id = ?')
    .bind(tenantId, claimId)
    .first<{ n: number }>();
  if (claim.support === 'unsupported' || !live?.n) throw new BadRequest('Claims without a valid evidence citation cannot be used for a remediation draft.');
  const parsed = JSON.parse(claim.signal_patterns || '{}') as { patterns?: SignalPattern[]; remediation?: { title: string; steps: string[] } | null };
  const remediation = parsed.remediation ?? {
    title: 'Investigate and fix the cited failure',
    steps: ['Review the cited evidence lines.', 'Agree a fix with the service owner.', 'Upload post-fix evidence.'],
  };
  const checks: CheckDef[] = (parsed.patterns ?? []).map((p, i) => ({ name: `Signal ${i + 1} absent in post-fix evidence`, pattern: p }));
  const id = newId('rem');
  await db
    .prepare('INSERT INTO remediation_drafts (id, tenant_id, incident_id, investigation_id, claim_id, title, steps, checks, status, created_by, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)')
    .bind(id, tenantId, claim.incident_id, claim.investigation_id, claim.id, remediation.title, JSON.stringify(remediation.steps), JSON.stringify(checks), 'draft', actor, nowIso())
    .run();
  await audit(db, { tenantId, actor, action: 'remediation.draft', target: id, metadata: { claim: claim.id, incident: claim.incident_id } });
  return id;
}

export async function listDrafts(db: D1Database, tenantId: string, incidentId: string): Promise<DraftRow[]> {
  return (
    await db.prepare('SELECT * FROM remediation_drafts WHERE tenant_id = ? AND incident_id = ? ORDER BY created_at DESC').bind(tenantId, incidentId).all<DraftRow>()
  ).results;
}

export async function getDraft(db: D1Database, tenantId: string, id: string): Promise<DraftRow | null> {
  return db.prepare('SELECT * FROM remediation_drafts WHERE tenant_id = ? AND id = ?').bind(tenantId, id).first<DraftRow>();
}

/**
 * Records a human decision. Approval does NOT execute anything: Northcause has no execution path.
 * It marks the draft as approved for your team to carry out through your own change process.
 */
export async function decideDraft(
  db: D1Database,
  tenantId: string,
  actor: { userId: string; role: 'admin' | 'member' },
  draftId: string,
  decision: string,
  reason: string,
): Promise<void> {
  if (actor.role !== 'admin') throw new Forbidden('Only workspace admins can approve or reject remediation drafts.');
  if (decision !== 'approved' && decision !== 'rejected') throw new BadRequest('Invalid decision.');
  const why = reason.trim().slice(0, 1000);
  if (why.length < 5) throw new BadRequest('A reason of at least 5 characters is required.');
  const draft = await getDraft(db, tenantId, draftId);
  if (!draft) throw new NotFound();
  if (draft.status !== 'draft') throw new BadRequest('This draft has already been decided.');
  const r = await db
    .prepare("UPDATE remediation_drafts SET status = ? WHERE tenant_id = ? AND id = ? AND status = 'draft'")
    .bind(decision, tenantId, draftId)
    .run();
  if (!r.meta.changes) throw new BadRequest('This draft has already been decided.');
  await db
    .prepare('INSERT INTO approvals (id, tenant_id, draft_id, decision, reason, decided_by, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)')
    .bind(newId('apr'), tenantId, draftId, decision, why, actor.userId, nowIso())
    .run();
  await audit(db, { tenantId, actor: actor.userId, action: `remediation.${decision}`, target: draftId, metadata: { incident: draft.incident_id } });
}

export async function listApprovals(db: D1Database, tenantId: string, incidentId: string) {
  return (
    await db
      .prepare(
        `SELECT a.*, u.display_name FROM approvals a JOIN remediation_drafts d ON d.id = a.draft_id AND d.tenant_id = a.tenant_id
         LEFT JOIN users u ON u.id = a.decided_by WHERE a.tenant_id = ? AND d.incident_id = ? ORDER BY a.created_at DESC`,
      )
      .bind(tenantId, incidentId)
      .all<{ id: string; draft_id: string; decision: string; reason: string; decided_by: string; display_name: string | null; created_at: string }>()
  ).results;
}

function matchCount(text: string, p: SignalPattern): number {
  const lines = text.split(/\r?\n/);
  if (p.type === 'literal') return lines.filter((l) => l.includes(p.value)).length;
  const capped = lines.map((l) => l.slice(0, 4000));
  // Regex patterns come only from the server's own rule set (see local-rules.ts).
  let re: RegExp;
  try {
    re = new RegExp(p.value, 'i');
  } catch {
    return 0;
  }
  return capped.filter((l) => re.test(l)).length;
}

/**
 * Runs the draft's configured checks against post-fix evidence. Read-only: it only reads
 * evidence already uploaded. "pass" means the failure signal was absent from the uploaded
 * post-fix evidence — it is evidence the fix worked, not a guarantee.
 */
export async function runChecks(db: D1Database, bucket: R2Bucket, tenantId: string, actor: string, draftId: string): Promise<number> {
  const draft = await getDraft(db, tenantId, draftId);
  if (!draft) throw new NotFound();
  if (draft.status !== 'approved') throw new BadRequest('Checks run only after a human has approved the draft.');
  const checks = JSON.parse(draft.checks) as CheckDef[];
  const approval = await db
    .prepare("SELECT created_at FROM approvals WHERE tenant_id = ? AND draft_id = ? AND decision = 'approved' ORDER BY created_at DESC LIMIT 1")
    .bind(tenantId, draftId)
    .first<{ created_at: string }>();
  // Only post-fix evidence uploaded after the approval counts; older files cannot prove the change worked.
  const post = (await listEvidence(db, tenantId, draft.incident_id)).filter(
    (e) => e.phase === 'post_fix' && approval && e.created_at >= approval.created_at,
  );
  const texts = await Promise.all(post.map(async (e) => ({ id: e.id, text: await readEvidenceText(bucket, e) })));
  const stmts: D1PreparedStatement[] = [];
  const list = checks.length ? checks : [{ name: 'Post-fix evidence present', pattern: { type: 'literal', value: '' } as SignalPattern }];
  for (const chk of list) {
    let result: 'pass' | 'fail' | 'inconclusive';
    let detail: string;
    let ids: string[] = [];
    const nonEmpty = texts.reduce((a, t) => a + t.text.split(/\r?\n/).filter((l) => l.trim()).length, 0);
    if (texts.length === 0) {
      result = 'inconclusive';
      detail = 'No post-fix evidence uploaded since the approval. Upload logs or events captured after the change, then run checks again.';
    } else if (nonEmpty < MIN_POST_FIX_LINES) {
      result = 'inconclusive';
      ids = texts.map((t) => t.id);
      detail = `Post-fix evidence is too thin (${nonEmpty} line(s); at least ${MIN_POST_FIX_LINES} needed) to say anything.`;
    } else if (!checks.length) {
      result = 'inconclusive';
      detail = 'This draft has no machine-checkable signal. Review the post-fix evidence manually.';
      ids = texts.map((t) => t.id);
    } else {
      const hits = texts.map((t) => ({ id: t.id, n: matchCount(t.text, chk.pattern) })).filter((h) => h.n > 0);
      if (hits.length) {
        result = 'fail';
        ids = hits.map((h) => h.id);
        detail = `Failure signal still present: ${hits.reduce((a, h) => a + h.n, 0)} matching line(s) in post-fix evidence.`;
      } else {
        result = 'pass';
        ids = texts.map((t) => t.id);
        detail = `Signal absent from ${texts.length} post-fix evidence file(s). This supports, but does not guarantee, that the fix worked.`;
      }
    }
    stmts.push(
      db
        .prepare('INSERT INTO check_runs (id, tenant_id, incident_id, draft_id, check_name, result, detail, evidence_ids, created_by, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)')
        .bind(newId('chk'), tenantId, draft.incident_id, draftId, chk.name, result, detail, JSON.stringify(ids), actor, nowIso()),
    );
  }
  await db.batch(stmts);
  await audit(db, { tenantId, actor, action: 'checks.run', target: draftId, metadata: { incident: draft.incident_id, checks: stmts.length, post_fix_files: texts.length } });
  return stmts.length;
}

export async function listCheckRuns(db: D1Database, tenantId: string, incidentId: string) {
  return (
    await db
      .prepare('SELECT * FROM check_runs WHERE tenant_id = ? AND incident_id = ? ORDER BY created_at DESC')
      .bind(tenantId, incidentId)
      .all<{ id: string; draft_id: string; check_name: string; result: string; detail: string; evidence_ids: string; created_at: string }>()
  ).results;
}
