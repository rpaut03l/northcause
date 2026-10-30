import { nowIso, sha256Hex } from './crypto';

export interface AuditInput {
  tenantId: string;
  actor: string; // user id, or "system"
  action: string; // e.g. incident.create
  target: string; // e.g. inc_abc
  metadata?: Record<string, string | number | boolean | null>;
}

/**
 * Append an audit event. Each event stores the hash of the previous event for the tenant,
 * so silent edits or gaps are detectable with verifyAuditChain. The table itself rejects
 * UPDATE and DELETE via triggers (see migrations/0001_init.sql).
 * Callers must pass metadata that holds identifiers and counts only — never evidence
 * content, secrets, passwords or tokens.
 */
export async function audit(db: D1Database, e: AuditInput): Promise<void> {
  const metadata = JSON.stringify(e.metadata ?? {});
  // UNIQUE(tenant_id, prev_hash) makes a concurrent writer that read the same tail fail
  // instead of forking the chain; it then re-reads the tail and retries.
  for (let attempt = 0; attempt < 12; attempt++) {
    if (attempt > 0) await new Promise((r) => setTimeout(r, Math.random() * 15 * attempt)); // jittered backoff
    const prev = await db
      .prepare('SELECT hash FROM audit_events WHERE tenant_id = ? ORDER BY seq DESC LIMIT 1')
      .bind(e.tenantId)
      .first<{ hash: string }>();
    const prevHash = prev?.hash ?? 'genesis';
    const createdAt = nowIso();
    const hash = await sha256Hex([prevHash, e.tenantId, e.actor, e.action, e.target, metadata, createdAt].join('|'));
    try {
      await db
        .prepare(
          'INSERT INTO audit_events (tenant_id, actor, action, target, metadata, created_at, prev_hash, hash) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
        )
        .bind(e.tenantId, e.actor, e.action, e.target, metadata, createdAt, prevHash, hash)
        .run();
      return;
    } catch (err) {
      if (!/UNIQUE/i.test(err instanceof Error ? err.message : '')) throw err;
    }
  }
  throw new Error('audit_chain_contention');
}

export interface AuditRow {
  seq: number;
  tenant_id: string;
  actor: string;
  action: string;
  target: string;
  metadata: string;
  created_at: string;
  prev_hash: string;
  hash: string;
}

export async function listAudit(db: D1Database, tenantId: string, limit = 200): Promise<AuditRow[]> {
  const r = await db
    .prepare('SELECT * FROM audit_events WHERE tenant_id = ? ORDER BY seq DESC LIMIT ?')
    .bind(tenantId, limit)
    .all<AuditRow>();
  return r.results;
}

export async function verifyAuditChain(db: D1Database, tenantId: string): Promise<{ ok: boolean; checked: number; brokenAt?: number }> {
  const r = await db
    .prepare('SELECT * FROM audit_events WHERE tenant_id = ? ORDER BY seq ASC')
    .bind(tenantId)
    .all<AuditRow>();
  let prev = 'genesis';
  for (const row of r.results) {
    const expected = await sha256Hex(
      [prev, row.tenant_id, row.actor, row.action, row.target, row.metadata, row.created_at].join('|'),
    );
    if (row.prev_hash !== prev || row.hash !== expected) return { ok: false, checked: r.results.length, brokenAt: row.seq };
    prev = row.hash;
  }
  return { ok: true, checked: r.results.length };
}
