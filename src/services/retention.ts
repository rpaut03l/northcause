import { audit } from '../lib/audit';
import { nowIso } from '../lib/crypto';
import { pruneRateLimits } from '../lib/ratelimit';

/**
 * Retention sweep (runs from the hourly cron trigger).
 * - Evidence older than the tenant's retention_days is deleted from R2 and D1
 *   (timeline events and citations cascade). Audit events are kept.
 * - Expired sandbox tenants are deleted completely, including their audit events.
 * - Expired sessions and old rate-limit windows are removed.
 */
// R2 accepts at most 1000 keys per delete call.
async function deleteKeys(bucket: R2Bucket, keys: string[]): Promise<void> {
  for (let i = 0; i < keys.length; i += 1000) await bucket.delete(keys.slice(i, i + 1000));
}

export async function retentionSweep(db: D1Database, bucket: R2Bucket): Promise<{ evidence: number; sandboxes: number }> {
  const now = nowIso();
  let evidenceDeleted = 0;

  const expired = (
    await db
      .prepare(
        `SELECT e.id, e.tenant_id, e.r2_key FROM evidence e JOIN tenants t ON t.id = e.tenant_id
         WHERE datetime(e.created_at) < datetime('now', '-' || t.retention_days || ' days') LIMIT 500`,
      )
      .all<{ id: string; tenant_id: string; r2_key: string }>()
  ).results;
  if (expired.length) {
    await deleteKeys(bucket, expired.map((e) => e.r2_key));
    const stmt = db.prepare('DELETE FROM evidence WHERE id = ?');
    await db.batch(expired.map((e) => stmt.bind(e.id)));
    evidenceDeleted = expired.length;
    const perTenant = new Map<string, number>();
    for (const e of expired) perTenant.set(e.tenant_id, (perTenant.get(e.tenant_id) ?? 0) + 1);
    for (const [tenantId, n] of perTenant) {
      await audit(db, { tenantId, actor: 'system', action: 'retention.evidence_deleted', target: tenantId, metadata: { count: n } });
    }
  }

  const sandboxes = (
    await db.prepare("SELECT id FROM tenants WHERE kind = 'sandbox' AND expires_at IS NOT NULL AND expires_at < ? LIMIT 100").bind(now).all<{ id: string }>()
  ).results;
  let purged = 0;
  for (const t of sandboxes) {
    // One bad tenant must not stop the sweep for everyone else.
    try {
      const keys = (await db.prepare('SELECT r2_key FROM evidence WHERE tenant_id = ?').bind(t.id).all<{ r2_key: string }>()).results;
      await deleteKeys(bucket, keys.map((k) => k.r2_key));
      await db.batch([
        db.prepare('INSERT OR IGNORE INTO retention_purge_allowed (tenant_id) VALUES (?)').bind(t.id),
        db.prepare('DELETE FROM audit_events WHERE tenant_id = ?').bind(t.id),
        db.prepare('DELETE FROM retention_purge_allowed WHERE tenant_id = ?').bind(t.id),
        db.prepare('DELETE FROM tenants WHERE id = ?').bind(t.id),
      ]);
      purged++;
    } catch (err) {
      console.error('sandbox_purge_failed', { tenantId: t.id, error: err instanceof Error ? err.name : 'unknown' });
    }
  }

  await db.prepare('DELETE FROM sessions WHERE expires_at < ?').bind(now).run();
  await pruneRateLimits(db);
  return { evidence: evidenceDeleted, sandboxes: purged };
}
