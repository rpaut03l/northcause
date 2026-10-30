import { audit } from '../lib/audit';
import { newId, randomToken } from '../lib/crypto';
import { createSession, createTenant, createUser } from './accounts';
import { SAMPLE_EVIDENCE, SAMPLE_INCIDENT } from './sample-data';
import { addEvidence, createIncident } from './workflow';

export const SANDBOX_TTL_HOURS = 24;

/**
 * Creates an isolated, short-lived sandbox tenant seeded with synthetic sample data and
 * returns a session token. Each visitor gets their own tenant; nothing is shared.
 */
export async function createSandbox(db: D1Database, bucket: R2Bucket): Promise<string> {
  const expiresAt = new Date(Date.now() + SANDBOX_TTL_HOURS * 3600_000).toISOString();
  const tenantId = await createTenant(db, 'Demo sandbox', 'sandbox', { expiresAt, retentionDays: 1 });
  // Random, unguessable credentials; the visitor never sees or uses them.
  const userId = await createUser(db, tenantId, `${newId('sandbox')}@sandbox.invalid`, 'Sandbox admin', randomToken(24), 'admin');
  await audit(db, { tenantId, actor: 'system', action: 'sandbox.create', target: tenantId, metadata: { expires_at: expiresAt } });
  const incidentId = await createIncident(db, tenantId, userId, SAMPLE_INCIDENT);
  const enc = new TextEncoder();
  for (const ev of SAMPLE_EVIDENCE.filter((e) => e.phase === 'incident')) {
    await addEvidence(db, bucket, tenantId, userId, incidentId, { name: ev.name, type: ev.type, bytes: enc.encode(ev.text) }, {
      label: ev.label,
      phase: ev.phase,
      source: 'sample-data',
    });
  }
  return createSession(db, userId, tenantId);
}
