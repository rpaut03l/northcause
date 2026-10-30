import type { SessionUser } from '../env';
import { hashPassword, newId, nowIso, randomToken, sha256Hex, verifyPassword } from '../lib/crypto';

export const SESSION_TTL_HOURS = 12;
export const SESSION_COOKIE = '__Host-nc_session';

export async function createTenant(
  db: D1Database,
  name: string,
  kind: 'pilot' | 'sandbox',
  opts: { expiresAt?: string | null; retentionDays?: number } = {},
): Promise<string> {
  const id = newId('ten');
  await db
    .prepare('INSERT INTO tenants (id, name, kind, retention_days, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?)')
    .bind(id, name, kind, opts.retentionDays ?? 30, nowIso(), opts.expiresAt ?? null)
    .run();
  return id;
}

export async function createUser(
  db: D1Database,
  tenantId: string,
  email: string,
  displayName: string,
  password: string,
  role: 'admin' | 'member',
): Promise<string> {
  const id = newId('usr');
  await db
    .prepare('INSERT INTO users (id, tenant_id, email, display_name, password_hash, role, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)')
    .bind(id, tenantId, email.toLowerCase().trim(), displayName, await hashPassword(password), role, nowIso())
    .run();
  return id;
}

// A fixed dummy hash so unknown emails take the same time as wrong passwords.
const DUMMY_HASH = 'pbkdf2$100000$00000000000000000000000000000000$0000000000000000000000000000000000000000000000000000000000000000';

export async function authenticate(db: D1Database, email: string, password: string): Promise<{ userId: string; tenantId: string } | null> {
  const row = await db
    .prepare(
      `SELECT u.id, u.tenant_id, u.password_hash, t.expires_at FROM users u JOIN tenants t ON t.id = u.tenant_id WHERE u.email = ?`,
    )
    .bind(email.toLowerCase().trim())
    .first<{ id: string; tenant_id: string; password_hash: string; expires_at: string | null }>();
  const ok = await verifyPassword(password, row?.password_hash ?? DUMMY_HASH);
  if (!row || !ok) return null;
  if (row.expires_at && row.expires_at < nowIso()) return null;
  return { userId: row.id, tenantId: row.tenant_id };
}

export async function createSession(db: D1Database, userId: string, tenantId: string): Promise<string> {
  const token = randomToken();
  const expires = new Date(Date.now() + SESSION_TTL_HOURS * 3600_000).toISOString();
  await db
    .prepare('INSERT INTO sessions (token_hash, user_id, tenant_id, csrf_token, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?)')
    .bind(await sha256Hex(token), userId, tenantId, randomToken(24), nowIso(), expires)
    .run();
  return token;
}

export async function loadSession(db: D1Database, token: string): Promise<SessionUser | null> {
  const row = await db
    .prepare(
      `SELECT s.user_id, s.tenant_id, s.csrf_token, s.expires_at, u.email, u.display_name, u.role,
              t.name AS tenant_name, t.kind AS tenant_kind, t.external_model_enabled, t.retention_days, t.expires_at AS tenant_expires
       FROM sessions s
       JOIN users u ON u.id = s.user_id AND u.tenant_id = s.tenant_id
       JOIN tenants t ON t.id = s.tenant_id
       WHERE s.token_hash = ?`,
    )
    .bind(await sha256Hex(token))
    .first<Record<string, string | number | null>>();
  if (!row) return null;
  const now = nowIso();
  if (String(row.expires_at) < now) return null;
  if (row.tenant_expires && String(row.tenant_expires) < now) return null;
  return {
    userId: String(row.user_id),
    tenantId: String(row.tenant_id),
    email: String(row.email),
    displayName: String(row.display_name),
    role: row.role === 'admin' ? 'admin' : 'member',
    tenantName: String(row.tenant_name),
    tenantKind: row.tenant_kind === 'sandbox' ? 'sandbox' : 'pilot',
    externalModelEnabled: Number(row.external_model_enabled) === 1,
    retentionDays: Number(row.retention_days),
    csrfToken: String(row.csrf_token),
  };
}

export async function deleteSession(db: D1Database, token: string): Promise<void> {
  await db.prepare('DELETE FROM sessions WHERE token_hash = ?').bind(await sha256Hex(token)).run();
}

export async function setExternalModel(db: D1Database, tenantId: string, enabled: boolean): Promise<void> {
  await db.prepare('UPDATE tenants SET external_model_enabled = ? WHERE id = ?').bind(enabled ? 1 : 0, tenantId).run();
}
