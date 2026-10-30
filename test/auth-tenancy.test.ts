import { describe, expect, it } from 'vitest';
import { Client, fileForm, idFrom, makeEnv, seedTenant } from './helpers';

const LOG = [
  '2026-10-29T10:02:40Z deploy: rollout started api version 2.0',
  '2026-10-29T10:06:33Z pod/api-1 OOMKilled (exit code 137)',
  '2026-10-29T10:07:33Z pod/api-2 OOMKilled (exit code 137)',
  '2026-10-29T10:08:33Z pod/api-3 OOMKilled (exit code 137)',
].join('\n');

async function setupIncident(c: Client, title = 'API outage') {
  const csrf = await c.csrf();
  const res = await c.post('/app/incidents', { _csrf: csrf, title, service: 'api', severity: 'sev2', summary: '' });
  expect(res.status).toBe(303);
  const incidentId = idFrom(res.headers.get('Location'), 'inc');
  const up = await c.post(`/app/incidents/${incidentId}/evidence`, fileForm(csrf, 'events.log', LOG, 'text/plain', { phase: 'incident', label: 'events' }));
  expect(up.status).toBe(303);
  return { csrf, incidentId };
}

describe('authentication', () => {
  it('redirects anonymous users away from the workspace', async () => {
    const { env } = makeEnv();
    const res = await new Client(env).req('/app');
    expect(res.status).toBe(303);
    expect(res.headers.get('Location')).toBe('/login');
  });

  it('rejects a wrong password with a generic message and accepts the right one', async () => {
    const { env } = makeEnv();
    const t = await seedTenant(env, 'Acme');
    const c = new Client(env);
    const bad = await c.post('/login', { email: t.adminEmail, password: 'wrong-password' });
    expect(bad.status).toBe(401);
    expect(await bad.text()).toContain('Email or password is incorrect.');
    const unknown = await c.post('/login', { email: 'nobody@acme.test', password: 'x' });
    expect(unknown.status).toBe(401);
    await c.login(t.adminEmail, t.password);
    const app = await c.req('/app');
    expect(app.status).toBe(200);
  });

  it('sets a hardened session cookie', async () => {
    const { env } = makeEnv();
    const t = await seedTenant(env, 'Acme');
    const res = await new Client(env).post('/login', { email: t.adminEmail, password: t.password });
    const cookie = res.headers.getSetCookie().find((s) => s.startsWith('__Host-nc_session='))!;
    expect(cookie).toMatch(/HttpOnly/);
    expect(cookie).toMatch(/Secure/);
    expect(cookie).toMatch(/SameSite=Strict/);
    expect(cookie).toMatch(/Path=\//);
    expect(cookie).not.toMatch(/Domain=/);
  });

  it('stores only a hash of the session token and invalidates it on logout', async () => {
    const { env, db } = makeEnv();
    const t = await seedTenant(env, 'Acme');
    const c = new Client(env);
    await c.login(t.adminEmail, t.password);
    const token = c.cookies.get('__Host-nc_session')!;
    const row = db.raw.prepare('SELECT token_hash FROM sessions').get() as { token_hash: string };
    expect(row.token_hash).not.toBe(token);
    expect(row.token_hash).toMatch(/^[a-f0-9]{64}$/);
    const csrf = await c.csrf();
    await c.post('/logout', { _csrf: csrf });
    const stale = new Client(env);
    stale.cookies.set('__Host-nc_session', token);
    expect((await stale.req('/app')).status).toBe(303);
  });

  it('rate limits repeated sign-in attempts for one account', async () => {
    const { env } = makeEnv();
    const t = await seedTenant(env, 'Acme');
    const c = new Client(env);
    for (let i = 0; i < 10; i++) expect((await c.post('/login', { email: t.adminEmail, password: 'nope' })).status).toBe(401);
    expect((await c.post('/login', { email: t.adminEmail, password: t.password })).status).toBe(429);
  });

  it('does not let failures from other addresses lock the real user out', async () => {
    const { env } = makeEnv();
    const t = await seedTenant(env, 'Acme');
    const attacker = new Client(env, '203.0.113.99');
    for (let i = 0; i < 15; i++) await attacker.post('/login', { email: t.adminEmail, password: 'nope' });
    const real = new Client(env, '198.51.100.50');
    expect((await real.post('/login', { email: t.adminEmail, password: t.password })).status).toBe(303);
  });

  it('does not count successful sign-ins toward the limit', async () => {
    const { env } = makeEnv();
    const t = await seedTenant(env, 'Acme');
    for (let i = 0; i < 12; i++) expect((await new Client(env).post('/login', { email: t.adminEmail, password: t.password })).status).toBe(303);
  });

  it('never stores plaintext passwords', async () => {
    const { env, db } = makeEnv();
    const t = await seedTenant(env, 'Acme');
    const rows = db.raw.prepare('SELECT password_hash FROM users').all() as Array<{ password_hash: string }>;
    for (const r of rows) {
      expect(r.password_hash).toMatch(/^pbkdf2\$100000\$[a-f0-9]{32}\$[a-f0-9]{64}$/);
      expect(r.password_hash).not.toContain(t.password);
    }
  });
});

describe('CSRF and origin protection', () => {
  it('rejects workspace POSTs without a valid CSRF token', async () => {
    const { env } = makeEnv();
    const t = await seedTenant(env, 'Acme');
    const c = new Client(env);
    await c.login(t.adminEmail, t.password);
    expect((await c.post('/app/incidents', { title: 'x', service: 'y', severity: 'sev3' })).status).toBe(403);
    expect((await c.post('/app/incidents', { _csrf: 'forged', title: 'x', service: 'y', severity: 'sev3' })).status).toBe(403);
  });

  it('rejects cross-origin POSTs even with a valid token', async () => {
    const { env } = makeEnv();
    const t = await seedTenant(env, 'Acme');
    const c = new Client(env);
    await c.login(t.adminEmail, t.password);
    const csrf = await c.csrf();
    const res = await c.post('/app/incidents', { _csrf: csrf, title: 'x', service: 'y', severity: 'sev3' }, { headers: { Origin: 'https://evil.example' } });
    expect(res.status).toBe(403);
    const res2 = await c.post('/app/incidents', { _csrf: csrf, title: 'x', service: 'y', severity: 'sev3' }, { headers: { 'Sec-Fetch-Site': 'cross-site' } });
    expect(res2.status).toBe(403);
  });

  it('rejects POSTs that carry neither Origin nor Sec-Fetch-Site (login CSRF)', async () => {
    const { env } = makeEnv();
    const t = await seedTenant(env, 'Acme');
    const res = await new Client(env).post('/login', { email: t.adminEmail, password: t.password }, { headers: { Origin: '' } });
    expect(res.status).toBe(403);
    expect((await new Client(env).post('/sandbox', {}, { headers: { Origin: '' } })).status).toBe(403);
  });

  it('sends security headers including a strict CSP', async () => {
    const { env } = makeEnv();
    const res = await new Client(env).req('/');
    expect(res.headers.get('Content-Security-Policy')).toContain("script-src 'none'");
    expect(res.headers.get('Content-Security-Policy')).toContain("frame-ancestors 'none'");
    expect(res.headers.get('X-Content-Type-Options')).toBe('nosniff');
  });
});

describe('tenant isolation', () => {
  it('hides every record of tenant A from tenant B', async () => {
    const { env, db } = makeEnv();
    const a = await seedTenant(env, 'Alpha');
    const b = await seedTenant(env, 'Beta');
    const ca = new Client(env, '198.51.100.1');
    const cb = new Client(env, '198.51.100.2');
    await ca.login(a.adminEmail, a.password);
    await cb.login(b.adminEmail, b.password);

    const { csrf: csrfA, incidentId } = await setupIncident(ca, 'Alpha secret incident');
    await ca.post(`/app/incidents/${incidentId}/investigate`, { _csrf: csrfA, provider: 'local' });
    const evidenceId = (db.raw.prepare('SELECT id FROM evidence').get() as { id: string }).id;
    const invId = (db.raw.prepare('SELECT id FROM investigations').get() as { id: string }).id;
    const claimId = (db.raw.prepare("SELECT id FROM claims WHERE kind='hypothesis'").get() as { id: string }).id;
    await ca.post(`/app/claims/${claimId}/draft`, { _csrf: csrfA });
    const draftId = (db.raw.prepare('SELECT id FROM remediation_drafts').get() as { id: string }).id;

    const csrfB = await cb.csrf();
    const list = await (await cb.req('/app')).text();
    expect(list).not.toContain('Alpha secret incident');

    for (const path of [
      `/app/incidents/${incidentId}`,
      `/app/evidence/${evidenceId}`,
      `/app/evidence/${evidenceId}/download`,
      `/app/investigations/${invId}`,
      `/app/incidents/${incidentId}/report.md`,
    ]) {
      expect((await cb.req(path)).status, path).toBe(404);
    }
    const posts: Array<[string, Record<string, string>]> = [
      [`/app/incidents/${incidentId}/status`, { status: 'resolved' }],
      [`/app/incidents/${incidentId}/investigate`, { provider: 'local' }],
      [`/app/incidents/${incidentId}/delete`, { confirm: 'yes' }],
      [`/app/evidence/${evidenceId}/delete`, {}],
      [`/app/claims/${claimId}/draft`, {}],
      [`/app/drafts/${draftId}/decision`, { decision: 'approved', reason: 'cross tenant attempt' }],
      [`/app/drafts/${draftId}/checks`, {}],
    ];
    for (const [path, form] of posts) {
      expect((await cb.post(path, { _csrf: csrfB, ...form })).status, path).toBe(404);
    }
    const up = await cb.post(`/app/incidents/${incidentId}/evidence`, fileForm(csrfB, 'x.log', 'hello'));
    expect(up.status).toBe(404);

    // Nothing in tenant A changed.
    expect((db.raw.prepare('SELECT status FROM incidents WHERE id = ?').get(incidentId) as { status: string }).status).toBe('investigating');
    expect((db.raw.prepare('SELECT COUNT(*) AS n FROM evidence').get() as { n: number }).n).toBe(1);
    expect((db.raw.prepare('SELECT status FROM remediation_drafts').get() as { status: string }).status).toBe('draft');
    expect((db.raw.prepare('SELECT COUNT(*) AS n FROM audit_events WHERE tenant_id = ?').get(b.tenantId) as { n: number }).n).toBe(1); // B's login only
  });

  it('isolates each sandbox visitor in its own tenant', async () => {
    const { env, db } = makeEnv();
    const c1 = new Client(env, '192.0.2.1');
    const c2 = new Client(env, '192.0.2.2');
    expect((await c1.post('/sandbox', {})).status).toBe(303);
    expect((await c2.post('/sandbox', {})).status).toBe(303);
    const tenants = db.raw.prepare("SELECT id FROM tenants WHERE kind = 'sandbox'").all();
    expect(tenants.length).toBe(2);
    const inc1 = idFrom(await (await c1.req('/app')).text(), 'inc');
    expect((await c2.req(`/app/incidents/${inc1}`)).status).toBe(404);
    expect(await (await c1.req('/app')).text()).toContain('Demo sandbox');
  });
});
