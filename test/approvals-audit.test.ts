import { describe, expect, it, vi } from 'vitest';
import { githubActionsAdapter, runsToNdjson, validRepoRef } from '../src/integrations/github-actions';
import { audit, verifyAuditChain } from '../src/lib/audit';
import { retentionSweep } from '../src/services/retention';
import { Client, fileForm, idFrom, makeEnv, seedTenant } from './helpers';

const LOG = '2026-10-29T10:00:00Z deploy: rollout started\n2026-10-29T10:02:00Z pod OOMKilled\n2026-10-29T10:03:00Z pod OOMKilled';

async function withDraft() {
  const { env, db, r2 } = makeEnv();
  const t = await seedTenant(env, 'Acme');
  const admin = new Client(env, '198.51.100.7');
  await admin.login(t.adminEmail, t.password);
  const csrf = await admin.csrf();
  const res = await admin.post('/app/incidents', { _csrf: csrf, title: 'T', service: 's', severity: 'sev2', summary: '' });
  const incidentId = idFrom(res.headers.get('Location'), 'inc');
  await admin.post(`/app/incidents/${incidentId}/evidence`, fileForm(csrf, 'e.log', LOG));
  await admin.post(`/app/incidents/${incidentId}/investigate`, { _csrf: csrf, provider: 'local' });
  const claimId = (db.raw.prepare("SELECT id FROM claims WHERE kind='hypothesis' ORDER BY rank").get() as { id: string }).id;
  await admin.post(`/app/claims/${claimId}/draft`, { _csrf: csrf });
  const draftId = (db.raw.prepare('SELECT id FROM remediation_drafts').get() as { id: string }).id;
  return { env, db, r2, t, admin, csrf, incidentId, draftId };
}

describe('human approval', () => {
  it('blocks members from approving', async () => {
    const { env, db, t, draftId } = await withDraft();
    const member = new Client(env, '198.51.100.8');
    await member.login(t.memberEmail, t.password);
    const res = await member.post(`/app/drafts/${draftId}/decision`, { _csrf: await member.csrf(), decision: 'approved', reason: 'looks fine to me' });
    expect(res.status).toBe(403);
    expect((db.raw.prepare('SELECT status FROM remediation_drafts').get() as { status: string }).status).toBe('draft');
    expect((db.raw.prepare('SELECT COUNT(*) AS n FROM approvals').get() as { n: number }).n).toBe(0);
  });

  it('requires a reason, records the approver, and cannot be decided twice', async () => {
    const { db, admin, csrf, draftId, t } = await withDraft();
    await admin.post(`/app/drafts/${draftId}/decision`, { _csrf: csrf, decision: 'approved', reason: '' });
    expect((db.raw.prepare('SELECT status FROM remediation_drafts').get() as { status: string }).status).toBe('draft');
    await admin.post(`/app/drafts/${draftId}/decision`, { _csrf: csrf, decision: 'approved', reason: 'Raise limit per review' });
    await admin.post(`/app/drafts/${draftId}/decision`, { _csrf: csrf, decision: 'rejected', reason: 'changed my mind' });
    const rows = db.raw.prepare('SELECT * FROM approvals').all() as Array<Record<string, string>>;
    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({ decision: 'approved', decided_by: t.adminId, reason: 'Raise limit per review' });
    expect((db.raw.prepare('SELECT status FROM remediation_drafts').get() as { status: string }).status).toBe('approved');
  });

  it('runs checks only after approval and records post-fix evidence results', async () => {
    const { db, admin, csrf, draftId, incidentId } = await withDraft();
    await admin.post(`/app/drafts/${draftId}/checks`, { _csrf: csrf });
    expect((db.raw.prepare('SELECT COUNT(*) AS n FROM check_runs').get() as { n: number }).n).toBe(0);

    await admin.post(`/app/drafts/${draftId}/decision`, { _csrf: csrf, decision: 'approved', reason: 'approved for change window' });
    await admin.post(`/app/drafts/${draftId}/checks`, { _csrf: csrf });
    let run = db.raw.prepare('SELECT * FROM check_runs ORDER BY created_at DESC').get() as Record<string, string>;
    expect(run.result).toBe('inconclusive'); // no post-fix evidence yet

    await admin.post(`/app/incidents/${incidentId}/evidence`, fileForm(csrf, 'after.log', '2026-10-29T14:00:00Z pod started\n2026-10-29T14:05:00Z pod OOMKilled again\n2026-10-29T14:06:00Z pod restarting', 'text/plain', { phase: 'post_fix' }));
    await admin.post(`/app/drafts/${draftId}/checks`, { _csrf: csrf });
    run = db.raw.prepare("SELECT * FROM check_runs WHERE result != 'inconclusive'").get() as Record<string, string>;
    expect(run.result).toBe('fail');
  });

  it('marks a check as pass when the signal is absent from post-fix evidence', async () => {
    const { db, admin, csrf, draftId, incidentId } = await withDraft();
    await admin.post(`/app/drafts/${draftId}/decision`, { _csrf: csrf, decision: 'approved', reason: 'approved for change window' });
    await admin.post(`/app/incidents/${incidentId}/evidence`, fileForm(csrf, 'thin.log', 'ok', 'text/plain', { phase: 'post_fix' }));
    await admin.post(`/app/drafts/${draftId}/checks`, { _csrf: csrf });
    expect((db.raw.prepare('SELECT result FROM check_runs').get() as { result: string }).result).toBe('inconclusive'); // too thin to prove anything
    await admin.post(
      `/app/incidents/${incidentId}/evidence`,
      fileForm(csrf, 'after.log', '2026-10-29T14:00:00Z pod started\n2026-10-29T14:30:00Z pod healthy restarts=0\n2026-10-29T15:00:00Z peak traffic served', 'text/plain', { phase: 'post_fix' }),
    );
    await admin.post(`/app/drafts/${draftId}/checks`, { _csrf: csrf });
    const run = db.raw.prepare("SELECT * FROM check_runs WHERE result = 'pass'").get() as Record<string, string>;
    expect(run.result).toBe('pass');
    expect(run.detail).toMatch(/does not guarantee/);
  });

  it('ignores post-fix evidence uploaded before the approval', async () => {
    const { db, admin, csrf, draftId, incidentId } = await withDraft();
    await admin.post(
      `/app/incidents/${incidentId}/evidence`,
      fileForm(csrf, 'early.log', 'a healthy line\nanother healthy line\nthird healthy line', 'text/plain', { phase: 'post_fix' }),
    );
    db.raw.exec("UPDATE evidence SET created_at = '2000-01-01T00:00:00.000Z' WHERE phase = 'post_fix'");
    await admin.post(`/app/drafts/${draftId}/decision`, { _csrf: csrf, decision: 'approved', reason: 'approved for change window' });
    await admin.post(`/app/drafts/${draftId}/checks`, { _csrf: csrf });
    const run = db.raw.prepare('SELECT * FROM check_runs').get() as Record<string, string>;
    expect(run.result).toBe('inconclusive');
    expect(run.detail).toMatch(/since the approval/);
  });

  it('runs the full sandbox demo: approve, add sample post-fix evidence, checks pass', async () => {
    const { env, db } = makeEnv();
    const c = new Client(env);
    await c.post('/sandbox', {});
    const csrf = await c.csrf();
    const incidentId = idFrom(await (await c.req('/app')).text(), 'inc');
    expect((db.raw.prepare("SELECT COUNT(*) AS n FROM evidence WHERE phase = 'post_fix'").get() as { n: number }).n).toBe(0);
    await c.post(`/app/incidents/${incidentId}/investigate`, { _csrf: csrf, provider: 'local' });
    const top = db.raw.prepare("SELECT id, statement FROM claims WHERE kind = 'hypothesis' ORDER BY rank").get() as { id: string; statement: string };
    expect(top.statement).toMatch(/memory limits/);
    await c.post(`/app/claims/${top.id}/draft`, { _csrf: csrf });
    const draftId = (db.raw.prepare('SELECT id FROM remediation_drafts').get() as { id: string }).id;
    await c.post(`/app/drafts/${draftId}/decision`, { _csrf: csrf, decision: 'approved', reason: 'demo approval' });
    await c.post(`/app/incidents/${incidentId}/sample-post-fix`, { _csrf: csrf });
    await c.post(`/app/drafts/${draftId}/checks`, { _csrf: csrf });
    expect((db.raw.prepare('SELECT result FROM check_runs').get() as { result: string }).result).toBe('pass');
  });

  it('only lets admins delete evidence, and claims lose support when their evidence is deleted', async () => {
    const { env, db, t, admin, csrf, incidentId } = await withDraft();
    const evId = (db.raw.prepare('SELECT id FROM evidence').get() as { id: string }).id;
    const member = new Client(env, '198.51.100.9');
    await member.login(t.memberEmail, t.password);
    expect((await member.post(`/app/evidence/${evId}/delete`, { _csrf: await member.csrf() })).status).toBe(403);
    await admin.post(`/app/evidence/${evId}/delete`, { _csrf: csrf });
    const page = await (await admin.req(`/app/incidents/${incidentId}`)).text();
    expect(page).not.toContain('>SUPPORTED<');
    expect(page).toContain('UNSUPPORTED');
    const claimId = (db.raw.prepare("SELECT id FROM claims WHERE kind='hypothesis' ORDER BY rank").get() as { id: string }).id;
    const before = (db.raw.prepare('SELECT COUNT(*) AS n FROM remediation_drafts').get() as { n: number }).n;
    expect((await admin.post(`/app/claims/${claimId}/draft`, { _csrf: csrf })).status).toBe(400);
    expect((db.raw.prepare('SELECT COUNT(*) AS n FROM remediation_drafts').get() as { n: number }).n).toBe(before);
    const report = await (await admin.req(`/app/incidents/${incidentId}/report.md`)).text();
    expect(report).toContain('UNSUPPORTED');
  });

  it('has no execution path: approval changes only records', async () => {
    const { admin, csrf, draftId } = await withDraft();
    const fetchSpy = vi.spyOn(globalThis, 'fetch');
    await admin.post(`/app/drafts/${draftId}/decision`, { _csrf: csrf, decision: 'approved', reason: 'approved for change window' });
    await admin.post(`/app/drafts/${draftId}/checks`, { _csrf: csrf });
    expect(fetchSpy).not.toHaveBeenCalled();
    fetchSpy.mockRestore();
  });
});

describe('audit log', () => {
  it('records workflow actions in order with a valid hash chain', async () => {
    const { db, admin, csrf, draftId, t } = await withDraft();
    await admin.post(`/app/drafts/${draftId}/decision`, { _csrf: csrf, decision: 'approved', reason: 'approved for change window' });
    const actions = (db.raw.prepare('SELECT action FROM audit_events WHERE tenant_id = ? ORDER BY seq').all(t.tenantId) as Array<{ action: string }>).map((r) => r.action);
    expect(actions).toEqual(['auth.login', 'incident.create', 'evidence.upload', 'investigation.run', 'remediation.draft', 'remediation.approved']);
    expect(await verifyAuditChain(db as unknown as D1Database, t.tenantId)).toMatchObject({ ok: true, checked: 6 });
    const page = await (await admin.req('/app/audit')).text();
    expect(page).toContain('Hash chain verified across 6 event(s).');
  });

  it('rejects UPDATE and DELETE on audit events', async () => {
    const { db } = await withDraft();
    expect(() => db.raw.exec("UPDATE audit_events SET action = 'tampered'")).toThrow(/append-only/);
    expect(() => db.raw.exec('DELETE FROM audit_events')).toThrow(/append-only/);
  });

  it('detects tampering if the database is modified out of band', async () => {
    const { db, t } = await withDraft();
    db.raw.exec('DROP TRIGGER audit_no_update');
    db.raw.exec("UPDATE audit_events SET metadata = '{\"forged\":true}' WHERE action = 'incident.create'");
    const r = await verifyAuditChain(db as unknown as D1Database, t.tenantId);
    expect(r.ok).toBe(false);
  });

  it('keeps a valid chain under concurrent writes', async () => {
    const { env } = makeEnv();
    await Promise.all(Array.from({ length: 8 }, (_, i) => audit(env.DB, { tenantId: 'ten_c', actor: 'x', action: `a${i}`, target: 't' })));
    expect(await verifyAuditChain(env.DB, 'ten_c')).toMatchObject({ ok: true, checked: 8 });
  });

  it('keeps tenants on separate chains', async () => {
    const { env, db } = makeEnv();
    await audit(env.DB, { tenantId: 'ten_a', actor: 'x', action: 'a', target: 't' });
    await audit(env.DB, { tenantId: 'ten_b', actor: 'x', action: 'a', target: 't' });
    const rows = db.raw.prepare('SELECT prev_hash FROM audit_events').all() as Array<{ prev_hash: string }>;
    expect(rows.every((r) => r.prev_hash === 'genesis')).toBe(true);
  });
});

describe('report export', () => {
  it('exports a Markdown report with neutralised untrusted text', async () => {
    const { env } = makeEnv();
    const t = await seedTenant(env, 'Acme');
    const c = new Client(env);
    await c.login(t.adminEmail, t.password);
    const csrf = await c.csrf();
    const res = await c.post('/app/incidents', { _csrf: csrf, title: '<img src=x> [click](http://evil)', service: 's', severity: 'sev1', summary: '' });
    const incidentId = idFrom(res.headers.get('Location'), 'inc');
    const rep = await c.req(`/app/incidents/${incidentId}/report.md`);
    expect(rep.headers.get('Content-Type')).toBe('text/markdown; charset=utf-8');
    const text = await rep.text();
    expect(text).toContain('\\<img src=x\\>');
    expect(text).toContain('\\[click\\]');
    expect(text).toContain('No investigation has been run.');
  });
});

describe('retention', () => {
  it('deletes expired sandboxes completely, including audit events and R2 objects', async () => {
    const { env, db, r2 } = makeEnv();
    const c = new Client(env);
    await c.post('/sandbox', {});
    expect(r2.objects.size).toBeGreaterThan(0);
    db.raw.exec("UPDATE tenants SET expires_at = '2000-01-01T00:00:00.000Z'");
    expect((await c.req('/app')).status).toBe(303); // expired sandbox session no longer works
    const r = await retentionSweep(env.DB, env.EVIDENCE);
    expect(r.sandboxes).toBe(1);
    expect(r2.objects.size).toBe(0);
    for (const table of ['tenants', 'users', 'incidents', 'evidence', 'audit_events', 'sessions']) {
      expect((db.raw.prepare(`SELECT COUNT(*) AS n FROM ${table}`).get() as { n: number }).n, table).toBe(0);
    }
  });

  it('purges a sandbox holding more than 1000 objects (chunked R2 deletes)', async () => {
    const { env, db, r2 } = makeEnv();
    const c = new Client(env);
    await c.post('/sandbox', {});
    const tenantId = (db.raw.prepare('SELECT id FROM tenants').get() as { id: string }).id;
    const inc = (db.raw.prepare('SELECT id FROM incidents').get() as { id: string }).id;
    const ins = db.raw.prepare("INSERT INTO evidence (id, tenant_id, incident_id, label, original_filename, format, phase, source, size_bytes, sha256, r2_key, line_count, uploaded_by, created_at) VALUES (?, ?, ?, 'x', 'x.log', 'text', 'incident', 'upload', 1, 'h', ?, 1, 'u', '2026-01-01T00:00:00Z')");
    for (let i = 0; i < 1200; i++) {
      const key = `tenants/${tenantId}/incidents/${inc}/bulk${i}`;
      ins.run(`ev_bulk${i}`, tenantId, inc, key);
      r2.objects.set(key, 'x');
    }
    db.raw.exec("UPDATE tenants SET expires_at = '2000-01-01T00:00:00.000Z', retention_days = 100000");
    const r = await retentionSweep(env.DB, env.EVIDENCE);
    expect(r.sandboxes).toBe(1);
    expect(r2.objects.size).toBe(0);
    expect(r2.deleteCalls).toBeGreaterThanOrEqual(2);
  });

  it('deletes pilot evidence past the retention window but keeps the audit trail', async () => {
    const { env, db, r2, t } = await withDraft();
    db.raw.exec("UPDATE evidence SET created_at = '2000-01-01T00:00:00.000Z'");
    const r = await retentionSweep(env.DB, env.EVIDENCE);
    expect(r.evidence).toBe(1);
    expect(r2.objects.size).toBe(0);
    expect((db.raw.prepare('SELECT COUNT(*) AS n FROM evidence').get() as { n: number }).n).toBe(0);
    expect((db.raw.prepare("SELECT COUNT(*) AS n FROM audit_events WHERE action = 'retention.evidence_deleted' AND tenant_id = ?").get(t.tenantId) as { n: number }).n).toBe(1);
    expect(await verifyAuditChain(env.DB, t.tenantId)).toMatchObject({ ok: true });
  });
});

describe('GitHub Actions adapter (read-only)', () => {
  it('reports not connected without a token and never calls the API', async () => {
    const fetchMock = vi.fn();
    const a = githubActionsAdapter({} as never, fetchMock as unknown as typeof fetch);
    expect(a.status()).toBe('not_connected');
    await expect(a.listRecentRuns('o', 'r')).rejects.toThrow(/not connected/);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('uses GET only, validates repository names and maps runs to timeline evidence', async () => {
    const fetchMock = vi.fn(async (_url: string, init: RequestInit) => {
      expect(init.method).toBe('GET');
      return new Response(JSON.stringify({ workflow_runs: [{ id: 1, name: 'deploy', status: 'completed', conclusion: 'failure', head_sha: 'abcdef1234567', head_branch: 'main', event: 'push', created_at: '2026-10-29T10:00:00Z', updated_at: '2026-10-29T10:05:00Z' }] }));
    });
    const a = githubActionsAdapter({ GITHUB_TOKEN: 'ghp_test' } as never, fetchMock as unknown as typeof fetch);
    expect(a.status()).toBe('configured_unverified');
    expect(validRepoRef('../etc', 'x')).toBe(false);
    await expect(a.listRecentRuns('a/b', 'c')).rejects.toThrow(/Invalid repository/);
    const runs = await a.listRecentRuns('acme', 'api');
    expect(fetchMock.mock.calls[0]![0]).toBe('https://api.github.com/repos/acme/api/actions/runs?per_page=20');
    expect(runsToNdjson(runs, 'acme', 'api')).toContain('"conclusion":"failure"');
  });

  it('only imports from repositories allow-listed for the workspace, as an admin, never in a sandbox', async () => {
    const { env, db } = makeEnv({ GITHUB_TOKEN: 'ghp_operator_token' });
    const a = await seedTenant(env, 'Acme');
    const admin = new Client(env, '198.51.100.20');
    await admin.login(a.adminEmail, a.password);
    const csrf = await admin.csrf();
    const res = await admin.post('/app/incidents', { _csrf: csrf, title: 'T', service: 's', severity: 'sev3', summary: '' });
    const incidentId = idFrom(res.headers.get('Location'), 'inc');

    // Token configured but nothing allow-listed: still not connected, no API call.
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response(JSON.stringify({ workflow_runs: [{ id: 1, name: 'ci', status: 'completed', conclusion: 'success', head_sha: 'abc1234', head_branch: 'main', created_at: '2026-10-29T10:00:00Z', updated_at: '2026-10-29T10:01:00Z' }] })),
    );
    expect(await (await admin.req('/app/integrations')).text()).toContain('NOT CONNECTED');
    await admin.post('/app/integrations/github/import', { _csrf: csrf, repo: 'other/private', incident: incidentId });
    expect(fetchSpy).not.toHaveBeenCalled();

    db.raw.prepare("INSERT INTO integrations (id, tenant_id, kind, config, created_at) VALUES ('int_1', ?, 'github_actions', ?, '2026-10-30T00:00:00Z')")
      .run(a.tenantId, JSON.stringify({ repos: ['acme/api'] }));
    await admin.post('/app/integrations/github/import', { _csrf: csrf, repo: 'other/private', incident: incidentId });
    expect(fetchSpy).not.toHaveBeenCalled();

    const member = new Client(env, '198.51.100.21');
    await member.login(a.memberEmail, a.password);
    expect((await member.post('/app/integrations/github/import', { _csrf: await member.csrf(), repo: 'acme/api', incident: incidentId })).status).toBe(403);

    await admin.post('/app/integrations/github/import', { _csrf: csrf, repo: 'acme/api', incident: incidentId });
    expect(fetchSpy).toHaveBeenCalledTimes(1);
    expect((db.raw.prepare("SELECT source FROM evidence").get() as { source: string }).source).toBe('github_actions');

    const sb = new Client(env, '198.51.100.22');
    await sb.post('/sandbox', {});
    expect(await (await sb.req('/app/integrations')).text()).toContain('NOT CONNECTED');
    fetchSpy.mockRestore();
  });

  it('shows NOT CONNECTED in the workspace when no token is configured', async () => {
    const { env } = makeEnv();
    const t = await seedTenant(env, 'Acme');
    const c = new Client(env);
    await c.login(t.adminEmail, t.password);
    const page = await (await c.req('/app/integrations')).text();
    expect(page).toContain('NOT CONNECTED');
    expect(page).not.toContain('Import recent runs');
    const csrf = await c.csrf();
    await c.post('/app/integrations/github/import', { _csrf: csrf, repo: 'a/b', incident: 'inc_x' });
    expect(await (await c.req('/app/integrations')).text()).toContain('GitHub Actions is not connected.');
  });
});

describe('public pages', () => {
  it.each(['/', '/product', '/security', '/docs', '/pricing', '/contact', '/login'])('%s renders without invented claims', async (path) => {
    const { env } = makeEnv();
    const res = await new Client(env).req(path);
    expect(res.status).toBe(200);
    const html = await res.text();
    expect(html).toContain('Northcause');
    expect(html).not.toMatch(/\$\d|SOC ?2 (certified|compliant)|ISO ?27001 certified|trusted by|production[- ]ready/i);
  });

  it('pricing uses honest launch-stage wording', async () => {
    const { env } = makeEnv();
    const html = await (await new Client(env).req('/pricing')).text();
    expect(html).toContain('Free');
    expect(html).toContain('Agreed after scoping');
    expect(html).toContain('Custom');
  });

  it('rate limits the contact form', async () => {
    const { env, db } = makeEnv();
    const c = new Client(env);
    for (let i = 0; i < 5; i++) expect((await c.post('/contact', { name: 'A', email: 'a@b.co', message: 'hello there' })).status).toBe(303);
    expect((await c.post('/contact', { name: 'A', email: 'a@b.co', message: 'hello there' })).status).toBe(429);
    expect((db.raw.prepare('SELECT COUNT(*) AS n FROM contact_messages').get() as { n: number }).n).toBe(5);
  });
});
