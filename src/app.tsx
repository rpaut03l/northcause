import { Hono, type Context } from 'hono';
import { deleteCookie, getCookie, setCookie } from 'hono/cookie';
import type { AppEnv, SessionUser } from './env';
import { audit, listAudit, verifyAuditChain } from './lib/audit';
import { newId, nowIso, timingSafeEqual } from './lib/crypto';
import { EvidenceError } from './lib/evidence-validate';
import { clientIp, rateLimit, rateLimitExceeded } from './lib/ratelimit';
import { githubActionsAdapter, runsToNdjson, validRepoRef } from './integrations/github-actions';
import { externalModelConfigured, externalModelProvider } from './providers/external-model';
import { localRulesProvider } from './providers/local-rules';
import {
  SESSION_COOKIE,
  SESSION_TTL_HOURS,
  authenticate,
  createSession,
  deleteSession,
  loadSession,
  setExternalModel,
} from './services/accounts';
import { buildReport } from './services/report';
import { SAMPLE_POST_FIX } from './services/sample-data';
import { createSandbox } from './services/sandbox';
import {
  BadRequest,
  Forbidden,
  NotFound,
  addEvidence,
  createDraft,
  createIncident,
  decideDraft,
  deleteEvidence,
  deleteIncident,
  getEvidence,
  getIncident,
  getInvestigationDetail,
  listApprovals,
  listCheckRuns,
  listDrafts,
  listEvidence,
  listIncidents,
  listInvestigations,
  listTimeline,
  readEvidenceText,
  runChecks,
  runInvestigation,
  updateIncidentStatus,
} from './services/workflow';
import {
  AuditPage,
  EvidencePage,
  IncidentDetailPage,
  IncidentListPage,
  IntegrationsPage,
  InvestigationPage,
  NewIncidentPage,
  SettingsPage,
} from './views/app-pages';
import { ContactPage, DocsPage, ErrorPage, HomePage, LoginPage, PricingPage, ProductPage, SecurityPage } from './views/public-pages';

export const app = new Hono<AppEnv>();

const CSP = [
  "default-src 'self'",
  "script-src 'none'",
  "style-src 'self'",
  "img-src 'self' data:",
  "font-src 'self'",
  "connect-src 'self'",
  "form-action 'self'",
  "frame-ancestors 'none'",
  "base-uri 'none'",
  "object-src 'none'",
].join('; ');

// ---- Global middleware: request id + security headers ----
app.use('*', async (c, next) => {
  c.set('requestId', newId('req'));
  await next();
  const h = c.res.headers;
  h.set('Content-Security-Policy', CSP);
  h.set('X-Content-Type-Options', 'nosniff');
  h.set('X-Frame-Options', 'DENY');
  h.set('Referrer-Policy', 'same-origin');
  h.set('Permissions-Policy', 'camera=(), microphone=(), geolocation=(), payment=()');
  h.set('Cross-Origin-Opener-Policy', 'same-origin');
  h.set('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  if (c.req.path.startsWith('/app') || c.req.path === '/login') h.set('Cache-Control', 'no-store');
});

// ---- Same-origin check on every state-changing request ----
app.use('*', async (c, next) => {
  if (c.req.method !== 'GET' && c.req.method !== 'HEAD') {
    const origin = c.req.header('Origin');
    const site = c.req.header('Sec-Fetch-Site');
    const self = new URL(c.req.url).origin;
    // Browsers send Origin and/or Sec-Fetch-Site on every POST; a request with neither is not
    // from a browser form on this site, so it is refused too (covers login, sandbox, contact).
    const missing = !origin && !site;
    if (missing || (origin && origin !== self) || (site && site !== 'same-origin' && site !== 'none')) {
      return c.html(<ErrorPage status={403} message="Cross-site request blocked." />, 403);
    }
  }
  await next();
  return undefined;
});

// ---- Session loading ----
app.use('*', async (c, next) => {
  const token = getCookie(c, SESSION_COOKIE);
  if (token && token.length < 200) {
    const user = await loadSession(c.env.DB, token);
    if (user) c.set('user', user);
  }
  await next();
});

function requireUser(c: Context<AppEnv>): SessionUser {
  const u = c.get('user');
  if (!u) throw new Unauthenticated();
  return u;
}
class Unauthenticated extends Error {}
class CsrfError extends Error {}
class RateLimited extends Error {}

async function form(c: Context<AppEnv>): Promise<Record<string, string | File>> {
  const body = await c.req.parseBody();
  const out: Record<string, string | File> = {};
  for (const [k, v] of Object.entries(body)) if (typeof v === 'string' || v instanceof File) out[k] = v;
  return out;
}

function str(body: Record<string, string | File>, key: string, max = 4000): string {
  const v = body[key];
  return typeof v === 'string' ? v.slice(0, max) : '';
}

/** Auth + CSRF guard for all /app POSTs. */
async function guardPost(c: Context<AppEnv>): Promise<{ user: SessionUser; body: Record<string, string | File> }> {
  const user = requireUser(c);
  const body = await form(c);
  const token = str(body, '_csrf', 200);
  if (!token || !timingSafeEqual(token, user.csrfToken)) throw new CsrfError();
  return { user, body };
}

async function limit(c: Context<AppEnv>, key: string, max: number, windowSec: number) {
  const r = await rateLimit(c.env.DB, key, max, windowSec);
  if (!r.allowed) throw new RateLimited();
}

// One-shot flash messages travel in a short-lived SameSite=Strict cookie rather than the URL,
// so a third party cannot craft a link that displays arbitrary text inside the workspace.
const FLASH_COOKIE = '__Host-nc_flash';

function redirectWith(c: Context<AppEnv>, path: string, msg?: { flash?: string; error?: string }) {
  if (msg) {
    setCookie(c, FLASH_COOKIE, encodeURIComponent(JSON.stringify({ f: msg.flash?.slice(0, 300), e: msg.error?.slice(0, 300) })), {
      httpOnly: true, secure: true, sameSite: 'Strict', path: '/', maxAge: 60,
    });
  }
  return c.redirect(path, 303);
}

function msgs(c: Context<AppEnv>): { flash?: string; error?: string } {
  const raw = getCookie(c, FLASH_COOKIE);
  if (!raw) return {};
  deleteCookie(c, FLASH_COOKIE, { path: '/', secure: true });
  try {
    const v = JSON.parse(decodeURIComponent(raw)) as { f?: unknown; e?: unknown };
    return {
      flash: typeof v.f === 'string' ? v.f.slice(0, 300) : undefined,
      error: typeof v.e === 'string' ? v.e.slice(0, 300) : undefined,
    };
  } catch {
    return {};
  }
}

const sandboxEnabled = (c: Context<AppEnv>) => c.env.SANDBOX_ENABLED === 'true';

// ================= Public =================

app.get('/', (c) => c.html(<HomePage sandboxEnabled={sandboxEnabled(c)} />));
app.get('/product', (c) => c.html(<ProductPage />));
app.get('/security', (c) => c.html(<SecurityPage />));
app.get('/docs', (c) => c.html(<DocsPage />));
app.get('/pricing', (c) => c.html(<PricingPage />));
app.get('/contact', (c) => c.html(<ContactPage sent={c.req.query('sent') === '1'} />));
app.get('/healthz', (c) => c.json({ ok: true }));

app.post('/contact', async (c) => {
  await limit(c, `contact:${clientIp(c.req.raw)}`, 5, 3600);
  const b = await form(c);
  const name = str(b, 'name', 100).trim();
  const email = str(b, 'email', 200).trim();
  const message = str(b, 'message', 4000).trim();
  if (!name || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || message.length < 5) {
    return c.html(<ContactPage error="Please fill in name, a valid email and a message." />, 400);
  }
  await c.env.DB.prepare('INSERT INTO contact_messages (id, name, email, company, message, created_at) VALUES (?, ?, ?, ?, ?, ?)')
    .bind(newId('msg'), name, email, str(b, 'company', 120).trim(), message, nowIso())
    .run();
  return c.redirect('/contact?sent=1', 303);
});

app.get('/login', (c) => (c.get('user') ? c.redirect('/app') : c.html(<LoginPage sandboxEnabled={sandboxEnabled(c)} />)));

function setSessionCookie(c: Context<AppEnv>, token: string) {
  setCookie(c, SESSION_COOKIE, token, {
    httpOnly: true,
    secure: true,
    sameSite: 'Strict',
    path: '/',
    maxAge: SESSION_TTL_HOURS * 3600,
  });
}

app.post('/login', async (c) => {
  const b = await form(c);
  const email = str(b, 'email', 200).toLowerCase().trim();
  const password = str(b, 'password', 200);
  // Only FAILED attempts are counted, so a third party cannot lock a user out by spamming
  // requests: the per-account limit is keyed on account + IP, with a looser per-account cap.
  const ip = clientIp(c.req.raw);
  const keys: Array<[string, number]> = [
    [`login-fail-ip:${ip}`, 30],
    [`login-fail-acct-ip:${email}:${ip}`, 10],
    [`login-fail-acct:${email}`, 100],
  ];
  for (const [k, max] of keys) if (await rateLimitExceeded(c.env.DB, k, max, 900)) throw new RateLimited();
  const auth = email && password ? await authenticate(c.env.DB, email, password) : null;
  if (!auth) {
    for (const [k, max] of keys) await rateLimit(c.env.DB, k, max, 900);
    return c.html(<LoginPage error="Email or password is incorrect." sandboxEnabled={sandboxEnabled(c)} />, 401);
  }
  const token = await createSession(c.env.DB, auth.userId, auth.tenantId);
  await audit(c.env.DB, { tenantId: auth.tenantId, actor: auth.userId, action: 'auth.login', target: auth.userId });
  setSessionCookie(c, token);
  return c.redirect('/app', 303);
});

app.post('/logout', async (c) => {
  const user = c.get('user');
  if (user) {
    const b = await form(c);
    if (!timingSafeEqual(str(b, '_csrf', 200), user.csrfToken)) throw new CsrfError();
    const token = getCookie(c, SESSION_COOKIE);
    if (token) await deleteSession(c.env.DB, token);
    await audit(c.env.DB, { tenantId: user.tenantId, actor: user.userId, action: 'auth.logout', target: user.userId });
  }
  deleteCookie(c, SESSION_COOKIE, { path: '/', secure: true });
  return c.redirect('/', 303);
});

app.post('/sandbox', async (c) => {
  if (!sandboxEnabled(c)) return c.html(<ErrorPage status={404} message="The sandbox is not enabled here." />, 404);
  await limit(c, `sandbox:${clientIp(c.req.raw)}`, 5, 3600);
  const token = await createSandbox(c.env.DB, c.env.EVIDENCE);
  setSessionCookie(c, token);
  return c.redirect('/app', 303);
});

// ================= Workspace =================

app.get('/app', async (c) => {
  const user = requireUser(c);
  return c.html(<IncidentListPage user={user} incidents={await listIncidents(c.env.DB, user.tenantId)} {...msgs(c)} />);
});

app.get('/app/incidents/new', (c) => c.html(<NewIncidentPage user={requireUser(c)} {...msgs(c)} />));

app.post('/app/incidents', async (c) => {
  const { user, body } = await guardPost(c);
  try {
    const id = await createIncident(c.env.DB, user.tenantId, user.userId, {
      title: str(body, 'title', 200),
      service: str(body, 'service', 100),
      severity: str(body, 'severity', 10),
      summary: str(body, 'summary', 2000),
    });
    return redirectWith(c, `/app/incidents/${id}`, { flash: 'Incident created.' });
  } catch (e) {
    if (e instanceof BadRequest) return redirectWith(c, '/app/incidents/new', { error: e.message });
    throw e;
  }
});

app.get('/app/incidents/:id', async (c) => {
  const user = requireUser(c);
  const db = c.env.DB;
  const inc = await getIncident(db, user.tenantId, c.req.param('id'));
  if (!inc) throw new NotFound();
  const [evidence, timeline, investigations, drafts, approvals, checks] = await Promise.all([
    listEvidence(db, user.tenantId, inc.id),
    listTimeline(db, user.tenantId, inc.id),
    listInvestigations(db, user.tenantId, inc.id),
    listDrafts(db, user.tenantId, inc.id),
    listApprovals(db, user.tenantId, inc.id),
    listCheckRuns(db, user.tenantId, inc.id),
  ]);
  const latest = investigations[0] ? await getInvestigationDetail(db, user.tenantId, investigations[0].id) : null;
  return c.html(
    <IncidentDetailPage
      user={user}
      incident={inc}
      evidence={evidence}
      timeline={timeline}
      investigations={investigations}
      latest={latest}
      drafts={drafts}
      approvals={approvals}
      checks={checks}
      externalAvailable={user.externalModelEnabled && externalModelConfigured(c.env)}
      githubConnected={Boolean(c.env.GITHUB_TOKEN)}
      {...msgs(c)}
    />,
  );
});

app.post('/app/incidents/:id/status', async (c) => {
  const { user, body } = await guardPost(c);
  const id = c.req.param('id');
  await updateIncidentStatus(c.env.DB, user.tenantId, user.userId, id, str(body, 'status', 20));
  return redirectWith(c, `/app/incidents/${id}`, { flash: 'Status updated.' });
});

app.post('/app/incidents/:id/delete', async (c) => {
  const { user, body } = await guardPost(c);
  if (user.role !== 'admin') throw new Forbidden('Only admins can delete incidents.');
  if (str(body, 'confirm', 5) !== 'yes') return redirectWith(c, `/app/incidents/${c.req.param('id')}`, { error: 'Tick the confirmation box to delete.' });
  await deleteIncident(c.env.DB, c.env.EVIDENCE, user.tenantId, user.userId, c.req.param('id'));
  return redirectWith(c, '/app', { flash: 'Incident deleted.' });
});

app.post('/app/incidents/:id/evidence', async (c) => {
  const { user, body } = await guardPost(c);
  const id = c.req.param('id');
  await limit(c, `upload:${user.userId}`, 60, 3600);
  const file = body.file;
  if (!(file instanceof File)) return redirectWith(c, `/app/incidents/${id}`, { error: 'Choose a file to upload.' });
  try {
    await addEvidence(
      c.env.DB, c.env.EVIDENCE, user.tenantId, user.userId, id,
      { name: file.name, type: file.type, bytes: new Uint8Array(await file.arrayBuffer()) },
      { label: str(body, 'label', 120), phase: str(body, 'phase', 20), source: 'upload' },
    );
    return redirectWith(c, `/app/incidents/${id}`, { flash: 'Evidence uploaded and redacted.' });
  } catch (e) {
    if (e instanceof EvidenceError) return redirectWith(c, `/app/incidents/${id}`, { error: e.message });
    throw e;
  }
});

// Sandbox only: adds the synthetic post-fix file so the demo can show the full prove-it step.
app.post('/app/incidents/:id/sample-post-fix', async (c) => {
  const { user } = await guardPost(c);
  if (user.tenantKind !== 'sandbox') throw new NotFound();
  const id = c.req.param('id');
  await addEvidence(
    c.env.DB, c.env.EVIDENCE, user.tenantId, user.userId, id,
    { name: SAMPLE_POST_FIX.name, type: SAMPLE_POST_FIX.type, bytes: new TextEncoder().encode(SAMPLE_POST_FIX.text) },
    { label: SAMPLE_POST_FIX.label, phase: 'post_fix', source: 'sample-data' },
  );
  return redirectWith(c, `/app/incidents/${id}`, { flash: 'Sample post-fix evidence added.' });
});

app.get('/app/evidence/:id', async (c) => {
  const user = requireUser(c);
  const ev = await getEvidence(c.env.DB, user.tenantId, c.req.param('id'));
  if (!ev) throw new NotFound();
  return c.html(<EvidencePage user={user} ev={ev} text={await readEvidenceText(c.env.EVIDENCE, ev)} />);
});

app.get('/app/evidence/:id/download', async (c) => {
  const user = requireUser(c);
  const ev = await getEvidence(c.env.DB, user.tenantId, c.req.param('id'));
  if (!ev) throw new NotFound();
  const text = await readEvidenceText(c.env.EVIDENCE, ev);
  await audit(c.env.DB, { tenantId: user.tenantId, actor: user.userId, action: 'evidence.download', target: ev.id });
  return new Response(text, {
    headers: {
      'Content-Type': 'text/plain; charset=utf-8',
      'Content-Disposition': `attachment; filename="redacted-${ev.original_filename}"`,
      'X-Content-Type-Options': 'nosniff',
      'Cache-Control': 'no-store',
    },
  });
});

app.post('/app/evidence/:id/delete', async (c) => {
  const { user } = await guardPost(c);
  if (user.role !== 'admin') throw new Forbidden('Only admins can delete evidence.');
  const ev = await getEvidence(c.env.DB, user.tenantId, c.req.param('id'));
  if (!ev) throw new NotFound();
  await deleteEvidence(c.env.DB, c.env.EVIDENCE, user.tenantId, user.userId, ev.id);
  return redirectWith(c, `/app/incidents/${ev.incident_id}`, { flash: 'Evidence deleted.' });
});

app.post('/app/incidents/:id/investigate', async (c) => {
  const { user, body } = await guardPost(c);
  const id = c.req.param('id');
  await limit(c, `investigate:${user.tenantId}`, 30, 3600);
  let provider = localRulesProvider;
  if (str(body, 'provider', 20) === 'external') {
    if (!user.externalModelEnabled || !externalModelConfigured(c.env)) {
      return redirectWith(c, `/app/incidents/${id}`, { error: 'External model is not enabled for this workspace.' });
    }
    if (str(body, 'consent', 5) !== 'yes') {
      return redirectWith(c, `/app/incidents/${id}`, { error: 'Confirm that redacted evidence may be sent to the external model.' });
    }
    await limit(c, `investigate-ext:${user.tenantId}`, 10, 3600);
    provider = externalModelProvider(c.env);
  }
  const invId = await runInvestigation(c.env.DB, c.env.EVIDENCE, user.tenantId, user.userId, id, provider);
  return redirectWith(c, `/app/incidents/${id}#${invId}`, { flash: 'Investigation finished.' });
});

app.get('/app/investigations/:id', async (c) => {
  const user = requireUser(c);
  const d = await getInvestigationDetail(c.env.DB, user.tenantId, c.req.param('id'));
  if (!d) throw new NotFound();
  const ev = await listEvidence(c.env.DB, user.tenantId, d.inv.incident_id);
  return c.html(<InvestigationPage user={user} latest={d} evLabel={new Map(ev.map((e) => [e.id, e.label]))} />);
});

app.post('/app/claims/:id/draft', async (c) => {
  const { user } = await guardPost(c);
  const draftId = await createDraft(c.env.DB, user.tenantId, user.userId, c.req.param('id'));
  const d = await c.env.DB.prepare('SELECT incident_id FROM remediation_drafts WHERE tenant_id = ? AND id = ?').bind(user.tenantId, draftId).first<{ incident_id: string }>();
  return redirectWith(c, `/app/incidents/${d!.incident_id}`, { flash: 'Remediation draft created. An admin must approve it.' });
});

app.post('/app/drafts/:id/decision', async (c) => {
  const { user, body } = await guardPost(c);
  const id = c.req.param('id');
  const d = await c.env.DB.prepare('SELECT incident_id FROM remediation_drafts WHERE tenant_id = ? AND id = ?').bind(user.tenantId, id).first<{ incident_id: string }>();
  if (!d) throw new NotFound();
  try {
    await decideDraft(c.env.DB, user.tenantId, user, id, str(body, 'decision', 20), str(body, 'reason', 1000));
  } catch (e) {
    if (e instanceof BadRequest) return redirectWith(c, `/app/incidents/${d.incident_id}`, { error: e.message });
    throw e;
  }
  return redirectWith(c, `/app/incidents/${d.incident_id}`, { flash: 'Decision recorded.' });
});

app.post('/app/drafts/:id/checks', async (c) => {
  const { user } = await guardPost(c);
  const id = c.req.param('id');
  const d = await c.env.DB.prepare('SELECT incident_id FROM remediation_drafts WHERE tenant_id = ? AND id = ?').bind(user.tenantId, id).first<{ incident_id: string }>();
  if (!d) throw new NotFound();
  try {
    await runChecks(c.env.DB, c.env.EVIDENCE, user.tenantId, user.userId, id);
  } catch (e) {
    if (e instanceof BadRequest) return redirectWith(c, `/app/incidents/${d.incident_id}`, { error: e.message });
    throw e;
  }
  return redirectWith(c, `/app/incidents/${d.incident_id}`, { flash: 'Checks recorded.' });
});

app.get('/app/incidents/:id/report.md', async (c) => {
  const user = requireUser(c);
  const report = await buildReport(c.env.DB, user.tenantId, c.req.param('id'));
  if (!report) throw new NotFound();
  await audit(c.env.DB, { tenantId: user.tenantId, actor: user.userId, action: 'report.export', target: c.req.param('id') });
  return new Response(report, {
    headers: {
      'Content-Type': 'text/markdown; charset=utf-8',
      'Content-Disposition': `attachment; filename="northcause-${c.req.param('id')}.md"`,
      'X-Content-Type-Options': 'nosniff',
      'Cache-Control': 'no-store',
    },
  });
});

app.get('/app/audit', async (c) => {
  const user = requireUser(c);
  const [rows, chain] = await Promise.all([listAudit(c.env.DB, user.tenantId), verifyAuditChain(c.env.DB, user.tenantId)]);
  return c.html(<AuditPage user={user} rows={rows} chain={chain} />);
});

app.get('/app/settings', (c) =>
  c.html(<SettingsPage user={requireUser(c)} externalConfigured={externalModelConfigured(c.env)} {...msgs(c)} />),
);

app.post('/app/settings/external-model', async (c) => {
  const { user, body } = await guardPost(c);
  if (user.role !== 'admin') throw new Forbidden('Only admins can change this setting.');
  if (user.tenantKind === 'sandbox') throw new Forbidden('Not available in the sandbox.');
  const enabled = str(body, 'enabled', 5) === 'yes';
  await setExternalModel(c.env.DB, user.tenantId, enabled);
  await audit(c.env.DB, { tenantId: user.tenantId, actor: user.userId, action: 'settings.external_model', target: user.tenantId, metadata: { enabled } });
  return redirectWith(c, '/app/settings', { flash: `External model ${enabled ? 'enabled' : 'disabled'}.` });
});

/**
 * The GitHub token is an operator-level secret, so a workspace may only import from repositories
 * the operator has allow-listed for that workspace (integrations.config = {"repos":["owner/repo"]}).
 * Sandbox workspaces can never use it.
 */
async function allowedRepos(c: Context<AppEnv>, user: SessionUser): Promise<string[]> {
  if (user.tenantKind !== 'pilot' || !c.env.GITHUB_TOKEN) return [];
  const row = await c.env.DB.prepare("SELECT config FROM integrations WHERE tenant_id = ? AND kind = 'github_actions'")
    .bind(user.tenantId)
    .first<{ config: string }>();
  try {
    const repos = (JSON.parse(row?.config ?? '{}') as { repos?: unknown }).repos;
    return Array.isArray(repos) ? repos.filter((r): r is string => typeof r === 'string' && /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(r)) : [];
  } catch {
    return [];
  }
}

app.get('/app/integrations', async (c) => {
  const user = requireUser(c);
  const repos = await allowedRepos(c, user);
  return c.html(
    <IntegrationsPage
      user={user}
      githubStatus={repos.length ? 'configured_unverified' : 'not_connected'}
      repos={repos}
      incidents={await listIncidents(c.env.DB, user.tenantId)}
      {...msgs(c)}
    />,
  );
});

app.post('/app/integrations/github/import', async (c) => {
  const { user, body } = await guardPost(c);
  const adapter = githubActionsAdapter(c.env);
  const repos = await allowedRepos(c, user);
  if (adapter.status() === 'not_connected' || !repos.length) return redirectWith(c, '/app/integrations', { error: 'GitHub Actions is not connected.' });
  if (user.role !== 'admin') throw new Forbidden('Only admins can import from integrations.');
  const full = str(body, 'repo', 201);
  const [owner = '', repo = ''] = full.split('/');
  const incidentId = str(body, 'incident', 60);
  if (!repos.includes(full) || !validRepoRef(owner, repo)) return redirectWith(c, '/app/integrations', { error: 'That repository is not enabled for this workspace.' });
  if (!(await getIncident(c.env.DB, user.tenantId, incidentId))) throw new NotFound();
  await limit(c, `gh-import:${user.tenantId}`, 20, 3600);
  let runs;
  try {
    runs = await adapter.listRecentRuns(owner, repo);
  } catch {
    return redirectWith(c, '/app/integrations', { error: 'GitHub request failed. Check the token scope and repository name.' });
  }
  if (!runs.length) return redirectWith(c, '/app/integrations', { error: 'No workflow runs found.' });
  await addEvidence(
    c.env.DB, c.env.EVIDENCE, user.tenantId, user.userId, incidentId,
    { name: 'github-actions-runs.ndjson', type: 'application/x-ndjson', bytes: new TextEncoder().encode(runsToNdjson(runs, owner, repo)) },
    { label: `GitHub Actions runs: ${owner}/${repo}`, phase: 'incident', source: 'github_actions' },
  );
  return redirectWith(c, `/app/incidents/${incidentId}`, { flash: `Imported ${runs.length} workflow runs.` });
});

// ================= Errors =================

app.notFound((c) => c.html(<ErrorPage status={404} message="This page does not exist." />, 404));

app.onError((err, c) => {
  if (err instanceof Unauthenticated) return c.redirect('/login', 303);
  if (err instanceof NotFound) return c.html(<ErrorPage status={404} message="Not found." />, 404);
  if (err instanceof Forbidden) return c.html(<ErrorPage status={403} message={err.message || 'Not allowed.'} />, 403);
  if (err instanceof CsrfError) return c.html(<ErrorPage status={403} message="Your session form token was invalid. Reload the page and try again." />, 403);
  if (err instanceof RateLimited) return c.html(<ErrorPage status={429} message="Too many requests. Please wait and try again." />, 429);
  if (err instanceof BadRequest) return c.html(<ErrorPage status={400} message={err.message} />, 400);
  const requestId = c.get('requestId');
  // Log the error class and a short message only — never request bodies, cookies or evidence.
  console.error('unhandled_error', { requestId, path: c.req.path, name: err.name });
  return c.html(<ErrorPage status={500} message="An unexpected error occurred." requestId={requestId} />, 500);
});
