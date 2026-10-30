import type { SessionUser } from '../env';
import type { AuditRow } from '../lib/audit';
import { MAX_EVIDENCE_BYTES } from '../lib/evidence-validate';
import type {
  CitationRow,
  ClaimRow,
  DraftRow,
  EvidenceRow,
  Incident,
  InvestigationRow,
  TimelineRow,
} from '../services/workflow';
import { SEVERITIES, STATUSES } from '../services/workflow';
import { AppLayout, Badge, Csrf } from './layout';

type Msg = { flash?: string; error?: string };

const supportKind = { supported: 'supported', uncertain: 'uncertain', unsupported: 'unsupported' } as const;

export function IncidentListPage(props: { user: SessionUser; incidents: Incident[] } & Msg) {
  return (
    <AppLayout title="Incidents" user={props.user} flash={props.flash} error={props.error}>
      <div class="page-head">
        <h1>Incidents</h1>
        <a class="btn btn-primary" href="/app/incidents/new">New incident</a>
      </div>
      {props.incidents.length === 0 ? (
        <div class="panel empty">
          <p>No incidents yet. Create one and upload the evidence you are authorised to share.</p>
        </div>
      ) : (
        <div class="table-wrap">
          <table>
            <thead>
              <tr><th>Title</th><th>Service</th><th>Severity</th><th>Status</th><th>Created (UTC)</th></tr>
            </thead>
            <tbody>
              {props.incidents.map((i) => (
                <tr>
                  <td><a href={`/app/incidents/${i.id}`}>{i.title}</a></td>
                  <td><code>{i.service}</code></td>
                  <td><Badge kind={i.severity}>{i.severity.toUpperCase()}</Badge></td>
                  <td>{i.status}</td>
                  <td class="mono small">{i.created_at.replace('T', ' ').slice(0, 19)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </AppLayout>
  );
}

export function NewIncidentPage(props: { user: SessionUser } & Msg) {
  return (
    <AppLayout title="New incident" user={props.user} error={props.error}>
      <h1>New incident</h1>
      <form method="post" action="/app/incidents" class="form narrow">
        <Csrf user={props.user} />
        <label>Title<input name="title" required maxlength={160} /></label>
        <label>Service<input name="service" required maxlength={80} placeholder="e.g. checkout-api" /></label>
        <label>Severity
          <select name="severity">{SEVERITIES.map((s) => <option value={s}>{s.toUpperCase()}</option>)}</select>
        </label>
        <label>Summary (optional)<textarea name="summary" maxlength={2000} rows={4}></textarea></label>
        <button class="btn btn-primary" type="submit">Create incident</button>
      </form>
    </AppLayout>
  );
}

function shortTs(s: string) {
  return s.replace('T', ' ').slice(0, 19);
}

export function IncidentDetailPage(props: {
  user: SessionUser;
  incident: Incident;
  evidence: EvidenceRow[];
  timeline: TimelineRow[];
  investigations: InvestigationRow[];
  latest: { inv: InvestigationRow; claims: ClaimRow[]; citations: CitationRow[] } | null;
  drafts: DraftRow[];
  approvals: Array<{ draft_id: string; decision: string; reason: string; display_name: string | null; created_at: string }>;
  checks: Array<{ draft_id: string; check_name: string; result: string; detail: string; evidence_ids: string; created_at: string }>;
  externalAvailable: boolean;
  githubConnected: boolean;
} & Msg) {
  const { user, incident: inc } = props;
  const evLabel = new Map(props.evidence.map((e) => [e.id, e.label]));
  return (
    <AppLayout title={inc.title} user={user} flash={props.flash} error={props.error}>
      <p class="crumbs"><a href="/app">Incidents</a> / <span class="mono">{inc.id}</span></p>
      <div class="page-head">
        <div>
          <h1>{inc.title}</h1>
          <p class="muted">
            <code>{inc.service}</code> · <Badge kind={inc.severity}>{inc.severity.toUpperCase()}</Badge> · status {inc.status} · created {shortTs(inc.created_at)} UTC
          </p>
        </div>
        <div class="actions">
          <a class="btn btn-secondary" href={`/app/incidents/${inc.id}/report.md`}>Export report (.md)</a>
          <form method="post" action={`/app/incidents/${inc.id}/status`} class="inline">
            <Csrf user={user} />
            <label class="sr-only" for="status">Status</label>
            <select id="status" name="status">{STATUSES.map((s) => <option value={s} selected={s === inc.status}>{s}</option>)}</select>
            <button class="btn btn-ghost" type="submit">Update</button>
          </form>
        </div>
      </div>
      {inc.summary && <p>{inc.summary}</p>}

      <section class="section-sm">
        <h2>1 · Evidence</h2>
        {props.evidence.length > 0 && (
          <div class="table-wrap">
            <table>
              <thead><tr><th>ID</th><th>Label</th><th>Phase</th><th>Format</th><th>Lines</th><th>Redacted</th><th>Flags</th><th></th></tr></thead>
              <tbody>
                {props.evidence.map((e) => (
                  <tr id={e.id}>
                    <td class="mono small"><a href={`/app/evidence/${e.id}`}>{e.id}</a></td>
                    <td>{e.label}</td>
                    <td>{e.phase === 'post_fix' ? 'post-fix' : 'incident'}</td>
                    <td>{e.format}</td>
                    <td>{e.line_count}</td>
                    <td>{e.secrets_redacted}</td>
                    <td>{e.injection_flags > 0 ? <Badge kind="warn">{`${e.injection_flags} injection-like`}</Badge> : '—'}</td>
                    <td>
                      {user.role === 'admin' && (
                        <form method="post" action={`/app/evidence/${e.id}/delete`} class="inline">
                          <Csrf user={user} />
                          <button class="btn btn-link" type="submit" aria-label={`Delete ${e.label}`}>Delete</button>
                        </form>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        <form method="post" action={`/app/incidents/${inc.id}/evidence`} enctype="multipart/form-data" class="form upload">
          <Csrf user={user} />
          <label>File (≤ {MAX_EVIDENCE_BYTES / 1024 / 1024} MiB: .log .txt .json .ndjson .jsonl .csv .yaml .yml)
            <input type="file" name="file" required accept=".log,.txt,.json,.ndjson,.jsonl,.csv,.yaml,.yml" />
          </label>
          <label>Label<input name="label" maxlength={120} placeholder="e.g. Pod events 10:00–10:30" /></label>
          <label>Phase
            <select name="phase"><option value="incident">Incident</option><option value="post_fix">Post-fix</option></select>
          </label>
          <p class="muted small">Upload only data you are authorised to share. Secrets are redacted before storage; content is treated as untrusted data.</p>
          <button class="btn btn-primary" type="submit">Upload evidence</button>
        </form>
        <div class="panel muted small">
          GitHub Actions import: {props.githubConnected ? <a href="/app/integrations">configured — import from Integrations</a> : 'not connected'}.
        </div>
      </section>

      <section class="section-sm">
        <h2>2 · Timeline <span class="muted small">(UTC)</span></h2>
        {props.timeline.length === 0 ? (
          <p class="muted">No timestamped events yet.</p>
        ) : (
          <ol class="timeline">
            {props.timeline.slice(0, 300).map((t) => (
              <li class={`tl tl-${t.kind}`}>
                <span class="mono small">{shortTs(t.occurred_at)}</span>
                <Badge kind={t.kind}>{t.kind}</Badge>
                <span class="tl-text">{t.summary}</span>
                <a class="mono small" href={`/app/evidence/${t.evidence_id}#L${t.line_no}`}>{`${t.evidence_id} L${t.line_no}`}</a>
              </li>
            ))}
          </ol>
        )}
      </section>

      <section class="section-sm">
        <h2>3 · Investigation</h2>
        <form method="post" action={`/app/incidents/${inc.id}/investigate`} class="form inline-form">
          <Csrf user={user} />
          <fieldset>
            <legend>Provider</legend>
            <label class="radio"><input type="radio" name="provider" value="local" checked /> Local rule-based analysis (not an AI model; nothing leaves Northcause)</label>
            {props.externalAvailable ? (
              <>
                <label class="radio"><input type="radio" name="provider" value="external" /> External model</label>
                <label class="check"><input type="checkbox" name="consent" value="yes" /> I understand redacted evidence for this incident will be sent to the configured external model provider.</label>
              </>
            ) : (
              <p class="muted small">External model: not available (disabled for this workspace or not configured by the operator).</p>
            )}
          </fieldset>
          <button class="btn btn-primary" type="submit">Run investigation</button>
        </form>

        {props.latest ? (
          <InvestigationResult user={user} latest={props.latest} evLabel={evLabel} />
        ) : (
          <p class="muted">No investigation yet.</p>
        )}
        {props.investigations.length > 1 && (
          <details>
            <summary>Earlier investigations ({props.investigations.length - 1})</summary>
            <ul>
              {props.investigations.slice(1).map((i) => (
                <li><a href={`/app/investigations/${i.id}`}>{shortTs(i.created_at)} · {i.provider_label} · {i.status}</a></li>
              ))}
            </ul>
          </details>
        )}
      </section>

      <section class="section-sm">
        <h2>4 · Remediation, approval and proof</h2>
        {props.drafts.length === 0 && <p class="muted">No drafts. Create one from a supported or uncertain hypothesis above.</p>}
        {props.drafts.map((d) => {
          const steps = JSON.parse(d.steps) as string[];
          const checks = JSON.parse(d.checks) as Array<{ name: string }>;
          return (
            <article class="panel draft">
              <div class="card-head">
                <h3>{d.title}</h3>
                <Badge kind={d.status}>{d.status.toUpperCase()}</Badge>
              </div>
              <p class="muted small">Draft only. Northcause does not execute changes. Carry out approved steps through your own change process.</p>
              <ol>{steps.map((s) => <li>{s}</li>)}</ol>
              <p class="small"><strong>Configured checks:</strong> {checks.length ? checks.map((c) => c.name).join('; ') : 'none (manual review)'}</p>
              {props.approvals.filter((a) => a.draft_id === d.id).map((a) => (
                <p class="small">Decision: <strong>{a.decision}</strong> by {a.display_name ?? 'unknown'} at {shortTs(a.created_at)} UTC — “{a.reason}”</p>
              ))}
              {d.status === 'draft' && (user.role === 'admin' ? (
                <form method="post" action={`/app/drafts/${d.id}/decision`} class="form inline-form">
                  <Csrf user={user} />
                  <label>Reason (required)<input name="reason" required minlength={5} maxlength={1000} /></label>
                  <div class="cta-row">
                    <button class="btn btn-primary" name="decision" value="approved" type="submit">Approve draft</button>
                    <button class="btn btn-secondary" name="decision" value="rejected" type="submit">Reject</button>
                  </div>
                </form>
              ) : (
                <p class="muted small">Waiting for a workspace admin to approve or reject.</p>
              ))}
              {d.status === 'approved' && (
                <div class="cta-row">
                  {user.tenantKind === 'sandbox' && (
                    <form method="post" action={`/app/incidents/${inc.id}/sample-post-fix`} class="inline">
                      <Csrf user={user} />
                      <button class="btn btn-ghost" type="submit">Add sample post-fix evidence (demo)</button>
                    </form>
                  )}
                  <form method="post" action={`/app/drafts/${d.id}/checks`} class="inline">
                    <Csrf user={user} />
                    <button class="btn btn-secondary" type="submit">Run checks on post-fix evidence</button>
                  </form>
                </div>
              )}
              {d.status === 'approved' && <p class="muted small">Checks use only post-fix evidence uploaded after this approval.</p>}
              {props.checks.filter((c) => c.draft_id === d.id).map((c) => (
                <p class="small">
                  <Badge kind={c.result}>{c.result.toUpperCase()}</Badge> {c.check_name} — {c.detail}{' '}
                  <span class="mono">{(JSON.parse(c.evidence_ids) as string[]).join(', ')}</span> <span class="muted">({shortTs(c.created_at)} UTC)</span>
                </p>
              ))}
            </article>
          );
        })}
      </section>

      {user.role === 'admin' && (
        <section class="section-sm danger-zone">
          <h2>Delete incident</h2>
          <p class="muted small">Deletes the incident, its evidence objects, timeline, investigations and drafts. Audit events are kept.</p>
          <form method="post" action={`/app/incidents/${inc.id}/delete`}>
            <Csrf user={user} />
            <label class="check"><input type="checkbox" name="confirm" value="yes" required /> I understand this cannot be undone.</label>
            <button class="btn btn-danger" type="submit">Delete incident</button>
          </form>
        </section>
      )}
    </AppLayout>
  );
}

export function InvestigationResult(props: {
  user: SessionUser;
  latest: { inv: InvestigationRow; claims: ClaimRow[]; citations: CitationRow[] };
  evLabel: Map<string, string>;
}) {
  const { inv, claims, citations } = props.latest;
  const hyps = claims.filter((c) => c.kind === 'hypothesis');
  const risks = claims.filter((c) => c.kind === 'risk');
  return (
    <div class="investigation">
      <p class="small">
        <Badge kind={inv.status}>{inv.status.replace('_', ' ').toUpperCase()}</Badge> {inv.provider_label}
        {inv.external_model_used ? ' · external model used' : ' · no external model'} · {shortTs(inv.created_at)} UTC ·{' '}
        <a href={`/app/investigations/${inv.id}`} class="mono">{inv.id}</a>
      </p>
      <p class="muted">{inv.notes}</p>
      {hyps.length > 0 && <h3>Ranked hypotheses</h3>}
      {hyps.map((c) => <ClaimCard user={props.user} claim={c} citations={citations.filter((x) => x.claim_id === c.id)} evLabel={props.evLabel} />)}
      {risks.length > 0 && <h3>Security and policy risks</h3>}
      {risks.map((c) => <ClaimCard user={props.user} claim={c} citations={citations.filter((x) => x.claim_id === c.id)} evLabel={props.evLabel} />)}
    </div>
  );
}

function ClaimCard(props: { user: SessionUser; claim: ClaimRow; citations: CitationRow[]; evLabel: Map<string, string> }) {
  const c = props.claim;
  return (
    <article class={`panel claim-card claim-${c.support}`}>
      <div class="card-head">
        <Badge kind={supportKind[c.support]}>{c.support.toUpperCase()}</Badge>
        <span class="muted small">{c.kind === 'hypothesis' ? `Hypothesis ${c.rank}` : `Risk ${c.rank}`} · {c.category} · confidence {c.confidence}</span>
      </div>
      <p class="claim">{c.statement}</p>
      {props.citations.length === 0 ? (
        <p class="small notice-err">No valid evidence citation. Treat this claim as unsupported.</p>
      ) : (
        <ul class="citations">
          {props.citations.map((x) => (
            <li>
              <a class="mono small" href={`/app/evidence/${x.evidence_id}${x.line_no ? `#L${x.line_no}` : ''}`}>
                {x.evidence_id}{x.line_no ? ` L${x.line_no}` : ''}
              </a>{' '}
              <span class="muted small">{props.evLabel.get(x.evidence_id) ?? ''}</span>
              <pre class="code"><code>{x.excerpt}</code></pre>
            </li>
          ))}
        </ul>
      )}
      {c.kind === 'hypothesis' && c.support !== 'unsupported' && (
        <form method="post" action={`/app/claims/${c.id}/draft`} class="inline">
          <Csrf user={props.user} />
          <button class="btn btn-ghost" type="submit">Create remediation draft</button>
        </form>
      )}
    </article>
  );
}

export function EvidencePage(props: { user: SessionUser; ev: EvidenceRow; text: string }) {
  const lines = props.text.split(/\r?\n/);
  return (
    <AppLayout title={props.ev.label} user={props.user}>
      <p class="crumbs"><a href="/app">Incidents</a> / <a href={`/app/incidents/${props.ev.incident_id}`}>{props.ev.incident_id}</a> / <span class="mono">{props.ev.id}</span></p>
      <h1>{props.ev.label}</h1>
      <p class="muted small">
        {props.ev.original_filename} · {props.ev.format} · {props.ev.size_bytes} bytes · SHA-256 <span class="mono">{props.ev.sha256}</span> · {props.ev.secrets_redacted} redaction(s) · source {props.ev.source}
      </p>
      {props.ev.injection_flags > 0 && (
        <p class="notice notice-warn" role="note">This file contains {props.ev.injection_flags} line(s) that look like instructions to an AI system. They are shown as data and were never followed.</p>
      )}
      <p><a class="btn btn-ghost" href={`/app/evidence/${props.ev.id}/download`}>Download redacted copy</a></p>
      <div class="viewer" role="region" aria-label="Evidence content">
        {lines.map((l, i) => (
          <div class="line" id={`L${i + 1}`}>
            <a class="ln" href={`#L${i + 1}`}>{i + 1}</a>
            <code>{l}</code>
          </div>
        ))}
      </div>
    </AppLayout>
  );
}

export function InvestigationPage(props: { user: SessionUser; latest: { inv: InvestigationRow; claims: ClaimRow[]; citations: CitationRow[] }; evLabel: Map<string, string> }) {
  return (
    <AppLayout title="Investigation" user={props.user}>
      <p class="crumbs"><a href="/app">Incidents</a> / <a href={`/app/incidents/${props.latest.inv.incident_id}`}>{props.latest.inv.incident_id}</a> / <span class="mono">{props.latest.inv.id}</span></p>
      <h1>Investigation</h1>
      <InvestigationResult user={props.user} latest={props.latest} evLabel={props.evLabel} />
    </AppLayout>
  );
}

export function AuditPage(props: { user: SessionUser; rows: AuditRow[]; chain: { ok: boolean; checked: number; brokenAt?: number } }) {
  return (
    <AppLayout title="Audit log" user={props.user}>
      <h1>Audit log</h1>
      <p class={props.chain.ok ? 'notice notice-ok' : 'notice notice-err'} role="status">
        {props.chain.ok
          ? `Hash chain verified across ${props.chain.checked} event(s).`
          : `Hash chain check FAILED at event #${props.chain.brokenAt}. Contact support.`}
      </p>
      <p class="muted small">Append-only. Events record identifiers and counts, never evidence content or secrets.</p>
      <div class="table-wrap">
        <table>
          <thead><tr><th>#</th><th>Time (UTC)</th><th>Actor</th><th>Action</th><th>Target</th><th>Details</th></tr></thead>
          <tbody>
            {props.rows.map((r) => (
              <tr>
                <td class="mono small">{r.seq}</td>
                <td class="mono small">{shortTs(r.created_at)}</td>
                <td class="mono small">{r.actor}</td>
                <td>{r.action}</td>
                <td class="mono small">{r.target}</td>
                <td class="mono small">{r.metadata}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </AppLayout>
  );
}

export function SettingsPage(props: { user: SessionUser; externalConfigured: boolean } & Msg) {
  const u = props.user;
  return (
    <AppLayout title="Settings" user={u} flash={props.flash} error={props.error}>
      <h1>Workspace settings</h1>
      <section class="panel">
        <h2>External model</h2>
        <p>
          Status for this workspace: <strong>{u.externalModelEnabled ? 'enabled' : 'disabled'}</strong>. Operator configuration:{' '}
          <strong>{props.externalConfigured ? 'model endpoint configured' : 'not configured'}</strong>.
        </p>
        <p class="muted small">
          When enabled, users can choose to send redacted evidence for an incident to the configured model provider. Each run requires
          explicit confirmation and is recorded in the audit log. Redaction is pattern-based and may miss unusual secret formats.
        </p>
        {u.role === 'admin' && u.tenantKind === 'pilot' ? (
          <form method="post" action="/app/settings/external-model" class="inline">
            <Csrf user={u} />
            <input type="hidden" name="enabled" value={u.externalModelEnabled ? 'no' : 'yes'} />
            <button class="btn btn-secondary" type="submit">{u.externalModelEnabled ? 'Disable external model' : 'Enable external model'}</button>
          </form>
        ) : (
          <p class="muted small">{u.tenantKind === 'sandbox' ? 'Not available in the sandbox.' : 'Only admins can change this.'}</p>
        )}
      </section>
      <section class="panel">
        <h2>Retention</h2>
        <p>Evidence is deleted automatically {u.tenantKind === 'sandbox' ? 'when the sandbox expires (24 hours)' : `after ${u.retentionDays} days`}. Admins can delete evidence or whole incidents at any time. Audit events are retained.</p>
      </section>
    </AppLayout>
  );
}

export function IntegrationsPage(props: {
  user: SessionUser;
  githubStatus: 'not_connected' | 'configured_unverified';
  repos: string[];
  incidents: Incident[];
} & Msg) {
  return (
    <AppLayout title="Integrations" user={props.user} flash={props.flash} error={props.error}>
      <h1>Integrations</h1>
      <section class="panel">
        <div class="card-head">
          <h2>GitHub Actions (read-only)</h2>
          {props.githubStatus === 'not_connected' ? <Badge kind="muted">NOT CONNECTED</Badge> : <Badge kind="warn">CONFIGURED · UNVERIFIED</Badge>}
        </div>
        <p class="muted small">Imports recent workflow runs as evidence so CI and deploy events appear on the timeline. Only GET requests are made. The operator configures a read-only token and enables specific repositories for this workspace. "Unverified" means no import has been attempted with it yet.</p>
        {props.githubStatus === 'configured_unverified' && props.incidents.length > 0 && props.user.role === 'admin' && (
          <form method="post" action="/app/integrations/github/import" class="form inline-form">
            <Csrf user={props.user} />
            <label>Repository
              <select name="repo">{props.repos.map((r) => <option value={r}>{r}</option>)}</select>
            </label>
            <label>Into incident
              <select name="incident">{props.incidents.map((i) => <option value={i.id}>{i.title}</option>)}</select>
            </label>
            <button class="btn btn-secondary" type="submit">Import recent runs</button>
          </form>
        )}
      </section>
      <section class="panel">
        <div class="card-head">
          <h2>OpenTelemetry</h2>
          <Badge kind="muted">NOT CONNECTED</Badge>
        </div>
        <p class="muted small">Live OTLP ingestion is not built yet. Export logs as NDJSON and upload them as evidence.</p>
      </section>
    </AppLayout>
  );
}
