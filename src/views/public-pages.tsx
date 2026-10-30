import { BRAND_LINE, PublicLayout } from './layout';

const steps = [
  ['Ingest', 'Upload logs, Kubernetes events, CI output and change history you are authorised to share. Secrets are redacted on arrival.'],
  ['Correlate', 'Timestamped lines become one incident timeline, so a deploy and the first error sit side by side.'],
  ['Hypothesise', 'Ranked hypotheses, each linked to the exact evidence lines behind it. No citation, no claim.'],
  ['Assess risk', 'Security and policy risks found in the evidence, including prompt-injection text and leaked credentials.'],
  ['Draft the fix', 'A remediation draft for a human to review. Northcause never runs commands or changes your systems.'],
  ['Approve', 'An admin approves or rejects with a reason. Every decision lands in an append-only audit log.'],
  ['Prove it', 'Upload post-fix evidence and run checks that confirm the failure signal is gone — or show that it is not.'],
];

export function HomePage(props: { sandboxEnabled: boolean }) {
  return (
    <PublicLayout title="Evidence-led AI operations assurance">
      <section class="hero">
        <div class="wrap hero-grid">
          <div>
            <p class="eyebrow">Pilot · AI operations assurance</p>
            <h1>{BRAND_LINE}</h1>
            <p class="lead">
              Northcause helps teams investigate failures across LLM apps, RAG pipelines, agents, CI/CD, Kubernetes, cloud and GPU
              infrastructure — with every finding tied to the evidence that supports it.
            </p>
            <div class="cta-row">
              {props.sandboxEnabled && (
                <form method="post" action="/sandbox">
                  <button class="btn btn-primary" type="submit">Try the sandbox</button>
                </form>
              )}
              <a class="btn btn-secondary" href="/contact">Talk to us about a pilot</a>
            </div>
            <p class="muted small">The sandbox uses synthetic sample data and is deleted within 24 hours.</p>
          </div>
          <div class="hero-card" aria-label="Example finding">
            <div class="card-head">
              <span class="badge badge-supported">SUPPORTED</span>
              <span class="muted small">Hypothesis 1 · confidence high</span>
            </div>
            <p class="claim">Containers were killed for exceeding memory limits. First seen 2 min after a deploy event.</p>
            <pre class="code"><code>{'ev_…3f  L2  OOMKilled (exit code 137)\nev_…a9  L3  rollout status 3/6 replicas updated'}</code></pre>
            <p class="muted small">Example from the synthetic sandbox incident.</p>
          </div>
        </div>
      </section>

      <section class="wrap section">
        <h2>How it works</h2>
        <ol class="steps">
          {steps.map(([t, d], i) => (
            <li class="step">
              <span class="step-n">{i + 1}</span>
              <div>
                <h3>{t}</h3>
                <p>{d}</p>
              </div>
            </li>
          ))}
        </ol>
      </section>

      <section class="wrap section grid-3">
        <div class="panel">
          <h3>Evidence first</h3>
          <p>Every claim cites evidence IDs and lines checked by the server. Claims without a valid citation are labelled unsupported.</p>
        </div>
        <div class="panel">
          <h3>Says “not enough evidence”</h3>
          <p>When the evidence does not show the cause, Northcause says so instead of guessing.</p>
        </div>
        <div class="panel">
          <h3>Humans approve</h3>
          <p>Remediation stays a draft until an admin decides. There is no execution path in the product.</p>
        </div>
      </section>
    </PublicLayout>
  );
}

export function ProductPage() {
  return (
    <PublicLayout title="Product" active="/product">
      <section class="wrap section prose">
        <h1>Product</h1>
        <p class="lead">What the pilot does today, and what it does not.</p>
        <h2>Available in the pilot</h2>
        <ul>
          <li>Incidents: create, list, update status, delete.</li>
          <li>Evidence upload: .log, .txt, .json, .ndjson/.jsonl, .csv, .yaml/.yml up to 2 MiB per file, 25 files per incident. Secrets are redacted before storage; the SHA-256 of the original upload is kept.</li>
          <li>Incident timeline built from timestamped lines and JSON fields.</li>
          <li>Investigations with ranked hypotheses and security/policy risks. Each claim is labelled supported, uncertain or unsupported based on server-checked citations.</li>
          <li>Two investigation providers: a local rule-based analyser (not an AI model, always available) and an optional external model reached through a server-side API key, used only after an admin opts in and the user confirms each run.</li>
          <li>Remediation drafts, admin approval or rejection with a reason, and post-fix checks against post-fix evidence uploaded after the approval.</li>
          <li>Append-only, hash-chained audit log; Markdown incident report export.</li>
          <li>Read-only GitHub Actions adapter. It shows “not connected” unless an operator configures a token and enables specific repositories for your workspace.</li>
        </ul>
        <h2>Not in the pilot</h2>
        <ul>
          <li>No automated remediation, shell execution or changes to your systems.</li>
          <li>No live streaming ingestion yet (OpenTelemetry ingestion is planned; today you upload exported files).</li>
          <li>No SSO/SAML yet; pilot accounts use email and password issued by us.</li>
          <li>The local analyser recognises a fixed set of failure signatures; unfamiliar failures return “insufficient evidence”.</li>
        </ul>
      </section>
    </PublicLayout>
  );
}

export function SecurityPage() {
  return (
    <PublicLayout title="Security" active="/security">
      <section class="wrap section prose">
        <h1>Security</h1>
        <p class="lead">Controls that are implemented in the pilot today. We hold no third-party certifications yet.</p>
        <h2>Data handling</h2>
        <ul>
          <li>Evidence is treated as untrusted data. Instructions found inside evidence are never followed or executed; text that looks like prompt injection is flagged.</li>
          <li>Common secrets (API keys, tokens, private keys, passwords in key=value form, emails, card numbers) are redacted before storage. Pattern-based redaction can miss formats it does not know — please scrub highly sensitive data before upload.</li>
          <li>Evidence is stored in Cloudflare R2 under server-generated keys; metadata in Cloudflare D1.</li>
          <li>Default evidence retention: 30 days for pilot workspaces, then deletion. Sandbox workspaces are deleted within 24 hours. You can delete evidence or incidents at any time.</li>
        </ul>
        <h2>External models</h2>
        <ul>
          <li>Off by default. A workspace admin must opt in, and each run asks the user to confirm.</li>
          <li>Redacted evidence is sent to the configured model endpoint. API keys live only in server-side secrets.</li>
          <li>Model output is untrusted: citations that do not match stored evidence are discarded and uncited claims are marked unsupported.</li>
        </ul>
        <h2>Application controls</h2>
        <ul>
          <li>Tenant isolation enforced in every server-side query; cross-tenant IDs return “not found”.</li>
          <li>Session cookies: HttpOnly, Secure, SameSite=Strict, host-only. Passwords hashed with PBKDF2-SHA256.</li>
          <li>CSRF tokens on every workspace form; every state-changing request must pass an Origin / Sec-Fetch-Site same-origin check. Strict Content Security Policy; no third-party scripts.</li>
          <li>Rate limits on failed sign-ins, sandbox creation, uploads, investigations and the contact form.</li>
          <li>Append-only audit events with a hash chain you can verify in the workspace.</li>
        </ul>
        <p>Report a vulnerability through the <a href="/contact">contact page</a>. Full threat model: <code>docs/THREAT_MODEL.md</code> in the repository.</p>
      </section>
    </PublicLayout>
  );
}

export function DocsPage() {
  return (
    <PublicLayout title="Docs" active="/docs">
      <section class="wrap section prose">
        <h1>Docs</h1>
        <h2>Quick start</h2>
        <ol>
          <li>Sign in, or start the sandbox from the home page.</li>
          <li>Create an incident with a title, service and severity.</li>
          <li>Upload evidence: logs, Kubernetes events, CI logs, deploy history. Use ISO 8601 timestamps (e.g. <code>2026-10-29T10:06:33Z</code>) so lines join the timeline. Timestamps without an offset are read as UTC.</li>
          <li>Run an investigation. Read each hypothesis with its cited lines; follow the links to the evidence.</li>
          <li>Create a remediation draft from a supported hypothesis. An admin approves or rejects it with a reason.</li>
          <li>Make the change through your own process. After the draft is approved, upload post-fix evidence (phase “post-fix”, at least 3 lines), then run checks.</li>
          <li>Export the Markdown report for your post-incident review.</li>
        </ol>
        <h2>Supported evidence</h2>
        <p>.log .txt .json .ndjson .jsonl .csv .yaml .yml — UTF-8 text, up to 2 MiB per file and 50,000 lines. For JSON, timestamps are read from <code>timestamp</code>, <code>time</code>, <code>ts</code>, <code>@timestamp</code> or <code>created_at</code>.</p>
        <h2>Reading results</h2>
        <ul>
          <li><strong>Supported</strong>: at least one citation matched stored evidence, confidence medium or high.</li>
          <li><strong>Uncertain</strong>: cited, but weak (e.g. a single matching line).</li>
          <li><strong>Unsupported</strong>: no valid citation. Do not act on it without your own evidence.</li>
          <li><strong>Insufficient evidence</strong>: nothing in the evidence explains the failure. Add more evidence.</li>
          <li>Check <strong>pass</strong> means the failure signal was absent from uploaded post-fix evidence. It is not a guarantee.</li>
        </ul>
      </section>
    </PublicLayout>
  );
}

export function PricingPage() {
  const tiers = [
    ['Sandbox', 'Free', 'Explore the workflow with synthetic sample data. Deleted within 24 hours.'],
    ['Pilot', 'Agreed after scoping', 'Your team, your evidence, a defined scope and success criteria. Pricing is set once we agree the scope.'],
    ['Enterprise', 'Custom', 'Larger rollouts and specific requirements, subject to what we can actually deliver at the time.'],
  ];
  return (
    <PublicLayout title="Pricing" active="/pricing">
      <section class="wrap section">
        <h1>Pricing</h1>
        <p class="lead">Northcause is at launch stage. We do not publish price points yet.</p>
        <div class="grid-3">
          {tiers.map(([name, price, desc]) => (
            <div class="panel tier">
              <h2>{name}</h2>
              <p class="price">{price}</p>
              <p>{desc}</p>
            </div>
          ))}
        </div>
        <p><a class="btn btn-primary" href="/contact">Discuss a pilot</a></p>
      </section>
    </PublicLayout>
  );
}

export function ContactPage(props: { sent?: boolean; error?: string }) {
  return (
    <PublicLayout title="Contact" active="/contact">
      <section class="wrap section narrow">
        <h1>Contact</h1>
        <p class="lead">Ask about a pilot or report a security issue.</p>
        {props.sent && <p class="notice notice-ok" role="status">Thanks — your message was received.</p>}
        {props.error && <p class="notice notice-err" role="alert">{props.error}</p>}
        <form method="post" action="/contact" class="form">
          <label>Name<input name="name" required maxlength={100} autocomplete="name" /></label>
          <label>Work email<input name="email" type="email" required maxlength={200} autocomplete="email" /></label>
          <label>Company<input name="company" maxlength={120} autocomplete="organization" /></label>
          <label>Message<textarea name="message" required maxlength={4000} rows={6}></textarea></label>
          <p class="muted small">We store your message to reply to it. Please do not include secrets or production logs here.</p>
          <button class="btn btn-primary" type="submit">Send</button>
        </form>
      </section>
    </PublicLayout>
  );
}

export function LoginPage(props: { error?: string; sandboxEnabled: boolean }) {
  return (
    <PublicLayout title="Sign in">
      <section class="wrap section narrow">
        <h1>Sign in</h1>
        <p class="muted">Pilot accounts are issued by the Northcause team.</p>
        {props.error && <p class="notice notice-err" role="alert">{props.error}</p>}
        <form method="post" action="/login" class="form">
          <label>Email<input name="email" type="email" required autocomplete="username" maxlength={200} /></label>
          <label>Password<input name="password" type="password" required autocomplete="current-password" maxlength={200} /></label>
          <button class="btn btn-primary" type="submit">Sign in</button>
        </form>
        {props.sandboxEnabled && (
          <form method="post" action="/sandbox" class="mt">
            <button class="btn btn-secondary" type="submit">Or try the sandbox with sample data</button>
          </form>
        )}
      </section>
    </PublicLayout>
  );
}

export function ErrorPage(props: { status: number; message: string; requestId?: string }) {
  return (
    <PublicLayout title={`Error ${props.status}`}>
      <section class="wrap section narrow">
        <h1>{props.status === 404 ? 'Not found' : 'Something went wrong'}</h1>
        <p>{props.message}</p>
        {props.requestId && <p class="muted small">Reference: {props.requestId}</p>}
        <p><a href="/">Back to home</a></p>
      </section>
    </PublicLayout>
  );
}
