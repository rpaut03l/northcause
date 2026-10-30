import type { Child } from 'hono/jsx';
import type { SessionUser } from '../env';

export const BRAND_LINE = 'Find it. Fix it. Prove it.';

const Logo = () => (
  <a class="logo" href="/" aria-label="Northcause home">
    <svg width="22" height="22" viewBox="0 0 24 24" aria-hidden="true">
      <circle cx="12" cy="12" r="10.5" fill="none" stroke="currentColor" stroke-width="1.6" />
      <path d="M12 4.5 15 12h-6z" fill="currentColor" />
      <path d="M12 19.5 9 12h6z" fill="currentColor" opacity=".35" />
    </svg>
    <span>Northcause</span>
  </a>
);

export function PublicLayout(props: { title: string; children: Child; active?: string }) {
  const nav = [
    ['/product', 'Product'],
    ['/security', 'Security'],
    ['/docs', 'Docs'],
    ['/pricing', 'Pricing'],
    ['/contact', 'Contact'],
  ];
  return (
    <html lang="en">
      <head>
        <meta charset="utf-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1" />
        <title>{`${props.title} · Northcause`}</title>
        <meta name="description" content="Northcause helps teams find what failed, understand why from evidence, and prove the fix worked." />
        <link rel="icon" href="/favicon.svg" type="image/svg+xml" />
        <link rel="stylesheet" href="/styles.css" />
      </head>
      <body>
        <a class="skip" href="#main">Skip to content</a>
        <header class="site-header">
          <div class="wrap header-row">
            <Logo />
            <nav aria-label="Main">
              <ul class="nav">
                {nav.map(([href, label]) => (
                  <li>
                    <a href={href} aria-current={props.active === href ? 'page' : undefined}>
                      {label}
                    </a>
                  </li>
                ))}
              </ul>
            </nav>
            <div class="header-cta">
              <a class="btn btn-ghost" href="/login">Sign in</a>
            </div>
          </div>
        </header>
        <main id="main">{props.children}</main>
        <footer class="site-footer">
          <div class="wrap footer-row">
            <div>
              <Logo />
              <p class="muted">{BRAND_LINE}</p>
            </div>
            <p class="muted small">
              Pilot software. Features are described as they exist today; see <a href="/security">Security</a> for current controls and known limits.
            </p>
          </div>
        </footer>
      </body>
    </html>
  );
}

export function AppLayout(props: { title: string; user: SessionUser; children: Child; flash?: string; error?: string }) {
  const u = props.user;
  return (
    <html lang="en">
      <head>
        <meta charset="utf-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1" />
        <title>{`${props.title} · Northcause`}</title>
        <link rel="icon" href="/favicon.svg" type="image/svg+xml" />
        <link rel="stylesheet" href="/styles.css" />
      </head>
      <body class="app">
        <a class="skip" href="#main">Skip to content</a>
        {u.tenantKind === 'sandbox' && (
          <div class="demo-banner" role="status">
            Demo sandbox — synthetic sample data only. This workspace and its data are deleted within 24 hours.
          </div>
        )}
        <header class="site-header">
          <div class="wrap header-row">
            <Logo />
            <nav aria-label="Workspace">
              <ul class="nav">
                <li><a href="/app">Incidents</a></li>
                <li><a href="/app/integrations">Integrations</a></li>
                <li><a href="/app/audit">Audit log</a></li>
                <li><a href="/app/settings">Settings</a></li>
              </ul>
            </nav>
            <div class="header-cta">
              <span class="muted small who">
                {u.displayName} · {u.tenantName} ({u.role})
              </span>
              <form method="post" action="/logout">
                <input type="hidden" name="_csrf" value={u.csrfToken} />
                <button class="btn btn-ghost" type="submit">Sign out</button>
              </form>
            </div>
          </div>
        </header>
        <main id="main" class="wrap app-main">
          {props.flash && <p class="notice notice-ok" role="status">{props.flash}</p>}
          {props.error && <p class="notice notice-err" role="alert">{props.error}</p>}
          {props.children}
        </main>
      </body>
    </html>
  );
}

export function Csrf(props: { user: SessionUser }) {
  return <input type="hidden" name="_csrf" value={props.user.csrfToken} />;
}

export function Badge(props: { kind: string; children: Child }) {
  return <span class={`badge badge-${props.kind}`}>{props.children}</span>;
}
