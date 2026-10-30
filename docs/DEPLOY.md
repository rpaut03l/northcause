# Deploying Northcause

Runs as one Cloudflare Worker with static assets, D1 for metadata and R2 for evidence. No containers, Kubernetes or GPUs are needed for the pilot.

## Bindings

| Binding | Type | Purpose |
|---|---|---|
| `DB` | D1 database | All metadata (schema in `migrations/`) |
| `EVIDENCE` | R2 bucket | Redacted evidence objects, key `tenants/{tenant}/incidents/{incident}/{evidence}` |
| `ASSETS` | Static assets (`public/`) | CSS, favicon, robots.txt |
| `APP_ENV` | var | `development` / `staging` / `production` |
| `SANDBOX_ENABLED` | var | `"true"` to offer the public sandbox (default `"false"`; staging sets `"true"`) |
| Cron `17 * * * *` | trigger | Retention sweep |

Optional secrets (`wrangler secret put NAME --env staging`), never in `wrangler.toml` or git:

| Secret | Purpose |
|---|---|
| `MODEL_ENDPOINT`, `MODEL_API_KEY`, `MODEL_NAME` | OpenAI-compatible chat completions endpoint for the opt-in external model provider |
| `GITHUB_TOKEN` | Fine-grained token with **Actions: read** (and Metadata: read) on the pilot repositories only. Each workspace must also be allow-listed: `INSERT INTO integrations (id, tenant_id, kind, config, created_at) VALUES ('int_1', '<tenant id>', 'github_actions', '{"repos":["owner/repo"]}', datetime('now'));` |

## Local development

```bash
npm ci
npm run db:migrate:local            # creates .wrangler/state D1 with the schema
cp .dev.vars.example .dev.vars      # enables the local sandbox; optional secrets; never commit
npm run dev                         # http://127.0.0.1:8787
```

Create a local pilot admin:

```bash
NC_PASSWORD='a long local passphrase' node scripts/create-user.mjs --tenant "Local" --email you@example.com --name "You" > /tmp/seed.sql
npx wrangler d1 execute northcause-db --local --file /tmp/seed.sql && rm /tmp/seed.sql
```

Or press **Try the sandbox** on the home page for a synthetic demo workspace.

Checks:

```bash
npm run typecheck && npm test && npm run build && npm audit --omit=dev
```

## Staging

1. `npx wrangler login`
2. Create resources:
   ```bash
   npx wrangler d1 create northcause-db-staging        # copy the database_id
   npx wrangler r2 bucket create northcause-evidence-staging
   ```
3. Put the D1 `database_id` into `[env.staging]` in `wrangler.toml` (replace `REPLACE_WITH_STAGING_D1_ID`).
4. Apply the schema: `npm run db:migrate:staging`
5. Optional secrets: `npx wrangler secret put MODEL_API_KEY --env staging` (and the others above).
6. Deploy: `npx wrangler deploy --env staging`
7. Create the first pilot admin with `scripts/create-user.mjs` and
   `npx wrangler d1 execute northcause-db-staging --remote --env staging --file /tmp/seed.sql`.
8. Smoke test: `/healthz`, sign in, create an incident, upload `deploy-history.log`-style evidence, run an investigation, export the report.
9. Optional: attach a custom domain (e.g. `staging.northcause.com`) in the Cloudflare dashboard and restrict access with Cloudflare Access during the pilot.

## Production

Not authorised yet. Before production, close the gaps listed at the end of `docs/THREAT_MODEL.md`, add a `[env.production]` block with its own D1/R2, and set `SANDBOX_ENABLED` deliberately.
