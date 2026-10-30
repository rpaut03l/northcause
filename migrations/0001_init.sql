-- Northcause initial schema (Cloudflare D1 / SQLite)
-- Every tenant-owned table carries tenant_id. All application queries filter on it.

PRAGMA foreign_keys = ON;

CREATE TABLE tenants (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  kind TEXT NOT NULL CHECK (kind IN ('pilot', 'sandbox')),
  external_model_enabled INTEGER NOT NULL DEFAULT 0,
  retention_days INTEGER NOT NULL DEFAULT 30,
  created_at TEXT NOT NULL,
  expires_at TEXT
);

CREATE TABLE users (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  email TEXT NOT NULL UNIQUE,
  display_name TEXT NOT NULL,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL CHECK (role IN ('admin', 'member')),
  created_at TEXT NOT NULL
);
CREATE INDEX idx_users_tenant ON users(tenant_id);

CREATE TABLE sessions (
  token_hash TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  csrf_token TEXT NOT NULL,
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL
);
CREATE INDEX idx_sessions_user ON sessions(user_id);

CREATE TABLE incidents (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  title TEXT NOT NULL,
  service TEXT NOT NULL,
  severity TEXT NOT NULL CHECK (severity IN ('sev1', 'sev2', 'sev3', 'sev4')),
  status TEXT NOT NULL CHECK (status IN ('open', 'investigating', 'mitigated', 'resolved')),
  summary TEXT NOT NULL DEFAULT '',
  created_by TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE INDEX idx_incidents_tenant ON incidents(tenant_id, created_at);

CREATE TABLE evidence (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  incident_id TEXT NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
  label TEXT NOT NULL,
  original_filename TEXT NOT NULL,
  format TEXT NOT NULL CHECK (format IN ('text', 'json', 'ndjson', 'csv', 'yaml')),
  phase TEXT NOT NULL CHECK (phase IN ('incident', 'post_fix')),
  source TEXT NOT NULL,
  size_bytes INTEGER NOT NULL,
  sha256 TEXT NOT NULL,
  r2_key TEXT NOT NULL,
  line_count INTEGER NOT NULL,
  secrets_redacted INTEGER NOT NULL DEFAULT 0,
  injection_flags INTEGER NOT NULL DEFAULT 0,
  uploaded_by TEXT NOT NULL,
  created_at TEXT NOT NULL
);
CREATE INDEX idx_evidence_incident ON evidence(tenant_id, incident_id);

CREATE TABLE timeline_events (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  incident_id TEXT NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
  evidence_id TEXT NOT NULL REFERENCES evidence(id) ON DELETE CASCADE,
  occurred_at TEXT NOT NULL,
  line_no INTEGER NOT NULL,
  kind TEXT NOT NULL,
  summary TEXT NOT NULL
);
CREATE INDEX idx_timeline_incident ON timeline_events(tenant_id, incident_id, occurred_at);

CREATE TABLE investigations (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  incident_id TEXT NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
  provider TEXT NOT NULL,
  provider_label TEXT NOT NULL,
  external_model_used INTEGER NOT NULL DEFAULT 0,
  status TEXT NOT NULL CHECK (status IN ('complete', 'insufficient_evidence', 'failed')),
  notes TEXT NOT NULL DEFAULT '',
  created_by TEXT NOT NULL,
  created_at TEXT NOT NULL
);
CREATE INDEX idx_investigations_incident ON investigations(tenant_id, incident_id, created_at);

-- Hypotheses and risks are "claims". support is computed server-side from validated citations.
CREATE TABLE claims (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  investigation_id TEXT NOT NULL REFERENCES investigations(id) ON DELETE CASCADE,
  kind TEXT NOT NULL CHECK (kind IN ('hypothesis', 'risk')),
  rank INTEGER NOT NULL,
  category TEXT NOT NULL DEFAULT '',
  statement TEXT NOT NULL,
  confidence TEXT NOT NULL CHECK (confidence IN ('high', 'medium', 'low')),
  support TEXT NOT NULL CHECK (support IN ('supported', 'uncertain', 'unsupported')),
  signal_patterns TEXT NOT NULL DEFAULT '[]'
);
CREATE INDEX idx_claims_investigation ON claims(tenant_id, investigation_id);

CREATE TABLE claim_citations (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  claim_id TEXT NOT NULL REFERENCES claims(id) ON DELETE CASCADE,
  evidence_id TEXT NOT NULL REFERENCES evidence(id) ON DELETE CASCADE,
  line_no INTEGER,
  excerpt TEXT NOT NULL
);
CREATE INDEX idx_citations_claim ON claim_citations(tenant_id, claim_id);

CREATE TABLE remediation_drafts (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  incident_id TEXT NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
  investigation_id TEXT NOT NULL REFERENCES investigations(id) ON DELETE CASCADE,
  claim_id TEXT NOT NULL REFERENCES claims(id) ON DELETE CASCADE,
  title TEXT NOT NULL,
  steps TEXT NOT NULL,
  checks TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('draft', 'approved', 'rejected')),
  created_by TEXT NOT NULL,
  created_at TEXT NOT NULL
);
CREATE INDEX idx_drafts_incident ON remediation_drafts(tenant_id, incident_id);

CREATE TABLE approvals (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  draft_id TEXT NOT NULL REFERENCES remediation_drafts(id) ON DELETE CASCADE,
  decision TEXT NOT NULL CHECK (decision IN ('approved', 'rejected')),
  reason TEXT NOT NULL,
  decided_by TEXT NOT NULL,
  created_at TEXT NOT NULL
);
CREATE INDEX idx_approvals_draft ON approvals(tenant_id, draft_id);

CREATE TABLE check_runs (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  incident_id TEXT NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
  draft_id TEXT NOT NULL REFERENCES remediation_drafts(id) ON DELETE CASCADE,
  check_name TEXT NOT NULL,
  result TEXT NOT NULL CHECK (result IN ('pass', 'fail', 'inconclusive')),
  detail TEXT NOT NULL,
  evidence_ids TEXT NOT NULL DEFAULT '[]',
  created_by TEXT NOT NULL,
  created_at TEXT NOT NULL
);
CREATE INDEX idx_checks_incident ON check_runs(tenant_id, incident_id);

-- Append-only, hash-chained audit log. Metadata never holds evidence content or secrets.
CREATE TABLE audit_events (
  seq INTEGER PRIMARY KEY AUTOINCREMENT,
  tenant_id TEXT NOT NULL,
  actor TEXT NOT NULL,
  action TEXT NOT NULL,
  target TEXT NOT NULL,
  metadata TEXT NOT NULL DEFAULT '{}',
  created_at TEXT NOT NULL,
  prev_hash TEXT NOT NULL,
  hash TEXT NOT NULL
);
CREATE INDEX idx_audit_tenant ON audit_events(tenant_id, seq);
CREATE UNIQUE INDEX idx_audit_chain ON audit_events(tenant_id, prev_hash);

-- Only the retention job inserts a row here, and only for an expired sandbox tenant being purged.
CREATE TABLE retention_purge_allowed (
  tenant_id TEXT PRIMARY KEY
);

CREATE TRIGGER audit_no_update BEFORE UPDATE ON audit_events
BEGIN SELECT RAISE(ABORT, 'audit_events is append-only'); END;

CREATE TRIGGER audit_no_delete BEFORE DELETE ON audit_events
WHEN NOT EXISTS (SELECT 1 FROM retention_purge_allowed WHERE tenant_id = OLD.tenant_id)
BEGIN SELECT RAISE(ABORT, 'audit_events is append-only'); END;

CREATE TABLE rate_limits (
  key TEXT NOT NULL,
  window_start INTEGER NOT NULL,
  count INTEGER NOT NULL,
  PRIMARY KEY (key, window_start)
);

CREATE TABLE contact_messages (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  email TEXT NOT NULL,
  company TEXT NOT NULL,
  message TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE TABLE integrations (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  kind TEXT NOT NULL CHECK (kind IN ('github_actions', 'otel')),
  config TEXT NOT NULL DEFAULT '{}',
  created_at TEXT NOT NULL,
  UNIQUE (tenant_id, kind)
);
