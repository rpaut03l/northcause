#!/usr/bin/env node
// Creates SQL that provisions a pilot workspace (tenant) and its first admin.
// Usage:
//   NC_PASSWORD='a long passphrase' node scripts/create-user.mjs --tenant "Acme" --email admin@acme.com --name "Asha Rao" > /tmp/seed.sql
//   npx wrangler d1 execute northcause-db --local --file /tmp/seed.sql            # local
//   npx wrangler d1 execute northcause-db-staging --remote --env staging --file /tmp/seed.sql
//   rm /tmp/seed.sql
// Add --tenant-id ten_xxx to add a user to an existing workspace, and --role member for non-admins.
// If NC_PASSWORD is unset, a random password is generated and printed to stderr once.
import { randomBytes, webcrypto } from 'node:crypto';

const args = Object.fromEntries(
  process.argv.slice(2).reduce((acc, cur, i, arr) => (cur.startsWith('--') ? [...acc, [cur.slice(2), arr[i + 1]]] : acc), []),
);
const email = (args.email ?? '').toLowerCase().trim();
if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
  console.error('Provide --email');
  process.exit(1);
}
const role = args.role === 'member' ? 'member' : 'admin';
const name = args.name ?? email;
let password = process.env.NC_PASSWORD;
if (!password) {
  password = randomBytes(18).toString('base64url');
  console.error(`Generated password for ${email}: ${password}\nShare it over a secure channel and ask the user to keep it safe.`);
}
if (password.length < 12) {
  console.error('Password must be at least 12 characters.');
  process.exit(1);
}

const hex = (b) => Buffer.from(b).toString('hex');
const id = (p) => `${p}_${hex(randomBytes(12))}`;
const salt = randomBytes(16);
const key = await webcrypto.subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveBits']);
const bits = await webcrypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations: 100000 }, key, 256);
const hash = `pbkdf2$100000$${hex(salt)}$${hex(bits)}`;
const q = (s) => `'${String(s).replace(/'/g, "''")}'`;
const now = new Date().toISOString();

const lines = [];
let tenantId = args['tenant-id'];
if (!tenantId) {
  tenantId = id('ten');
  lines.push(`INSERT INTO tenants (id, name, kind, retention_days, created_at) VALUES (${q(tenantId)}, ${q(args.tenant ?? 'Pilot workspace')}, 'pilot', 30, ${q(now)});`);
}
lines.push(
  `INSERT INTO users (id, tenant_id, email, display_name, password_hash, role, created_at) VALUES (${q(id('usr'))}, ${q(tenantId)}, ${q(email)}, ${q(name)}, ${q(hash)}, ${q(role)}, ${q(now)});`,
);
console.log(lines.join('\n'));
console.error(`Tenant: ${tenantId}`);
