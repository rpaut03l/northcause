// Test harness: runs the real Hono app against an in-process SQLite database (same engine as D1)
// with the real migrations applied, and an in-memory R2 bucket.
import { readFileSync } from 'node:fs';
import { DatabaseSync } from 'node:sqlite';
import { app } from '../src/app';
import type { Env } from '../src/env';
import { createTenant, createUser } from '../src/services/accounts';

type Row = Record<string, unknown>;

class Stmt {
  constructor(private db: DatabaseSync, readonly sql: string, readonly params: unknown[] = []) {}
  bind(...params: unknown[]) {
    return new Stmt(this.db, this.sql, params.map((p) => (p === undefined ? null : typeof p === 'boolean' ? (p ? 1 : 0) : p)));
  }
  private s() {
    return this.db.prepare(this.sql);
  }
  async first<T = Row>(): Promise<T | null> {
    return ((this.s().get(...(this.params as never[])) as T) ?? null);
  }
  async all<T = Row>(): Promise<{ results: T[] }> {
    return { results: this.s().all(...(this.params as never[])) as T[] };
  }
  async run() {
    const r = this.s().run(...(this.params as never[]));
    return { success: true, meta: { changes: Number(r.changes) } };
  }
  runSync() {
    return this.s().run(...(this.params as never[]));
  }
}

export class FakeD1 {
  readonly raw: DatabaseSync;
  constructor() {
    this.raw = new DatabaseSync(':memory:');
    this.raw.exec('PRAGMA foreign_keys = ON;');
    this.raw.exec(readFileSync('migrations/0001_init.sql', 'utf8') as string);
  }
  prepare(sql: string) {
    return new Stmt(this.raw, sql);
  }
  async batch(stmts: Stmt[]) {
    this.raw.exec('BEGIN');
    try {
      const out = stmts.map((s) => s.runSync());
      this.raw.exec('COMMIT');
      return out;
    } catch (e) {
      this.raw.exec('ROLLBACK');
      throw e;
    }
  }
  async exec(sql: string) {
    this.raw.exec(sql);
  }
}

export class FakeR2 {
  readonly objects = new Map<string, string>();
  async put(key: string, value: string | ArrayBuffer | Uint8Array) {
    this.objects.set(key, typeof value === 'string' ? value : new TextDecoder().decode(value));
    return {};
  }
  async get(key: string) {
    const v = this.objects.get(key);
    return v === undefined ? null : { text: async () => v };
  }
  deleteCalls = 0;
  async delete(keys: string | string[]) {
    const list = Array.isArray(keys) ? keys : [keys];
    if (list.length > 1000) throw new Error('R2 delete accepts at most 1000 keys'); // mirrors the real API limit
    this.deleteCalls++;
    for (const k of list) this.objects.delete(k);
  }
}

export interface TestEnv extends Env {
  DB: D1Database;
  EVIDENCE: R2Bucket;
}

export function makeEnv(overrides: Partial<Env> = {}) {
  const db = new FakeD1();
  const r2 = new FakeR2();
  const env = {
    DB: db as unknown as D1Database,
    EVIDENCE: r2 as unknown as R2Bucket,
    APP_ENV: 'test',
    SANDBOX_ENABLED: 'true',
    ...overrides,
  } as Env;
  return { env, db, r2 };
}

export const ORIGIN = 'http://localhost';

export class Client {
  cookies = new Map<string, string>();
  constructor(private env: Env, private ip = '203.0.113.10') {}

  async req(path: string, init: RequestInit & { form?: Record<string, string> | FormData } = {}) {
    const headers = new Headers(init.headers);
    headers.set('CF-Connecting-IP', this.ip);
    if (this.cookies.size) headers.set('Cookie', [...this.cookies].map(([k, v]) => `${k}=${v}`).join('; '));
    let body = init.body;
    if (init.form) {
      if (init.form instanceof FormData) body = init.form;
      else {
        body = new URLSearchParams(init.form).toString();
        headers.set('Content-Type', 'application/x-www-form-urlencoded');
      }
    }
    if (init.method && init.method !== 'GET' && !headers.has('Origin')) headers.set('Origin', ORIGIN);
    const res = await app.request(`${ORIGIN}${path}`, { ...init, headers, body }, this.env);
    for (const sc of res.headers.getSetCookie()) {
      const [pair] = sc.split(';');
      const [k, ...rest] = pair!.split('=');
      const v = rest.join('=');
      if (/max-age=0/i.test(sc) || v === '') this.cookies.delete(k!);
      else this.cookies.set(k!, v);
    }
    return res;
  }

  async post(path: string, form: Record<string, string> | FormData, extra: RequestInit = {}) {
    return this.req(path, { method: 'POST', form, ...extra });
  }

  /** Reads the CSRF token from any workspace page. */
  async csrf(): Promise<string> {
    const html = await (await this.req('/app/settings')).text();
    const m = /name="_csrf" value="([^"]+)"/.exec(html);
    if (!m) throw new Error('no csrf token on page');
    return m[1]!;
  }

  async login(email: string, password: string) {
    const res = await this.post('/login', { email, password });
    if (res.status !== 303) throw new Error(`login failed: ${res.status}`);
    return res;
  }
}

export async function seedTenant(env: Env, name: string) {
  const tenantId = await createTenant(env.DB, name, 'pilot');
  const adminEmail = `admin@${name.toLowerCase()}.test`;
  const memberEmail = `member@${name.toLowerCase()}.test`;
  const password = 'correct horse battery staple';
  const adminId = await createUser(env.DB, tenantId, adminEmail, `${name} Admin`, password, 'admin');
  const memberId = await createUser(env.DB, tenantId, memberEmail, `${name} Member`, password, 'member');
  return { tenantId, adminEmail, memberEmail, adminId, memberId, password };
}

export function fileForm(csrf: string, name: string, content: string, type = 'text/plain', extra: Record<string, string> = {}) {
  const fd = new FormData();
  fd.set('_csrf', csrf);
  fd.set('file', new File([content], name, { type }));
  for (const [k, v] of Object.entries(extra)) fd.set(k, v);
  return fd;
}

export function idFrom(location: string | null, prefix: string): string {
  const m = new RegExp(`${prefix}_[a-f0-9]+`).exec(location ?? '');
  if (!m) throw new Error(`no ${prefix} id in ${location}`);
  return m[0];
}
