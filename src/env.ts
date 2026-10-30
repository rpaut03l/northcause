export interface Env {
  DB: D1Database;
  EVIDENCE: R2Bucket;
  ASSETS?: Fetcher;
  APP_ENV: string;
  SANDBOX_ENABLED?: string;
  // Server-side secrets (wrangler secret put ...). Never sent to the browser.
  MODEL_API_KEY?: string;
  MODEL_ENDPOINT?: string;
  MODEL_NAME?: string;
  GITHUB_TOKEN?: string;
}

export interface SessionUser {
  userId: string;
  tenantId: string;
  email: string;
  displayName: string;
  role: 'admin' | 'member';
  tenantName: string;
  tenantKind: 'pilot' | 'sandbox';
  externalModelEnabled: boolean;
  retentionDays: number;
  csrfToken: string;
}

export type AppEnv = {
  Bindings: Env;
  Variables: {
    user?: SessionUser;
    requestId: string;
  };
};
