import type { Env } from '../env';

/**
 * Read-only GitHub Actions context adapter.
 * Status is "not_connected" unless a GITHUB_TOKEN secret is configured; even then the UI shows
 * "configured, unverified" until a real fetch succeeds. The adapter only issues GET requests.
 */
export type IntegrationStatus = 'not_connected' | 'configured_unverified';

export interface CiRun {
  id: number;
  name: string;
  status: string;
  conclusion: string | null;
  headSha: string;
  headBranch: string;
  event: string;
  createdAt: string;
  updatedAt: string;
}

export interface CiContextAdapter {
  kind: 'github_actions';
  status(): IntegrationStatus;
  listRecentRuns(owner: string, repo: string): Promise<CiRun[]>;
}

const NAME_RE = /^[A-Za-z0-9_.-]{1,100}$/;

export function validRepoRef(owner: string, repo: string): boolean {
  return NAME_RE.test(owner) && NAME_RE.test(repo) && !owner.startsWith('.') && !repo.startsWith('.');
}

export function githubActionsAdapter(env: Env, fetchImpl: typeof fetch = fetch): CiContextAdapter {
  return {
    kind: 'github_actions',
    status: () => (env.GITHUB_TOKEN ? 'configured_unverified' : 'not_connected'),
    async listRecentRuns(owner, repo) {
      if (!env.GITHUB_TOKEN) throw new Error('GitHub Actions integration is not connected.');
      if (!validRepoRef(owner, repo)) throw new Error('Invalid repository reference.');
      const res = await fetchImpl(
        `https://api.github.com/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}/actions/runs?per_page=20`,
        {
          method: 'GET',
          headers: {
            Accept: 'application/vnd.github+json',
            Authorization: `Bearer ${env.GITHUB_TOKEN}`,
            'X-GitHub-Api-Version': '2022-11-28',
            'User-Agent': 'northcause-pilot',
          },
          signal: AbortSignal.timeout(15_000),
        },
      );
      if (!res.ok) throw new Error(`GitHub API returned HTTP ${res.status}`);
      const body = (await res.json()) as { workflow_runs?: Array<Record<string, unknown>> };
      return (body.workflow_runs ?? []).map((r) => ({
        id: Number(r.id),
        name: String(r.name ?? ''),
        status: String(r.status ?? ''),
        conclusion: r.conclusion == null ? null : String(r.conclusion),
        headSha: String(r.head_sha ?? '').slice(0, 40),
        headBranch: String(r.head_branch ?? ''),
        event: String(r.event ?? ''),
        createdAt: String(r.created_at ?? ''),
        updatedAt: String(r.updated_at ?? ''),
      }));
    },
  };
}

/** Converts runs into NDJSON evidence so they flow through the same validation and timeline path. */
export function runsToNdjson(runs: CiRun[], owner: string, repo: string): string {
  return runs
    .map((r) =>
      JSON.stringify({
        timestamp: r.updatedAt || r.createdAt,
        service: `${owner}/${repo}`,
        event: r.conclusion === 'success' ? 'deploy' : 'ci_run',
        name: r.name,
        status: r.status,
        conclusion: r.conclusion ?? 'pending',
        message: `workflow ${r.name} on ${r.headBranch}@${r.headSha.slice(0, 7)} ${r.conclusion === 'failure' ? 'failed' : r.conclusion ?? r.status}`,
      }),
    )
    .join('\n');
}
