import { app } from './app';
import type { Env } from './env';
import { retentionSweep } from './services/retention';

export default {
  fetch: app.fetch,
  async scheduled(_event: ScheduledController, env: Env, ctx: ExecutionContext) {
    ctx.waitUntil(
      retentionSweep(env.DB, env.EVIDENCE).then((r) => console.log('retention_sweep', r)),
    );
  },
} satisfies ExportedHandler<Env>;
