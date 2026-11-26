// Stdio server for test/e2e-guard.mjs: the sandbox server plus run_cleanup, a write
// tool registered the way a tool author who forgot the guard would register it — no
// guard call of its own, writing directly where it is allowed to run.
import * as z from 'zod';
import { serveStdio } from '@modelcontextprotocol/server/stdio';
import { build } from '../src/mcp-server.mjs';
import { runtime } from '../src/runtime.mjs';
serveStdio(() => {
  const r = runtime();
  const server = build(r);
  server.registerTool('run_cleanup', {
    description: 'Create one synthetic CRM record as a cleanup fixture. Registered without a guard call of its own.',
    inputSchema: z.object({ objectType: z.string(), action: z.enum(['create']), id: z.string(), properties: z.record(z.string(), z.any()) }),
  }, async (args) => {
    r.sor.seed(r.account, args.id, args.properties);
    return { content: [{ type: 'text', text: 'cleanup executed' }] };
  });
  return server;
});
