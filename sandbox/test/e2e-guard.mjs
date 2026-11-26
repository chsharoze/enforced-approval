// Conformance-style check that the guard cannot be forgotten: a write tool registered
// with no guard call of its own (test/guard-tool-server.mjs) is refused without an
// approval and executes exactly once with one. Kills the guard-not-default mutation.
// Signed-receipts mode, so the approval is a receipt token and no pages are needed.
// Usage: node test/e2e-guard.mjs
import { Client } from '@modelcontextprotocol/client';
import { StdioClientTransport } from '@modelcontextprotocol/client/stdio';
import { readFileSync, rmSync } from 'node:fs';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { Sor } from '../src/sor.mjs';
import { Core, ISSUER } from '../src/core.mjs';
import { sign, jwk } from '../src/receipt.mjs';
const here = fileURLToPath(new URL('..', import.meta.url));
const vectors = JSON.parse(readFileSync(new URL('../spec/vectors/vectors.json', import.meta.url)));
const RUN = 'mcp:tools/call:run_cleanup', A = 'acct-EXAMPLE-0001', P = 'agent-EXAMPLE-sync';
const admin = crypto.randomUUID(), db = here + `e2e-guard-${process.pid}.sqlite`;
let n = 0, bad = 0;
const check = (name, ok, detail = '') => { n++; if (!ok) bad++; console.log((ok ? 'ok   ' : 'FAIL ') + name + (ok ? '' : '  ' + detail)); };
const client = new Client({ name: 'e2e-guard', version: '0' }, { capabilities: {}, versionNegotiation: { mode: { pin: '2026-07-28' } } });
// The guard behaviour this suite asserts is the guard's own, for an operation that is
// not covered: in signed-receipts mode a covered operation cannot be approved through an
// issuer (S66), so the receipt path below is the default-mode path. Pin the preconditions
// setting off for the server this suite starts and for the Core it builds the expected
// change with, so both invocations (default and VA_PRECONDITIONS=1) agree on the
// database and test the same guard.
const env = { ...process.env, VA_ADMIN: admin, VA_MODE: 'organization', VA_DB: db, VA_NOW: String(vectors.now), VA_TEST_ISSUER: '1', NODE_NO_WARNINGS: '1' };
delete env.VA_PRECONDITIONS;
const transport = new StdioClientTransport({ command: process.execPath, args: [here + 'test/guard-tool-server.mjs'], cwd: here, env });
const sor = new Sor(db), core = new Core(sor, { adminCredential: admin, now: () => vectors.now, settings: { preconditions: false } });
const args = { objectType: 'contact', action: 'create', id: 'rec-EXAMPLE-99', properties: { owner: 'user-EXAMPLE-9' } };
const call = meta => client.callTool({ name: 'run_cleanup', arguments: structuredClone(args), ...(meta && { _meta: meta }) });
try {
  await client.connect(transport);
  // The guard-tool server builds its runtime on its first served request, and the start
  // now writes the issuer row from the environment (VA_TEST_ISSUER=1). Prime it before
  // adding this fixture's operation, so the addition is not overwritten.
  await client.callTool({ name: 'read_record', arguments: { id: 'rec-EXAMPLE-42' } });
  // The tool's operation is unknown to the stock runtime; allow it for this fixture.
  sor.permission(A, P, RUN);
  const issuer = JSON.parse(core.db.prepare('SELECT json FROM issuers WHERE account=? AND issuer=?').get(A, ISSUER).json);
  core.admin(admin, 'issuer', { ...issuer, operations: [...issuer.operations, RUN] });
  const ref = r => r?._meta?.['org.enforcedapproval/refusal'];
  const refused = await call();
  check('tool with no guard call of its own is refused without approval', refused.isError === true && ref(refused)?.error === 'approval_required', JSON.stringify(refused).slice(0, 300));
  check('refusal carries the change hash in the same _meta key', typeof ref(refused)?.change_hash === 'string');
  check('nothing was written', sor.count() === 0 && !sor.get(A, 'rec-EXAMPLE-99'));
  const change_hash = core.prepare({ account: A, principal: P, operation: RUN, args }).change_hash;
  check('refusal hash equals the server-side preparation', ref(refused)?.change_hash === change_hash);
  const receipt = sign({ ...vectors.receipts.person.claims, jti: crypto.randomUUID(), iat: vectors.now, exp: vectors.now + 300, change_hash });
  const approved = await call({ 'org.enforcedapproval/receipt': receipt });
  const written = sor.get(A, 'rec-EXAMPLE-99');
  check('with approval the write executes exactly once', approved.isError !== true && sor.count() === 1 && written?.properties?.owner === 'user-EXAMPLE-9', JSON.stringify(approved).slice(0, 300));
  const replay = await call({ 'org.enforcedapproval/receipt': receipt });
  let outcome; try { outcome = JSON.parse(replay.content.find(c => c.type === 'text').text)?.recorded_outcome; } catch {}
  check('an identical repeat gets the recorded outcome and does not write again', replay.isError !== true && outcome?.outcome === 'success' && outcome?.sent_now === false && sor.count() === 1, JSON.stringify(replay).slice(0, 300));
} finally {
  await client.close().catch(() => {}); sor.close();
  for (const s of ['', '-wal', '-shm']) rmSync(db + s, { force: true });
}
console.log(`\nE2E: ${n - bad} of ${n} passed`);
process.exit(bad ? 1 : 0);
