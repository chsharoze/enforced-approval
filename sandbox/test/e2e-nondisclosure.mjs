// Nondisclosure before approval (S60, S62, S63, S64, S68(1)) in the mode people run:
// the real default server, started exactly as sandbox/README.md tells a reader to
// start it (no VA_MODE and no VA_PRECONDITIONS), and again with VA_PRECONDITIONS=1
// (covered operations), each with fresh databases per entry point. Every check runs in
// both modes: the HTTP PATCH /records mapping and the MCP-over-HTTP connector of
// mcp-http.mjs, and the MCP stdio server in server mode and with no VA_MODE. For a
// principal that may write but may not read, every answer before any approval is
// consumed must be independent of the state and existence of the record: within each
// operation the answers are identical in every member, in status and in headers, except
// values taken from the request, clock values and the random part of the approval link,
// and no answer carries a preconditions, current, version or state_hash member or the
// error conflict. The same holds for update_by_query (0, 1 and 2 matching records) and
// read_record (existing, absent and a merged alias of a denied record); in the default
// mode S66 refuses the query with approver_not_authorized without reading record state,
// and in covered mode S72 refuses it at step 1 before anything is evaluated. A database
// created with preconditions on must refuse a restart whose VA_PRECONDITIONS requests
// the opposite, in both directions.
// An answer of the default mode carries no request_key (the operation is not covered,
// S67) — that check kills the default-preconditions-on mutation; an answer of the
// covered mode on an entry point that offers the server-issued profile carries
// request_key and, for the non-reader, no change and no change_hash (S68(1)). The
// default stdio entry point (organization mode) offers no server-issued profile for a
// covered operation, so S66 answers approver_not_authorized with no change_hash there.
// Kills the default-preconditions-on, query-allowed-in-default,
// query-default-refusal-permission-denied, stored-preconditions-adopted,
// read-record-ignores-permission, read-record-alias-permission,
// step1-reader-operation-level and nonstring-identifier-accepted mutations.
// Usage: node test/e2e-nondisclosure.mjs
import { Client, StreamableHTTPClientTransport } from '@modelcontextprotocol/client';
import { StdioClientTransport } from '@modelcontextprotocol/client/stdio';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import fs from 'node:fs';
import net from 'node:net';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { Sor } from '../src/sor.mjs';
import { OP, QUERY, CREATE } from '../src/core.mjs';
const here = fileURLToPath(new URL('..', import.meta.url));
const account = 'acct-EXAMPLE-0001', principal = 'agent-EXAMPLE-sync';
const DELETE = 'mcp:tools/call:delete_records', HTTP = 'http:PATCH:/records';
const OPS = [OP, QUERY, CREATE, DELETE, HTTP];
let n = 0, bad = 0;
const check = (name, ok, detail = '') => { n++; if (!ok) bad++; console.log((ok ? 'ok   ' : 'FAIL ') + name + (ok ? '' : '  ' + detail)); };
async function freePort() {
  const s = net.createServer(); await new Promise((resolve, reject) => { s.once('error', reject); s.listen(0, '127.0.0.1', resolve); });
  const p = s.address().port; await new Promise(r => s.close(r)); return p;
}
// Start every child from a base environment with VA_MODE, VA_PRECONDITIONS, VA_NOW and
// VA_TEST_FAULT cleared; callers add what they need (VA_MUTATE is left alone).
const envFor = (db, log, extra = {}) => {
  const e = { ...process.env };
  delete e.VA_MODE; delete e.VA_PRECONDITIONS; delete e.VA_NOW; delete e.VA_TEST_FAULT;
  return { ...e, VA_ADMIN: crypto.randomUUID(), VA_DB: db, VA_LOG: log, VA_TEST_ISSUER: '1', NODE_NO_WARNINGS: '1', ...extra };
};
const startedDb = new Set(), startedLog = new Set(), webs = [], clients = [];
const track = (db, log) => { startedDb.add(db); startedLog.add(log); };
async function stopChild(child) {
  if (child.exitCode !== null || child.signalCode !== null) return;
  const exit = once(child, 'exit');
  child.kill('SIGTERM');
  const timer = setTimeout(() => child.kill('SIGKILL'), 2000);
  await exit; clearTimeout(timer);
}
async function startWeb(db, log, extra = {}) {
  const p = await freePort(), base = `http://127.0.0.1:${p}`, token = crypto.randomBytes(24).toString('hex');
  const child = spawn(process.execPath, [here + 'src/mcp-http.mjs'], { cwd: here, env: envFor(db, log, { VA_PATH_TOKEN: token, PORT: String(p), VA_BASE_URL: base, ...extra }), stdio: ['ignore', 'pipe', 'pipe'] });
  let stderr = ''; child.stderr.on('data', b => { stderr += b; });
  webs.push(child); track(db, log);
  await new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(Error('startup timeout: ' + stderr)), 10000);
    child.once('exit', code => { clearTimeout(timer); reject(Error('server exited ' + code + ': ' + stderr)); });
    child.stdout.on('data', b => { if (String(b).includes('MCP HTTP listening')) { clearTimeout(timer); resolve(); } });
  });
  return { base, token, child };
}
// Start a server and report whether it listened: resolves {listened:true} (then kills it)
// on "MCP HTTP listening", or {listened:false, code, stderr} when it exits first.
async function expectRefusal(db, log, extra = {}) {
  const p = await freePort(), base = `http://127.0.0.1:${p}`, token = crypto.randomBytes(24).toString('hex');
  const child = spawn(process.execPath, [here + 'src/mcp-http.mjs'], { cwd: here, env: envFor(db, log, { VA_PATH_TOKEN: token, PORT: String(p), VA_BASE_URL: base, ...extra }), stdio: ['ignore', 'pipe', 'pipe'] });
  let stderr = ''; child.stderr.on('data', b => { stderr += b; });
  webs.push(child); track(db, log);
  const result = await new Promise(resolve => {
    const timer = setTimeout(() => { child.kill('SIGKILL'); resolve({ listened: true }); }, 10000);
    child.once('close', code => { clearTimeout(timer); resolve({ listened: false, code }); });
    child.stdout.on('data', b => { if (String(b).includes('MCP HTTP listening')) { clearTimeout(timer); resolve({ listened: true }); } });
  });
  if (result.listened) await stopChild(child);
  return { ...result, stderr };
}
// Start the stdio entry point and report how it ended. A restart whose stored setting
// disagrees must refuse at start: exit non-zero with the reason on stderr, never answer
// every call with "Internal server error".
async function expectStdioRefusal(db, log, extra = {}) {
  const child = spawn(process.execPath, [here + 'src/mcp-server.mjs'], { cwd: here, env: envFor(db, log, extra), stdio: ['ignore', 'pipe', 'pipe'] });
  let stderr = ''; child.stderr.on('data', b => { stderr += b; });
  const result = await new Promise(resolve => {
    const timer = setTimeout(() => { child.kill('SIGKILL'); resolve({ exited: false, code: null }); }, 10000);
    child.once('close', code => { clearTimeout(timer); resolve({ exited: true, code }); });
  });
  return { ...result, stderr };
}
const withSor = (db, fn) => { const s = new Sor(db); try { return fn(s); } finally { s.close(); } };
const seed = (db, id, props) => withSor(db, s => s.seed(account, id, props));
const remove = (db, id) => withSor(db, s => s.db.prepare('DELETE FROM records WHERE account=? AND id=?').run(account, id));
// A principal that may write but not read (S60), as tests 99, 100, 106, 116, 139 and
// 140 set one up. Call it only after the entry point's runtime has created the database
// and granted its defaults (a stdio server builds its runtime on its first served
// request); a later start does not grant them again.
function setNonReader(db) {
  withSor(db, s => { for (const op of OPS) s.permission(account, principal, op, false, true); });
}
function assertNonReader(phase, db) {
  withSor(db, s => check(phase + ': the principal may write but may not read every operation used', OPS.every(op => s.can(account, principal, op, 'write') && !s.can(account, principal, op, 'read')),
    OPS.map(op => `${op} read=${s.can(account, principal, op, 'read')} write=${s.can(account, principal, op, 'write')}`).join('; ')));
}
// The random part of the approval link is allowed to differ; everything else is not.
const normalize = v => JSON.stringify(v, (k, x) => typeof x === 'string' ? x.replace(/\/approve\/[a-f0-9]{48}/g, '/approve/ID') : x);
const FORBIDDEN = new Set(['preconditions', 'current', 'version', 'state_hash']);
const leaks = v => !v || typeof v !== 'object' ? false : Object.entries(v).some(([k, x]) => FORBIDDEN.has(k) || leaks(x));
const hasMember = (v, name) => !v || typeof v !== 'object' ? false : Object.entries(v).some(([k, x]) => k === name || hasMember(x, name));
// The answer payload: the refusal object. The protocol envelope around it (for
// example _meta's io.modelcontextprotocol/serverInfo) is not part of the answer. A tool
// whose refusal is not in _meta still carries it in the single text block.
const textPayload = a => { try { return JSON.parse(a?.content?.find(c => c.type === 'text')?.text ?? ''); } catch { return undefined; } };
const payloadOf = a => a.body?.approval ?? a?._meta?.['org.enforcedapproval/refusal'] ?? textPayload(a) ?? a;
const errorOf = a => payloadOf(a)?.error;
const args = {
  update: id => ({ objectType: 'contact', action: 'update', records: [{ id, properties: { owner: 'nd-owner', lifecycle_stage: 'lead' } }] }),
  create: id => ({ objectType: 'contact', action: 'create', id, properties: { owner: 'nd-owner' } }),
  delete: id => ({ objectType: 'contact', action: 'delete', records: [{ id }] }),
};
// The MCP tools of one connected client, named as the suite's channels name operations.
const toolChannel = client => ({
  update: id => client.callTool({ name: 'manage_records', arguments: args.update(id) }),
  create: id => client.callTool({ name: 'create_record', arguments: args.create(id) }),
  delete: id => client.callTool({ name: 'delete_records', arguments: args.delete(id) }),
  query: body => client.callTool({ name: 'update_by_query', arguments: body }),
  read: id => client.callTool({ name: 'read_record', arguments: { id } }),
});
const httpChannel = (base, token) => Object.fromEntries(['update', 'create', 'delete'].map(op => [op, async id => {
  const res = await fetch(base + '/records', { method: 'PATCH', headers: { authorization: 'Bearer ' + token }, body: JSON.stringify(args[op](id)) });
  const headers = Object.fromEntries(res.headers); delete headers.date; // a clock value
  return { status: res.status, headers, body: await res.json() };
}]));
// Update: the record exists; its value changed by another path; only its version
// changed; the record id does not exist. The request is identical throughout.
async function compare(label, channel, db, { covered, expected, requestKey }) {
  const upd = 'rec-EXAMPLE-nd-update';
  seed(db, upd, { owner: 'nd-seed-1', lifecycle_stage: 'lead' });
  const updates = [await channel.update(upd)];
  seed(db, upd, { owner: 'nd-seed-2', lifecycle_stage: 'prospect' });
  updates.push(await channel.update(upd));
  withSor(db, s => s.db.prepare('UPDATE records SET version=version+1 WHERE account=? AND id=?').run(account, upd));
  updates.push(await channel.update(upd));
  remove(db, upd);
  updates.push(await channel.update(upd));
  // Create: the record id does not exist, then it does.
  const cre = 'rec-EXAMPLE-nd-create';
  remove(db, cre);
  const creates = [await channel.create(cre)];
  seed(db, cre, { owner: 'nd-seed-3' });
  creates.push(await channel.create(cre));
  // Delete: the record id exists, then it does not.
  const del = 'rec-EXAMPLE-nd-delete';
  seed(db, del, { owner: 'nd-seed-4' });
  const deletes = [await channel.delete(del)];
  remove(db, del);
  deletes.push(await channel.delete(del));
  for (const [op, answers] of [['update', updates], ['create', creates], ['delete', deletes]]) {
    check(`${label} ${op}: every answer before any approval is ${expected}, never conflict`, answers.every(a => errorOf(a) === expected), answers.map(errorOf).join(', '));
    check(`${label} ${op}: every answer is identical in every member, status and headers`, answers.every(a => normalize(a) === normalize(answers[0])), JSON.stringify(answers).slice(0, 400));
    check(`${label} ${op}: no answer carries a preconditions, current, version or state_hash member`, answers.every(a => !leaks(payloadOf(a))), JSON.stringify(answers.map(payloadOf)).slice(0, 400));
    if (requestKey === true)
      check(`${label} ${op}: every answer carries request_key (S67)`, answers.every(a => typeof payloadOf(a)?.request_key === 'string'), JSON.stringify(answers.map(payloadOf)).slice(0, 400));
    if (requestKey === false)
      check(`${label} ${op}: no answer carries a request_key member (the operation is not covered, S67)`, answers.every(a => !hasMember(payloadOf(a), 'request_key')), JSON.stringify(answers.map(payloadOf)).slice(0, 400));
    if (covered)
      check(`${label} ${op}: no answer carries change or change_hash (S68(1))`, answers.every(a => !hasMember(payloadOf(a), 'change') && !hasMember(payloadOf(a), 'change_hash')), JSON.stringify(answers.map(payloadOf)).slice(0, 400));
  }
}
// A covered operation (S67). In the default mode the server offers no server-issued
// profile for it, so S66 refuses every request with approver_not_authorized, without
// reading record state and with no change_hash. In the covered mode S72's whole-domain
// read check refuses a non-reader at step 1 before the query runs with
// permission_denied. Either way, changing how many records match must not change one
// byte of the answer.
async function compareQuery(label, channel, db, expected) {
  const q = f => ({ objectType: 'contact', filter: { lifecycle_stage: f }, set: { owner: 'nd-query' } });
  const answers = [await channel.query(q('nd-q-none'))]; // 0 matches
  seed(db, 'rec-EXAMPLE-nd-q1', { lifecycle_stage: 'nd-q1' });
  answers.push(await channel.query(q('nd-q1'))); // 1 match
  seed(db, 'rec-EXAMPLE-nd-q2a', { lifecycle_stage: 'nd-q2' });
  seed(db, 'rec-EXAMPLE-nd-q2b', { lifecycle_stage: 'nd-q2' });
  answers.push(await channel.query(q('nd-q2'))); // 2 matches
  check(`${label} query: each answer is ${expected}`, answers.every(a => errorOf(a) === expected), answers.map(errorOf).join());
  check(`${label} query: 0/1/2 matches are byte-identical`, answers.every(a => normalize(a) === normalize(answers[0])), JSON.stringify(answers).slice(0, 400));
  check(`${label} query: the answer is only {"error":"${expected}"}`, answers.every(a => JSON.stringify(Object.keys(payloadOf(a)).sort()) === '["error"]' && errorOf(a) === expected), JSON.stringify(answers.map(payloadOf)).slice(0, 200));
  check(`${label} query: no change/change_hash/resolved/count/approval_url/message/records/issuers`,
    answers.every(a => ['change', 'change_hash', 'resolved', 'approval_url', 'message', 'records', 'issuers'].every(k => !Object.hasOwn(payloadOf(a), k))), JSON.stringify(answers.map(payloadOf)).slice(0, 300));
}
// R3: read_record must answer a non-reader identically whether the record exists or not,
// and carry no field value either way. Section 2: a record the principal may
// not read is answered exactly as an absent identifier (`null`), at record and operation
// level, so the read is not an oracle on which records exist.
async function compareReadRecord(label, channel) {
  const existing = await channel.read('rec-EXAMPLE-42');
  const absent = await channel.read('rec-EXAMPLE-nd-' + process.pid + '-absent');
  check(`${label} read_record: a non-reader gets the absent answer for an existing record`, textPayload(existing) === null && textPayload(absent) === null, `${JSON.stringify(textPayload(existing))}, ${JSON.stringify(textPayload(absent))}`);
  check(`${label} read_record: the answers are byte-identical`, normalize(existing) === normalize(absent), JSON.stringify([existing, absent]).slice(0, 400));
  check(`${label} read_record: no record content`, !/user-EXAMPLE-3|lifecycle_stage|owner/.test(JSON.stringify(existing)), JSON.stringify(existing).slice(0, 300));
}
// S60(c) with the full read model (S60(a), S76): a principal that is a reader at
// operation level, whose write permission is scoped by record and which is denied read
// on the record or on a field the request writes, gets the same step 1 refusal for a
// record that exists and one that does not. The whole answer is compared, on both
// channels: the MCP connector and the HTTP mapping.
async function compareScopedRefusal(label, channel, db, operation, fieldLevel) {
  const id = fieldLevel ? 'rec-EXAMPLE-nd-scope-field' : 'rec-EXAMPLE-nd-scope-record';
  withSor(db, s => {
    s.db.exec('DELETE FROM write_scopes; DELETE FROM record_permissions; DELETE FROM read_fields;');
    for (const op of OPS) s.permission(account, principal, op, true, true);
    s.recordWriteScope(account, principal);
    if (fieldLevel) s.fieldPermission(account, principal, operation, '/owner', false, 'read');
    else s.recordPermission(account, principal, id, false, false);
  });
  seed(db, id, { owner: 'nd-secret', lifecycle_stage: 'lead' });
  const present = await channel.update(id);
  remove(db, id);
  const absent = await channel.update(id);
  const what = fieldLevel ? 'field-level' : 'record-level';
  check(`${label} ${what} read denial: present and absent are permission_denied`, errorOf(present) === 'permission_denied' && errorOf(absent) === 'permission_denied', `${errorOf(present)}, ${errorOf(absent)}`);
  check(`${label} ${what} read denial: the whole answer is byte-identical`, normalize(present) === normalize(absent), JSON.stringify([present, absent]).slice(0, 400));
  check(`${label} ${what} read denial: the answer is only {"error":"permission_denied"}`, [present, absent].every(a => JSON.stringify(Object.keys(payloadOf(a)).sort()) === '["error"]'), JSON.stringify([payloadOf(present), payloadOf(absent)]).slice(0, 300));
  check(`${label} ${what} read denial: no approval link, no change_hash and no record content`, [present, absent].every(a => !Object.hasOwn(payloadOf(a), 'approval_url') && !hasMember(payloadOf(a), 'change_hash') && !/nd-secret|lifecycle_stage/.test(JSON.stringify(payloadOf(a)))), JSON.stringify([payloadOf(present), payloadOf(absent)]).slice(0, 300));
}
// S78/S77: read_record refuses the record the principal may not read, and an identifier
// that resolves to it is answered exactly as an identifier that names no record. A
// readable alias is still read.
async function compareReadAlias(label, channel, db) {
  withSor(db, s => {
    s.permission(account, principal, OP, true, true);
    // The earlier scoped-refusal cases leave a field read denial behind; the readable
    // alias this case checks holds only an ordinary read.
    s.db.prepare('DELETE FROM read_fields WHERE account=? AND principal=?').run(account, principal);
    s.seed(account, 'rec-SECRET-nd', { owner: 'secret-owner-nd', notes: 'confidential-nd' });
    s.recordPermission(account, principal, 'rec-SECRET-nd', false, true);
    s.merge(account, 'rec-ALIAS-nd', 'rec-SECRET-nd');
    s.seed(account, 'rec-OPEN-nd', { owner: 'open-owner-nd' });
    s.merge(account, 'rec-OPEN-ALIAS-nd', 'rec-OPEN-nd');
  });
  const denied = await channel.read('rec-SECRET-nd');
  const aliased = await channel.read('rec-ALIAS-nd');
  const absent = await channel.read('rec-ABSENT-nd');
  // Section 2: the unreadable record itself, named directly, is answered
  // exactly as an absent identifier at record and operation level.
  check(`${label} read_record alias: the unreadable record answers exactly as an absent identifier`, normalize(denied) === normalize(absent), JSON.stringify([denied, absent]).slice(0, 400));
  check(`${label} read_record alias: the unreadable record answer is null`, textPayload(denied) === null, JSON.stringify(denied).slice(0, 300));
  check(`${label} read_record alias: the alias answers exactly as an absent identifier`, normalize(aliased) === normalize(absent), JSON.stringify([aliased, absent]).slice(0, 400));
  check(`${label} read_record alias: the alias answer is null`, textPayload(aliased) === null, JSON.stringify(aliased).slice(0, 300));
  check(`${label} read_record alias: no record content`, !/secret-owner-nd|confidential-nd/.test(JSON.stringify([denied, aliased])), JSON.stringify([denied, aliased]).slice(0, 300));
  const open = await channel.read('rec-OPEN-ALIAS-nd');
  check(`${label} read_record alias: a readable alias is still read`, textPayload(open)?.properties?.owner === 'open-owner-nd', JSON.stringify(open).slice(0, 300));
}
async function stdioClient(db, log, extra = {}) {
  const client = new Client({ name: 'e2e-nondisclosure-' + log, version: '1' }, { capabilities: {}, versionNegotiation: { mode: { pin: '2026-07-28' } } });
  clients.push(client);
  await client.connect(new StdioClientTransport({ command: process.execPath, args: [here + 'src/mcp-server.mjs'], cwd: here, env: envFor(db, log, extra) }));
  track(db, log);
  // The stdio server builds its runtime lazily: the SDK probes with one process at
  // connect and the serving process builds its runtime only when it first serves a
  // request, creating a fresh database and granting its defaults then. Prime it with one
  // unguarded call; its answer proves the setup has run, so the non-reader override below
  // cannot be reverted by it. Do not prime after writing the non-reader.
  await client.callTool({ name: 'read_record', arguments: { id: 'rec-EXAMPLE-42' } });
  return client;
}
async function run(covered) {
  const mode = covered ? 'covered mode' : 'default mode';
  // Each entry point gets its own fresh database in each mode: a shared one would let
  // mcp-http's server mode (or a mutation's preconditions) change what another entry
  // point sees on start.
  const dbFor = name => here + `e2e-nd-${process.pid}${covered ? '-cov' : ''}-${name}.sqlite`;
  const logFor = name => here + `e2e-nd-${process.pid}${covered ? '-cov' : ''}-${name}.log`;
  // The MCP-over-HTTP connector and the HTTP mapping share one default mcp-http.mjs
  // process, as the README presents them.
  const httpDb = dbFor('http');
  const web = await startWeb(httpDb, logFor('http'), covered ? { VA_PRECONDITIONS: '1' } : {});
  setNonReader(httpDb);

  assertNonReader(`${mode}, before the HTTP mapping requests`, httpDb);
  await compare(`${mode}, HTTP mapping`, httpChannel(web.base, web.token), httpDb, { covered, expected: 'approval_required', requestKey: covered });
  assertNonReader(`${mode}, after the HTTP mapping requests`, httpDb);

  const connector = new Client({ name: 'e2e-nd-connector', version: '1' }, { capabilities: {}, versionNegotiation: { mode: { pin: '2026-07-28' } } });
  clients.push(connector);
  await connector.connect(new StreamableHTTPClientTransport(new URL(web.base + '/mcp/' + web.token)));
  const connectorChannel = toolChannel(connector);
  assertNonReader(`${mode}, before the MCP connector requests`, httpDb);
  await compare(`${mode}, MCP connector`, connectorChannel, httpDb, { covered, expected: 'approval_required', requestKey: covered });
  await compareQuery(`${mode}, MCP connector`, connectorChannel, httpDb, covered ? 'permission_denied' : 'approver_not_authorized');
  await compareReadRecord(`${mode}, MCP connector`, connectorChannel);
  assertNonReader(`${mode}, after the MCP connector requests`, httpDb);

  // S60(c) with the full read model (S60(a), S76): a record-level and a field-level
  // read denial for a principal whose write permission is scoped by record. Present and
  // absent must give the same step 1 refusal on both channels.
  await compareScopedRefusal(`${mode}, HTTP mapping`, httpChannel(web.base, web.token), httpDb, HTTP, false);
  await compareScopedRefusal(`${mode}, HTTP mapping`, httpChannel(web.base, web.token), httpDb, HTTP, true);
  await compareScopedRefusal(`${mode}, MCP connector`, connectorChannel, httpDb, OP, false);
  await compareScopedRefusal(`${mode}, MCP connector`, connectorChannel, httpDb, OP, true);
  await compareReadAlias(`${mode}, MCP connector`, connectorChannel, httpDb);

  // stdio in server mode (VA_MODE=server) and in the default organization mode. In the
  // covered mode the server-issued entry points answer approval_required, and their query
  // answer is S72's permission_denied. The default stdio entry point (organization mode)
  // offers no server-issued profile for a covered operation, so S66 answers
  // approver_not_authorized with no change_hash, and by item 6 (S66 before S72) its query
  // is approver_not_authorized too, not permission_denied.
  for (const [label, name, extra, expected, keys, queryExpected] of [
    ['MCP stdio', 'server', { VA_MODE: 'server', ...(covered ? { VA_PRECONDITIONS: '1' } : {}) }, 'approval_required', covered, covered ? 'permission_denied' : 'approver_not_authorized'],
    // Covered mode: the S66 refusal is given before a request key reaches the answer,
    // so request_key is not asserted there (S66 requires no change_hash, checked above).
    ['MCP stdio default', 'default', covered ? { VA_PRECONDITIONS: '1' } : {}, covered ? 'approver_not_authorized' : 'approval_required', covered ? undefined : false, 'approver_not_authorized'],
  ]) {
    const db = dbFor(name);
    const client = await stdioClient(db, logFor(name), extra);
    setNonReader(db);
    const channel = toolChannel(client);
    assertNonReader(`${mode}, before the ${label} requests`, db);
    await compare(`${mode}, ${label}`, channel, db, { covered, expected, requestKey: keys });
    await compareQuery(`${mode}, ${label}`, channel, db, queryExpected);
    await compareReadRecord(`${mode}, ${label}`, channel);
    assertNonReader(`${mode}, after the ${label} requests`, db);
  }

  // A stored preconditions setting is authoritative for an existing database: a start
  // whose VA_PRECONDITIONS disagrees must refuse in either direction.
  const onDb = dbFor('stored-on');
  const on = await startWeb(onDb, logFor('stored-on-1'), { VA_PRECONDITIONS: '1' });
  await stopChild(on.child);
  const r1 = await expectRefusal(onDb, logFor('stored-on-2')); // stored true, requested false
  const offDb = dbFor('stored-off');
  const off = await startWeb(offDb, logFor('stored-off-1'));
  await stopChild(off.child);
  const r2 = await expectRefusal(offDb, logFor('stored-off-2'), { VA_PRECONDITIONS: '1' }); // stored false, requested true
  const r3 = await expectStdioRefusal(onDb, logFor('stored-on-stdio')); // stored true, requested false
  const r4 = await expectStdioRefusal(offDb, logFor('stored-off-stdio'), { VA_PRECONDITIONS: '1' }); // stored false, requested true
  for (const r of [r1, r2]) {
    check(`${mode}: a mismatched stored setting refuses to start`, r.listened === false, JSON.stringify(r));
    check(`${mode}: the refusal names stored and requested values`, /\btrue\b/.test(r.stderr) && /\bfalse\b/.test(r.stderr), r.stderr);
    check(`${mode}: the refusal names preconditions and the remedy`, /preconditions/i.test(r.stderr) && /VA_PRECONDITIONS/.test(r.stderr) && /database/i.test(r.stderr), r.stderr);
    check(`${mode}: the refusal offers a new database file first and names the covered mode`, /new database file/i.test(r.stderr) && /experimental covered mode/i.test(r.stderr) && r.stderr.indexOf('new database file') < r.stderr.indexOf('VA_PRECONDITIONS'), r.stderr);
  }
  for (const r of [r3, r4]) {
    check(`${mode}: the stdio entry point refuses a mismatched stored setting at start`, r.exited && r.code !== 0, JSON.stringify(r));
    check(`${mode}: the stdio refusal is not an Internal server error answer`, !/Internal server error/.test(r.stderr), r.stderr);
    check(`${mode}: the stdio refusal names stored and requested values`, /\btrue\b/.test(r.stderr) && /\bfalse\b/.test(r.stderr), r.stderr);
    check(`${mode}: the stdio refusal names preconditions and the remedy`, /preconditions/i.test(r.stderr) && /VA_PRECONDITIONS/.test(r.stderr) && /database/i.test(r.stderr), r.stderr);
    check(`${mode}: the stdio refusal offers a new database file first and names the covered mode`, /new database file/i.test(r.stderr) && /experimental covered mode/i.test(r.stderr) && r.stderr.indexOf('new database file') < r.stderr.indexOf('VA_PRECONDITIONS'), r.stderr);
  }
}
try {
  await run(false);
  await run(true);
} finally {
  for (const c of clients) await c.close().catch(() => {});
  for (const child of webs) await stopChild(child).catch(() => {});
  for (const db of startedDb) for (const s of ['', '-wal', '-shm']) fs.rmSync(db + s, { force: true });
  for (const log of startedLog) fs.rmSync(log, { force: true });
}
console.log(`\nE2E: ${n - bad} of ${n} passed`);
process.exit(bad ? 1 : 0);
