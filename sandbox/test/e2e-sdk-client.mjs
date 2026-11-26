// Drives the sandbox with the real MCP client SDK (@modelcontextprotocol/client) over a
// real loopback stdio connection, with a pass-through transport tap recording every
// JSON-RPC message both ways. Prints what the client does as OBSERVED lines and asserts
// only what the specification requires. Pages are served by src/http.mjs on 127.0.0.1,
// one shared database, as in test/e2e-server-issued.mjs. Usage: node test/e2e-sdk-client.mjs
import { Client } from '@modelcontextprotocol/client';
import { StdioClientTransport } from '@modelcontextprotocol/client/stdio';
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import { DatabaseSync } from 'node:sqlite';
import { fileURLToPath } from 'node:url';
const here = fileURLToPath(new URL('..', import.meta.url));
const PORT = 8798, BASE = `http://127.0.0.1:${PORT}`, db = here + `e2e-sdk-${process.pid}.sqlite`, pageLog = here + `e2e-sdk-pages-${process.pid}.log`;
const env = { ...process.env, VA_ADMIN: 'e2e-sdk-admin', VA_MODE: 'server', VA_DB: db, PORT: String(PORT), VA_BASE_URL: BASE, VA_LOG: pageLog, VA_SIGNIN_SECRET: 'e2e-sdk-signin-secret', NODE_NO_WARNINGS: '1' };
let n = 0, bad = 0;
const check = (name, ok, detail = '') => { n++; if (!ok) bad++; console.log((ok ? 'ok   ' : 'FAIL ') + name + (ok ? '' : '  ' + detail)); };
const observed = text => console.log('OBSERVED: ' + text);
const web = spawn('node', [here + 'src/http.mjs'], { cwd: here, env, stdio: 'ignore' });
await new Promise(r => setTimeout(r, 700));
const database = new DatabaseSync(db, { readOnly: true });
const count = () => database.prepare('SELECT count(*) n FROM history').get().n;
const args = owner => ({ objectType: 'contact', action: 'update', records: [{ id: 'rec-EXAMPLE-42', properties: { lifecycle_stage: 'customer', owner } }] });
const ref = r => r?._meta?.['org.enforcedapproval/refusal'];
const text = r => r?.content?.filter(c => c.type === 'text').map(c => c.text).join('\n') ?? '';
const toolCalls = log => log.filter(e => e.dir === 'c->s' && e.msg.method === 'tools/call');
const responseTo = (log, id) => log.find(e => e.dir === 's->c' && e.msg.id === id);

// A pass-through Transport that records every message in both directions.
function tap(transport, log) {
  const t = {
    onmessage: undefined, onclose: undefined, onerror: undefined,
    async start() {
      transport.onmessage = (msg, extra) => { log.push({ dir: 's->c', msg }); t.onmessage?.(msg, extra); };
      transport.onclose = () => t.onclose?.();
      transport.onerror = e => t.onerror?.(e);
      return transport.start();
    },
    send(msg, opts) { log.push({ dir: 'c->s', msg }); return transport.send(msg, opts); },
    close() { return transport.close(); },
  };
  return t;
}
function stdio(log) {
  return tap(new StdioClientTransport({ command: 'node', args: [here + 'src/mcp-server.mjs'], cwd: here, env }), log);
}
async function approveInBrowser(url, decision) {
  const first = await fetch(url);
  const preCookie = (first.headers.get('set-cookie') ?? '').split(';')[0], preCsrf = /name="csrf" value="([a-f0-9]+)"/.exec(await first.text())?.[1];
  const s = await fetch(BASE + '/signin', { method: 'POST', headers: { cookie: preCookie }, redirect: 'manual', body: new URLSearchParams({ person: 'test-person', csrf: preCsrf, secret: env.VA_SIGNIN_SECRET }) });
  const cookie = (s.headers.get('set-cookie') ?? '').split(';')[0];
  const page = await (await fetch(url, { headers: { cookie } })).text();
  const csrf = /name="csrf" value="([a-f0-9]+)"/.exec(page)?.[1];
  // S68(4): for a covered operation the page's form names the displayed record; a real
  // browser posts it back, so the driver does the same.
  const record = /name="record" value="([a-f0-9]+)"/.exec(page)?.[1];
  const done = await fetch(url, { method: 'POST', headers: { cookie }, body: new URLSearchParams({ csrf, decision, ...(record ? { record } : {}) }) });
  return { status: done.status, doneText: await done.text() };
}
const clients = [];
async function connect(capabilities) {
  const log = [];
  const client = new Client({ name: 'e2e-sdk-client', version: '1' }, { capabilities, versionNegotiation: { mode: { pin: '2026-07-28' } } });
  await client.connect(stdio(log));
  clients.push(client);
  return { client, log };
}
try {
  // 1. A client that does not declare URL-mode elicitation.
  {
    const { client, log } = await connect({});
    const before = count();
    const r = await client.callTool({ name: 'manage_records', arguments: args('sdk-no-elicitation') });
    const calls = toolCalls(log);
    observed(`no-elicitation client: the guarded call came back as a plain tool result (isError=${r.isError}), not an input-required; the client sent ${calls.length} tools/call request and did not retry`);
    observed(`no-elicitation client: refusal error=${ref(r)?.error}; message carries the link itself: ${String(ref(r)?.message).includes('Approval page: ' + ref(r)?.approval_url)}`);
    check('without URL mode the refusal carries approval_url and the message includes the link (S59)', ref(r)?.error === 'approval_required' && typeof ref(r)?.approval_url === 'string' && ref(r).message.includes('Approval page: ' + ref(r).approval_url));
    check('nothing was written without an approval', count() === before && r.isError === true);
  }
  // 2 to 5. A client that declares URL-mode elicitation.
  const { client, log } = await connect({ elicitation: { url: {} } });
  let mode = 'accept-only'; const seen = [];
  client.setRequestHandler('elicitation/create', async req => {
    seen.push(req.params);
    if (mode === 'approve') await approveInBrowser(req.params.url, 'approve');
    return { action: mode === 'approve' || mode === 'accept-only' ? 'accept' : mode };
  });
  // 2. The elicitation handler answers accept without any page decision.
  {
    const before = count(), mark = log.length;
    const r = await client.callTool({ name: 'manage_records', arguments: args('sdk-accept-only') });
    const calls = toolCalls(log.slice(mark));
    const first = responseTo(log.slice(mark), calls[0]?.msg.id);
    observed(`elicitation client, accept-only: the first answer was ${first?.msg.result?.resultType ?? (first?.msg.result ? 'complete result' : 'error')} with inputRequests keys ${JSON.stringify(Object.keys(first?.msg.result?.inputRequests ?? {}))}`);
    observed(`elicitation client, accept-only: the client retried by itself after the handler answered accept: ${calls.length === 2}; retry id ${JSON.stringify(calls[1]?.msg.id)} vs first id ${JSON.stringify(calls[0]?.msg.id)} (fresh id: ${calls[1]?.msg.id !== calls[0]?.msg.id})`);
    observed(`elicitation client, accept-only: retry arguments byte-identical: ${JSON.stringify(calls[1]?.msg.params?.arguments) === JSON.stringify(calls[0]?.msg.params?.arguments)}`);
    observed(`elicitation client, accept-only: retry sends inputResponses=${JSON.stringify(calls[1]?.msg.params?.inputResponses)} requestState=${JSON.stringify(calls[1]?.msg.params?.requestState ?? null)} _meta keys=${JSON.stringify(Object.keys(calls[1]?.msg.params?._meta ?? {}))}`);
    observed(`elicitation client, accept-only: while the approval is still pending the client stops after ${calls.length} requests (1 retry); it does not poll. Final result isError=${r.isError} error=${ref(r)?.error}`);
    observed(`elicitation client, accept-only: the elicitation carried the link in url and not in the message (message has link: ${String(seen.at(-1)?.message).includes('/approve/')}); the refusal after the answer does not repeat the link (message has link: ${String(ref(r)?.message).includes('/approve/')})`);
    check('accept is only a signal to look again (S21): no write, still approval_required', count() === before && ref(r)?.error === 'approval_required');
  }
  // 3. The person approves on the page; the handler answers accept.
  {
    mode = 'approve';
    const before = count(), mark = log.length;
    const r = await client.callTool({ name: 'manage_records', arguments: args('sdk-approved') });
    const calls = toolCalls(log.slice(mark));
    observed(`approve flow: the handler visited the page and answered accept; the client retried once (requests: ${calls.length}) and the retry executed; result isError=${r.isError === true}`);
    check('an approval on the page lets the retried call execute exactly once', r.isError !== true && count() === before + 1, JSON.stringify(r).slice(0, 200));
    // Draft 0.2 (S80): the operation is not covered, so an identical request after
    // consumption is answered with the recorded outcome and does not execute, even
    // though the write changed the record.
    mode = 'accept-only'; let promptsBefore = seen.length;
    const again = await client.callTool({ name: 'manage_records', arguments: args('sdk-approved') });
    let outcome; try { outcome = JSON.parse(text(again))?.recorded_outcome; } catch {}
    observed(`identical arguments after the write: ${seen.length - promptsBefore} new elicitations; result carries recorded_outcome=${JSON.stringify(outcome)}`);
    check('an identical request after consumption is answered with the recorded outcome and does not execute (S80)', count() === before + 1 && seen.length === promptsBefore && again.isError !== true && outcome?.outcome === 'success' && outcome?.sent_now === false, JSON.stringify(again).slice(0, 240));
    promptsBefore = seen.length;
    const again2 = await client.callTool({ name: 'manage_records', arguments: args('sdk-approved') });
    let outcome2; try { outcome2 = JSON.parse(text(again2))?.recorded_outcome; } catch {}
    observed(`second identical request: ${seen.length - promptsBefore} new elicitations; result carries recorded_outcome=${JSON.stringify(outcome2)}`);
    check('a further identical request is still the recorded outcome and still does not execute (S80)', count() === before + 1 && seen.length === promptsBefore && again2.isError !== true && outcome2?.outcome === 'success' && outcome2?.sent_now === false, JSON.stringify(again2).slice(0, 240));
  }
  // 4 and 5. Decline and cancel answers.
  for (const [action, owner] of [['decline', 'sdk-decline'], ['cancel', 'sdk-cancel']]) {
    mode = action;
    const before = count(), mark = log.length;
    const r = await client.callTool({ name: 'manage_records', arguments: args(owner) });
    const calls = toolCalls(log.slice(mark));
    observed(`${action} answer: the client retried once with inputResponses=${JSON.stringify(calls[1]?.msg.params?.inputResponses)}; final result error=${ref(r)?.error}`);
    check(`${action} voids the request (S30): no write, approval_cancelled`, count() === before && ref(r)?.error === 'approval_cancelled', JSON.stringify(ref(r) ?? r).slice(0, 200));
    mode = 'accept-only'; const prompts = seen.length;
    const later = await client.callTool({ name: 'manage_records', arguments: args(owner) });
    check(`${action} stays in force for the change until the record expires: no new elicitation, still approval_cancelled`, seen.length === prompts && ref(later)?.error === 'approval_cancelled', JSON.stringify(ref(later) ?? later).slice(0, 200));
  }
  mode = 'accept-only';
} finally {
  for (const c of clients) await c.close().catch(() => {});
  database.close(); web.kill();
  for (const s of ['', '-wal', '-shm']) fs.rmSync(db + s, { force: true });
  fs.rmSync(pageLog, { force: true });
}
console.log(`\nE2E: ${n - bad} of ${n} passed`);
process.exit(bad ? 1 : 0);
