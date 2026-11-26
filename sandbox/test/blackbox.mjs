// Independent black-box check, written separately from the sandbox and its own test
// runner. It talks to src/mcp-server.mjs over stdio only and compares against the
// published vectors. Usage: node test/blackbox.mjs
import { Client } from '@modelcontextprotocol/client';
import { StdioClientTransport } from '@modelcontextprotocol/client/stdio';
import fs from 'node:fs';
import { fileURLToPath } from 'node:url';
const here = fileURLToPath(new URL('..', import.meta.url));
const V = JSON.parse(fs.readFileSync(here + 'spec/vectors/vectors.json', 'utf8'));
const vec = n => V.change_hash_vectors.find(v => v.name.startsWith(n + '-'));
const KEY = 'org.enforcedapproval/receipt', REFUSAL = 'org.enforcedapproval/refusal';
let n = 0, bad = 0;
const check = (name, ok, detail = '') => { n++; if (!ok) bad++; console.log((ok ? 'ok   ' : 'FAIL ') + name + (ok ? '' : '  ' + detail)); };

async function session(mode, fn, extraEnv = {}) {
  const db = here + `bb-${process.pid}-${Math.random().toString(36).slice(2)}.sqlite`;
  const client = new Client({ name: 'blackbox', version: '0' }, { capabilities: { elicitation: { url: {} } }, versionNegotiation: { mode: { pin: '2026-07-28' } } });
  const transport = new StdioClientTransport({ command: 'node', args: [here + 'src/mcp-server.mjs'], cwd: here,
    env: { ...process.env, VA_ADMIN: 'bb-admin', VA_MODE: mode, VA_DB: db, VA_NOW: String(V.now), VA_TEST_ISSUER: '1', ...extraEnv } });
  await client.connect(transport);
  const call = async (name, args, meta) => { try { return await client.callTool({ name, arguments: args, ...(meta && { _meta: meta }) }); } catch (e) { return { thrown: e?.message, code: e?.code }; } };
  try { await fn(call); } finally { await client.close().catch(() => {}); for (const s of ['', '-wal', '-shm']) fs.rmSync(db + s, { force: true }); }
}
const refusal = r => r?._meta?.[REFUSAL] ?? (() => { try { return JSON.parse(r?.content?.find(c => c.type === 'text')?.text ?? 'null'); } catch { return null; } })();
const read = async call => JSON.parse((await call('read_record', { id: 'rec-EXAMPLE-42' })).content[0].text);
const v1 = vec('V1'), v2 = vec('V2'), v3 = vec('V3'), v4 = vec('V4');
const covered = process.env.VA_PRECONDITIONS === '1';

await session('organization', async call => {
  const before = await read(call);
  const r = await call('manage_records', v1.request_arguments);
  const a = refusal(r);
  check('no receipt is refused', r.isError === true && a?.error === (covered ? 'approver_not_authorized' : 'approval_required'), JSON.stringify(r).slice(0, 300));
  check(covered ? 'covered refusal has no change_hash (S66)' : 'refusal hash equals vector V1', covered ? !Object.hasOwn(a ?? {}, 'change_hash') : a?.change_hash === v1.change_hash, `${a?.change_hash} vs ${v1.change_hash}`);
  const text = r.content?.find(c => c.type === 'text')?.text ?? '';
  check('refusal is also JSON in the text block', (() => { try { const j = JSON.parse(text), a = j.approval ?? j; return covered ? a.error === 'approver_not_authorized' && !Object.hasOwn(a, 'change_hash') : a.change_hash === v1.change_hash; } catch { return false; } })(), text.slice(0, 200));
  const r2 = await call('manage_records', v2.request_arguments);
  check('approval field set, still refused, same hash', refusal(r2)?.error === (covered ? 'approver_not_authorized' : 'approval_required') && (covered ? !Object.hasOwn(refusal(r2) ?? {}, 'change_hash') : refusal(r2)?.change_hash === v1.change_hash), JSON.stringify(refusal(r2)));
  const after = await read(call);
  check('record unchanged after refusals', JSON.stringify(before) === JSON.stringify(after));
  for (const [name, want] of [['tampered_payload', 'approval_invalid'], ['wrong_audience', 'approval_invalid'], ['expired', 'approval_expired']]) {
    const x = await call('manage_records', name === 'tampered_payload' ? v4.request_arguments : v1.request_arguments, { [KEY]: V.receipts[name].jws });
    check(`${name} receipt -> ${covered ? 'approver_not_authorized' : want}`, refusal(x)?.error === (covered ? 'approver_not_authorized' : want), JSON.stringify(refusal(x) ?? x).slice(0, 200));
  }
  const m = await call('manage_records', v4.request_arguments, { [KEY]: V.receipts.person.jws });
  check(covered ? 'changed argument with a receipt is refused for a covered operation (S66)' : 'changed argument with V1 receipt -> approval_mismatch', refusal(m)?.error === (covered ? 'approver_not_authorized' : 'approval_mismatch'), JSON.stringify(refusal(m) ?? m).slice(0, 200));
  check('record still unchanged', JSON.stringify(await read(call)) === JSON.stringify(before));
  const okRes = await call('manage_records', v3.request_arguments, { [KEY]: V.receipts.person.jws });
  const got = await read(call);
  check(covered ? 'valid receipt is refused for a covered operation (S66)' : 'valid receipt with reordered members executes', covered ? okRes.isError === true && refusal(okRes)?.error === 'approver_not_authorized' && !Object.hasOwn(refusal(okRes) ?? {}, 'change_hash') && (got?.properties ?? got)?.owner === 'user-EXAMPLE-3' : !okRes.isError && (got?.properties ?? got)?.owner === 'user-EXAMPLE-7', JSON.stringify(okRes).slice(0, 200) + ' ' + JSON.stringify(got));
  const ver = got?.version;
  const rep = await call('manage_records', v1.request_arguments, { [KEY]: V.receipts.person.jws });
  const got2 = await read(call);
  check('replay does not execute again', got2?.version === ver && (!covered || (rep.isError === true && refusal(rep)?.error === 'approver_not_authorized')), `version ${ver} -> ${got2?.version}; ${JSON.stringify(refusal(rep) ?? rep).slice(0, 160)}`);
  const both = await call('manage_records', { ...v1.request_arguments, approval_receipt: V.receipts.grant.jws }, { [KEY]: V.receipts.grant.jws });
  check(covered ? 'receipt in both places is refused for a covered operation (S66)' : 'receipt in both places -> approval_invalid', refusal(both)?.error === (covered ? 'approver_not_authorized' : 'approval_invalid'), JSON.stringify(refusal(both) ?? both).slice(0, 200));
});
await session('organization', async call => {
  const r = await call('manage_records', { ...v1.request_arguments, approval_receipt: V.receipts.person.jws });
  const got = await read(call);
  check(covered ? 'receipt as argument is refused for a covered operation (S66)' : 'receipt as argument executes (same hash)', covered ? r.isError === true && refusal(r)?.error === 'approver_not_authorized' && !Object.hasOwn(refusal(r) ?? {}, 'change_hash') && (got?.properties ?? got)?.owner === 'user-EXAMPLE-3' : !r.isError && (got?.properties ?? got)?.owner === 'user-EXAMPLE-7', JSON.stringify(r).slice(0, 200));
});
await session('organization', async call => {
  const r = await call('manage_records', v1.request_arguments, { [KEY]: V.receipts.person.jws });
  check(covered ? 'other principal receipt is refused for a covered operation (S66)' : 'other principal cannot spend the receipt', refusal(r)?.error === (covered ? 'approver_not_authorized' : 'approval_mismatch'), JSON.stringify(refusal(r) ?? r).slice(0, 200));
}, { VA_PRINCIPAL: 'agent-EXAMPLE-other' });
await session('server', async call => {
  const r = await call('manage_records', v1.request_arguments);
  const txt = JSON.stringify(r);
  check('server-issued: no write when the client only answers accept', (await read(call))?.version === 1 || /approval_required|input_required/.test(txt), txt.slice(0, 300));
  const got = await read(call);
  check('server-issued: record unchanged', (got?.properties ?? got)?.owner === 'user-EXAMPLE-3', JSON.stringify(got));
});
console.log(`\nBLACKBOX: ${n - bad} of ${n} passed`);
process.exit(bad ? 1 : 0);
