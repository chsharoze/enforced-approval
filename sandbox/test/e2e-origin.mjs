// Browser-like origin check on the approval pages. Usage: node test/e2e-origin.mjs
// Added after the first real-browser sign-in failed: the in-process tests sent no Origin
// header, so they never saw what a browser sends.
import { spawn } from 'node:child_process';
import fs from 'node:fs';
const here = new URL('..', import.meta.url).pathname;
// Browser-like origin handling (added after the first real-browser sign-in failed):
// a form post carrying the page's own Origin is accepted; "null" or a foreign origin is refused.
{
  const P2 = 8798, B2 = `http://127.0.0.1:${P2}`, db2 = here + `e2e-origin-${process.pid}.sqlite`;
  const env2 = { ...process.env, VA_ADMIN: 'e2e-admin', VA_MODE: 'server', VA_DB: db2, PORT: String(P2), VA_BASE_URL: B2, NODE_NO_WARNINGS: '1' };
  const web2 = spawn('node', [here + 'src/http.mjs'], { cwd: here, env: env2, stdio: 'ignore' });
  await new Promise(r => setTimeout(r, 700));
  let ok = 0, total = 0; const chk = (name, c, d = '') => { total++; if (c) ok++; console.log((c ? 'ok   ' : 'FAIL ') + name + (c ? '' : '  ' + d)); };
  try {
    const first = await fetch(B2 + '/grants');
    const cookie = (first.headers.get('set-cookie') ?? '').split(';')[0];
    const html = await first.text();
    const csrf = /name="csrf" value="([^"]+)"/.exec(html)?.[1];
    chk('pages send Referrer-Policy: same-origin', first.headers.get('referrer-policy') === 'same-origin', String(first.headers.get('referrer-policy')));
    const post = origin => fetch(B2 + '/signin', { method: 'POST', redirect: 'manual', headers: { cookie, ...(origin && { origin }) }, body: new URLSearchParams({ csrf: csrf ?? '', person: 'test-person' }) });
    const rNull = await post('null'), rEvil = await post('https://evil.example'), rOwn = await post(B2);
    chk('sign-in with Origin: null is refused', rNull.status >= 400, String(rNull.status));
    chk('sign-in from another origin is refused', rEvil.status >= 400, String(rEvil.status));
    chk('sign-in with the page\'s own Origin is accepted', rOwn.status < 400, `${rOwn.status} ${(await rOwn.text()).slice(0, 80)} csrf=${csrf ? 'found' : 'missing'}`);
  } finally { web2.kill(); for (const s of ['', '-wal', '-shm']) fs.rmSync(db2 + s, { force: true }); }
  console.log(`ORIGIN: ${ok} of ${total} passed`);
  if (ok !== total) process.exitCode = 1;
}
