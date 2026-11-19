import crypto from 'node:crypto';
export function jcs(v) {
  if (typeof v === 'string' && !v.isWellFormed()) throw Error('surrogate');
  if (v === null || typeof v !== 'object') {
    if (typeof v === 'number' && (!Number.isFinite(v) || (Number.isInteger(v) && !Number.isSafeInteger(v)))) throw Error('number');
    const s = JSON.stringify(v); if (s === undefined) throw Error('not JSON'); return s;
  }
  if (Array.isArray(v)) return '[' + v.map(jcs).join(',') + ']';
  return '{' + Object.keys(v).sort().map(k => { if (!k.isWellFormed()) throw Error('key'); return JSON.stringify(k) + ':' + jcs(v[k]); }).join(',') + '}';
}
export const hash = v => crypto.createHash('sha256').update(jcs(v)).digest('base64url');
export const object = x => x !== null && typeof x === 'object' && !Array.isArray(x);
// Parse raw JSON before JSON.parse can erase duplicate keys or rounded integers.
export function parseJSON(s) {
  let i = 0;
  const ws = () => { while (/\s/.test(s[i] ?? '') && i < s.length) i++; };
  function str() { const start = i++; while (i < s.length) { if (s[i] === '\\') { i += 2; continue; } if (s[i++] === '"') return JSON.parse(s.slice(start, i)); } throw Error('string'); }
  function val() {
    ws(); const c = s[i];
    if (c === '{') { i++; ws(); const keys = new Set(); if (s[i] === '}') { i++; return; } for (;;) { ws(); if (s[i] !== '"') throw Error('key'); const k = str(); if (keys.has(k)) throw Error('duplicate'); keys.add(k); ws(); if (s[i++] !== ':') throw Error('colon'); val(); ws(); const end = s[i++]; if (end === '}') return; if (end !== ',') throw Error('comma'); } }
    if (c === '[') { i++; ws(); if (s[i] === ']') { i++; return; } for (;;) { val(); ws(); const end = s[i++]; if (end === ']') return; if (end !== ',') throw Error('comma'); } }
    if (c === '"') { str(); return; }
    const m = /^(?:true|false|null|-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?)/.exec(s.slice(i)); if (!m) throw Error('value'); i += m[0].length;
    if (/^-?\d+$/.test(m[0]) && (BigInt(m[0]) > 9007199254740991n || BigInt(m[0]) < -9007199254740991n)) throw Error('unsafe integer');
  }
  val(); ws(); if (i !== s.length) throw Error('trailing'); const v = JSON.parse(s); jcs(v); return v;
}
export function changeObject({ audience, account, principal, operation, args = {}, approvalFields = ['/confirmation', '/approval_receipt'], preconditions, resolved }) {
  if (!object(args)) throw Error('arguments must be object'); jcs(args);
  const a = structuredClone(args);
  for (const pointer of approvalFields) {
    const parts = pointer.slice(1).split('/').map(x => x.replace(/~1/g, '/').replace(/~0/g, '~'));
    let o = a; for (const p of parts.slice(0, -1)) o = o?.[p]; if (object(o)) delete o[parts.at(-1)];
  }
  const c = { v: 1, audience, account, principal, operation, arguments: a };
  if (preconditions) c.preconditions = preconditions;
  if (resolved) c.resolved = resolved;
  jcs(c); return c;
}
