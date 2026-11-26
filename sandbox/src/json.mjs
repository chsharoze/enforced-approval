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
// S65: a value read from the system of record need not have an RFC 8785 form. An
// integer beyond the safe range, a string with a lone surrogate, or a number that is not
// finite cannot be serialized, but hashing record state must still be total and must
// tell distinct values apart. Such a value is hashed over a tagged encoding of the whole
// object it belongs to; every value carries a type tag and every string its code points,
// so no two values encode alike. The objects this is used for always carry members the
// wrapper does not (a state hash input's `purpose`, a change's `v`), so an encoded object
// never hashes as the object itself would.
function encoded(v) {
  if (v === null) return ['z'];
  if (typeof v === 'number') return ['n', Object.is(v, -0) ? '-0' : String(v)];
  if (typeof v === 'boolean') return ['b', String(v)];
  if (typeof v === 'string') return ['s', [...v].map(c => c.codePointAt(0))];
  if (Array.isArray(v)) return ['a', v.map(encoded)];
  if (object(v)) return ['o', Object.keys(v).sort().map(k => [[...k].map(c => c.codePointAt(0)), encoded(v[k])])];
  return ['x', String(v)];
}
const hasNoRFC8785Form = v => { try { jcs(v); return false; } catch { return true; } };
const recordForm = v => ({ $unencodable: encoded(v) });
export const jcsTotal = v => hasNoRFC8785Form(v) ? jcs(recordForm(v)) : jcs(v);
export const hashTotal = v => hasNoRFC8785Form(v) ? hash(recordForm(v)) : hash(v);
const SAFE = 9007199254740991n;
// Exact integer value of a JSON number token, or null when the token is not an integer.
function exactInteger(token) {
  const m = /^(-?)(\d+)(?:\.(\d+))?(?:[eE]([+-]?\d+))?$/.exec(token);
  if (!m) return null;
  const sign = m[1] === '-' ? -1n : 1n, frac = m[3] ?? '';
  if ((m[4] ?? '').replace(/^[+-]/, '').length > 4) throw Error('number');
  const digits = BigInt(m[2] + frac), shift = BigInt(m[4] ?? '0') - BigInt(frac.length);
  if (shift >= 0n) return sign * digits * 10n ** shift;
  const divisor = 10n ** -shift;
  if (digits % divisor !== 0n) return null;
  return sign * (digits / divisor);
}
function numberToken(token) {
  if (process.env.VA_MUTATE === 'unsafe-integer-all-digits-only') {
    if (/^-?\d+$/.test(token) && (BigInt(token) > SAFE || BigInt(token) < -SAFE)) throw Error('unsafe integer');
    return;
  }
  const exact = exactInteger(token);
  if (exact !== null && (exact > SAFE || exact < -SAFE)) throw Error('unsafe integer');
}
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
    numberToken(m[0]);
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
  const c = { v: 2, audience, account, principal, operation, arguments: a };
  if (preconditions) c.preconditions = preconditions;
  if (resolved) c.resolved = resolved;
  jcs(c); return c;
}
