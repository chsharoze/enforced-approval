#!/usr/bin/env node
// Computes the test vectors for the Enforced Approval draft.
// Not a reference implementation: it only produces and self-checks the examples.
// Usage: node make-vectors.mjs > vectors.json   (deterministic; no dependencies)
import crypto from 'node:crypto';

// RFC 8785 (JCS): object keys sorted by UTF-16 code units, no whitespace,
// ECMAScript serialization of primitives. JSON.stringify gives the primitive
// forms; Array.prototype.sort on strings compares UTF-16 code units.
// The helper refuses what RFC 8785 says cannot be canonicalized (non-finite numbers,
// lone surrogates). The profile's own input check (draft S3) is profileCheck below.
const wellFormed = s => s.isWellFormed();
function jcs(v) {
  if (typeof v === 'string' && !wellFormed(v)) throw new Error('lone surrogate');
  if (v === null || typeof v !== 'object') {
    if (typeof v === 'number' && !Number.isFinite(v)) throw new Error('non-finite number');
    return JSON.stringify(v);
  }
  if (Array.isArray(v)) return '[' + v.map(jcs).join(',') + ']';
  return '{' + Object.keys(v).sort().map(k => { if (!wellFormed(k)) throw new Error('lone surrogate'); return JSON.stringify(k) + ':' + jcs(v[k]); }).join(',') + '}';
}
const b64u = b => Buffer.from(b).toString('base64url');
const sha256 = s => crypto.createHash('sha256').update(s, 'utf8').digest();

// Draft S3: integers beyond 2^53-1 are refused in guarded arguments, because parsers
// round them silently. Duplicate member names cannot be seen after parsing; a server
// checks those on the raw request.
function profileCheck(v) {
  if (typeof v === 'number' && Number.isInteger(v) && !Number.isSafeInteger(v)) throw new Error('unsafe integer');
  if (v && typeof v === 'object') for (const x of Object.values(v)) profileCheck(x);
}

// The change object and its hash (draft Section 4).
function changeObject({ audience, account, principal, operation, args = {}, approvalFields = [], preconditions, resolved }) {
  const a = { ...args };
  for (const f of approvalFields) delete a[f.slice(1)]; // JSON Pointers to top-level members only in these vectors
  profileCheck(a);
  const c = { account, arguments: a, audience, operation, principal, v: 1 };
  if (preconditions) c.preconditions = preconditions;
  if (resolved) c.resolved = resolved;
  return c;
}
const changeHash = c => b64u(sha256(jcs(c)));

// Fixed Ed25519 test key: the secret seed of RFC 8032 Section 7.1, TEST 1.
// Public test material. Never use it outside these vectors.
const seed = Buffer.from('9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60', 'hex');
const pkcs8 = Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), seed]);
const priv = crypto.createPrivateKey({ key: pkcs8, format: 'der', type: 'pkcs8' });
const pub = crypto.createPublicKey(priv);
const jwk = { ...pub.export({ format: 'jwk' }), kid: 'test-key-1', use: 'sig', alg: 'EdDSA' };

function sign(claims) {
  const header = { alg: 'EdDSA', kid: jwk.kid, typ: 'approval-receipt+jwt' };
  const input = b64u(JSON.stringify(header)) + '.' + b64u(JSON.stringify(claims));
  return input + '.' + b64u(crypto.sign(null, Buffer.from(input), priv));
}
function verify(jws) {
  const [h, p, s] = jws.split('.');
  return crypto.verify(null, Buffer.from(h + '.' + p), pub, Buffer.from(s, 'base64url'));
}

// ---- Placeholders only. No real account, record or user identifiers. ----
const audience = 'https://mcp.crm.example/mcp';
const account = 'acct-EXAMPLE-0001';
const principal = 'agent-EXAMPLE-sync';
const issuer = 'https://approvals.org.example';
const T0 = 1795000000; // fixed "now" for the vectors (seconds since epoch)

const baseCall = {
  audience, account, principal,
  operation: 'mcp:tools/call:manage_records',
  approvalFields: ['/confirmation'],
  args: {
    objectType: 'contact',
    action: 'update',
    records: [{ id: 'rec-EXAMPLE-42', properties: { lifecycle_stage: 'customer', owner: 'user-EXAMPLE-7' } }],
  },
};

const vectors = [];
function vec(name, call, note) {
  const c = changeObject(call);
  const out = { name, note, request_arguments: call.args ?? null, approval_fields: call.approvalFields ?? [], change_object: c, canonical: jcs(c), change_hash: changeHash(c) };
  vectors.push(out);
  return out;
}

const v1 = vec('V1-base', baseCall, 'Base update of one record.');
const v2 = vec('V2-ai-flag-set', { ...baseCall, args: { ...baseCall.args, confirmation: 'CONFIRMED' } },
  'Same call with the AI-set confirmation field present. Hash MUST equal V1.');
const v3 = vec('V3-key-order', { ...baseCall, args: { records: baseCall.args.records.map(r => ({ properties: { owner: r.properties.owner, lifecycle_stage: r.properties.lifecycle_stage }, id: r.id })), action: 'update', objectType: 'contact' } },
  'Same call with members in a different order. Hash MUST equal V1.');
const v4 = vec('V4-changed-argument', { ...baseCall, args: { ...baseCall.args, records: [{ id: 'rec-EXAMPLE-42', properties: { lifecycle_stage: 'customer', owner: 'user-EXAMPLE-8' } }] } },
  'One property value changed. Hash MUST differ from V1.');
const v5 = vec('V5-wrong-account', { ...baseCall, account: 'acct-EXAMPLE-0002' },
  'Same arguments, different account. Hash MUST differ from V1.');
const v6 = vec('V6-wrong-audience', { ...baseCall, audience: 'https://mcp.other.example/mcp' },
  'Same arguments, different server. Hash MUST differ from V1.');
const v7 = vec('V7-rest', { audience: 'https://api.crm.example', account, principal, operation: 'http:PATCH:/v1/objects/contact/rec-EXAMPLE-42', args: { properties: { lifecycle_stage: 'customer', owner: 'user-EXAMPLE-7' } } },
  'The REST mapping: method and path in operation, JSON body as arguments.');
const v8 = vec('V8-unicode-number', { ...baseCall, args: { objectType: 'deal', action: 'update', records: [{ id: 'rec-EXAMPLE-43', properties: { name: 'Café €', amount: 1250.5, closed: false, note: null } }] } },
  'Non-ASCII text, a non-integer number, false and null.');

const v9 = vec('V9-wrong-principal', { ...baseCall, principal: 'agent-EXAMPLE-other' },
  'Same arguments sent with another credential. Hash MUST differ from V1.');
const v10 = vec('V10-other-tool', { ...baseCall, operation: 'mcp:tools/call:delete_records' },
  'Same arguments sent to another tool. Hash MUST differ from V1.');
const v11 = vec('V11-no-arguments', { ...baseCall, operation: 'mcp:tools/call:run_cleanup', args: undefined, approvalFields: [] },
  'A call with no arguments member: arguments is the empty object.');

const current = { lifecycle_stage: 'lead', owner: 'user-EXAMPLE-3' };
const v12 = vec('V12-precondition', { ...baseCall, preconditions: [{ record: 'rec-EXAMPLE-42', state_hash: b64u(sha256(jcs(current))) }] },
  'V1 with a precondition: state_hash is the hash of the current values {"lifecycle_stage":"lead","owner":"user-EXAMPLE-3"}.');
const ids = ['rec-EXAMPLE-11', 'rec-EXAMPLE-12', 'rec-EXAMPLE-13'];
const v13 = vec('V13-update-by-query', { ...baseCall, operation: 'mcp:tools/call:update_by_query', approvalFields: [],
  args: { objectType: 'contact', filter: { lifecycle_stage: 'lead' }, set: { owner: 'user-EXAMPLE-7' } },
  resolved: { count: ids.length, manifest_hash: b64u(sha256(jcs([...ids].sort()))) } },
  'An update by query resolved to 3 records: manifest_hash is the hash of the sorted identifier array.');

const assert = (c, m) => { if (!c) { console.error('SELF-CHECK FAILED: ' + m); process.exit(1); } };
assert(v2.change_hash === v1.change_hash, 'V2 == V1');
assert(v3.change_hash === v1.change_hash, 'V3 == V1');
for (const v of [v4, v5, v6, v7, v8, v9, v10, v11, v12, v13]) assert(v.change_hash !== v1.change_hash, v.name + ' != V1');
// RFC 8785 Section 3.2.3 sample for key sorting and primitives.
assert(jcs({ numbers: [333333333.33333329, 1e30, 4.5, 2e-3, 1e-27], string: '€$\u000f\nA\'B"\\\\"/', literals: [null, true, false] }) ===
  '{"literals":[null,true,false],"numbers":[333333333.3333333,1e+30,4.5,0.002,1e-27],"string":"€$\\u000f\\nA\'B\\"\\\\\\\\\\"/"}', 'RFC 8785 sample');

// Inputs the helper must refuse.
const throws = f => { try { f(); return false; } catch { return true; } };
assert(throws(() => jcs({ x: '\ud800' })), 'lone surrogate refused');
assert(throws(() => changeObject({ ...baseCall, args: { x: 9007199254740993 } })), 'unsafe integer refused');
assert(throws(() => jcs({ x: Infinity })), 'non-finite refused');
assert(jcs({ x: 0.1 }) === '{"x":0.1}', 'ordinary decimals accepted');

// ---- Receipts (default encoding, draft Section 5.2) ----
const person = { iss: issuer, aud: audience, iat: T0, exp: T0 + 300, jti: 'rcpt-EXAMPLE-0001',
  change_hash: v1.change_hash, approver: { type: 'person', id: 'approver-EXAMPLE-ops-lead' } };
const grantIssued = { iss: issuer, aud: audience, iat: T0, exp: T0 + 300, jti: 'rcpt-EXAMPLE-0002',
  change_hash: v1.change_hash, approver: { type: 'grant', id: 'approver-EXAMPLE-ops-lead' },
  grant: { id: 'grant-EXAMPLE-0001', max_records: 50, expires: T0 + 28800 } };
const policyIssued = { iss: issuer, aud: audience, iat: T0, exp: T0 + 300, jti: 'rcpt-EXAMPLE-0003',
  change_hash: v1.change_hash, approver: { type: 'policy', id: 'policy-EXAMPLE-routine-updates' },
  policy: { id: 'policy-EXAMPLE-routine-updates', version_hash: b64u(sha256('example policy text, version 3')) } };
const grant = { id: 'grant-EXAMPLE-0001', granted_by: 'approver-EXAMPLE-ops-lead', principal,
  audience, account, operations: ['mcp:tools/call:manage_records'], fields: ['lifecycle_stage', 'owner'],
  max_records: 50, not_before: T0, expires: T0 + 28800 };

const receipts = {
  person: { claims: person, jws: sign(person) },
  grant: { claims: grantIssued, jws: sign(grantIssued) },
  policy: { claims: policyIssued, jws: sign(policyIssued) },
  expired: { claims: { ...person, jti: 'rcpt-EXAMPLE-0004', iat: T0 - 900, exp: T0 - 600 }, jws: sign({ ...person, jti: 'rcpt-EXAMPLE-0004', iat: T0 - 900, exp: T0 - 600 }) },
  wrong_audience: { claims: { ...person, jti: 'rcpt-EXAMPLE-0005', aud: 'https://mcp.other.example/mcp' }, jws: sign({ ...person, jti: 'rcpt-EXAMPLE-0005', aud: 'https://mcp.other.example/mcp' }) },
};
for (const [k, r] of Object.entries(receipts)) assert(verify(r.jws), 'signature ' + k);
const tampered = receipts.person.jws.replace(/\.[^.]+\./, '.' + b64u(JSON.stringify({ ...person, change_hash: v4.change_hash })) + '.');
assert(!verify(tampered), 'tampered payload must not verify');
receipts.tampered_payload = { note: 'Payload replaced with the V4 hash; signature left unchanged. MUST fail verification.', jws: tampered };

console.log(JSON.stringify({
  note: 'Test vectors for the Enforced Approval draft. Placeholders only. Generated by make-vectors.mjs; do not edit by hand.',
  now: T0, issuer, issuer_jwks: { keys: [jwk] }, change_hash_vectors: vectors, grant_example: grant, receipts,
}, null, 2));
