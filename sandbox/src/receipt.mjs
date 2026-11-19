import crypto from 'node:crypto';
import { object, parseJSON } from './json.mjs';
const seed = Buffer.from('9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60', 'hex');
export const privateKey = crypto.createPrivateKey({ key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), seed]), format: 'der', type: 'pkcs8' });
export const jwk = { ...crypto.createPublicKey(privateKey).export({ format: 'jwk' }), kid: 'test-key-1', alg: 'EdDSA', use: 'sig' };
export function sign(claims, header = { alg: 'EdDSA', kid: jwk.kid, typ: 'approval-receipt+jwt' }, key = privateKey) {
  const s = [header, claims].map(x => Buffer.from(JSON.stringify(x)).toString('base64url')).join('.');
  return s + '.' + crypto.sign(header.alg === 'ES256' ? 'sha256' : null, Buffer.from(s), { key, dsaEncoding: 'ieee-p1363' }).toString('base64url');
}
const nonempty = x => typeof x === 'string' && x.length > 0;
export function parseReceipt(token, allowNone = false) {
  if (typeof token !== 'string' || Buffer.byteLength(token) > 8192) throw Error('receipt size/type');
  const parts = token.split('.'); if (parts.length !== 3 || parts.some(p => !/^[A-Za-z0-9_-]+$/.test(p) || Buffer.from(p, 'base64url').toString('base64url') !== p)) throw Error('encoding');
  const [h,c] = parts.slice(0,2).map(p => parseJSON(new TextDecoder('utf-8',{fatal:true}).decode(Buffer.from(p, 'base64url'))));
  if (!object(h) || Object.keys(h).sort().join() !== 'alg,kid,typ' || !nonempty(h.kid) || h.typ !== 'approval-receipt+jwt' || !(['EdDSA','ES256'].includes(h.alg) || (allowNone && h.alg === 'none'))) throw Error('header');
  if (!object(c) || !['iss','aud','jti','change_hash'].every(k => nonempty(c[k])) || !URL.canParse(c.iss) || !Number.isSafeInteger(c.iat) || !Number.isSafeInteger(c.exp) || c.iat >= c.exp || !object(c.approver) || !['person','grant','policy'].includes(c.approver.type) || !nonempty(c.approver.id)) throw Error('claims');
  const type = c.approver.type;
  if ((type === 'grant') !== Object.hasOwn(c,'grant') || (type === 'policy') !== Object.hasOwn(c,'policy')) throw Error('type mismatch');
  if (type === 'grant' && (!object(c.grant) || !nonempty(c.grant.id) || !Number.isSafeInteger(c.grant.max_records) || c.grant.max_records < 1 || !Number.isSafeInteger(c.grant.expires))) throw Error('grant');
  if (type === 'policy' && (!object(c.policy) || !nonempty(c.policy.id) || !nonempty(c.policy.version_hash))) throw Error('policy');
  return { header: h, claims: c, input: parts.slice(0,2).join('.'), signature: Buffer.from(parts[2], 'base64url') };
}
