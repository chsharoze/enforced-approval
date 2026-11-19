import { formatTime, plural, shapeWords, withDuration } from './presentation.mjs';
import { finite } from './server-grants.mjs';
import crypto from 'node:crypto';
import { changeObject, hash, jcs, parseJSON } from './json.mjs';
import { parseReceipt } from './receipt.mjs';
export { changeObject, hash } from './json.mjs';
export const OP = 'mcp:tools/call:manage_records';
export const QUERY = 'mcp:tools/call:update_by_query';
// Plain-word guidance in server-issued refusals (spec 6.2, S59). Nothing is carried by the
// client and no message names a protocol member. Durations are for people only:
// plain words plus the absolute moment, never a raw second count.
const MESSAGES = {
  approval_required: () => mutated('message-names-member')
    ? 'This change needs approval. A person approves or denies it on the approval page at approval_url. Nothing needs to be copied or pasted back. After the decision, send the same request again.'
    : "This change needs a person's approval. Open the approval page, review the change, and approve or deny it there. Nothing needs to be copied or pasted back. Then continue here.",
  approval_denied: (d,now) => `A person denied this change on the approval page. It will not run. It cannot be asked for again for ${withDuration(d.retry_after ?? 0,now)}, and no approval prompt will appear before then. Do not ask again unless the person asks.`,
  approval_cancelled: (d,now) => `The request was declined in the client, so the change did not run and its approval was cancelled. ${d.retry_after ? `No approval prompt will appear for this change for ${withDuration(d.retry_after,now)}.` : 'It can be asked for again.'}`,
  approval_limit_reached: (d,now) => `No approval can be requested now: ${d.open} of ${plural(d.limit,'approval request')} are open or were recently declined or denied, and those count until they expire. Nothing is pending for this change. Try again in ${withDuration(d.retry_after,now)}.`,
};
// S3/S48: an invalid_input refusal says what kind of input was refused, and names undefined properties.
const INPUT_KINDS = {
  'arguments must be object': 'The arguments are not a JSON object, so the change was refused.',
  surrogate: 'A string in the arguments contains a lone surrogate character, which cannot be serialized, so the change was refused.',
  number: 'A number in the arguments cannot be serialized exactly as JSON, so the change was refused.',
  duplicate: 'The arguments contain a duplicate member name, so the change was refused.',
  'unsafe integer': 'The arguments contain an integer beyond the safe range for exact JSON numbers, so the change was refused.',
  key: 'A member name in the arguments is not valid JSON, so the change was refused.',
  'not JSON': 'The arguments contain a value that is not JSON, so the change was refused.',
  trailing: 'The arguments have extra content after the JSON value, so the change was refused.',
  value: 'The arguments are not valid JSON, so the change was refused.',
  string: 'A string in the arguments is not valid JSON, so the change was refused.',
  colon: 'The arguments are not valid JSON, so the change was refused.',
  comma: 'The arguments are not valid JSON, so the change was refused.',
};
export const CREATE = 'mcp:tools/call:create_record';
export const ISSUER = 'https://approvals.org.example';
export const DEFAULT = { audience: 'https://mcp.crm.example/mcp', maxLifetime: 300, skew: 0, selectionLimit: 100, preconditions: false, approverTypes: ['person','grant','policy'], pendingLifetime: 600, pendingCap: 10, keyCacheSeconds: 3600, removalSeconds: 3600, grantConfig: {}, pageAdministrators: {} };
export const mutated = name => process.env.VA_MUTATE === name;
class Refusal extends Error { constructor(code) { super(code); this.code = code; } }
const refuse = code => { throw new Refusal(code); };
export class Core {
  constructor(sor, { adminCredential, now = () => Math.floor(Date.now()/1000), settings = {} } = {}) {
    if (!adminCredential) throw Error('admin credential required');
    this.sor = sor; this.db = sor.db; this.adminCredential = adminCredential; this.now = now; this.unavailable = {}; this.preconditionCache = new Map();
    this.db.exec(`CREATE TABLE IF NOT EXISTS settings(id INTEGER PRIMARY KEY, json TEXT);
      CREATE TABLE IF NOT EXISTS issuers(account TEXT, issuer TEXT, json TEXT, refreshed INTEGER DEFAULT -10000000000, refreshes INTEGER DEFAULT 0, PRIMARY KEY(account,issuer));
      CREATE TABLE IF NOT EXISTS used(issuer TEXT, jti TEXT, expires INTEGER, PRIMARY KEY(issuer,jti));
      CREATE TABLE IF NOT EXISTS grants(account TEXT, issuer TEXT, id TEXT, max_records INTEGER, expires INTEGER, charged INTEGER, PRIMARY KEY(account,issuer,id));
      CREATE TABLE IF NOT EXISTS audit(seq INTEGER PRIMARY KEY AUTOINCREMENT, json TEXT, hash TEXT);`);
    this.db.prepare('INSERT OR IGNORE INTO settings VALUES(1,?)').run(JSON.stringify({ ...DEFAULT, ...settings }));
  }
  settings() { return JSON.parse(this.db.prepare('SELECT json FROM settings WHERE id=1').get().json); }
  admin(credential, action, data) {
    if (credential !== this.adminCredential) throw Error('permission_denied');
    if (action === 'settings') {
      const s = { ...this.settings(), ...data };
      if (s.skew < 0 || s.skew > 60 || s.maxLifetime <= 0 || s.pendingLifetime <= 0 || s.pendingLifetime > 3600 || s.pendingCap < 1 || s.keyCacheSeconds > 86400 || s.removalSeconds > 3600) throw Error('invalid settings');
      for(const ops of Object.values(s.grantConfig??{}))for(const cfg of Object.values(ops))if(!finite(cfg))throw Error('invalid grant settings');
      this.db.prepare('UPDATE settings SET json=? WHERE id=1').run(JSON.stringify(s)); return;
    }
    if (action === 'removeIssuer') { this.db.prepare('DELETE FROM issuers WHERE account=? AND issuer=?').run(data.account, data.issuer); return; }
    if (action !== 'issuer') throw Error('unknown admin action');
    for (const row of this.db.prepare('SELECT issuer,json FROM issuers WHERE account=? AND issuer<>?').all(data.account,data.issuer)) {
      const existing = JSON.parse(row.json).keys;
      if (data.keys.some(k => existing.some(e => hash({kty:e.kty, ...(e.kty === 'OKP' ? {crv:e.crv,x:e.x} : {crv:e.crv,x:e.x,y:e.y})}) === hash({kty:k.kty, ...(k.kty === 'OKP' ? {crv:k.crv,x:k.x} : {crv:k.crv,x:k.x,y:k.y})})))) throw Error('key already registered');
    }
    this.db.prepare('INSERT INTO issuers(account,issuer,json) VALUES(?,?,?) ON CONFLICT(account,issuer) DO UPDATE SET json=excluded.json').run(data.account,data.issuer,JSON.stringify(data));
  }
  audit(phase, req, detail, outcome) {
    const ownTransaction=!this.db.isTransaction;
    if(ownTransaction)this.db.exec('BEGIN IMMEDIATE');
    try {
      const prev = this.db.prepare('SELECT hash FROM audit ORDER BY seq DESC LIMIT 1').get()?.hash ?? null;
      const record = { record_id: crypto.randomUUID(), timestamp: this.now(), agent_id: req.principal ?? 'unknown', principal: req.principal ?? 'unknown', action_type: req.operation ?? 'unknown', action_detail: detail, outcome, prev_hash: prev, record_phase: phase };
      this.db.prepare('INSERT INTO audit(json,hash) VALUES(?,?)').run(jcs(record), hash(record));
      if(ownTransaction)this.db.exec('COMMIT');return record.record_id;
    }catch(e){if(ownTransaction)this.db.exec('ROLLBACK');throw e;}
  }

  chainCheck() {
    let prev = null;
    for (const row of this.db.prepare('SELECT * FROM audit ORDER BY seq').all()) {
      try { const r = JSON.parse(row.json); if (r.prev_hash !== prev || hash(r) !== row.hash) return { ok:false, seq:row.seq }; prev = row.hash; } catch { return {ok:false,seq:row.seq}; }
    }
    return { ok:true, head:prev };
  }
  records() { return this.db.prepare('SELECT json FROM audit ORDER BY seq').all().map(r => JSON.parse(r.json)); }
  prepare(req) {
    const s = this.settings(); const args = req.rawArguments !== undefined ? parseJSON(req.rawArguments) : (req.args ?? {});
    const change = changeObject({ ...req, args, audience:s.audience });
    if (mutated('principal-not-in-hash')) change.principal = 'agent-EXAMPLE-sync';
    const a = change.arguments; let entries = a.records ?? [];
    if (req.operation === CREATE || a.action === 'create') entries = a.records ?? [{ id:a.id, properties:a.properties ?? {} }];
    for(const e of entries)this.sor.validateProperties(a.objectType,e.properties??{});
    if(a.set!==undefined)this.sor.validateProperties(a.objectType,a.set);
    if(a.properties!==undefined)this.sor.validateProperties(a.objectType,a.properties);
    let records;
    if (req.operation === QUERY) {
      records = this.sor.query(req.account,a.objectType,a.filter);
      if (records.length > s.selectionLimit) refuse('selection_limit');
      change.resolved = { count:records.length, manifest_hash:hash(records) };
      entries = records.map(id => ({id, properties:a.set}));
    }
    const action = req.operation === CREATE ? 'create' : a.action ?? 'update';
    const versions = {}; const current = {};
    if (s.preconditions && req.operation !== QUERY) {
      change.preconditions = entries.map(e => {
        const old = this.sor.get(req.account,e.id);
        if (action === 'create') { if (old) refuse('conflict'); return {record:e.id, absent:true}; }
        if (!old) refuse('conflict'); versions[e.id] = old.version;
        if (action==='delete') return {record:e.id,version:old.version};
        const state = Object.fromEntries(Object.keys(e.properties ?? {}).map(k => [k, old.properties[k] ?? null])); current[e.id] = state;
        return {record:e.id,state_hash:hash(state)};
      });
      if (mutated('skip-precondition-refill')) {
        const key = hash({account:req.account,args:a});
        if (this.preconditionCache.has(key)) change.preconditions = this.preconditionCache.get(key);
        else this.preconditionCache.set(key, change.preconditions);
      }
    }
    for(const e of entries)if(!current[e.id]){const old=this.sor.get(req.account,e.id);current[e.id]=Object.fromEntries(Object.keys(e.properties??{}).map(k=>[k,old?.properties[k]??null]));}
    return {change, change_hash:hash(change), entries, action, versions, current, records};
  }
  refusal(req, error, prepared, claims, details) {
    const s = this.settings(); const approval = {error};
    if (prepared) Object.assign(approval, {change_hash:prepared.change_hash, audience:s.audience, operation:req.operation, approver_types:s.approverTypes, max_lifetime:s.maxLifetime, change:prepared.change});
    if (this.pending && prepared && error==='approval_required') { const url=this.pending.url(prepared.change_hash); if (url) approval.approval_url=url; }
    if (details) Object.assign(approval, details);
    if (this.pending && MESSAGES[error]) approval.message = MESSAGES[error](approval, this.now());
    if(this.pending&&prepared&&error==='approval_required'&&!mutated('no-grant-reason')) {const reason=this.pending.grants.explain(prepared.change,prepared.records);if(reason){approval.grant_status=reason.status;approval.message+=' '+reason.message;}}
    if (error === 'approval_required' && !this.pending) approval.issuers = this.db.prepare('SELECT issuer FROM issuers WHERE account=?').all(req.account).map(r => r.issuer);
    if (prepared && this.sor.can(req.account,req.principal,req.operation,'read')) {
      if (prepared.change.preconditions?.some(p => p.state_hash)) approval.current = prepared.current;
      if (prepared.records) approval.records = prepared.records;
    }
    this.audit('refusal',req,{error,...(prepared ? {change_hash:prepared.change_hash} : {}),...(claims && prepared ? this.details(prepared,claims) : {})},'refused');
    return {ok:false,approval};
  }
  receipt(req) {
    const tokens = [];
    for (const [k,v] of Object.entries(req.meta ?? {})) if (k.endsWith('/receipt')) tokens.push(v);
    if (Object.hasOwn(req.args ?? {},'approval_receipt')) tokens.push(req.args.approval_receipt);
    if (req.receipt !== undefined) tokens.push(req.receipt);
    if (tokens.length > 1 || tokens.some(t => typeof t !== 'string' || t.includes(','))) refuse('approval_invalid');
    return tokens[0];
  }
  verify(token, req, p, onVerified=()=>{}) {
    let parsed; try { parsed = parseReceipt(token,mutated('accept-alg-none')); } catch { refuse('approval_invalid'); }
    const {claims:c,header:h} = parsed;
    if (this.unavailable.registry) refuse('approval_unavailable');
    let row = this.db.prepare('SELECT * FROM issuers WHERE account=? AND issuer=?').get(req.account,c.iss);
    if (!row) refuse('approval_invalid'); let issuer = JSON.parse(row.json);
    let key = issuer.keys.find(k => k.kid === h.kid);
    const ttl=Math.min(this.settings().keyCacheSeconds,this.settings().removalSeconds || this.settings().keyCacheSeconds);
    const expired=issuer.cachedAt !== undefined && this.now()-issuer.cachedAt>=ttl;
    if (!key || expired) {
      if (this.unavailable.keys) refuse('approval_unavailable');
      const updated = this.db.prepare('UPDATE issuers SET refreshed=?,refreshes=refreshes+1 WHERE account=? AND issuer=? AND refreshed<=?').run(this.now(),req.account,c.iss,this.now()-60);
      if (updated.changes && this.keyRefresh) {
        issuer.keys = this.keyRefresh(req.account,c.iss); if (!Array.isArray(issuer.keys)) refuse('approval_unavailable'); issuer.cachedAt = this.now();
        this.db.prepare('UPDATE issuers SET json=? WHERE account=? AND issuer=?').run(JSON.stringify(issuer),req.account,c.iss);
      }
      else if (expired) refuse('approval_unavailable');
      key = issuer.keys.find(k => k.kid === h.kid);
    }
    if (!key) refuse('approval_invalid');
    if (!(mutated('accept-alg-none') && h.alg === 'none')) {
      if (key.alg !== h.alg) refuse('approval_invalid');
      if (!mutated('skip-signature')) {
        try { if (!crypto.verify(h.alg === 'ES256' ? 'sha256' : null, Buffer.from(parsed.input), {key:crypto.createPublicKey({key,format:'jwk'}),dsaEncoding:'ieee-p1363'},parsed.signature)) refuse('approval_invalid'); } catch { refuse('approval_invalid'); }
      }
    }
    onVerified(c);
    if (!mutated('skip-issuer-scope') && (!issuer.operations.includes(req.operation) || !issuer.types.includes(c.approver.type))) refuse('approver_not_authorized');
    if (!mutated('skip-audience') && c.aud !== this.settings().audience) refuse('approval_invalid');
    return c;
  }
  consume(req, p, c) {
    if (this.unavailable.store) refuse('approval_unavailable');
    this.sor.hit('before-consume',{req,p,c});
    this.db.exec('BEGIN IMMEDIATE');
    try {
      if (!mutated('skip-single-use') && this.db.prepare('SELECT 1 FROM used WHERE issuer=? AND jti=?').get(c.iss,c.jti)) refuse('approval_used');
      if(c.iss==='server'&&this.pending) {
        const record=this.pending.get(c.jti);
        if(record&&['denied','cancelled'].includes(record.status))throw Object.assign(Error(record.status),{code:'approval_'+record.status,details:{retry_after:Math.max(0,record.expires-this.now())}});
      }
      this.sor.hit('before-grant-charge',{req,p,c});
      if (c.iss==='server'&&c.grant) this.pending.grants.charge(req,p,c);
      else if (c.grant) {
        const g = c.grant; const count = p.change.resolved?.count ?? (Array.isArray(p.change.arguments.records) ? p.change.arguments.records.length : (req.operation === CREATE ? 1 : undefined));
        if (count === undefined) refuse('grant_exceeded');
        const old = this.db.prepare('SELECT * FROM grants WHERE account=? AND issuer=? AND id=?').get(req.account,c.iss,g.id);
        if (this.now() >= g.expires || (old && (old.max_records !== g.max_records || old.expires !== g.expires))) refuse('grant_exceeded');
        if (!mutated('skip-grant-limit') && (old?.charged ?? 0) + count > g.max_records) refuse('grant_exceeded');
        this.db.prepare('INSERT INTO grants VALUES(?,?,?,?,?,?) ON CONFLICT(account,issuer,id) DO UPDATE SET charged=charged+excluded.charged').run(req.account,c.iss,g.id,g.max_records,g.expires,count);
      }
      this.db.prepare('INSERT OR IGNORE INTO used VALUES(?,?,?)').run(c.iss,c.jti,c.exp+this.settings().skew);
      if(c.iss==='server'&&!c.grant)this.db.prepare("UPDATE pending SET status='consumed' WHERE id=?").run(c.jti);
      const id = this.audit('consumption',req,this.details(p,c),'consumed');
      this.db.exec('COMMIT'); return id;
    } catch (e) { this.db.exec('ROLLBACK'); throw e; }
  }
  details(p,c) { return { change_hash:p.change_hash, receipt_id:c.jti, issuer:c.iss, approver_type:c.approver.type, approver_id:c.approver.id, ...(c.grant ? {grant_id:c.grant.id,...(c.grant.shape?{grant_shape:c.grant.shape}:{})} : {}), ...(c.policy ? {policy:c.policy} : {}) }; }
  handle(req) {
    let p,c;
    try {
      if (!this.sor.can(req.account,req.principal,req.operation)) refuse('permission_denied');
      try { p = this.prepare(req); } catch (e) {
        if (e.code) throw e;
        if (mutated('invalid-input-no-reason')) refuse('invalid_input');
        if (e.invalid?.length) throw Object.assign(new Refusal('invalid_input'),{details:{invalid:e.invalid,message:`The system of record does not define ${e.invalid.length===1?'this property':'these properties'}: ${e.invalid.join(', ')}. The change was refused.`}});
        throw Object.assign(new Refusal('invalid_input'),{details:{message:INPUT_KINDS[e.message] ?? 'The arguments cannot be hashed and serialized, so the change was refused.'}});
      }
      if (req.effects && Object.keys(req.effects).length) throw Object.assign(new Refusal('invalid_input'),{details:{message:'The request carries inputs outside the change object, which cannot be approved, so the change was refused.'}});
      if (req.rawArguments !== undefined) req = {...req,args:parseJSON(req.rawArguments)};
      const token = this.receipt(req);
      if (this.pending) c = this.pending.lookup(req,p);
      else if (token === undefined) {
        if (mutated('approval-field-authorizes') && req.args?.confirmation) c = {iss:ISSUER,jti:crypto.randomUUID(),iat:this.now(),exp:this.now()+300,change_hash:p.change_hash,approver:{type:'person',id:'agent'}};
        else refuse('approval_required');
      } else c = this.verify(token,req,p,claims=>{c=claims;});
      const s = this.settings();
      if (!mutated('skip-expiry') && (c.iat > this.now()+s.skew || this.now() >= c.exp+s.skew || c.exp-c.iat > s.maxLifetime)) refuse('approval_expired');
      if (!mutated('skip-hash-compare') && c.change_hash !== p.change_hash) refuse('approval_mismatch');
      if (!mutated('skip-approver-type') && !(s.operationTypes?.[req.operation] ?? s.approverTypes).includes(c.approver.type)) refuse('approver_not_authorized');
      let authorization;
      try {authorization=this.consume(req,p,c);}catch(e){if(e.code==='server_grant_unavailable')return this.pending.grantFallback(req,p,c);throw e;}
      try {
        this.sor.hit('after-consume',{req,p,c});
        if (mutated('requery-at-execution') && p.records) {
          this.sor.hit('before-write',{account:req.account,entries:p.entries});
          p.entries = this.sor.query(req.account,p.change.arguments.objectType,p.change.arguments.filter).map(id => ({id,properties:p.change.arguments.set}));
        }
        const result = this.sor.write(req.account,p.entries,p.action,p.change.arguments.objectType,p.versions);
        this.audit('outcome',req,{...this.details(p,c),authorization_record_id:authorization},'success'); return {ok:true,result,...(c.iss==='server'&&c.grant?{grant:this.pending.grants.get(c.grant.id)}:{})};
      } catch (e) {
        this.audit('outcome',req,{...this.details(p,c),authorization_record_id:authorization},'failed_or_unknown');
        return {...this.refusal(req,e.message === 'conflict' ? 'conflict' : 'execution_failed',p,c),...(c.iss==='server'&&c.grant?{grant:this.pending.grants.get(c.grant.id)}:{})};
      }
    } catch (e) { return this.refusal(req,e instanceof Refusal || (this.pending && ['approval_required','approval_denied','approval_cancelled','approval_limit_reached','approval_used'].includes(e.code)) ? e.code : 'approval_unavailable',p,c,e.details); }
  }
}
export function mcpResult(result) {
  const grantText=result.grant?[{type:'text',text:`Ran under grant ${result.grant.id}; a standing permission, not an approval of this one change. Shape: ${shapeWords(result.grant.shape)} (${result.grant.shape}); records remaining: ${plural(result.grant.max_records-result.grant.charged)}; expires: ${formatTime(result.grant.expires)}.`}]:[];
  if (result.ok) return {content:[{type:'text',text:JSON.stringify(result.result)},...grantText]};
  return {isError:true,content:[{type:'text',text:JSON.stringify(result.approval)},...grantText],_meta:{'com.example.approval/refusal':result.approval}};
}
