import crypto from 'node:crypto';
import { hash, jcs } from './json.mjs';
import { sign } from './receipt.mjs';
import { ISSUER } from './core.mjs';
export class Issuer {
  constructor(core) {
    this.core = core; this.db = core.db;
    this.db.exec(`CREATE TABLE IF NOT EXISTS decisions(issuer TEXT, receipt_id TEXT PRIMARY KEY, json TEXT);
      CREATE TABLE IF NOT EXISTS issuer_grants(id TEXT PRIMARY KEY, json TEXT, charged INTEGER);
      CREATE TABLE IF NOT EXISTS policies(id TEXT PRIMARY KEY, json TEXT);`);
    this.policyFunctions = new Map();
  }
  display(change, {current,records} = {}) {
    jcs(change);
    for (const p of change.preconditions ?? []) if (p.state_hash && (!current || hash(current[p.record]) !== p.state_hash)) throw Error('current mismatch');
    if (change.resolved && (!records || hash(records) !== change.resolved.manifest_hash || records.length !== change.resolved.count)) throw Error('manifest mismatch');
    return {change:structuredClone(change),current,records,displayed_at:this.core.now()};
  }
  authorized(person, change) { return person?.authenticated === true && this.core.sor.can(change.account,person.id,change.operation); }
  record(receipt_id, data) { this.core.audit('decision',{principal:data.change?.principal ?? data.terms?.principal ?? 'person',operation:data.change?.operation ?? 'grant'},{...data,issuer:ISSUER,receipt_id},data.decision); this.db.prepare('INSERT INTO decisions VALUES(?,?,?)').run(ISSUER,receipt_id,jcs({...data,issuer:ISSUER,receipt_id})); }
  decision(issuer, id) { const r = this.db.prepare('SELECT json FROM decisions WHERE issuer=? AND receipt_id=?').get(issuer,id); return r && JSON.parse(r.json); }
  #mint(change, approver, extras = {}, displayTime = this.core.now()) {
    const c = {iss:ISSUER,aud:change.audience,iat:this.core.now(),exp:this.core.now()+this.core.settings().maxLifetime,jti:crypto.randomUUID(),change_hash:hash(change),approver,...extras};
    this.record(c.jti,{change,approver,displayed_at:displayTime,decided_at:this.core.now(),decision:'approved'});
    return sign(c);
  }
  decide(display, person, approve) {
    if (!this.authorized(person,display.change)) throw Error('permission_denied');
    // Revalidate old values and selection against the displayed object, never a caller's summary/hash.
    this.display(display.change,display);
    if (approve !== true) { const id=crypto.randomUUID(); this.record(id,{change:display.change,displayed_at:display.displayed_at,decided_at:this.core.now(),decision:'denied',person:person.id}); return {denied:true,receipt_id:id}; }
    return this.#mint(display.change,{type:'person',id:person.id},{},display.displayed_at);
  }
  #deny(data,message) {const receipt_id=crypto.randomUUID();this.record(receipt_id,{...data,decision:'denied',decided_at:this.core.now()});throw Object.assign(Error(message),{receipt_id});}
  request() { return {error:'person_action_required'}; }
  displayGrant(terms) { return {terms:structuredClone(terms),displayed_at:this.core.now()}; }
  createGrant(display, person, approve) {
    const t=display.terms;
    if (!person?.authenticated || !t.operations.every(operation => this.authorized(person,{account:t.account,operation}))) throw Error('permission_denied');
    if (approve!==true) this.#deny({terms:t,displayed_at:display.displayed_at},'grant denied');
    if (!t.id || !t.fields?.length || !Number.isSafeInteger(t.max_records) || t.max_records < 1 || t.expires <= this.core.now()) throw Error('grant terms');
    const terms = {...t,granted_by:person.id}; this.db.prepare('INSERT INTO issuer_grants VALUES(?,?,0)').run(t.id,jcs(terms));
    this.record(crypto.randomUUID(),{decision:'grant_created',terms,displayed_at:display.displayed_at,decided_at:this.core.now()}); return terms;
  }
  underGrant(id, change, proof = {}) {
    this.display(change,proof);
    const row=this.db.prepare('SELECT * FROM issuer_grants WHERE id=?').get(id); if (!row) throw Error('unknown grant'); const t=JSON.parse(row.json);
    const count=change.resolved?.count ?? change.arguments.records?.length;
    const fields=Object.keys(change.arguments.set ?? change.arguments.properties ?? Object.assign({},...(change.arguments.records ?? []).map(r=>r.properties)));
    if (['principal','audience','account'].some(k=>change[k]!==t[k]) || !t.operations.includes(change.operation) || fields.some(f=>!t.fields.includes(f)) || this.core.now()<t.not_before || this.core.now()>=t.expires || count === undefined || row.charged+count>t.max_records) this.#deny({change,grant_id:id,displayed_at:this.core.now()},'grant terms');
    this.db.prepare('UPDATE issuer_grants SET charged=charged+? WHERE id=?').run(count,id);
    return this.#mint(change,{type:'grant',id:t.granted_by},{grant:{id,max_records:t.max_records,expires:t.expires}});
  }
  registerPolicy(admin, id, version, evaluate) {
    if (admin !== this.core.adminCredential) throw Error('permission_denied');
    this.db.prepare('INSERT OR REPLACE INTO policies VALUES(?,?)').run(id,jcs({id,version_hash:hash(version)})); this.policyFunctions.set(id,evaluate);
  }
  underPolicy(id, change, proof = {}) {
    this.display(change,proof);
    const p=this.db.prepare('SELECT json FROM policies WHERE id=?').get(id); const fn=this.policyFunctions.get(id);
    if (!p || !fn) throw Error('unknown policy');
    if (!fn(structuredClone(change))) { const rid=crypto.randomUUID(); this.record(rid,{decision:'denied',policy:id,change,displayed_at:this.core.now(),decided_at:this.core.now()}); throw Error('policy denied'); }
    return this.#mint(change,{type:'policy',id},{policy:JSON.parse(p.json)});
  }
}
