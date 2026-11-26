import { grantState } from './presentation.mjs';
import crypto from 'node:crypto';
import { OP, QUERY, CREATE, mutated } from './core.mjs';
import { hash, object } from './json.mjs';
import { fields, hasArray, identifiers } from './fields.mjs';
import { authorize } from './authorize.mjs';
export const THESE='these_records', ANY='any_record';
export const finite=cfg=>object(cfg)&&Number.isSafeInteger(cfg.maxRecords)&&cfg.maxRecords>0&&Number.isSafeInteger(cfg.maxSeconds)&&cfg.maxSeconds>0&&cfg.maxSeconds<8640000000000&&(cfg.anyRecord===undefined||typeof cfg.anyRecord==='boolean');
export class ServerGrants {
  constructor(core) {
    this.core=core;this.db=core.db;
    this.db.exec('CREATE TABLE IF NOT EXISTS server_grants(id TEXT PRIMARY KEY, account TEXT, json TEXT, charged INTEGER NOT NULL DEFAULT 0, revoked INTEGER)');
  }
  config(c) {return this.core.settings().grantConfig?.[c.account]?.[c.operation];}
  classify(c,resolved,{assumeDefined=false}={}) {
    const a=c.arguments,keys=Object.keys(a);let selectors,count,creating=false;
    // S69(4): the distinguishing argument of a covered operation is not a selector, a
    // field or a record identifier; it is left out of a grant's terms and of matching.
    const dta=this.core.settings().preconditions&&!mutated('distinguishing-breaks-grant')?['change_tag']:[];
    if(c.operation===OP) {
      if(keys.some(k=>!['objectType','action','records',...dta].includes(k))||typeof a.objectType!=='string'||!['update','create'].includes(a.action)||!Array.isArray(a.records))return;
      if(a.records.some(r=>!object(r)||typeof r.id!=='string'||Object.keys(r).some(k=>!['id','properties'].includes(k))||!object(r.properties)||hasArray(r.properties)))return;
      selectors={objectType:a.objectType,action:a.action};count=a.records.length;creating=a.action==='create';
    }else if(c.operation===QUERY) {
      if(keys.some(k=>!['objectType','filter','set',...dta].includes(k))||typeof a.objectType!=='string'||!object(a.filter)||!object(a.set)||hasArray(a.set)||!c.resolved||!Array.isArray(resolved))return;
      selectors={objectType:a.objectType,filter:a.filter};count=c.resolved.count;
    }else if(c.operation===CREATE) {
      if(keys.some(k=>!['objectType','id','properties',...dta].includes(k))||typeof a.objectType!=='string'||typeof a.id!=='string'||!object(a.properties)||hasArray(a.properties))return;
      selectors={objectType:a.objectType,action:'create'};count=1;creating=true;
    }else return;
    const props=a.records?.map(r=>r.properties)??[a.set??a.properties??{}];if(!assumeDefined&&!props.every(v=>this.core.sor.defined(a.objectType,v)))return;
    const names=fields(c),records=identifiers(c,resolved);if(!Number.isSafeInteger(count)||count<0||!names.length)return;
    return {selectors,fields:names,count,records,creating};
  }
  get(id) {const r=this.db.prepare('SELECT * FROM server_grants WHERE id=?').get(id);return r&&{...JSON.parse(r.json),charged:r.charged,revoked:r.revoked};}
  offer(change,person,resolved) {
    const cfg=this.config(change),s=this.classify(change,resolved);
    // S33/S46: the maker of a grant must hold the permission to make the change.
    if(!person?.authenticated||!finite(cfg)||!s||(!mutated('grant-skips-permission')&&!authorize(this.core.sor,person,{change,records:s.records},'grant').allowed))return;
    const shapes=[...(!s.creating?[THESE]:[]),...(cfg.anyRecord||mutated('grant-any-record-without-config')?[ANY]:[])];if(!shapes.length)return;
    return {principal:change.principal,account:change.account,audience:change.audience,operation:change.operation,selectors:s.selectors,fields:s.fields,shapes,records:s.creating?[]:s.records,max_records:cfg.maxRecords,max_expires:this.core.now()+cfg.maxSeconds};
  }
  create(change,person,max_records,expires,displayed_at,shape=ANY,resolved,auditExtra={}) {
    const t=this.offer(change,person,resolved);if(!t)throw Error('permission_denied');
    if(!t.shapes.includes(shape))throw Error('shape not offered');
    if(!Number.isSafeInteger(max_records)||max_records<1||max_records>t.max_records||!Number.isSafeInteger(expires)||expires<=this.core.now()||expires>t.max_expires)throw Error('grant limits');
    const g={id:crypto.randomBytes(24).toString('hex'),granted_by:person.id,principal:t.principal,account:t.account,audience:t.audience,operation:t.operation,selectors:t.selectors,fields:t.fields,shape,...(shape===THESE?{records:t.records}:{}),max_records,expires,made_at:this.core.now(),
      // S85: the effect record in force when the grant was made. A grant under a
      // different one no longer matches (matches below), so a change to who may approve
      // or to what a write does retires the grant until a new one is made.
      effect_hash:this.core.effectHash()};
    this.db.prepare('INSERT INTO server_grants(id,account,json) VALUES(?,?,?)').run(g.id,g.account,JSON.stringify(g));
    this.core.audit('decision',{principal:g.principal,operation:g.operation},{grant_id:g.id,...auditExtra,grant_shape:shape,approver_type:'grant',approver_id:g.granted_by,terms:g,displayed_at,decided_at:this.core.now()},'granted');return this.get(g.id);
  }
  matches(g,change,resolved) {
    const s=this.classify(change,resolved),settings=this.core.settings();
    // Item 3 (S18, S35, S84): the grant-record and grant-second limits are ceilings on
    // every grant, existing ones included. Tightening a ceiling is applied to the grant at
    // once and written down on the grant (tighten below), so an existing grant's effective
    // record limit and expiry are its own stored terms. Matching then reads those stored
    // terms, so a later loosening of the ceiling never restores the authority a tightening
    // took away (item 2). Off: grant-tightening-not-stored leaves the old ceiling in the
    // grant and recomputes it here, so a loosening widens it again.
    const effectiveRecords=mutated('grant-tightening-not-stored')
      ? Math.min(g.max_records,Number.isSafeInteger(settings.grantChargeLimit)?settings.grantChargeLimit:Infinity)
      : g.max_records;
    const effectiveExpiry=mutated('grant-tightening-not-stored')
      ? Math.min(g.expires,(g.made_at??0)+(Number.isSafeInteger(settings.grantSecondsLimit)?settings.grantSecondsLimit:Infinity))
      : g.expires;
    return s&&g.account===change.account&&g.principal===change.principal&&g.audience===change.audience&&g.operation===change.operation&&
      (mutated('grant-ignores-selector')||hash(g.selectors)===hash(s.selectors))&&
      (mutated('grant-ignores-field-cover')||s.fields.every(f=>g.fields.includes(f)))&&
      (g.shape===ANY||(g.shape===THESE&&(mutated('grant-ignores-record-set')||s.records.every(id=>g.records.includes(id)))))&&
      // S46: "Each write under a grant MUST also be one that the person who made the grant
      // is permitted to make at that moment, on those records (S22 applied at use)."
      (mutated('grant-skips-authority-at-use')||authorize(this.core.sor,{id:g.granted_by,authenticated:true},{change,records:s.records},'grant').allowed)&&
      (mutated('grant-ignores-expiry')||this.core.now()<effectiveExpiry)&&(mutated('grant-ignores-revocation')||g.revoked===null)&&
      // S85: a grant made under a different effect record no longer matches. A grant from
      // before the binding existed carries none and matches, so an upgrade does not
      // retire it (the same rule ServerIssued.approvalBinds uses).
      (g.effect_hash===undefined||g.effect_hash===this.core.effectHash())&&
      (mutated('grant-ignores-limit')||g.charged+s.count<=effectiveRecords);
  }
  match(change,resolved,exclude=[]) {return this.db.prepare('SELECT id FROM server_grants WHERE account=? ORDER BY rowid').all(change.account).filter(r=>!exclude.includes(r.id)).map(r=>this.get(r.id)).find(g=>this.matches(g,change,resolved));}
  // S84: "Loosening a setting MUST NOT ... widen an existing approval or grant." Tightening
  // a ceiling takes effect at once, so the tightened limit is written down on the grant
  // itself: its effective record limit and expiry are lowered and stored. A later loosening
  // of the ceiling therefore finds the tightened grant and restores no earlier authority.
  // `made_at` and every other term are unchanged, and a grant already expired or revoked is
  // left as it is. Off: grant-tightening-not-stored.
  tighten(oldSettings,newSettings=this.core.settings()) {
    if (mutated('grant-tightening-not-stored')) return;
    const recordCeiling=Number.isSafeInteger(newSettings.grantChargeLimit)?newSettings.grantChargeLimit:Infinity;
    const secondCeiling=Number.isSafeInteger(newSettings.grantSecondsLimit)?newSettings.grantSecondsLimit:Infinity;
    const oldRecords=Number.isSafeInteger(oldSettings?.grantChargeLimit)?oldSettings.grantChargeLimit:Infinity;
    const oldSeconds=Number.isSafeInteger(oldSettings?.grantSecondsLimit)?oldSettings.grantSecondsLimit:Infinity;
    // Only a tightening of a ceiling lowers anything; a loosening leaves every grant alone.
    if (recordCeiling>=oldRecords && secondCeiling>=oldSeconds) return;
    for (const row of this.db.prepare('SELECT id,json FROM server_grants').all()) {
      const g=JSON.parse(row.json); let changed=false;
      if (recordCeiling<oldRecords && g.max_records>recordCeiling) { g.max_records=recordCeiling; changed=true; }
      const storedExpiry=g.expires, tightenedExpiry=secondCeiling<oldSeconds ? Math.min(storedExpiry,(g.made_at??0)+secondCeiling) : storedExpiry;
      if (tightenedExpiry<storedExpiry) { g.expires=tightenedExpiry; changed=true; }
      if (changed) this.db.prepare('UPDATE server_grants SET json=? WHERE id=?').run(JSON.stringify(g),row.id);
    }
  }
  // S48/S65 and Section 3: which property definitions exist is told only
  // to a principal established to see them. For any other principal the reason is
  // computed as if every property the request names were defined, so a restricted
  // definition and an undefined property get the same `grant_status`.
  explain(change,resolved,{definitions=true}={}) {
    const g=this.db.prepare('SELECT id FROM server_grants WHERE account=? ORDER BY rowid DESC').all(change.account).map(r=>this.get(r.id)).find(g=>g.principal===change.principal&&g.operation===change.operation);
    if(!g)return;
    const state=grantState(g,this.core.now()),s=this.classify(change,resolved,{assumeDefined:!definitions&&!mutated('grant-status-reveals-definitions')});
    if(state==='revoked')return {status:'revoked',message:'The newest standing grant was revoked.'};
    if(state==='expired')return {status:'expired',message:'The newest standing grant has expired.'};
    if(state==='used_up'||(s&&g.charged+s.count>g.max_records))return {status:'used_up',message:'The newest standing grant has used up its record allowance for this change.'};
    if(!s||s.fields.some(f=>!g.fields.includes(f)))return {status:'outside',message:'A field in this change is not covered by the newest standing grant.'};
    return {status:'outside',message:'A record or kind of write in this change is not covered by the newest standing grant under its current scope and maker permissions.'};
  }
  charge(req,p,c) {
    // S68(6): for a covered operation the records closed at consumption are those of
    // the context (the same request key), not only those of the change hash.
    const rows=p.contextToken?this.db.prepare('SELECT * FROM pending WHERE context=? ORDER BY rowid').all(p.contextToken):this.db.prepare('SELECT * FROM pending WHERE hash=? ORDER BY rowid').all(p.change_hash);
    const consumed=rows.find(x=>x.status==='consumed');
    if(consumed&&!mutated('grant-double-execution')) {
      // A concurrent identical request already consumed this change; the repeat is
      // answered with the recorded outcome, or with an unknown outcome while the first
      // execution is still in progress (S80).
      throw Object.assign(Error('recorded'),{recorded:this.core.outcomeByHash(p.change_hash)??{outcome:'unknown',at:this.core.now()}});
    }
    const sticky=rows.find(x=>['denied','cancelled'].includes(x.status));
    if(sticky)throw Object.assign(Error(sticky.status),{code:'approval_'+sticky.status,details:{retry_after:Math.max(0,sticky.expires-this.core.now())}});
    if(rows.some(x=>x.status==='approved'&&JSON.parse(x.claims??'{}').approver?.type==='person'))throw Object.assign(Error('person decided first'),{code:'server_grant_unavailable'});
    const g=this.get(c.grant.id);if(!g||!this.matches(g,p.change,p.records))throw Object.assign(Error('grant no longer matches'),{code:'server_grant_unavailable'});
    // S35/S50: close every other pending or approved record for the same change hash in
    // this same atomic step as the charge and the consumption; if the unit rolls back,
    // they are still open. Superseding moves the hash aside so the consuming record can
    // own it.
    for (const x of rows) if(x.id!==c.jti&&['pending','approved'].includes(x.status)) mutated('supersede-deletes-record')?this.db.prepare('DELETE FROM pending WHERE id=?').run(x.id):this.core.pending.supersede(x.id);
    const own=rows.find(x=>x.id===c.jti);
    if(own)this.db.prepare('DELETE FROM pending WHERE id=?').run(own.id);
    this.db.prepare("INSERT INTO pending(id,hash,principal,expires,status,json,claims,context) VALUES(?,?,?,?,'approved',?,?,?)").run(c.jti,p.change_hash,req.principal,Math.max(this.core.now()+this.core.settings().pendingLifetime,g.expires),JSON.stringify({change:p.change,current:p.current,records:p.records??null}),JSON.stringify(c),p.contextToken??null);
    try{this.core.sor.hit('grant-charge',{req,p,c});}catch(e){e.code='server_grant_unavailable';throw e;}
    this.db.prepare('UPDATE server_grants SET charged=charged+? WHERE id=?').run(this.classify(p.change,p.records).count,g.id);
    this.db.prepare("UPDATE pending SET status='consumed' WHERE id=?").run(c.jti);
  }
  administrator(account,person) {return person?.authenticated&&(this.core.settings().pageAdministrators?.[account]??[]).includes(person.id);}
  list(account,person) {
    if(!authorize(this.core.sor,person,{account},'view').allowed)throw Error('permission_denied');
    return this.db.prepare('SELECT id FROM server_grants WHERE account=?').all(account).map(r=>this.get(r.id)).filter(g=>g.granted_by===person.id||this.administrator(account,person));
  }
  revoke(account,id,person) {
    this.db.exec('BEGIN IMMEDIATE');try {
      const g=this.get(id);if(!g||g.account!==account||!authorize(this.core.sor,person,{account},'view').allowed||(g.granted_by!==person.id&&!this.administrator(account,person)))throw Error('permission_denied');
      this.db.prepare('UPDATE server_grants SET revoked=? WHERE id=?').run(this.core.now(),id);
      this.core.audit('decision',{principal:person.id,operation:g.operation},{grant_id:id,grant_shape:g.shape,approver_id:person.id},'revoked');this.db.exec('COMMIT');
    }catch(e){this.db.exec('ROLLBACK');throw e;}
  }
}
