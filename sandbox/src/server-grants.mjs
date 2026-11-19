import { grantState } from './presentation.mjs';
import crypto from 'node:crypto';
import { OP, QUERY, CREATE, mutated } from './core.mjs';
import { hash, object } from './json.mjs';
import { fields, hasArray, identifiers } from './fields.mjs';
export const THESE='these_records', ANY='any_record';
export const finite=cfg=>object(cfg)&&Number.isSafeInteger(cfg.maxRecords)&&cfg.maxRecords>0&&Number.isSafeInteger(cfg.maxSeconds)&&cfg.maxSeconds>0&&cfg.maxSeconds<8640000000000&&(cfg.anyRecord===undefined||typeof cfg.anyRecord==='boolean');
export class ServerGrants {
  constructor(core) {
    this.core=core;this.db=core.db;
    this.db.exec('CREATE TABLE IF NOT EXISTS server_grants(id TEXT PRIMARY KEY, account TEXT, json TEXT, charged INTEGER NOT NULL DEFAULT 0, revoked INTEGER)');
  }
  config(c) {return this.core.settings().grantConfig?.[c.account]?.[c.operation];}
  classify(c,resolved) {
    const a=c.arguments,keys=Object.keys(a);let selectors,count,creating=false;
    if(c.operation===OP) {
      if(keys.some(k=>!['objectType','action','records'].includes(k))||typeof a.objectType!=='string'||!['update','create'].includes(a.action)||!Array.isArray(a.records))return;
      if(a.records.some(r=>!object(r)||typeof r.id!=='string'||Object.keys(r).some(k=>!['id','properties'].includes(k))||!object(r.properties)||hasArray(r.properties)))return;
      selectors={objectType:a.objectType,action:a.action};count=a.records.length;creating=a.action==='create';
    }else if(c.operation===QUERY) {
      if(keys.some(k=>!['objectType','filter','set'].includes(k))||typeof a.objectType!=='string'||!object(a.filter)||!object(a.set)||hasArray(a.set)||!c.resolved||!Array.isArray(resolved))return;
      selectors={objectType:a.objectType,filter:a.filter};count=c.resolved.count;
    }else if(c.operation===CREATE) {
      if(keys.some(k=>!['objectType','id','properties'].includes(k))||typeof a.objectType!=='string'||typeof a.id!=='string'||!object(a.properties)||hasArray(a.properties))return;
      selectors={objectType:a.objectType,action:'create'};count=1;creating=true;
    }else return;
    const props=a.records?.map(r=>r.properties)??[a.set??a.properties??{}];if(!props.every(v=>this.core.sor.defined(a.objectType,v)))return;
    const names=fields(c),records=identifiers(c,resolved);if(!Number.isSafeInteger(count)||count<0||!names.length)return;
    return {selectors,fields:names,count,records,creating};
  }
  get(id) {const r=this.db.prepare('SELECT * FROM server_grants WHERE id=?').get(id);return r&&{...JSON.parse(r.json),charged:r.charged,revoked:r.revoked};}
  offer(change,person,resolved) {
    const cfg=this.config(change),s=this.classify(change,resolved);
    if(!person?.authenticated||!finite(cfg)||!s||(!mutated('grant-skips-permission')&&!this.core.sor.authorized(change,person.id,s.records)))return;
    const shapes=[...(!s.creating?[THESE]:[]),...(cfg.anyRecord||mutated('grant-any-record-without-config')?[ANY]:[])];if(!shapes.length)return;
    return {principal:change.principal,account:change.account,audience:change.audience,operation:change.operation,selectors:s.selectors,fields:s.fields,shapes,records:s.creating?[]:s.records,max_records:cfg.maxRecords,max_expires:this.core.now()+cfg.maxSeconds};
  }
  create(change,person,max_records,expires,displayed_at,shape=ANY,resolved) {
    const t=this.offer(change,person,resolved);if(!t)throw Error('permission_denied');
    if(!t.shapes.includes(shape))throw Error('shape not offered');
    if(!Number.isSafeInteger(max_records)||max_records<1||max_records>t.max_records||!Number.isSafeInteger(expires)||expires<=this.core.now()||expires>t.max_expires)throw Error('grant limits');
    const g={id:crypto.randomBytes(24).toString('hex'),granted_by:person.id,principal:t.principal,account:t.account,audience:t.audience,operation:t.operation,selectors:t.selectors,fields:t.fields,shape,...(shape===THESE?{records:t.records}:{}),max_records,expires,made_at:this.core.now()};
    this.db.prepare('INSERT INTO server_grants(id,account,json) VALUES(?,?,?)').run(g.id,g.account,JSON.stringify(g));
    this.core.audit('decision',{principal:g.principal,operation:g.operation},{grant_id:g.id,grant_shape:shape,approver_type:'grant',approver_id:g.granted_by,terms:g,displayed_at,decided_at:this.core.now()},'granted');return this.get(g.id);
  }
  matches(g,change,resolved) {
    const s=this.classify(change,resolved);
    return s&&g.account===change.account&&g.principal===change.principal&&g.audience===change.audience&&g.operation===change.operation&&
      (mutated('grant-ignores-selector')||hash(g.selectors)===hash(s.selectors))&&
      (mutated('grant-ignores-field-cover')||s.fields.every(f=>g.fields.includes(f)))&&
      (g.shape===ANY||(g.shape===THESE&&(mutated('grant-ignores-record-set')||s.records.every(id=>g.records.includes(id)))))&&
      (mutated('grant-skips-authority-at-use')||this.core.sor.authorized(change,g.granted_by,s.records))&&
      (mutated('grant-ignores-expiry')||this.core.now()<g.expires)&&(mutated('grant-ignores-revocation')||g.revoked===null)&&
      (mutated('grant-ignores-limit')||g.charged+s.count<=g.max_records);
  }
  match(change,resolved,exclude=[]) {return this.db.prepare('SELECT id FROM server_grants WHERE account=? ORDER BY rowid').all(change.account).filter(r=>!exclude.includes(r.id)).map(r=>this.get(r.id)).find(g=>this.matches(g,change,resolved));}
  explain(change,resolved) {
    const g=this.db.prepare('SELECT id FROM server_grants WHERE account=? ORDER BY rowid DESC').all(change.account).map(r=>this.get(r.id)).find(g=>g.principal===change.principal&&g.operation===change.operation);
    if(!g)return;
    const state=grantState(g,this.core.now()),s=this.classify(change,resolved);
    if(state==='revoked')return {status:'revoked',message:'The newest standing grant was revoked.'};
    if(state==='expired')return {status:'expired',message:'The newest standing grant has expired.'};
    if(state==='used_up'||(s&&g.charged+s.count>g.max_records))return {status:'used_up',message:'The newest standing grant has used up its record allowance for this change.'};
    if(!s||s.fields.some(f=>!g.fields.includes(f)))return {status:'outside',message:'A field in this change is not covered by the newest standing grant.'};
    return {status:'outside',message:'A record or kind of write in this change is not covered by the newest standing grant under its current scope and maker permissions.'};
  }
  charge(req,p,c) {
    const previous=this.db.prepare('SELECT * FROM pending WHERE hash=?').get(p.change_hash);
    if(previous?.status==='consumed'&&!mutated('grant-double-execution'))throw Object.assign(Error('approval_used'),{code:'approval_used'});
    if(previous&&['denied','cancelled'].includes(previous.status))throw Object.assign(Error(previous.status),{code:'approval_'+previous.status,details:{retry_after:Math.max(0,previous.expires-this.core.now())}});
    if(previous?.status==='approved'&&JSON.parse(previous.claims??'{}').approver?.type==='person')throw Object.assign(Error('person decided first'),{code:'server_grant_unavailable'});
    const g=this.get(c.grant.id);if(!g||!this.matches(g,p.change,p.records))throw Object.assign(Error('grant no longer matches'),{code:'server_grant_unavailable'});
    if(previous)this.db.prepare('DELETE FROM pending WHERE id=?').run(previous.id);
    this.db.prepare("INSERT INTO pending VALUES(?,?,?,?,'approved',?,?)").run(c.jti,p.change_hash,req.principal,Math.max(this.core.now()+this.core.settings().pendingLifetime,g.expires),JSON.stringify({change:p.change,current:p.current,records:p.records??null}),JSON.stringify(c));
    try{this.core.sor.hit('grant-charge',{req,p,c});}catch(e){e.code='server_grant_unavailable';throw e;}
    this.db.prepare('UPDATE server_grants SET charged=charged+? WHERE id=?').run(this.classify(p.change,p.records).count,g.id);
    this.db.prepare("UPDATE pending SET status='consumed' WHERE id=?").run(c.jti);
  }
  administrator(account,person) {return person?.authenticated&&(this.core.settings().pageAdministrators?.[account]??[]).includes(person.id);}
  list(account,person) {
    if(!person?.authenticated||!this.core.sor.belongs(account,person.id))throw Error('permission_denied');
    return this.db.prepare('SELECT id FROM server_grants WHERE account=?').all(account).map(r=>this.get(r.id)).filter(g=>g.granted_by===person.id||this.administrator(account,person));
  }
  revoke(account,id,person) {
    this.db.exec('BEGIN IMMEDIATE');try {
      const g=this.get(id);if(!g||g.account!==account||!person?.authenticated||!this.core.sor.belongs(account,person.id)||(g.granted_by!==person.id&&!this.administrator(account,person)))throw Error('permission_denied');
      this.db.prepare('UPDATE server_grants SET revoked=? WHERE id=?').run(this.core.now(),id);
      this.core.audit('decision',{principal:person.id,operation:g.operation},{grant_id:id,grant_shape:g.shape,approver_id:person.id},'revoked');this.db.exec('COMMIT');
    }catch(e){this.db.exec('ROLLBACK');throw e;}
  }
}
