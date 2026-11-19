import crypto from 'node:crypto';
import { ServerGrants } from './server-grants.mjs';
import { hash } from './json.mjs';
import { mutated } from './core.mjs';
export class ServerIssued {
  constructor(core, baseURL='http://127.0.0.1:8787') {
    this.core=core; this.db=core.db; this.baseURL=baseURL;
    this.db.exec('CREATE TABLE IF NOT EXISTS displays(id TEXT PRIMARY KEY, at INTEGER)');
    this.db.exec(`CREATE TABLE IF NOT EXISTS pending(id TEXT PRIMARY KEY, hash TEXT UNIQUE, principal TEXT, expires INTEGER, status TEXT, json TEXT, claims TEXT);`);
    this.db.exec('CREATE TABLE IF NOT EXISTS page_displays(record TEXT, session TEXT,person TEXT,at INTEGER,PRIMARY KEY(record,session))');
    this.db.exec('CREATE TABLE IF NOT EXISTS page_offers(record TEXT,session TEXT,shapes TEXT,PRIMARY KEY(record,session))');
    this.db.exec('CREATE TABLE IF NOT EXISTS page_decisions(record TEXT PRIMARY KEY, fingerprint TEXT, result TEXT)');
    this.grants=new ServerGrants(core);core.pending=this;
  }
  get(id) { const r=this.db.prepare('SELECT * FROM pending WHERE id=?').get(id); return r && {...r,display:JSON.parse(r.json)}; }
  lookup(req,p) {
    this.db.exec('BEGIN IMMEDIATE');
    try {const claims=this.lookupLocked(req,p);this.db.exec('COMMIT');return claims;}
    catch(e) {
      this.db.exec(['approval_required','approval_denied','approval_cancelled','approval_limit_reached'].includes(e.code)?'COMMIT':'ROLLBACK');throw e;
    }
  }
  lookupLocked(req,p) {
    let r=this.db.prepare('SELECT * FROM pending WHERE hash=?').get(p.change_hash);
    const retained=r?.status==='consumed'&&JSON.parse(r.claims??'{}').grant;
    if(mutated('grant-double-execution')&&r?.status==='consumed'&&JSON.parse(r.claims??'{}').grant){this.db.prepare('DELETE FROM pending WHERE id=?').run(r.id);r=undefined;}
    if (r && r.expires<=this.core.now()&&!retained) { this.db.prepare('DELETE FROM pending WHERE id=?').run(r.id); r=undefined; }
    const act=req.inputResponses?.approve?.action, veto=act==='decline' || act==='cancel';
    const refuse=(code,details)=>{ throw Object.assign(Error(code),{code,details}); };
    const until=x=>({retry_after:Math.max(0,x.expires-this.core.now())});
    if (mutated('decline-erases-denial') && act==='decline' && r?.status==='denied') {
      this.db.prepare('DELETE FROM pending WHERE id=?').run(r.id);r=undefined;
    }
    if (r?.status==='denied') refuse('approval_denied',until(r)); // S31: no connection response changes a denial
    const ignoreApprovedDecline=mutated('ignore-decline') && act==='decline' && r?.status==='approved';
    const createOnVeto=mutated('veto-creates-pending') && veto && !r;
    if (veto && !ignoreApprovedDecline && !createOnVeto) { // S30: the connection may veto, never approve; a veto creates no record
      if (r && ['pending','approved'].includes(r.status)) {
        this.db.prepare("UPDATE pending SET status='cancelled' WHERE id=?").run(r.id);
        this.core.audit('decision',{principal:req.principal,operation:req.operation},{change_hash:p.change_hash,issuer:'server',receipt_id:r.id},'cancelled');
      }
      refuse('approval_cancelled',r ? until(r) : {retry_after:0});
    }
    if (mutated('cancel-not-sticky') && r?.status==='cancelled') {
      this.db.prepare('DELETE FROM pending WHERE id=?').run(r.id);r=undefined;
    }
    if (r?.status==='cancelled') refuse('approval_cancelled',until(r)); // stays cancelled until the record expires
    if(retained&&!mutated('grant-double-execution'))refuse('approval_used');
    if (r?.status==='approved'||r?.status==='consumed') return JSON.parse(r.claims);
    if(mutated('grant-from-connection')&&(req.args?.grant||req.inputResponses?.approve?.content?.grant)) {
      const change=structuredClone(p.change);delete change.arguments.grant;const who={id:'test-person',authenticated:true};
      if(this.grants.offer(change,who))this.grants.create(change,who,2,this.core.now()+100,this.core.now());
    }
    const grant=this.grants.match(p.change,p.records,req.excludeGrants);
    if(grant) {
      const id=r?.id??crypto.randomBytes(24).toString('hex');
      if(!r) {
        const open=this.db.prepare("SELECT count(*) n FROM pending WHERE principal=? AND expires>? AND status IN ('pending','denied','cancelled')").get(req.principal,this.core.now()).n;
        if(open<this.core.settings().pendingCap)this.db.prepare("INSERT INTO pending VALUES(?,?,?,?,'pending',?,NULL)").run(id,p.change_hash,req.principal,this.core.now()+this.core.settings().pendingLifetime,JSON.stringify({change:p.change,current:p.current,records:p.records??null}));
      }
      return {iss:'server',jti:id,iat:this.core.now(),exp:this.core.now()+this.core.settings().maxLifetime,change_hash:p.change_hash,approver:{type:'grant',id:grant.granted_by},grant:{id:grant.id,shape:grant.shape,max_records:grant.max_records,expires:grant.expires}};
    }
    // A grant decision sealed its page without approving the shown change.
    if(r?.status==='pending'&&this.db.prepare('SELECT 1 FROM page_decisions WHERE record=?').get(r.id)){this.db.prepare('DELETE FROM pending WHERE id=?').run(r.id);r=undefined;}

    if (mutated('accept-connection-accept') && (req.inputResponses?.approve?.action==='accept' || req.args?.confirmation)) return {iss:'server',jti:crypto.randomUUID(),iat:this.core.now(),exp:this.core.now()+300,change_hash:p.change_hash,approver:{type:'person',id:'connection'}};
    if (!r) {
      const statuses=mutated('cap-counts-pending-only') ? "status='pending'" : "status IN ('pending','denied','cancelled')";
      const count=this.db.prepare(`SELECT count(*) n FROM pending WHERE principal=? AND expires>? AND ${statuses}`).get(req.principal,this.core.now()).n;
      if (count<this.core.settings().pendingCap) {
        const id=crypto.randomBytes(24).toString('hex'); const display={change:p.change,current:p.current,records:p.records ?? null};
        this.db.prepare("INSERT INTO pending VALUES(?,?,?,?,'pending',?,NULL)").run(id,p.change_hash,req.principal,this.core.now()+this.core.settings().pendingLifetime,JSON.stringify(display));
      } else if (!mutated('cap-refuses-as-required')) { // S27: at the cap say so, never "approval required"
        const first=this.db.prepare(`SELECT min(expires) e FROM pending WHERE principal=? AND expires>? AND ${statuses}`).get(req.principal,this.core.now()).e;
        refuse('approval_limit_reached',{open:count,limit:this.core.settings().pendingCap,retry_after:Math.max(0,first-this.core.now())});
      }
    }
    const code=createOnVeto ? 'approval_cancelled' : 'approval_required';
    throw Object.assign(Error(code),{code});
  }
  url(change_hash) { const r=this.db.prepare('SELECT id FROM pending WHERE hash=? AND expires>?').get(change_hash,this.core.now()); return r ? `${this.baseURL}/approve/${r.id}` : undefined; }
  decision(id,person,kind,terms,session,act) {
    this.db.exec('BEGIN IMMEDIATE');
    try {
      const r=this.get(id);if(!r||r.expires<=this.core.now()||r.status==='consumed')throw Error('expired or consumed');
      if(!person?.authenticated||!(kind==='grant'&&mutated('grant-skips-permission'))&&!this.core.sor.authorized(r.display.change,person.id,r.display.records))throw Error('permission_denied');
      const shown=this.db.prepare('SELECT at FROM page_displays WHERE record=? AND session=? AND person=?').get(id,session,person.id);
      if(!shown&&!mutated('page-decision-without-display'))throw Error('change must be displayed to this session');
      const fingerprint=hash({person:person.id,kind,terms}),prior=this.db.prepare('SELECT * FROM page_decisions WHERE record=?').get(id);
      if(prior) {
        if(prior.fingerprint!==fingerprint)throw Error('first decision is final');
        if(!mutated('decision-replay-creates-second')) {this.db.exec('COMMIT');return JSON.parse(prior.result);}
      }else if(r.status!=='pending')throw Error('expired or decided');
      const result=act(r,shown?.at??this.core.now());
      this.db.prepare('INSERT OR IGNORE INTO page_decisions VALUES(?,?,?)').run(id,fingerprint,JSON.stringify(result));
      this.db.exec('COMMIT');return result;
    }catch(e){this.db.exec('ROLLBACK');throw e;}
  }
  decide(id,person,approve,session=person?.id) {
    return this.decision(id,person,approve?'approve':'deny',{},session,(r,displayed_at)=>{
      const c={iss:'server',jti:r.id,iat:this.core.now(),exp:Math.min(r.expires,this.core.now()+this.core.settings().maxLifetime),change_hash:r.hash,approver:{type:'person',id:person.id}};
      this.db.prepare('UPDATE pending SET status=?,claims=? WHERE id=?').run(approve?'approved':'denied',JSON.stringify(c),id);
      this.core.audit('decision',{principal:person.id,operation:r.display.change.operation},{change_hash:r.hash,issuer:'server',receipt_id:r.id,displayed_at,decided_at:this.core.now()},approve?'approved':'denied');
      return {approved:!!approve,usable_until:c.exp};
    });
  }
  grantFallback(req,p,c) {return this.core.handle({...req,excludeGrants:[...(req.excludeGrants??[]),c.grant.id]});}
  recordGrant(id,person,max_records,terms,expiry,session,shape) {
    return this.decision(id,person,'grant',{max_records,...terms,shape},session,(r,displayed_at)=>{const offered=JSON.parse(this.db.prepare('SELECT shapes FROM page_offers WHERE record=? AND session=?').get(id,session)?.shapes??'[]');if(!offered.includes(shape))throw Error('shape not offered on this page');return {...this.grants.create(r.display.change,person,max_records,expiry(),displayed_at,shape,r.display.records),change_hash:r.hash};});
  }
  createGrant(id,person,max_records,expires,session=person?.id,shape='any_record') {return this.recordGrant(id,person,max_records,{expires},()=>expires,session,shape);}
  createGrantMinutes(id,person,max_records,minutes,session,shape) {
    const seconds=Math.round(minutes*60);if(!Number.isFinite(minutes)||minutes<=0||!Number.isSafeInteger(seconds)||seconds<1)throw Error('invalid duration');
    return this.recordGrant(id,person,max_records,{seconds},()=>this.core.now()+seconds,session,shape);
  }
  cleanup() {
    // Consumed grant identities and outcomes are retained indefinitely, beyond S35's minimum.
    for(const row of this.db.prepare('SELECT id,claims FROM pending WHERE expires<=?').all(this.core.now()))if(!JSON.parse(row.claims??'{}').grant)this.db.prepare('DELETE FROM pending WHERE id=?').run(row.id);
  }
  // S50: what was decided for a record, and what state that decision is in now.
  // A grant-decided link says whether the shown change has run under the grant, and an
  // approval says when it was used. Use moments come from the consumption audit row
  // (person approvals, keyed by receipt id) and the retained consumed pending row (the
  // shown change's hash and the grant id), so they survive record cleanup.
  outcome(id) {
    const prior=this.db.prepare('SELECT result FROM page_decisions WHERE record=?').get(id);
    if (prior) {try {const g=JSON.parse(prior.result);if (g && typeof g==='object' && g.id && g.made_at!==undefined){const usedAt=this.grantUsedAt(g);return {kind:'grant',at:g.made_at,...(usedAt===undefined?{}:{usedAt})};}}catch {}}
    const r=this.get(id);
    if (!r) return undefined;
    let c={};try {c=JSON.parse(r.claims??'{}');}catch {}
    if (c.grant && ['approved','consumed'].includes(r.status)) {const g=this.grants.get(c.grant.id);return {kind:'grant',at:g?.made_at??c.iat,...(mutated('grant-outcome-stale')?{}:{usedAt:c.iat})};}
    if (r.expires<=this.core.now()) return undefined;
    if (r.status==='approved'||r.status==='consumed') return {kind:'approve',at:c.iat,until:c.exp,used:r.status==='consumed',...(r.status==='consumed'?{usedAt:this.consumedAt(id)}:{})};
    if (r.status==='denied') return {kind:'deny',at:c.iat};
    return undefined;
  }
  // When the shown change of a page-made grant ran under that grant, if it did.
  grantUsedAt(g) {
    if (mutated('grant-outcome-stale')||g.change_hash===undefined) return undefined;
    const row=this.db.prepare("SELECT claims FROM pending WHERE hash=? AND status='consumed'").get(g.change_hash);
    if (!row) return undefined;
    try {const c=JSON.parse(row.claims??'{}');if (c.grant?.id===g.id) return c.iat;}catch {}
    return undefined;
  }
  // When a person approval was consumed, from the consumption audit row.
  consumedAt(id) {
    for (const row of this.db.prepare('SELECT json FROM audit ORDER BY seq').all()) {try {const a=JSON.parse(row.json);if (a.record_phase==='consumption'&&a.action_detail?.receipt_id===id) return a.timestamp;}catch {}}
    return undefined;
  }
  page(id,person,session=person?.id) {
    const r=this.get(id);if(!r||r.expires<=this.core.now())throw Error('expired');
    if(r.status!=='pending')throw Error('expired or decided'); // S50: only a pending record is shown as open
    if(!person?.authenticated||(!mutated('page-view-without-permission')&&!this.core.sor.authorized(r.display.change,person.id,r.display.records,'read',r.display.current)))throw Error('permission_denied');
    this.db.prepare('INSERT OR REPLACE INTO page_displays VALUES(?,?,?,?)').run(id,session,person.id,this.core.now());
    const grantOffer=this.grants.offer(r.display.change,person,r.display.records);
    this.db.prepare('INSERT OR REPLACE INTO page_offers VALUES(?,?,?)').run(id,session,JSON.stringify(grantOffer?.shapes??[]));
    return {...r.display,grantOffer};
  }
}
