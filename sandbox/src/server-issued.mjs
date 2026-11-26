import crypto from 'node:crypto';
import { ServerGrants } from './server-grants.mjs';
import { hash, jcsTotal } from './json.mjs';
import { actionFor, mutated } from './core.mjs';
import { copySource, requestArguments } from './fields.mjs';
import { authorize, resolveIdentifier } from './authorize.mjs';
export class ServerIssued {
  constructor(core, baseURL='http://127.0.0.1:8787') {
    this.core=core; this.db=core.db; this.baseURL=baseURL;
    this.db.exec('CREATE TABLE IF NOT EXISTS displays(id TEXT PRIMARY KEY, at INTEGER)');
    this.db.exec(`CREATE TABLE IF NOT EXISTS pending(id TEXT PRIMARY KEY, hash TEXT UNIQUE, principal TEXT, expires INTEGER, status TEXT, json TEXT, claims TEXT);`);
    // S67: the approval records of one request key are grouped into an approval context.
    // A context has an unguessable token, a creation time and an expiry, all fixed when
    // its first record is created, and holds at most one open (pending) record. The
    // partial indexes make the one-context and one-open-record rules atomic.
    this.db.exec(`CREATE TABLE IF NOT EXISTS contexts(token TEXT PRIMARY KEY, request_key TEXT, principal TEXT, created INTEGER, expires INTEGER, status TEXT)`);
    const ctxCols=this.db.prepare('PRAGMA table_info(contexts)').all().map(r=>r.name);
    // S30/S31 with S68(5), S70 (item 12): the moment a denial or a cancellation on a
    // context stops locking the change: one hour after the decision, or the context's own
    // expiry where that is sooner. A row from before this column keeps its own expiry.
    if (!ctxCols.includes('locked_until')) this.db.prepare('ALTER TABLE contexts ADD COLUMN locked_until INTEGER').run();
    this.db.exec(`CREATE UNIQUE INDEX IF NOT EXISTS contexts_live ON contexts(request_key) WHERE status IN ('open','denied','cancelled')`);
    const cols=this.db.prepare('PRAGMA table_info(pending)').all().map(r=>r.name);
    if (!cols.includes('context')) this.db.prepare('ALTER TABLE pending ADD COLUMN context TEXT').run();
    // S30/S31 (item 4): a denial or a cancellation locks the change for at most one hour,
    // independent of the pending lifetime setting. `locked_until` is fixed when the record
    // is denied or cancelled; a row from before this column keeps its own expiry.
    if (!cols.includes('locked_until')) this.db.prepare('ALTER TABLE pending ADD COLUMN locked_until INTEGER').run();
    this.db.exec(`CREATE UNIQUE INDEX IF NOT EXISTS pending_one_open ON pending(context) WHERE status='pending'`);
    this.db.exec('CREATE TABLE IF NOT EXISTS page_displays(record TEXT, session TEXT,person TEXT,at INTEGER,PRIMARY KEY(record,session))');
    this.db.exec('CREATE TABLE IF NOT EXISTS page_offers(record TEXT,session TEXT,shapes TEXT,PRIMARY KEY(record,session))');
    this.db.exec('CREATE TABLE IF NOT EXISTS page_decisions(record TEXT PRIMARY KEY, fingerprint TEXT, result TEXT)');
    // S27/S81: the approver is told, on a channel the agent's credential cannot read, that
    // a pending record is open when the pending lifetime is longer than one hour. The
    // channel is this table: no MCP tool, refusal or result reads it.
    this.db.exec('CREATE TABLE IF NOT EXISTS notifications(id INTEGER PRIMARY KEY AUTOINCREMENT, record TEXT, person TEXT, account TEXT, at INTEGER, message TEXT)');
    this.db.exec('CREATE UNIQUE INDEX IF NOT EXISTS notifications_once ON notifications(record, person)');
    // S67: a counter that orders reads of record state against the
    // creation, rendering and decision of approval records, across instances. `touched`
    // is the counter's value when the record was last created, rendered or decided.
    if (!cols.includes('touched')) this.db.prepare('ALTER TABLE pending ADD COLUMN touched INTEGER DEFAULT 0').run();
    this.db.exec('CREATE TABLE IF NOT EXISTS read_epoch(id INTEGER PRIMARY KEY CHECK(id=1), n INTEGER)');
    this.db.prepare('INSERT OR IGNORE INTO read_epoch VALUES(1,0)').run();
    this.grants=new ServerGrants(core);core.pending=this;
  }
  epoch() { return this.db.prepare('SELECT n FROM read_epoch WHERE id=1').get().n; }
  touch(id) { this.db.prepare('UPDATE read_epoch SET n=n+1 WHERE id=1').run(); const n=this.epoch(); if(id)this.db.prepare('UPDATE pending SET touched=? WHERE id=?').run(n,id); return n; }
  // S67: "No pending or approved record outlives its context". There is no timer in the
  // sandbox, so every entry into the profile (a request, a page, a decision, a lookup of a
  // record) first closes what is due: each context past its expiry leaves the live index,
  // and its pending and approved records are closed as expired and kept, giving up their
  // change hash as a superseded record does. No caller can observe an open record of an
  // expired context through this class.
  expireDue() {
    const now=this.core.now();
    if (!this.db.prepare("SELECT 1 FROM contexts WHERE expires<=? AND status IN ('open','denied','cancelled') LIMIT 1").get(now)) return;
    this.db.prepare("UPDATE contexts SET status='expired' WHERE expires<=? AND status IN ('open','denied','cancelled')").run(now);
    this.db.prepare("UPDATE pending SET status=CASE WHEN status IN ('pending','approved') THEN 'expired' ELSE status END, hash=hash||'#'||id WHERE instr(hash,'#')=0 AND context IN (SELECT token FROM contexts WHERE status='expired')").run();
  }
  get(id) { if(!mutated('context-expiry-lazy'))this.expireDue(); const r=this.db.prepare('SELECT * FROM pending WHERE id=?').get(id); return r && {...r,display:JSON.parse(r.json)}; }
  contextOf(token) { return this.db.prepare('SELECT * FROM contexts WHERE token=?').get(token); }
  // S53/S58/S70: whether this signed-in person may see the request a token stands for.
  // The answer comes from the stored request and the permission model alone, never from
  // current record values or the record's existence (S53). An unknown token
  // and a person who may not see the request are one case for every page (S53, S58).
  visible(token,person) {
    const r=this.get(token);
    let display=r?.display;
    if (!r) {
      const ctx=this.contextOf(token); if (!ctx) return false;
      const base=this.db.prepare('SELECT json FROM pending WHERE context=? ORDER BY rowid DESC LIMIT 1').get(token); if (!base) return false;
      display=JSON.parse(base.json);
      if (mutated('context-page-without-permission')) return true;
    } else if (mutated('page-view-without-permission')) return true;
    if (mutated('page-outcome-without-permission')) return true;
    return authorize(this.core.sor,person,{change:display.change,records:display.records},'view').allowed;
  }
  // A context that has passed its expiry leaves the live index, so a later request for
  // the same request key may open a new context (S27/S70); a consumed context stays.
  expireContext(ctx) { if (ctx && ctx.expires<=this.core.now() && !['consumed','expired'].includes(ctx.status)) this.db.prepare("UPDATE contexts SET status='expired' WHERE token=?").run(ctx.token); }
  // S67/S68(2) (cold read, finding 3): the context of a request key is its live one.
  // A key can have had earlier contexts that expired; they are history and are never
  // the answer. Every lapsed context of the key leaves the live index first, then the
  // one live context (open, denied or cancelled; the partial unique index allows one)
  // is returned, or else a consumed one, which blocks a new context for the key while
  // its record is kept (S69(1)). Called inside the caller's atomic step.
  contextFor(request_key) {
    if (mutated('context-lookup-oldest')) { const ctx=this.db.prepare('SELECT * FROM contexts WHERE request_key=?').get(request_key); this.expireContext(ctx); return ctx; }
    this.db.prepare("UPDATE contexts SET status='expired' WHERE request_key=? AND expires<=? AND status IN ('open','denied','cancelled')").run(request_key,this.core.now());
    // S67: "No pending or approved record outlives its context." The records of an
    // expired context are closed and kept, and every record of it gives up its change
    // hash (moved aside, as for a superseded record), so that the next context's first
    // record can carry the same hash when record state has not changed. Without this
    // the first request after an expiry collides on the unique hash and is answered
    // approval_unavailable.
    this.db.prepare("UPDATE pending SET status=CASE WHEN status IN ('pending','approved') THEN 'expired' ELSE status END, hash=hash||'#'||id WHERE instr(hash,'#')=0 AND context IN (SELECT token FROM contexts WHERE request_key=? AND status='expired')").run(request_key);
    return this.db.prepare("SELECT * FROM contexts WHERE request_key=? AND status<>'expired' ORDER BY (status='consumed'), rowid DESC LIMIT 1").get(request_key);
  }
  // S67 (cold read, finding 8): "an approval is usable until the earlier of its own
  // expiry and the context's expiry". The test is the one step 7 of Section 6 applies. The
  // skew judged is the one in force now unless the approval records a smaller one, so a
  // later skew never revives a lapsed approval (S84, item 3).
  lapsed(claims) { return this.core.now()>=claims.exp+this.core.expirySkew(claims); }
  // S67: "When an approved record expires unused inside its context, a non-reader is
  // answered as before the approval and a reader as S63 provides, a new pending record
  // is created in the context on the next request, and the context still counts under
  // S70." The expired approval is closed and kept; its hash is moved aside so that the
  // next pending record can carry it. Called inside the caller's atomic step.
  closeLapsed(token) {
    if (mutated('covered-expired-approval-refused')) return;
    for (const row of this.db.prepare("SELECT id,claims FROM pending WHERE context=? AND status='approved'").all(token)) {
      let claims; try { claims=JSON.parse(row.claims); } catch { continue; }
      if (claims && this.lapsed(claims)) this.db.prepare("UPDATE pending SET status='expired', hash=hash||'#'||id WHERE id=?").run(row.id);
    }
  }
  // S30/S68(5)/S70: the answers that come from the context, independent of record
  // state, before any rebuild of it: a client veto, a denial and a cancellation.
  coveredPrelude(req, request_key) {
    this.db.exec('BEGIN IMMEDIATE');
    try { this.preludeLocked(req, request_key); this.db.exec('COMMIT'); }
    catch(e) { this.db.exec(['approval_denied','approval_cancelled'].includes(e.code)?'COMMIT':'ROLLBACK'); throw e; }
  }
  preludeLocked(req, request_key) {
    const now=this.core.now(), refuse=(code,details)=>{throw Object.assign(Error(code),{code,details});};
    let ctx=this.contextFor(request_key);
    if (ctx && (ctx.expires<=now || ctx.status==='consumed')) ctx=null;
    // S30/S31 (item 12): a denial or a cancellation locks the change for at most one hour,
    // whatever the pending lifetime is, for a covered operation too. `locked_until` is set
    // when the context is denied or cancelled; once it has passed the lockout is over even
    // though the context has not expired, so the change is answered afresh and a new
    // approval can be requested (S68(5), S70). Off: covered-lockout-follows-expiry holds
    // the context for its whole life.
    const locked=ctx ? (mutated('covered-lockout-follows-expiry') ? ctx.expires : Math.min(ctx.expires, ctx.locked_until ?? ctx.expires)) : undefined;
    if (ctx && locked<=now && ['denied','cancelled'].includes(ctx.status)) {
      this.db.prepare("UPDATE contexts SET status='expired' WHERE token=?").run(ctx.token);
      this.db.prepare("UPDATE pending SET status='expired', hash=hash||'#'||id WHERE context=? AND status IN ('denied','cancelled') AND instr(hash,'#')=0").run(ctx.token);
      ctx=null;
    }
    // S31/S68(5): a denied context stays denied; no connection response changes that.
    if (ctx?.status==='denied' && !mutated('covered-denial-not-sticky')) refuse('approval_denied',{retry_after:Math.max(0,locked-now),request_key,__hash:this.db.prepare("SELECT hash FROM pending WHERE context=? AND status='denied' ORDER BY rowid DESC LIMIT 1").get(ctx.token)?.hash});
    const act=req.inputResponses?.approve?.action;
    if (act==='decline' || act==='cancel') {
      // S30: the connection may veto, never approve; a veto creates no record. For a
      // covered operation the context's open record and the context are cancelled.
      if (ctx) {
        const open=this.db.prepare("SELECT * FROM pending WHERE context=? AND status IN ('pending','approved')").get(ctx.token);
        if (open) {
          this.db.prepare("UPDATE pending SET status='cancelled' WHERE id=?").run(open.id);
          this.core.audit('decision',{principal:req.principal,operation:req.operation},{change_hash:open.hash.split('#')[0],request_key,issuer:'server',receipt_id:open.id},'cancelled');
        }
        if (ctx.status==='open') this.db.prepare("UPDATE contexts SET status='cancelled', locked_until=? WHERE token=?").run(Math.min(ctx.expires,now+ServerIssued.LOCKOUT_SECONDS),ctx.token);
      }
      // With no context there is no stored record and no hash to record; ctx?.token must
      // not be bound to the query (node:sqlite rejects an undefined bind).
      const hashRow=ctx?this.db.prepare('SELECT hash FROM pending WHERE context=? ORDER BY rowid DESC LIMIT 1').get(ctx.token):undefined;
      refuse('approval_cancelled',{retry_after:ctx?Math.max(0,(mutated('covered-lockout-follows-expiry')?ctx.expires:Math.min(ctx.expires,ctx.locked_until??ctx.expires))-now):0,request_key,__hash:hashRow?.hash});
    }
    // S68(5): after a cancellation the answer is stable until the lockout ends, whether or
    // not record state changed; retry_after is computed from the context's lockout (S70).
    if (ctx?.status==='cancelled' && !mutated('covered-cancellation-not-sticky')) refuse('approval_cancelled',{retry_after:Math.max(0,locked-now),request_key});
  }
  // S85, "Binding": "Effect-changing configuration ... gets a version
  // stored with each approval record. A changed version means no approval." Each approval
  // record stores `effect_hash`; a record made under a different value of a setting that
  // changes what the write does or who may approve is not an approval, and the normal
  // approval request follows (S34: "When no grant matches, the request is treated as one
  // with no approved record"; S68(3) for a covered operation). A record from before the
  // binding existed carries none and matches, so an upgrade does not retire it.
  approvalBinds(claims) {
    if (mutated('binding-ignored')) return true;
    const made = claims?.effect_hash;
    return made === undefined || made === this.core.effectHash();
  }
  // S67: the lookup of an approved record in the request key's context, the one
  // open-record rule, supersession and staleness (S68(3)), and grant matching (S34).
  coveredLookup(req,p) {
    this.db.exec('BEGIN IMMEDIATE');
    try { const claims=this.coveredLocked(req,p); this.db.exec('COMMIT'); return claims; }
    catch(e) { this.db.exec(['approval_required','approval_denied','approval_cancelled','approval_limit_reached'].includes(e.code)?'COMMIT':'ROLLBACK'); throw e; }
  }
  // S67: "The server MUST NOT replace or close a record on the strength
  // of a read of record state that began before the latest of: the creation of that
  // record, its last rendering for a decision (S68(3)), and the recording of its
  // decision; it reads again." A record touched after the read began is not replaced;
  // the caller reads record state again.
  fresherThan(row,p) {
    if (mutated('late-read-replaces-record')) return false;
    return (row.touched??0)>(p.readEpoch??Infinity);
  }
  // S27/S34/S70: a context admitted at the cap only because a grant
  // matched is consumed in the same request. Where the grant then no longer matches
  // inside consumption, the context and its record are removed again, so the request is
  // answered as one with no approved record at the cap.
  releaseExempt(c) {
    if (!c?.capExempt) return;
    this.db.exec('BEGIN IMMEDIATE');
    try {
      this.db.prepare("DELETE FROM pending WHERE context=? AND status='pending'").run(c.capExempt);
      this.db.prepare("DELETE FROM contexts WHERE token=? AND status='open' AND NOT EXISTS (SELECT 1 FROM pending WHERE context=contexts.token)").run(c.capExempt);
      this.db.exec('COMMIT');
    } catch(e) { this.db.exec('ROLLBACK'); throw e; }
  }
  coveredLocked(req,p) {
    const now=this.core.now(), s=this.core.settings(), rk=p.request_key;
    const refuse=(code,details)=>{throw Object.assign(Error(code),{code,details});};
    let ctx=this.contextFor(rk);
    if (ctx && ctx.expires<=now && ctx.status!=='consumed') ctx=null;
    if (ctx?.status==='consumed' && !mutated('covered-replay-executes')) // the replay in Core.handle normally answers first
      throw Object.assign(Error('recorded'),{recorded:this.core.outcomeByRequestKey(rk)??{outcome:'unknown',at:now,change_hash:p.change_hash}});
    if (ctx?.status==='consumed') ctx=null; // covered-replay-executes: a new context, a new write
    const countLive=()=>{
      let n=this.db.prepare("SELECT (SELECT count(*) FROM pending WHERE principal=? AND expires>? AND context IS NULL AND status IN ('pending','denied','cancelled'))+(SELECT count(*) FROM contexts WHERE principal=? AND expires>? AND status IN ('open','denied','cancelled')) n").get(req.principal,now,req.principal,now).n;
      if(mutated('covered-cap-counts-consumed'))n+=this.db.prepare("SELECT count(*) n FROM contexts WHERE principal=? AND expires>? AND status='consumed'").get(req.principal,now).n;
      if(mutated('covered-cap-ignores-approved'))n-=this.db.prepare("SELECT count(*) n FROM contexts WHERE principal=? AND expires>? AND status='open' AND EXISTS (SELECT 1 FROM pending WHERE context=contexts.token AND status='approved')").get(req.principal,now).n;
      return n;
    };
    if(ctx&&mutated('covered-cap-repeats-count-again')&&countLive()>=s.pendingCap)ctx=null;
    let capExempt=false;
    if (!ctx) {
      // S27/S70: the limit is checked only when admitting another context. Replacing
      // a record inside a live context adds nothing to its count (test 113). A context
      // counts from creation until consumption or expiry, whatever its record state
      // (including approved but unconsumed, test 125).
      const count=countLive();
      // S34/S35/S27: grant matching precedes the cap. A request that a
      // grant covers creates no approval request: its context is consumed in the same
      // request and never counts ("A context counts toward the limit from its creation
      // until it is consumed", S70), so the cap does not refuse it.
      capExempt=count>=s.pendingCap&&!mutated('cap-before-grant-match')&&!!this.grants.match(p.change,p.records,req.excludeGrants);
      if (count>=s.pendingCap&&!capExempt) {
        if (mutated('cap-refuses-as-required')) refuse('approval_required');
        const first=this.db.prepare("SELECT min(e) m FROM (SELECT expires e FROM pending WHERE principal=? AND expires>? AND context IS NULL AND status IN ('pending','denied','cancelled') UNION ALL SELECT expires e FROM contexts WHERE principal=? AND expires>? AND status IN ('open','denied','cancelled'))").get(req.principal,now,req.principal,now).m;
        refuse('approval_limit_reached',{open:count,limit:s.pendingCap,retry_after:Math.max(0,(first??now+s.pendingLifetime)-now)});
      }
      ctx={token:crypto.randomBytes(24).toString('hex'),request_key:rk,principal:req.principal,created:now,expires:now+s.pendingLifetime,status:'open'};
      this.db.prepare('INSERT INTO contexts(token,request_key,principal,created,expires,status) VALUES(?,?,?,?,?,?)').run(ctx.token,ctx.request_key,ctx.principal,ctx.created,ctx.expires,ctx.status);
    }
    p.contextToken=ctx.token;
    // S67 (finding 8): an approval that expired unused is closed before the lookup, so
    // the request is answered as one with no approved record, never approval_expired.
    this.closeLapsed(ctx.token);
    // An approved, unconsumed record of the context is matched by its change hash
    // (S68(3)); where the hash differs it is closed as stale and kept.
    let approved=this.db.prepare("SELECT * FROM pending WHERE context=? AND status='approved' AND expires>?").get(ctx.token,now);
    // S85, "Binding": an approval made under a different value of a
    // setting that changes what the write does or who may approve is no approval. It is
    // closed as stale (kept, per S50) and the request is treated as one with no approved
    // record, so the normal approval request follows.
    if (approved && approved.hash===p.change_hash) {
      const claims=JSON.parse(approved.claims);
      if (this.approvalBinds(claims)) return claims;
      this.supersede(approved.id); approved=null;
    }
    if (approved && this.fresherThan(approved,p)) throw Object.assign(Error('read again'),{reread:true});
    if (approved && !mutated('no-supersede-on-state-change')) this.db.prepare("UPDATE pending SET status='stale', hash=hash||'#'||id WHERE id=?").run(approved.id);
    // S68(7): a stale record is never matched again, also when record state returns.
    if (mutated('stale-record-matches')) {
      const stale=this.db.prepare("SELECT * FROM pending WHERE context=? AND status='stale' AND expires>?").get(ctx.token,now);
      if (stale && stale.hash.split('#')[0]===p.change_hash) return JSON.parse(stale.claims);
    }
    // S34: a grant match approves the change and is consumed in the consumption transaction.
    const grant=this.grants.match(p.change,p.records,req.excludeGrants);
    if (grant) {
      const open=this.db.prepare("SELECT * FROM pending WHERE context=? AND status='pending'").get(ctx.token);
      let id=open && open.hash===p.change_hash && JSON.parse(open.json??'{}').grantMatch ? open.id : crypto.randomBytes(24).toString('hex');
      if (!open) this.db.prepare("INSERT INTO pending(id,hash,principal,expires,status,json,claims,context) VALUES(?,?,?,?,'pending',?,?,?)").run(id,p.change_hash,req.principal,Math.max(now+s.pendingLifetime,grant.expires),JSON.stringify({change:p.change,current:p.current,records:p.records??null,grantMatch:true,covered:true}),null,ctx.token);
      return {iss:'server',jti:id,iat:now,exp:Math.min(ctx.expires,now+s.maxLifetime),change_hash:p.change_hash,approver:{type:'grant',id:grant.granted_by},grant:{id:grant.id,shape:grant.shape,max_records:grant.max_records,expires:grant.expires},...(capExempt?{capExempt:ctx.token}:{})};
    }
    // The grant that admitted this context at the cap no longer matches: no approval
    // request can be opened at the cap (S27), and nothing is kept.
    if (capExempt) { this.db.prepare('DELETE FROM contexts WHERE token=?').run(ctx.token); refuse('approval_limit_reached',{open:countLive(),limit:s.pendingCap,retry_after:s.pendingLifetime}); }
    // The context's one open record. A record on which a grant was made is decided
    // (S70): it is closed with that outcome and kept, and a new record is created. The
    // decision closes it in its own transaction (see decision); this covers a record
    // decided before that was so.
    let open=this.db.prepare("SELECT * FROM pending WHERE context=? AND status='pending'").get(ctx.token);
    if (open && this.db.prepare('SELECT 1 FROM page_decisions WHERE record=?').get(open.id)) {
      this.db.prepare("UPDATE pending SET status='granted', hash=hash||'#'||id WHERE id=?").run(open.id); open=null;
    }
    // S68(3): whenever the computed hash differs from the open record's, the open
    // record is closed as superseded and a new one is created in the same context.
    if (open && open.hash!==p.change_hash && this.fresherThan(open,p)) throw Object.assign(Error('read again'),{reread:true});
    if (open && open.hash!==p.change_hash && !mutated('no-supersede-on-state-change')) { this.supersede(open.id); open=null; }
    if (!open) {
      const id=crypto.randomBytes(24).toString('hex');
      const display={change:p.change,current:p.current,records:p.records??null,covered:true};
      this.db.prepare('INSERT INTO pending(id,hash,principal,expires,status,json,claims,context) VALUES(?,?,?,?,?,?,?,?)').run(id,p.change_hash,req.principal,ctx.expires,'pending',JSON.stringify(display),null,ctx.token);
      this.touch(id);
      this.notify(req.account,id,req.principal,ctx.expires);
    }
    refuse('approval_required');
  }
  lookup(req,p) {
    this.db.exec('BEGIN IMMEDIATE');
    try {const claims=this.lookupLocked(req,p);this.db.exec('COMMIT');return claims;}
    catch(e) {
      this.db.exec(['approval_required','approval_denied','approval_cancelled','approval_limit_reached'].includes(e.code)?'COMMIT':'ROLLBACK');throw e;
    }
  }
  // S30/S31 (item 4): the latest moment a denial or a cancellation locks its change is one
  // hour after the decision, or the record's own expiry where that is sooner. The pending
  // lifetime setting never extends it past one hour.
  static LOCKOUT_SECONDS = 3600;
  lockoutEnd(row) { if (mutated('lockout-follows-expiry')) return row.expires; return Math.min(row.expires, row.locked_until ?? row.expires); }
  lockedNow(row) { return ['denied','cancelled'].includes(row.status) && this.lockoutEnd(row) <= this.core.now(); }
  lookupLocked(req,p) {
    let r=this.db.prepare('SELECT * FROM pending WHERE hash=?').get(p.change_hash);
    const retained=r?.status==='consumed'&&JSON.parse(r.claims??'{}').grant;
    if(mutated('grant-double-execution')&&r?.status==='consumed'&&JSON.parse(r.claims??'{}').grant){this.db.prepare('DELETE FROM pending WHERE id=?').run(r.id);r=null;}
    if (r && r.expires<=this.core.now()&&!retained) { this.db.prepare('DELETE FROM pending WHERE id=?').run(r.id); r=null; }
    // Item 4: once an hour has passed since a denial or a cancellation, the lockout is over
    // even when the record (which still counts toward the cap) has not expired. The record
    // gives up the change hash so a new request for the same change can open a record.
    if (r && this.lockedNow(r)) { this.db.prepare("UPDATE pending SET hash=hash||'#'||id WHERE id=? AND instr(hash,'#')=0").run(r.id); r=null; }
    const act=req.inputResponses?.approve?.action, veto=act==='decline' || act==='cancel';
    const refuse=(code,details)=>{ throw Object.assign(Error(code),{code,details}); };
    const until=x=>({retry_after:Math.max(0,this.lockoutEnd(x)-this.core.now())});
    if (mutated('decline-erases-denial') && act==='decline' && r?.status==='denied') {
      this.db.prepare('DELETE FROM pending WHERE id=?').run(r.id);r=null;
    }
    if (r?.status==='denied') refuse('approval_denied',until(r)); // S31: no connection response changes a denial
    const ignoreApprovedDecline=mutated('ignore-decline') && act==='decline' && r?.status==='approved';
    const createOnVeto=mutated('veto-creates-pending') && veto && !r;
    if (veto && !ignoreApprovedDecline && !createOnVeto) { // S30: the connection may veto, never approve; a veto creates no record
      if (r && ['pending','approved'].includes(r.status)) {
        this.db.prepare("UPDATE pending SET status='cancelled', locked_until=? WHERE id=?").run(Math.min(r.expires,this.core.now()+ServerIssued.LOCKOUT_SECONDS),r.id);
        this.core.audit('decision',{principal:req.principal,operation:req.operation},{change_hash:p.change_hash,issuer:'server',receipt_id:r.id},'cancelled');
      }
      refuse('approval_cancelled',r ? until(r) : {retry_after:0});
    }
    if (mutated('cancel-not-sticky') && r?.status==='cancelled') {
      this.db.prepare('DELETE FROM pending WHERE id=?').run(r.id);r=null;
    }
    if (r?.status==='cancelled') refuse('approval_cancelled',until(r)); // stays cancelled until the record expires
    // S80/S69(1): a change whose approval was consumed never opens an approval record and
    // never matches a grant again; the repeat is answered with the recorded outcome.
    if (!mutated('replay-bare-approval-used') && !mutated('grant-double-execution')) {
      const prior=this.core.outcomeByHash(p.change_hash);
      if (prior) throw Object.assign(Error('recorded'),{recorded:prior});
    }
    // S85, "Binding": a person's approval made under a different
    // value of a setting that changes what the write does or who may approve is no
    // approval. The record is closed as stale (kept, S50) and the request is treated as
    // one with no approved record; if a grant matches it still runs under the grant.
    if (r?.status==='approved' && !this.approvalBinds(JSON.parse(r.claims??'{}'))) {
      this.supersede(r.id); r=null;
    }
    if (r?.status==='approved'||r?.status==='consumed') return JSON.parse(r.claims);
    if(mutated('grant-from-connection')&&(req.args?.grant||req.inputResponses?.approve?.content?.grant)) {
      const change=structuredClone(p.change);delete change.arguments.grant;const who={id:'test-person',authenticated:true};
      if(this.grants.offer(change,who))this.grants.create(change,who,2,this.core.now()+100,this.core.now());
    }
    const grant=this.grants.match(p.change,p.records,req.excludeGrants);
    if(grant) {
      // S35/S50: the person's record for this change is closed as superseded in the same
      // atomic step as the consumption (grants.charge), never here: if the charge fails
      // and the unit rolls back, the person's record is still pending. A record an
      // earlier grant request for the same change opened is reused, so simultaneous
      // requests still share one consumption.
      if (mutated('supersede-at-lookup') && r?.status==='pending' && !JSON.parse(r.json??'{}').grantMatch) {
        mutated('supersede-deletes-record') ? this.db.prepare('DELETE FROM pending WHERE id=?').run(r.id) : this.supersede(r.id);
        r=null;
      }
      let id=null;
      if (r?.status==='pending' && JSON.parse(r.json??'{}').grantMatch) id=r.id;
      if (!id) {
        id=crypto.randomBytes(24).toString('hex');
        if (!r) {
          const open=this.db.prepare("SELECT count(*) n FROM pending WHERE principal=? AND expires>? AND status IN ('pending','denied','cancelled')").get(req.principal,this.core.now()).n;
          if(open<this.core.settings().pendingCap)this.db.prepare("INSERT INTO pending(id,hash,principal,expires,status,json,claims) VALUES(?,?,?,?,'pending',?,NULL)").run(id,p.change_hash,req.principal,this.core.now()+this.core.settings().pendingLifetime,JSON.stringify({change:p.change,current:p.current,records:p.records??null,grantMatch:true}));
        }
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
        this.db.prepare("INSERT INTO pending(id,hash,principal,expires,status,json,claims) VALUES(?,?,?,?,'pending',?,NULL)").run(id,p.change_hash,req.principal,this.core.now()+this.core.settings().pendingLifetime,JSON.stringify(display));
        this.notify(req.account,id,req.principal,this.core.now()+this.core.settings().pendingLifetime);
      } else if (!mutated('cap-refuses-as-required')) { // S27: at the cap say so, never "approval required"
        const first=this.db.prepare(`SELECT min(expires) e FROM pending WHERE principal=? AND expires>? AND ${statuses}`).get(req.principal,this.core.now()).e;
        refuse('approval_limit_reached',{open:count,limit:this.core.settings().pendingCap,retry_after:Math.max(0,first-this.core.now())});
      }
    }
    const code=createOnVeto ? 'approval_cancelled' : 'approval_required';
    throw Object.assign(Error(code),{code});
  }
  url(change_hash) { const r=this.db.prepare("SELECT id FROM pending WHERE hash=? AND expires>? AND status IN ('pending','approved')").get(change_hash,this.core.now()); return r ? `${this.baseURL}/approve/${r.id}` : undefined; }
  // S90: the expiry the `approval_required` refusal reports. For a covered operation it is
  // the context's expiry (S68(2)); otherwise it is the pending record's own expiry.
  pendingExpiry(change_hash) { return this.db.prepare("SELECT expires FROM pending WHERE hash=? AND expires>? AND status IN ('pending','approved','denied','cancelled')").get(change_hash,this.core.now())?.expires; }
  contextExpiry(token) { return this.contextOf(token)?.expires; }
  // S27/S81: one logged notification per new pending record, to the approvers the account
  // names, on a channel the agent's credential cannot read, when the pending limit is longer
  // than one hour. A repeat of the same request does not notify again.
  notify(account, record, principal, expires) {
    if (mutated('notification-omitted')) return;
    const s=this.core.settings();
    if (!s.approverNotification || (s.pendingLifetime ?? 0) <= 3600) return;
    const named=[...(s.approvers?.[account] ?? []), ...(s.pageAdministrators?.[account] ?? [])];
    const people=[...new Set(named)];
    for (const person of (people.length ? people : ['account administrator'])) {
      this.db.prepare('INSERT OR IGNORE INTO notifications(record,person,account,at,message) VALUES(?,?,?,?,?)')
        .run(record,person,account,this.core.now(),`An approval request from ${principal} in ${account} is open until ${expires}.`);
    }
  }
  // S84 with S67: lowering the pending lifetime takes effect for existing records and for
  // existing contexts, not just for new ones. A covered context expires no later than its
  // creation plus the lifetime now in force, so a person cannot approve into a context the
  // new limit has already closed. A record that is not in a context expires at the new
  // limit measured from now; its lockout cannot outlive it. Neither the refusal's
  // `pending_expires` (the context's expiry, S90) nor a page reads a later time.
  tightenLifetime(seconds) {
    if (mutated('tightening-waits-for-new-records')) return;
    const now=this.core.now();
    // A context expires no later than its creation plus the lifetime now in force.
    if (!mutated('covered-context-outlives-tightening'))
      this.db.prepare("UPDATE contexts SET expires=MIN(expires,created+?) WHERE status IN ('open','denied','cancelled') AND expires>created+?").run(seconds,seconds);
    // A record that is not in a context expires at the new limit measured from now; a
    // record in a context never outlives that context (S67: "No pending or approved record
    // outlives its context").
    this.db.prepare("UPDATE pending SET expires=MIN(expires,?) WHERE context IS NULL AND status IN ('pending','approved','denied','cancelled') AND expires>?").run(now+seconds,now);
    this.db.prepare("UPDATE pending SET expires=(SELECT MIN(contexts.expires,pending.expires) FROM contexts WHERE contexts.token=pending.context) WHERE context IS NOT NULL AND status IN ('pending','approved','denied','cancelled') AND EXISTS (SELECT 1 FROM contexts WHERE contexts.token=pending.context)").run();
    this.db.prepare("UPDATE pending SET locked_until=MIN(locked_until,expires) WHERE locked_until IS NOT NULL AND locked_until>expires").run();
  }
  // S50/S68(6): close a record as superseded, keeping it and its page; its hash is
  // moved aside so the change hash can belong to the consuming record.
  supersede(id) { this.db.prepare("UPDATE pending SET status='superseded', hash=hash||'#'||id WHERE id=?").run(id); }
  // S22 with S76: whether this signed-in person may decide the request.
  // S22 is unchanged in every model: the person must hold, in the account, the permission
  // to make the change (a grant applies the same rule at S46). The approver model only
  // decides which people are consulted at all:
  //   named           the people the account names as approvers, and its administrators;
  //                   where the account names none, the model decides, as before.
  //   administrators  only the account's administrators.
  //   permission      the documented permission model (S76) alone.
  // Every branch still asks Core.mayApprove, which applies S22.
  approverAllowed(person, r, purpose) {
    return this.core.mayApprove(person, { account:r.display.change.account, operation:r.display.change.operation, change:r.display.change, records:r.display.records }, purpose);
  }
  decision(id,person,kind,terms,session,act) {
    this.db.exec('BEGIN IMMEDIATE');
    try {
      const r=this.get(id);if(!r||r.expires<=this.core.now()||['consumed','superseded'].includes(r.status))throw Error('expired or consumed');
      // S22: "The approving person MUST hold, in the account, the permission to make the
      // change themselves." The same decision is made for a grant (S33, S46).
      if(!person?.authenticated||!this.approverAllowed(person,r,kind==='grant'?'grant':'approve'))throw Error('permission_denied');
      // S78: a record whose identifier resolves to another record offers no approval and
      // no grant; the page says so and a decision posted to it records nothing.
      if(!mutated('page-offers-approval-on-merge')&&this.resolutionsOf(r.display.change).length)throw Error('record resolved');
      const shown=this.db.prepare('SELECT at FROM page_displays WHERE record=? AND session=? AND person=?').get(id,session,person.id);
      if(!shown&&!mutated('page-decision-without-display'))throw Error('change must be displayed to this session');
      const fingerprint=hash({person:person.id,kind,terms}),prior=this.db.prepare('SELECT * FROM page_decisions WHERE record=?').get(id);
      if(prior) {
        if(prior.fingerprint!==fingerprint)throw Object.assign(Error('first decision is final'),{standing:this.outcome(id)});
        if(!mutated('decision-replay-creates-second')) {this.db.exec('COMMIT');return JSON.parse(prior.result);}
      }else if(r.status!=='pending')throw Error('expired or decided');
      const result=act(r,shown?.at??this.core.now());
      this.db.prepare('INSERT OR IGNORE INTO page_decisions VALUES(?,?,?)').run(id,fingerprint,JSON.stringify(result));
      // S50: "Recording a decision or a grant is one atomic step in the same domain as
      // S13". S70: "A record on which a grant was made is decided (S50): it is closed with
      // that outcome and kept, and it is not open." S50, S70: this holds in
      // the default mode as well as for a covered operation, so the record is closed here,
      // in the transaction that records the grant, and never lazily on the next request.
      // Its hash is moved aside so the change hash can belong to the record that consumes
      // the grant. Off: grant-decision-leaves-record-open.
      if(kind==='grant'&&!prior&&!mutated('grant-decision-leaves-record-open'))this.db.prepare("UPDATE pending SET status='granted', hash=hash||'#'||id WHERE id=? AND status='pending'").run(id);
      this.touch(id);
      this.db.exec('COMMIT');return result;
    }catch(e){this.db.exec('ROLLBACK');throw e;}
  }
  // S67: "The audit record carries it." The request key of the context a record is in.
  requestKeyOf(r) { const key=r?.context?this.contextOf(r.context)?.request_key:undefined; return key!==undefined&&!mutated('audit-omits-request-key')?{request_key:key}:{}; }
  // S78: the named records that now resolve to a record with another identifier.
  // For a covered copy (finding 1) these are its target, which it names, and its
  // source, which it only refers to: where either resolves to another record the write
  // is not sent (S78), so the page says so and offers no approval.
  resolutionsOf(change) {
    const a=change.arguments,copy=mutated('copy-follows-merged-source')?null:copySource(change);
    const named=a.records??(a.id?[{id:a.id}]:copy?[{id:copy.target},{id:copy.record}]:[]);
    return named.filter(e=>typeof e?.id==='string').map(e=>{const found=resolveIdentifier(this.core.sor,change.account,e.id);return found.redirected?{id:e.id,to:found.resolved}:null;}).filter(Boolean);
  }
  decide(id,person,approve,session=person?.id) {
    return this.decision(id,person,approve?'approve':'deny',{},session,(r,displayed_at)=>{
      // S85, "Binding": the approval stores the value of every
      // setting that changes what the write does or who may approve (`effect_hash`). If
      // that changes before consumption the approval no longer matches and the normal
      // approval request follows (see approvalBinds). It is never part of the change hash,
      // so the agent's change object and change hash are unaffected.
      const c={iss:'server',jti:r.id,iat:this.core.now(),exp:r.context&&mutated('covered-approval-outlives-context')?this.core.now()+this.core.settings().maxLifetime:Math.min(r.expires,this.core.now()+this.core.settings().maxLifetime),change_hash:r.hash,approver:{type:'person',id:person.id},effect_hash:this.core.effectHash(),
        // S84: the skew in force when the approval was made. A later, larger skew never
        // revives an approval that had already expired under the smaller one (item 3).
        skew_at:this.core.settings().skew};
      this.db.prepare('UPDATE pending SET status=?,claims=?,locked_until=? WHERE id=?').run(approve?'approved':'denied',JSON.stringify(c),approve?null:Math.min(r.expires,this.core.now()+ServerIssued.LOCKOUT_SECONDS),id);
      // S68(5): a denial marks the whole context; identical requests are answered from
      // it until the lockout ends, whether or not record state changes. S30/S31 with S70
      // (item 12): the lockout is one hour from the decision, or the context's expiry where
      // that is sooner, whatever the pending lifetime is.
      if (!approve && r.context) this.db.prepare("UPDATE contexts SET status='denied', locked_until=? WHERE token=?").run(Math.min(r.expires,this.core.now()+ServerIssued.LOCKOUT_SECONDS),r.context);
      this.core.audit('decision',{principal:person.id,operation:r.display.change.operation},{change_hash:r.hash,...this.requestKeyOf(r),issuer:'server',receipt_id:r.id,displayed_at,decided_at:this.core.now()},approve?'approved':'denied');
      return {approved:!!approve,usable_until:c.exp};
    });
  }
  grantFallback(req,p,c) {return this.core.handle({...req,excludeGrants:[...(req.excludeGrants??[]),c.grant.id]});}
  recordGrant(id,person,max_records,terms,expiry,session,shape) {
    return this.decision(id,person,'grant',{max_records,...terms,shape},session,(r,displayed_at)=>{const offered=JSON.parse(this.db.prepare('SELECT shapes FROM page_offers WHERE record=? AND session=?').get(id,session)?.shapes??'[]');if(!offered.includes(shape))throw Error('shape not offered on this page');return {...this.grants.create(r.display.change,person,max_records,expiry(),displayed_at,shape,r.display.records,this.requestKeyOf(r)),change_hash:r.hash};});
  }
  createGrant(id,person,max_records,expires,session=person?.id,shape='any_record') {return this.recordGrant(id,person,max_records,{expires},()=>expires,session,shape);}
  createGrantMinutes(id,person,max_records,minutes,session,shape) {
    const seconds=Math.round(minutes*60);if(!Number.isFinite(minutes)||minutes<=0||!Number.isSafeInteger(seconds)||seconds<1)throw Error('invalid duration');
    return this.recordGrant(id,person,max_records,{seconds},()=>this.core.now()+seconds,session,shape);
  }
  // S13, S35: "A consumed record may be discarded after the period S13
  // requires ... Should a longer minimum apply to operations a grant can approve?" The
  // panel decided yes: a consumed record a grant could approve again is kept for at least
  // the longer of the S13/S35 period (maxLifetime + skew) and the pending lifetime, so an
  // identical retry never matches the grant and writes again while the grant could still
  // apply. The registry's `retention_floor_seconds` can only raise it. A consumed record
  // keeps whatever expiry S35 already gave it, or this floor, whichever is later; the floor
  // is applied to the stored row at consumption (Core.consume), so `expires` alone decides
  // when cleanup may discard it.
  retentionSeconds() {
    const s = this.core.settings();
    return Math.max(Number.isSafeInteger(s.retentionFloor) ? s.retentionFloor : 0, (s.maxLifetime ?? 0) + (s.skew ?? 0), s.pendingLifetime ?? 0);
  }
  cleanup() {
    // A consumed record is kept at least until its stored expiry, which consumption set to
    // the retention floor (S13, S35). A grant-consumed record is kept until its grant
    // expires, as S35 requires, and a consumed context's record until its context ends.
    for(const row of this.db.prepare('SELECT id,status,expires,claims,json FROM pending WHERE expires<=?').all(this.core.now())) {
      if(!JSON.parse(row.claims??'{}').grant) this.db.prepare('DELETE FROM pending WHERE id=?').run(row.id);
    }
  }
  // S50: what was decided for a record, and what state that decision is in now.
  // A grant-decided link says whether the shown change has run under the grant, and an
  // approval says when it was used. Use moments come from the consumption audit row
  // (person approvals, keyed by receipt id) and the retained consumed pending row (the
  // shown change's hash and the grant id), so they survive record cleanup.
  outcome(id) {
    // S67: a covered link is the context token; its standing outcome is the context's.
    if (!this.get(id)) { const o=this.contextOutcome(id); if (o) return o; }
    const prior=this.db.prepare('SELECT result FROM page_decisions WHERE record=?').get(id);
    if (prior) {try {const g=JSON.parse(prior.result);if (g && typeof g==='object' && g.id && g.made_at!==undefined){const usedAt=this.grantUsedAt(g);return {kind:'grant',at:g.made_at,...(usedAt===undefined?{}:{usedAt})};}}catch {}}
    const r=this.get(id);
    if (!r) return undefined;
    // S68(6)/S70: a record closed at consumption says that the change already ran
    // under another approval; it is never matched or decided again.
    if (r.status==='superseded') return {kind:'superseded'};
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
    const r=this.get(id);
    // S67: the approval link of a covered operation is the context token.
    if (!r) return this.contextPage(id,person,session);
    if(r.expires<=this.core.now())throw Error('expired');
    if(r.status!=='pending')throw Error('expired or decided'); // S50: only a pending record is shown as open
    return this.renderRecord(r,person,session);
  }
  renderRecord(r,person,session) {
    // S53: "Before rendering a change, the server MUST check that the signed-in person
    // belongs to the account and may read the records and fields shown." The decision is
    // made from the stored change and the permission model, never from current values.
    if(!person?.authenticated||(!mutated('page-view-without-permission')&&!authorize(this.core.sor,person,{change:r.display.change,records:r.display.records},'view').allowed))throw Error('permission_denied');
    this.db.prepare('INSERT OR REPLACE INTO page_displays VALUES(?,?,?,?)').run(r.id,session,person.id,this.core.now());
    this.touch(r.id); // rendered for a decision (S67, S68(3))
    // S78: where the identifier a request names resolves to another record, the page
    // offers no approval or grant. It says which record the identifier now refers to, and
    // that it refers to another record at all, only to a person permitted to read that
    // other record too (S53); any other person is told only that the
    // change can no longer be decided here.
    const resolutions=this.resolutionsOf(r.display.change);
    if(resolutions.length&&!mutated('page-offers-approval-on-merge')) {
      const visible=new Set(resolutions.filter(x=>mutated('page-resolution-shown-to-all')||authorize(this.core.sor,person,{change:r.display.change,records:[x.to]},'view').allowed).map(x=>x.id));
      return {...r.display,resolution:resolutions.map(x=>({id:x.id,...(visible.has(x.id)?{to:x.to}:{}),shown:visible.has(x.id)}))};
    }
    // S64: the page tells the approver that a record the change names is missing, or that
    // a record a create names already exists.
    const a=r.display.change.arguments,create=actionFor(r.display.change.operation,a)==='create',notices={};
    // S70/S64 (finding 1): a covered copy names its target; the page says whether it
    // exists, and whether the source the value is copied from exists.
    const copy=copySource(r.display.change);
    const copyNote=copy?{source:copy.record,target:copy.target,sourceMissing:!resolveIdentifier(this.core.sor,r.display.change.account,copy.record).exists}:undefined;
    for(const e of a.records??(a.id?[{id:a.id}]:copy?[{id:copy.target}]:[])) {
      if(typeof e?.id!=='string')continue;
      const old=resolveIdentifier(this.core.sor,r.display.change.account,e.id).exists;
      // S64: a create whose identifier is free is missing nothing and exists nowhere; a
      // create whose record exists is told so, and an update whose record is gone is told
      // it is missing.
      if(mutated('page-create-notice-inverted')){if(!old)notices[e.id]=create?'exists':'missing';else if(create)notices[e.id]='exists';}
      else if(create){if(old)notices[e.id]='exists';}
      else if(!old)notices[e.id]='missing';
    }
    const grantOffer=this.grants.offer(r.display.change,person,r.display.records);
    this.db.prepare('INSERT OR REPLACE INTO page_offers VALUES(?,?,?)').run(r.id,session,JSON.stringify(grantOffer?.shapes??[]));
    return {...r.display,notices,grantOffer,...(copyNote?{copy:copyNote}:{})};
  }
  // The grant made from a record of this context, if any (S70: the earlier grant is
  // history the page shows). Its outcome comes from the record's stored decision, so it
  // says whether the shown change has since run under it (S50).
  grantOutcomeOf(token) {
    for (const row of this.db.prepare('SELECT id FROM pending WHERE context=?').all(token)) {
      const prior=this.db.prepare('SELECT result FROM page_decisions WHERE record=?').get(row.id);
      if (!prior) continue;
      try { const g=JSON.parse(prior.result); if (g && typeof g==='object' && g.id && g.made_at!==undefined) return this.outcome(row.id); } catch {}
    }
    return undefined;
  }
  // What a context's page shows when the context has no open record (S50, S70).
  contextOutcome(token) {
    const ctx=this.contextOf(token);
    if (!ctx) return undefined;
    // A grant-decided record keeps its S50 outcome page also after the change ran
    // under the grant; "already ran under another approval" is for the rest.
    if (ctx.status==='consumed') return this.grantOutcomeOf(token) ?? {kind:'superseded'};
    if (ctx.status==='denied') {
      let at; try { at=JSON.parse(this.db.prepare("SELECT claims FROM pending WHERE context=? AND status='denied' ORDER BY rowid DESC LIMIT 1").get(token)?.claims??'{}').iat; } catch {}
      return {kind:'deny',at};
    }
    if (ctx.status==='cancelled') return {kind:'cancelled'};
    // An open context can still hold the decision the page recorded: an approved
    // record, or a grant-decided one (S50's repeated-decision rule applies first, S68(4)).
    const approved=this.db.prepare("SELECT claims FROM pending WHERE context=? AND status='approved' ORDER BY rowid DESC LIMIT 1").get(token);
    if (approved) {
      try {
        const c=JSON.parse(approved.claims);
        // S67/S50 (finding 8): an approval that expired unused is not shown as usable.
        if (this.lapsed(c) && !mutated('covered-expired-approval-refused')) return {kind:'lapsed',at:c.iat,until:c.exp};
        return {kind:'approve',at:c.iat,until:c.exp,used:false};
      } catch {}
    }
    // S67: the context's latest record is an approval closed as expired unused, and no
    // later request has created the next pending record yet.
    const latest=this.db.prepare('SELECT status,claims FROM pending WHERE context=? ORDER BY rowid DESC LIMIT 1').get(token);
    if (latest?.status==='expired') { try { const c=JSON.parse(latest.claims); return {kind:'lapsed',at:c.iat,until:c.exp}; } catch {} }
    return this.grantOutcomeOf(token);
  }
  // S67/S68(3): whenever the approval page of a covered operation renders, the server
  // first reads record state and applies supersession and staleness, then renders the
  // resulting stored record (S42).
  contextPage(token,person,session=person?.id) {
    this.db.exec('BEGIN IMMEDIATE');
    try { const d=this.contextPageLocked(token,person,session); this.db.exec('COMMIT'); return d; }
    catch(e) { this.db.exec('ROLLBACK'); throw e; }
  }
  contextPageLocked(token,person,session) {
    const now=this.core.now();
    const ctx=this.contextOf(token);
    this.expireContext(ctx);
    if (!ctx || ctx.expires<=now) throw Error('expired');
    const base=this.db.prepare('SELECT * FROM pending WHERE context=? ORDER BY rowid DESC LIMIT 1').get(token);
    if (!base) throw Error('expired');
    const baseDisplay=JSON.parse(base.json);
    const permitted=!!person?.authenticated&&authorize(this.core.sor,person,{change:baseDisplay.change,records:baseDisplay.records},'view').allowed;
    // S53/S70/S58: the person's permission is checked before anything the record state
    // decides. A person not permitted to see the request gets the unknown-link wording
    // whether the approval still matches the record or the record has changed since.
    if (!permitted && !mutated('context-page-without-permission')) throw Error('expired');
    if (ctx.status!=='open') {
      // S70/S58: a valid token whose context has no open record gets the unknown-link
      // wording for a person not permitted to see the request.
      if (!permitted) throw Error('expired');
      const o=this.contextOutcome(token);
      if (!o) throw Error('expired');
      return {contextOutcome:o};
    }
    // S70/S50: the context's open record was decided by a grant. It is closed with that
    // outcome and kept; until a later request creates the context's next record, the
    // page shows the recorded outcome, not a decision form and not a new record.
    const decidedOpen=this.db.prepare("SELECT * FROM pending WHERE context=? AND status='pending'").get(token);
    if (decidedOpen && this.db.prepare('SELECT 1 FROM page_decisions WHERE record=?').get(decidedOpen.id)) {
      this.db.prepare("UPDATE pending SET status='granted', hash=hash||'#'||id WHERE id=?").run(decidedOpen.id);
      return {contextOutcome:this.outcome(decidedOpen.id)};
    }
    const change0=baseDisplay.change;
    // The request is rebuilt from its own arguments (S67: "before any value derived from
    // record state is copied in"); a value copied in earlier is read again, and one with
    // no RFC 8785 form is not mistaken for the request's input (S67).
    const p=this.core.prepare({account:change0.account,principal:change0.principal,operation:change0.operation,args:mutated('page-rebuilds-from-copied-value')?change0.arguments:requestArguments(change0)});
    // S67 (finding 8): an approval that expired unused is closed, and is not shown as usable.
    this.closeLapsed(token);
    const approved=this.db.prepare("SELECT * FROM pending WHERE context=? AND status='approved' AND expires>?").get(token,now);
    if (approved && approved.hash===p.change_hash) {
      const c=JSON.parse(approved.claims);
      // S85, "Binding": an approval made under a different effect
      // configuration is not shown as usable. It is closed as stale below and the page
      // shows the current request for a decision.
      if (this.approvalBinds(c)) return {contextOutcome:{kind:'approve',at:c.iat,until:c.exp,used:false}};
    }
    // Whether this render replaced a record under S68(3).
    let replaced=false;
    if (approved) { this.db.prepare("UPDATE pending SET status='stale', hash=hash||'#'||id WHERE id=?").run(approved.id); replaced=true; }
    let open=this.db.prepare("SELECT * FROM pending WHERE context=? AND status='pending'").get(token);
    // The read above was made inside this atomic step, so no record it would replace can
    // have been created, rendered or decided after it began (S67).
    if (open && this.db.prepare('SELECT 1 FROM page_decisions WHERE record=?').get(open.id)) {
      this.db.prepare("UPDATE pending SET status='granted', hash=hash||'#'||id WHERE id=?").run(open.id); open=null;
    }
    if (open && open.hash!==p.change_hash && !mutated('no-supersede-on-state-change')) { this.supersede(open.id); open=null; replaced=true; }
    // S67/S70 (findings 8 and 9): the page opens a record only to replace one under
    // S68(3). After an approval expired unused "a new pending record is created in the
    // context on the next request", and after a grant "where a later request is not
    // matched by the grant"; until that request comes the page shows the recorded
    // outcome, offers no decision and opens nothing. A person not permitted to see the
    // request gets the unknown-link wording (S58, S70).
    if (!open && !replaced && !mutated('context-page-opens-record')) {
      const o=permitted?this.contextOutcome(token):undefined;
      if (!o) throw Error('expired');
      return {contextOutcome:o};
    }
    if (!open) {
      const id=crypto.randomBytes(24).toString('hex');
      this.db.prepare('INSERT INTO pending(id,hash,principal,expires,status,json,claims,context) VALUES(?,?,?,?,?,?,?,?)').run(id,p.change_hash,change0.principal,ctx.expires,'pending',JSON.stringify({change:p.change,current:p.current,records:p.records??null,covered:true}),null,token);
      this.notify(p.change.account,id,p.change.principal,ctx.expires);
      open=this.db.prepare('SELECT * FROM pending WHERE id=?').get(id);
    }
    const r={...open,display:JSON.parse(open.json)};
    const d=this.renderRecord(r,person,session);
    // S70: the page tells the approver that an earlier approval was not used because it
    // no longer matched, and shows the current request for a decision.
    const staleNotice=!!this.db.prepare("SELECT 1 FROM pending WHERE context=? AND status='stale'").get(token);
    // S70: the page shows the new pending record for a decision and the earlier grant
    // as history.
    const grantHistory=this.grantOutcomeOf(token);
    // S69(4): the page tells the approver when a request of the same principal in the
    // same account that differs only in the distinguishing argument was denied,
    // cancelled or consumed and the server still holds that record.
    const siblings=this.earlierRequests(r.display.change);
    return {...d,recordId:open.id,contextToken:token,covered:true,staleNotice,grantHistory,siblings};
  }
  earlierRequests(change) {
    if (mutated('covered-earlier-requests-hidden')) return [];
    // S69(4): "a request from the same principal in the same account that differs only in
    // this argument". The comparison is on the request's own arguments (S67: "before any
    // value derived from record state is copied in"), so a copy whose source changed in
    // between is still the same request apart from its change tag, and a copied value
    // that has no RFC 8785 form cannot fail the page (S67).
    const strip=c=>{const a=mutated('sibling-compares-copied-value')?structuredClone(c.arguments):requestArguments(c);delete a.change_tag;return jcsTotal(a);};
    const mine=strip(change),out=[];
    for (const row of this.db.prepare("SELECT id,context,json,claims,status FROM pending WHERE status IN ('denied','cancelled','consumed')").all()) {
      try {
        const c=JSON.parse(row.json).change;
        if (!c || c.account!==change.account || c.principal!==change.principal || c.operation!==change.operation) continue;
        if (strip(c)!==mine) continue;
        let at; try { at=JSON.parse(row.claims??'{}').iat; } catch {}
        const item={status:row.status,at};
        // S69(3) (cold read, finding 11): "the approval page for a request that differs
        // only in the distinguishing argument MUST say that an earlier write's outcome
        // is not known." A consumed record is reported with the outcome recorded for
        // it, and as not known where none is recorded and the server cannot tell that
        // the execution is still running (S69(5)); it is never presented as a write
        // that ran unless a success is recorded.
        if (row.status==='consumed' && !mutated('covered-sibling-outcome-ignored')) {
          const recorded=this.core.outcomeByJti('server',row.id);
          const key=row.context?this.contextOf(row.context)?.request_key:undefined;
          // The outcome is recorded as unknown from the moment of consumption; while this
          // instance knows the execution is running, the page says so (S69(5)).
          item.outcome=key!==undefined&&this.core.inFlight.has('rk:'+key)?'in_progress':recorded?.outcome ?? 'unknown';
          if (recorded?.at!==undefined) item.at=recorded.at;
        }
        out.push(item);
      } catch {}
    }
    return out;
  }
  // S68(4)/S50/S70 (cold read, finding 9): the decision that stands against a decision
  // posted to a context's page is the one recorded for the record the form names, not
  // one recorded for an earlier record of the context. A grant made from an earlier
  // record is history (S70) and does not stop a decision on the context's new pending
  // record. A context that is denied, cancelled or consumed answers as a whole.
  decidedRecord(token,recordId) {
    const named=recordId?this.db.prepare('SELECT * FROM pending WHERE id=? AND context=?').get(recordId,token):undefined;
    if (!named || !this.db.prepare('SELECT 1 FROM page_decisions WHERE record=?').get(named.id)) return undefined;
    if (named.status==='pending' || named.status==='granted') return named; // a grant was made on it
    if (named.status!=='approved') return undefined; // stale, expired or superseded: the request changed (S70)
    let claims; try { claims=JSON.parse(named.claims); } catch { return undefined; }
    return claims && !(this.lapsed(claims) && !mutated('covered-expired-approval-refused')) ? named : undefined;
  }
  standingFor(token,recordId) {
    const ctx=this.contextOf(token);
    if (!ctx) return undefined;
    if (ctx.status!=='open' || mutated('context-standing-from-earlier-grant')) return this.contextOutcome(token);
    const named=this.decidedRecord(token,recordId);
    return named ? this.outcome(named.id) : undefined;
  }
  // S68(4): a decision posted from an approval page names the record the page
  // displayed. If the named record is no longer the context's open record the decision
  // is refused, nothing is recorded, and the current request is shown.
  decideNamed(token,recordId,person,act) {
    const ctx=this.contextOf(token);
    if (!ctx) throw Error('expired');
    if (ctx.status==='consumed') throw Error('expired or consumed');
    if (['denied','cancelled'].includes(ctx.status)) throw Error('expired or decided');
    // S68(4) (finding 9): "S50's rule for a repeated decision applies first." A record
    // of this context that carries a recorded decision takes the posted decision under
    // S50 (the same decision returns the first result, another one is refused), also
    // where the context has since been given a new pending record.
    if (!mutated('context-standing-from-earlier-grant') && this.decidedRecord(token,recordId)) return act(recordId);
    const open=this.db.prepare("SELECT id FROM pending WHERE context=? AND status='pending'").get(token);
    const latest=open?undefined:this.db.prepare("SELECT id,status,claims FROM pending WHERE context=? AND status IN ('approved','granted') ORDER BY rowid DESC LIMIT 1").get(token);
    // S67 (finding 8): an approval that expired unused takes no decision; the page
    // shows what the context holds now.
    const lapsedLatest=latest?.status==='approved' && !mutated('covered-expired-approval-refused') && (()=>{ try { return this.lapsed(JSON.parse(latest.claims)); } catch { return false; } })();
    if (lapsedLatest) throw Error('request changed');
    const current=open?.id ?? latest?.id;
    if (!current || current!==recordId) throw Error('request changed');
    return act(recordId);
  }
}
