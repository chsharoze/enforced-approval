import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { OP, QUERY, CREATE, COPY, changeObject } from '../src/core.mjs';
const vectors=JSON.parse(readFileSync(new URL('../spec/vectors/vectors.json',import.meta.url)));
// Covered-mode tests added after the cold read of 2026-11-23 (its findings 1 to 3 and
// 8 to 12). Every test runs in the covered mode (the preconditions setting, as
// VA_PRECONDITIONS=1 sets it for the runnable servers). Each names the requirement it
// checks and the Off hook (VA_MUTATE) that it kills.
export function cases({helpers:{setup,req,ask,browser},args,call,A,P,admin,sdk}) {
  const cov=(settings={})=>setup({preconditions:true,stateKey:vectors.state_manifest_hmac_key,...settings});
  // A principal that may write but not read: a non-reader (S60).
  const nonReader=(f,operation=OP)=>f.sor.permission(A,P,operation,false,true);
  const pending=(f,where="status='pending'")=>f.core.db.prepare(`SELECT count(*) n FROM pending WHERE ${where}`).get().n;
  const contextRows=(f,key)=>f.core.db.prepare('SELECT * FROM contexts WHERE request_key=? ORDER BY rowid').all(key);
  const openOf=(f,token)=>f.core.db.prepare("SELECT * FROM pending WHERE context=? AND status='pending'").all(token);
  const used=f=>f.core.db.prepare('SELECT count(*) n FROM used').get().n;
  const decisions=f=>f.core.db.prepare('SELECT count(*) n FROM page_decisions').get().n;
  const tokenOf=r=>r.approval.approval_url.split('/').at(-1);
  const keyOf=(f,r)=>f.core.requestKey(changeObject({...r,audience:f.core.settings().audience}));
  const withoutLink=({approval_url,...rest})=>rest;
  const withoutClock=({retry_after,message,...rest})=>rest;
  const tests=[
    // 159 (H1). A copy through a merged source (S78, S60(a), S63, S67). Finding 1.
    // Off: copy-follows-merged-source, copy-writes-through-merged-source.
    async function copyThroughMergedSource() {
      const build=merged=>{
        const f=cov();
        f.sor.seed(A,'rec-EXAMPLE-h1-other',{owner:'secret-owner-h1'});
        f.sor.recordPermission(A,P,'rec-EXAMPLE-h1-other',false,true); // the principal may not read this record
        f.sor.seed(A,'rec-EXAMPLE-h1-target',{owner:'target-owner-h1'});
        if(merged){f.sor.seed(A,'rec-EXAMPLE-h1-source',{owner:'source-owner-h1'});f.sor.merge(A,'rec-EXAMPLE-h1-source','rec-EXAMPLE-h1-other');}
        return f;
      };
      const copy=f=>f.req({objectType:'contact',source:'rec-EXAMPLE-h1-source',target:'rec-EXAMPLE-h1-target'},{operation:COPY});
      const f=build(true),g=build(false);
      const merged=call(f,copy(f)),missing=call(g,copy(g));
      assert.equal(merged.approval.error,'approval_required');assert.equal(missing.approval.error,'approval_required');
      assert(!JSON.stringify(merged).includes('secret-owner-h1'),'the value of the record the source resolves to is not returned');
      // S78: before consumption a source that resolves to another record is answered
      // as a source that names no record.
      assert.deepEqual(withoutLink(merged.approval),withoutLink(missing.approval),'a merged source is answered as a missing one');
      assert(!f.core.db.prepare('SELECT json FROM pending').all().some(x=>x.json.includes('secret-owner-h1')),'the stored record does not hold the other record\'s value');
      assert(!JSON.stringify(f.core.prepare(copy(f)).change).includes('secret-owner-h1'));
      // The page says that the source resolves to another record and offers no approval.
      const token=tokenOf(merged),b=browser(f);await b.login();
      await b.show(ask(f,req(f,'csrf-h1'))); // an ordinary page, to learn the session's form token
      const page=await b.show(token);
      assert(!page.body.includes('secret-owner-h1'),'the page shows nothing of the other record\'s value');
      assert(page.body.includes('rec-EXAMPLE-h1-source'),page.body.slice(0,400));
      assert(!page.body.includes('name="decision"'),'no approval is offered');
      const open=openOf(f,token);assert.equal(open.length,1);
      const before=decisions(f);
      const post=await b.send('POST','/approve/'+token,new URLSearchParams({csrf:b.token(),decision:'approve',record:open[0].id}));
      assert.equal(post.status,403,post.body);
      assert.equal(decisions(f),before,'a decision posted to it records nothing');
      assert.equal(f.core.db.prepare('SELECT status FROM pending WHERE id=?').get(open[0].id).status,'pending');
      assert.equal(f.count(),0);assert.equal(used(f),0);
      // S78: where the source comes to resolve to another record after the approval,
      // the write is not sent and the answer is execution_failed (S65).
      const h=cov();
      h.sor.seed(A,'rec-EXAMPLE-h1b-source',{lifecycle_stage:'lead'}); // no owner: the copied value is null
      h.sor.seed(A,'rec-EXAMPLE-h1b-other',{owner:'secret-owner-h1b'});
      h.sor.recordPermission(A,P,'rec-EXAMPLE-h1b-other',false,true);
      h.sor.seed(A,'rec-EXAMPLE-h1b-target',{owner:'target-owner-h1b'});
      const hr=h.req({objectType:'contact',source:'rec-EXAMPLE-h1b-source',target:'rec-EXAMPLE-h1b-target'},{operation:COPY});
      const htoken=ask(h,hr),hb=browser(h);await hb.login();await hb.show(htoken);assert.equal((await hb.decide(htoken,'approve')).status,200);
      h.sor.merge(A,'rec-EXAMPLE-h1b-source','rec-EXAMPLE-h1b-other');
      const out=call(h,hr);
      assert(!JSON.stringify(out).includes('secret-owner-h1b'),'the other record\'s value is not returned after the merge');
      assert.equal(out.approval?.error,'execution_failed',JSON.stringify(out));
      assert.equal(h.count(),0,'the write was not sent');
      assert.equal(h.sor.get(A,'rec-EXAMPLE-h1b-target').properties.owner,'target-owner-h1b','the target is unchanged');
      assert.equal(used(h),1,'the approval stays consumed');
      const outcome=h.core.records().findLast(x=>x.record_phase==='outcome');
      assert.equal(outcome.action_detail.reason,'reference_resolved','the audit record shows the failure and its reason');
      const replay=call(h,hr);
      assert.equal(replay.approval?.error,'execution_failed');assert.equal(replay.approval.recorded_outcome.sent_now,false);
      assert.equal(h.count(),0);assert.equal(used(h),1);
    },
    // 160 (H2). The approval page of a copy (S53, S22, S70). Finding 1.
    // Off: copy-page-hides-copied-value, copy-approver-unchecked.
    async function copyApprovalPage() {
      const f=cov();
      f.sor.seed(A,'rec-EXAMPLE-h2-source',{owner:'owner-of-source-h2'});f.sor.seed(A,'rec-EXAMPLE-h2-target',{owner:'old-target-owner-h2'});
      const r=f.req({objectType:'contact',source:'rec-EXAMPLE-h2-source',target:'rec-EXAMPLE-h2-target'},{operation:COPY});
      const token=ask(f,r),b=browser(f);await b.login();
      const page=await b.show(token);assert.equal(page.status,200,page.body);
      // S70: the page shows what the open record is bound to: the copied value as the
      // new value of the field it sets, and that field's current value.
      assert(!page.body.includes('No fields are being set'),'the copied value is not hidden');
      assert.match(page.body,/<dt>New value<\/dt><dd>owner-of-source-h2<\/dd>/);
      assert.match(page.body,/<dt>Old value<\/dt><dd>old-target-owner-h2<\/dd>/);
      assert(page.body.includes('copied from record rec-EXAMPLE-h2-source'),'the page names the source of the copied value');
      const record=openOf(f,token)[0].id;
      // S53: a person who may not read the source record is shown nothing from it.
      f.sor.recordPermission(A,'test-person','rec-EXAMPLE-h2-source',false,true);
      const unreadable=await b.show(token);
      assert.equal(unreadable.status,403,'the approver\'s read on the source is checked');
      for(const value of ['owner-of-source-h2','old-target-owner-h2','rec-EXAMPLE-h2-source'])assert(!unreadable.body.includes(value),value);
      assert.equal((await b.decide(token,'approve')).status,403,'and a decision is refused');
      assert.equal(decisions(f),0);
      f.sor.recordPermission(A,'test-person','rec-EXAMPLE-h2-source',true,true);
      // S53: the field read on the copied field is checked as well.
      f.sor.fieldPermission(A,'test-person',COPY,'/owner',false,'read');
      assert.equal((await b.show(token)).status,403,'the approver\'s read on the copied field is checked');
      f.sor.fieldPermission(A,'test-person',COPY,'/owner',true,'read');
      // S22: the approving person must hold the permission to make the change: the
      // write on the field the copy sets.
      f.sor.fieldPermission(A,'test-person',COPY,'/owner',false);
      assert.equal((await b.show(token)).status,200,'a person who may read may view');
      const denied=await b.decide(token,'approve');
      assert.equal(denied.status,403,'the approver\'s write on the field is checked');
      assert.equal(decisions(f),0,'nothing was recorded');
      assert.equal(f.core.db.prepare('SELECT status FROM pending WHERE id=?').get(record).status,'pending');
      f.sor.fieldPermission(A,'test-person',COPY,'/owner',true);
      await b.show(token);assert.equal((await b.decide(token,'approve')).status,200);
      const out=call(f,r);assert(out.ok,JSON.stringify(out));
      assert.equal(f.sor.get(A,'rec-EXAMPLE-h2-target').properties.owner,'owner-of-source-h2');
    },
    // 161 (H3). The state hash covers only the leaves the request sets (S61, S60(a)). Finding 2.
    // Off: state-hash-covers-siblings.
    function stateHashSetLeavesOnly() {
      const f=cov(),base={lifecycle_stage:'lead',owner:'user-EXAMPLE-3'};
      f.sor.seed(A,'rec-EXAMPLE-42',{...base,profile:{name:'name-h3',secret:'secret-h3-a'}});
      f.sor.fieldPermission(A,P,OP,'/profile/secret',false,'read'); // a sibling leaf the principal may not read
      const r=f.req({...args(),records:[{id:'rec-EXAMPLE-42',properties:{profile:{name:'new-name-h3'}}}]});
      const first=call(f,r);
      assert.equal(first.approval.error,'approval_required');
      assert(first.approval.change&&first.approval.change_hash,'the principal may read every leaf the request sets, so it is a reader');
      const token=tokenOf(first),record=openOf(f,token)[0];
      // Someone changes the sibling leaf: the answer, the hash and the open record stay.
      f.sor.seed(A,'rec-EXAMPLE-42',{...base,profile:{name:'name-h3',secret:'secret-h3-b'}});
      const repeat=call(f,r);
      assert.deepEqual(repeat,first,'the answer does not depend on a leaf the principal may not read');
      assert.equal(openOf(f,token)[0].id,record.id,'the open record was not replaced');
      assert(!JSON.stringify(JSON.parse(openOf(f,token)[0].json).current).includes('secret-h3'),'the stored current values hold the set leaves only');
      // The binding is kept: a change of the leaf the request sets gives another hash.
      f.sor.seed(A,'rec-EXAMPLE-42',{...base,profile:{name:'other-name-h3',secret:'secret-h3-b'}});
      const changed=call(f,r);
      assert.equal(changed.approval.error,'approval_required');
      assert.notEqual(changed.approval.change_hash,first.approval.change_hash,'the set leaf is bound into the hash');
      assert.deepEqual(JSON.parse(openOf(f,token)[0].json).current,{'rec-EXAMPLE-42':{profile:{name:'other-name-h3'}}});
    },
    // 162 (H4). A request key after its first context has expired (S67, S68(2), S68(5)). Finding 3.
    // Off: context-lookup-oldest.
    async function requestKeyAfterContextExpiry() {
      const second=f=>{
        const r=req(f,'expiry-h4'),first=call(f,r);assert.equal(first.approval.error,'approval_required');
        const ctx=f.pending.contextOf(tokenOf(first));f.time(ctx.expires);
        const fresh=call(f,r);assert.equal(fresh.approval.error,'approval_required');
        assert.notEqual(tokenOf(fresh),tokenOf(first),'a new context after the first expired');
        return {r,first,fresh,key:first.approval.request_key,token:tokenOf(fresh)};
      };
      const f=cov();nonReader(f);const s=second(f);
      const again=call(f,s.r);
      assert.deepEqual(again,s.fresh,'S68(2): every answer in the live context is identical');
      assert.equal(contextRows(f,s.key).length,2);assert.equal(openOf(f,s.token).length,1);
      const b=browser(f);await b.login();await b.show(s.token);assert.equal((await b.decide(s.token,'approve')).status,200);
      const out=call(f,s.r);assert(out.ok,JSON.stringify(out));assert.equal(f.count(),1);assert.equal(used(f),1);
      assert.equal(f.pending.contextOf(s.token).status,'consumed');
      // A denial in the second context is found.
      const g=cov();nonReader(g);const d=second(g);
      const gb=browser(g);await gb.login();await gb.show(d.token);assert.equal((await gb.decide(d.token,'deny')).status,200);
      const denied=call(g,d.r);assert.equal(denied.approval.error,'approval_denied',JSON.stringify(denied));
      assert.deepEqual(withoutClock(call(g,d.r).approval),withoutClock(denied.approval));
      assert.equal(contextRows(g,d.key).length,2);assert.equal(g.count(),0);
      // A decline in the second context is found, and stays.
      const h=cov();nonReader(h);const c=second(h);
      const declined=call(h,{...c.r,inputResponses:{approve:{action:'decline'}}});assert.equal(declined.approval.error,'approval_cancelled');
      const sticky=call(h,c.r);assert.equal(sticky.approval.error,'approval_cancelled',JSON.stringify(sticky));
      assert.equal(h.pending.contextOf(c.token).status,'cancelled');assert.equal(contextRows(h,c.key).length,2);
      // A third generation: the second context expires too.
      h.time(h.pending.contextOf(c.token).expires);
      const third=call(h,c.r);assert.equal(third.approval.error,'approval_required');
      assert.deepEqual(call(h,c.r),third);assert.equal(contextRows(h,c.key).length,3);
      // A first context that was approved, denied or declined frees the request key at
      // its expiry as well, with record state unchanged (the same change hash).
      for(const how of ['approve','deny','decline']) {
        const k=cov();nonReader(k);const r=req(k,'expiry-closed-h4-'+how),token=ask(k,r),ctx=k.pending.contextOf(token);
        if(how==='decline')assert.equal(call(k,{...r,inputResponses:{approve:{action:'decline'}}}).approval.error,'approval_cancelled');
        else {const kb=browser(k);await kb.login();await kb.show(token);assert.equal((await kb.decide(token,how)).status,200);}
        k.time(ctx.expires);
        const fresh=call(k,r);assert.equal(fresh.approval?.error,'approval_required',how+': '+JSON.stringify(fresh));
        assert.notEqual(tokenOf(fresh),token);assert.deepEqual(call(k,r),fresh,how);
        assert.equal(contextRows(k,ctx.request_key).length,2);assert.equal(openOf(k,tokenOf(fresh)).length,1);
        assert.equal(k.count(),0,'an approval does not outlive its context');assert.equal(used(k),0);
        assert.equal(k.core.db.prepare("SELECT count(*) n FROM pending WHERE context=? AND status IN ('pending','approved')").get(token).n,0,'no pending or approved record outlives its context');
      }
    },
    // 163 (H5). An approved record that expires unused inside its context (S67). Finding 8.
    // Off: covered-expired-approval-refused, context-page-opens-record.
    async function approvalExpiresInsideContext() {
      for(const nonreader of [true,false]) {
        const f=cov({pendingCap:1});if(nonreader)nonReader(f);
        const r=req(f,'lapse-h5-'+nonreader),first=call(f,r);assert.equal(first.approval.error,'approval_required');
        const token=tokenOf(first),ctx=f.pending.contextOf(token),key=first.approval.request_key;
        const b=browser(f);await b.login();await b.show(token);assert.equal((await b.decide(token,'approve')).status,200);
        const approved=f.core.db.prepare("SELECT * FROM pending WHERE context=? AND status='approved'").get(token),claims=JSON.parse(approved.claims);
        assert(claims.exp<ctx.expires,'the approval expires before its context');
        f.time(claims.exp);
        const out=call(f,r);
        assert.equal(out.approval?.error,'approval_required',JSON.stringify(out));
        // A non-reader is answered as before the approval; a reader as S63 provides.
        assert.deepEqual(out,first);
        if(nonreader){assert(!Object.hasOwn(out.approval,'change'));assert(!Object.hasOwn(out.approval,'change_hash'));}
        else {assert(out.approval.change);assert(out.approval.change_hash);}
        assert.deepEqual(call(f,r),first,'the answer stays the same');
        // A new pending record in the same context; the expired approval is kept.
        const contexts=contextRows(f,key);assert.equal(contexts.length,1);assert.equal(contexts[0].status,'open');
        const open=openOf(f,token);assert.equal(open.length,1,'a new pending record in the context');assert.notEqual(open[0].id,approved.id);
        assert.equal(f.core.db.prepare('SELECT status FROM pending WHERE id=?').get(approved.id).status,'expired','the expired approval is kept, closed');
        assert.equal(f.count(),0);assert.equal(used(f),0);
        // The context still counts toward the limit (S70).
        assert.equal(call(f,req(f,'lapse-other-h5-'+nonreader)).approval.error,'approval_limit_reached');
        // The page shows the new record for a decision, and the approval is usable.
        const page=await b.show(token);assert.equal(page.status,200,page.body);assert(page.body.includes('name="decision"'));
        assert.equal((await b.decide(token,'approve')).status,200);
        const done=call(f,r);assert(done.ok,JSON.stringify(done));assert.equal(f.count(),1);assert.equal(used(f),1);
      }
      // Between the expiry and the next request the page says that the approval
      // expired unused; it offers no decision and opens no record (S67, S50).
      const g=cov(),gr=req(g,'lapse-page-h5'),gtoken=ask(g,gr),gb=browser(g);await gb.login();await gb.show(gtoken);
      assert.equal((await gb.decide(gtoken,'approve')).status,200);
      const exp=JSON.parse(g.core.db.prepare("SELECT claims FROM pending WHERE context=? AND status='approved'").get(gtoken).claims).exp;
      g.time(exp);
      for(let n=0;n<2;n++) {
        const lapsed=await gb.show(gtoken);assert.equal(lapsed.status,200,lapsed.body);
        assert(lapsed.body.includes('was not used before it expired'),lapsed.body.slice(0,600));
        assert(!lapsed.body.includes('name="decision"'),'no decision is offered before the next request');
        assert(!lapsed.body.includes('It can be used until'),'the page does not present the expired approval as usable');
        assert.equal(openOf(g,gtoken).length,0,'the page opens no record');
      }
      const next=call(g,gr);assert.equal(next.approval.error,'approval_required');assert.equal(tokenOf(next),gtoken);
      assert.equal(openOf(g,gtoken).length,1,'the next request creates the new pending record');
    },
    // 164 (H6). After a grant in a context, the next record can be decided (S70, S68(4), S50). Finding 9.
    // Off: context-standing-from-earlier-grant, context-page-opens-record.
    async function nextRecordAfterGrant() {
      const grants=f=>f.core.db.prepare('SELECT count(*) n FROM server_grants').get().n;
      const start=async name=>{
        const f=cov(),r=req(f,name),token=ask(f,r),b=browser(f);await b.login();await b.show(token);
        const granted=openOf(f,token)[0].id;
        const made=await b.decide(token,'grant',{max_records:1,minutes:1});assert.equal(made.status,200,made.body);
        const outcome=await b.show(token);assert(outcome.body.includes('A standing grant was made from this change on'),outcome.body.slice(0,400));
        assert(!outcome.body.includes('name="decision"'));
        f.time(f.now()+61); // the grant has expired; the context has not
        const later=call(f,r);assert.equal(later.approval.error,'approval_required','the later request is not matched by the grant');
        assert.equal(tokenOf(later),token,'the same context');
        assert.equal(f.core.db.prepare('SELECT status FROM pending WHERE id=?').get(granted).status,'granted','the record on which the grant was made is closed and kept');
        const open=openOf(f,token);assert.equal(open.length,1,'a new pending record in the same context');assert.notEqual(open[0].id,granted);
        const page=await b.show(token);assert.equal(page.status,200,page.body);
        assert(page.body.includes('name="decision"'),'the page shows the new pending record for a decision');
        assert(page.body.includes('It is shown as history'),'and the earlier grant as history');
        return {f,r,token,b,granted,open:open[0].id};
      };
      const a=await start('after-grant-h6');
      const approve=await a.b.decide(a.token,'approve');
      assert.equal(approve.status,200,approve.body);
      assert.equal(a.f.core.db.prepare('SELECT status FROM pending WHERE id=?').get(a.open).status,'approved');
      const out=call(a.f,a.r);assert(out.ok,JSON.stringify(out));assert.equal(a.f.count(),1);assert(!out.grant,'the write ran under the person\'s approval');
      const d=await start('after-grant-deny-h6');
      const deny=await d.b.decide(d.token,'deny');
      assert.equal(deny.status,200,deny.body);
      assert.equal(call(d.f,d.r).approval.error,'approval_denied');assert.equal(d.f.count(),0);
      // S68(4): "S50's rule for a repeated decision applies first." The repeated grant
      // decision on the granted record returns the first result and creates nothing;
      // another decision on it is refused, and the first stands.
      const e=await start('after-grant-repeat-h6');
      const form=decision=>new URLSearchParams({csrf:e.b.token(),decision,record:e.granted,...(decision==='grant'?{shape:'any_record',max_records:'1',minutes:'1'}:{})});
      const repeated=await e.b.send('POST','/approve/'+e.token,form('grant'));
      assert.equal(repeated.status,200,repeated.body);assert.equal(grants(e.f),1,'no second grant');
      const other=await e.b.send('POST','/approve/'+e.token,form('approve'));
      assert.equal(other.status,403);assert(other.body.includes('A decision was already recorded'),other.body.slice(0,400));
      assert.equal(e.f.core.db.prepare('SELECT status FROM pending WHERE id=?').get(e.open).status,'pending','the open record is untouched');
      // Until a later request creates the context's next record, the page shows the
      // recorded grant, however often it is viewed, and opens no record (S70).
      const g=cov(),gr=req(g,'after-grant-views-h6'),gtoken=ask(g,gr),gb=browser(g);await gb.login();await gb.show(gtoken);
      assert.equal((await gb.decide(gtoken,'grant',{max_records:1,minutes:1})).status,200);
      for(let n=0;n<3;n++) {
        const view=await gb.show(gtoken);assert.equal(view.status,200,view.body);
        assert(view.body.includes('A standing grant was made from this change on'),view.body.slice(0,400));
        assert(!view.body.includes('name="decision"'),'view '+n+' offers no decision');
        assert.equal(openOf(g,gtoken).length,0,'view '+n+' opens no record');
      }
      const ran=call(g,gr);assert(ran.ok,JSON.stringify(ran));assert(ran.grant,'the identical retry still runs under the grant');
    },
    // 165 (H7). The record write scope for a query and a copy (S60(c), S72). Finding 10.
    // Off: record-scope-skips-query-and-copy.
    function recordScopeQueryAndCopy() {
      const denied={ok:false,approval:{error:'permission_denied'}};
      const f=cov();nonReader(f,COPY);
      f.sor.recordWriteScope(A,P);
      f.sor.recordPermission(A,P,'rec-EXAMPLE-42',true,true);
      f.sor.recordPermission(A,P,'forbidden-record',true,false);
      f.sor.seed(A,'rec-EXAMPLE-h7-source',{owner:'source-owner-h7'});
      const copy=target=>f.req({objectType:'contact',source:'rec-EXAMPLE-h7-source',target},{operation:COPY});
      const forbidden=call(f,copy('forbidden-record')),missing=call(f,copy('rec-EXAMPLE-h7-missing'));
      assert.deepEqual(forbidden,denied,'a target outside the scope is refused at step 1');
      assert.deepEqual(missing,denied,'a missing target gets the same step 1 refusal');
      // S78 with S60(c): a target that resolves to another record is treated as missing.
      f.sor.seed(A,'rec-EXAMPLE-h7-to',{owner:'x'});f.sor.recordPermission(A,P,'rec-EXAMPLE-h7-from',true,true);f.sor.merge(A,'rec-EXAMPLE-h7-from','rec-EXAMPLE-h7-to');
      assert.deepEqual(call(f,copy('rec-EXAMPLE-h7-from')),denied);
      assert.equal(pending(f,'1=1'),0,'no approval record was created');
      assert.equal(f.core.db.prepare('SELECT count(*) n FROM contexts').get().n,0,'and no context');
      assert.equal(call(f,copy('rec-EXAMPLE-42')).approval.error,'approval_required','a target inside the scope reaches the approval flow');
      // A query addresses every record of the object type. A write permission scoped by
      // record does not affirm that domain, so the query is refused at step 1 without
      // evaluating anything, whatever it would select.
      const q=f.req({objectType:'contact',filter:{lifecycle_stage:'lead'},set:{group:'scoped-h7'}},{operation:QUERY});
      const reads=f.sor.reads(),first=call(f,q);
      assert.deepEqual(first,denied,'a query under a record-scoped write permission is refused at step 1');
      assert.equal(f.sor.reads(),reads,'nothing was evaluated');
      f.sor.seed(A,'rec-EXAMPLE-h7-lead',{lifecycle_stage:'lead'});
      assert.deepEqual(call(f,q),first,'the answer does not depend on the selection');
      assert.equal(f.sor.reads(),reads);assert.equal(f.count(),0);
      // Without the scope the same requests reach the approval flow.
      const g=cov();g.sor.seed(A,'rec-EXAMPLE-h7-source',{owner:'source-owner-h7'});
      assert.equal(call(g,g.req(q.args,{operation:QUERY})).approval.error,'approval_required');
      assert.equal(call(g,g.req({objectType:'contact',source:'rec-EXAMPLE-h7-source',target:'forbidden-record'},{operation:COPY})).approval.error,'approval_required');
    },
    // 166 (H8). The page says what is known of an earlier write (S69(3), S69(4)). Finding 11.
    // Off: covered-sibling-outcome-ignored.
    async function earlierWriteOutcomeOnPage() {
      const lead='An earlier request from this agent in this account, differing only in its change tag, ';
      const run=async(name,inject)=>{
        const f=cov(),base=req(f,name),tagged=tag=>({...base,args:{...base.args,change_tag:tag}});
        const a=tagged('a'),token=ask(f,a),b=browser(f);await b.login();await b.show(token);assert.equal((await b.decide(token,'approve')).status,200);
        if(inject)f.sor.inject(...inject(f));
        const out=call(f,a),next=ask(f,tagged('b'));
        const view=async()=>{const p=await b.show(next);assert.equal(p.status,200,p.body);assert(p.body.includes(lead),p.body.slice(0,900));assert(p.body.includes('name="decision"'));return p.body;};
        return {f,out,view,hash:f.core.db.prepare('SELECT change_hash FROM outcomes').get().change_hash};
      };
      // The response to the write was lost: the outcome is not known, so the first answer
      // states that, never execution_failed (S25, S77, S69(3)).
      const lost=await run('sibling-lost-h8',()=>['after-write',()=>{throw Error('response lost');}]);
      assert.equal(lost.out.result?.outcome,'unknown');
      let body=await lost.view();
      assert(body.includes('the outcome of that earlier write is not known'),body.slice(0,900));
      assert(!body.includes('already ran'),'an unknown outcome is not presented as a write that ran');
      // When the server learns the outcome, the page gives the recorded one.
      lost.f.core.learnOutcome(lost.hash,{outcome:'success',changed:1});
      body=await lost.view();
      assert(body.includes(lead+'already ran'));assert(!body.includes('is not known'));
      // The write was refused: it did not run.
      const failed=await run('sibling-failed-h8',()=>['before-write',()=>{throw Error('write rejected');}]);
      assert.equal(failed.out.approval.error,'execution_failed');
      body=await failed.view();
      assert(body.includes('its write could not be carried out'),body.slice(0,900));
      assert(!body.includes('already ran'));assert(!body.includes('is not known'));
      // The write was answered conflict: it did not run.
      const conflict=await run('sibling-conflict-h8',f=>['before-write',()=>f.sor.db.prepare('DELETE FROM records WHERE account=? AND id=?').run(A,'rec-EXAMPLE-42')]);
      assert.equal(conflict.out.approval.error,'conflict');
      body=await conflict.view();
      assert(body.includes('its write was not made'),body.slice(0,900));
      assert(!body.includes('already ran'));assert(!body.includes('is not known'));
      // The write succeeded.
      const ok=await run('sibling-ok-h8');
      assert(ok.out.ok);
      body=await ok.view();
      assert(body.includes(lead+'already ran'));assert(!body.includes('is not known'));
    },
    // 167 (H9). request_key wherever the server computed one (S67). Finding 12.
    // Off: covered-early-refusal-omits-request-key.
    function requestKeyOnEarlyRefusals() {
      const carries=(f,r,out,error)=>{
        assert.equal(out.approval?.error,error,JSON.stringify(out));
        assert.equal(out.approval.request_key,keyOf(f,r),error+' carries the request key');
        assert(!Object.hasOwn(out.approval,'change'));assert(!Object.hasOwn(out.approval,'change_hash'));
      };
      for(const nonreader of [false,true]) {
        // S66: the account allows no approver type for the operation in this profile.
        const f=cov();if(nonreader)nonReader(f);f.core.admin(admin,'settings',{operationTypes:{[OP]:[]}});
        const r=req(f,'key-h9'),reads=f.sor.reads();
        carries(f,r,call(f,r),'approver_not_authorized');
        assert.equal(f.sor.reads(),reads,'without reading record state');
        // S66: a receipt presented for a covered operation.
        const g=cov();if(nonreader)nonReader(g);
        const gr=req(g,'key-receipt-h9');
        carries(g,gr,call(g,{...gr,receipt:vectors.receipts.person.jws}),'approver_not_authorized');
        // Refusals raised while the change object is built: a read that did not complete.
        const u=cov();if(nonreader)nonReader(u);
        const ur=req(u,'key-unavailable-h9');u.sor.inject('before-get',()=>{throw Error('the system of record timed out');});
        carries(u,ur,call(u,ur),'approval_unavailable');
      }
      // An undefined property, for a principal established to see every definition.
      const h=cov(),bad=req(h,'key-invalid-h9');bad.args.records[0].properties={owner:'x',not_a_defined_property_h9:'y'};
      const invalid=call(h,bad);carries(h,bad,invalid,'invalid_input');assert.deepEqual(invalid.approval.invalid,['/not_a_defined_property_h9']);
      // The selection limit, reached only by a principal for which S72 holds.
      const k=cov({selectionLimit:1});k.sor.seed(A,'rec-EXAMPLE-h9-b',{lifecycle_stage:'lead'});
      const q=k.req({objectType:'contact',filter:{lifecycle_stage:'lead'},set:{group:'limit-h9'}},{operation:QUERY});
      carries(k,q,call(k,q),'selection_limit');
      assert.equal(k.count(),0);assert.equal(pending(k,'1=1'),0);
    },
    // 168 (H10). Record values that have no RFC 8785 form (S65, S61). Finding P1.
    // Off: record-value-refused.
    async function recordValuesForNonReader() {
      const T='rec-EXAMPLE-h10',S='rec-EXAMPLE-h10-target',HTTP='http:PATCH:/records';
      const held={plain:'a',unsafe_integer:2**60,lone_surrogate:'\ud800'};
      // Each answer is compared byte for byte; the approval link's unguessable token is
      // the only member that differs between two fresh databases.
      const answer=r=>JSON.stringify(r).replace(/\/approve\/[a-f0-9]{48}/g,'/approve/ID');
      const arrange=f=>{
        for(const op of [OP,QUERY,CREATE,HTTP,COPY])f.sor.permission(A,P,op,false,true);
        f.sor.seed(A,S,{owner:'target-h10'});
      };
      const ops=[
        ['update',OP,{objectType:'contact',action:'update',records:[{id:T,properties:{owner:'nd-h10'}}]}],
        ['create',CREATE,{objectType:'contact',id:T,properties:{owner:'nd-h10'}}],
        ['PATCH',HTTP,{objectType:'contact',action:'update',records:[{id:T,properties:{owner:'nd-h10'}}]}],
        ['copy',COPY,{objectType:'contact',source:T,target:S}],
      ];
      for(const [label,operation,body] of ops) {
        const answers={};
        for(const [name,value] of Object.entries(held)) {
          const f=cov();arrange(f);f.sor.seed(A,T,{owner:value,notes:'h10'});
          answers[name]=answer(call(f,{account:A,principal:P,operation,args:structuredClone(body)}));
        }
        assert.equal(new Set(Object.values(answers)).size,1,label+' in-process: '+JSON.stringify(answers));
      }
      // The same three MCP tools over stdio, against one covered server and one database:
      // changing the value the record holds must not change one byte of the answer.
      for(const [label,tool,body] of [
        ['update','manage_records',{objectType:'contact',action:'update',records:[{id:T,properties:{owner:'nd-h10'}}]}],
        ['create','create_record',{objectType:'contact',id:T,properties:{owner:'nd-h10'}}],
        ['copy','copy_record_owner',{objectType:'contact',source:T,target:S}],
      ]) {
        const f=cov();arrange(f);f.sor.seed(A,T,{owner:'a',notes:'h10'});
        await sdk(f,'server',async c=>{
          const answers={};
          for(const [name,value] of Object.entries(held)) {
            f.sor.seed(A,T,{owner:value,notes:'h10'});
            answers[name]=JSON.stringify(await c.callTool({name:tool,arguments:structuredClone(body)}));
          }
          assert.equal(new Set(Object.values(answers)).size,1,label+' stdio: '+JSON.stringify(answers));
        },{},{VA_PRECONDITIONS:'1'});
      }
    },
    // 169 (H11). The context page for a person not permitted to see the request (S53,
    // S58, S70). Finding P2. Off: context-page-without-permission.
    async function pageForPersonNotPermitted() {
      const f=cov();nonReader(f);
      const r=req(f,'not-permitted-h11'),token=ask(f,r);
      const approver=browser(f);await approver.login();await approver.show(token);
      assert.equal((await approver.decide(token,'approve')).status,200,'the permitted person approved');
      // test-person-4 is a member of the account who is not permitted (setup).
      const outsider=browser(f);await outsider.login('test-person-4');
      const unchanged=await outsider.show(token);
      // A permitted person still sees the recorded outcome while the approval matches.
      const viewer=browser(f);await viewer.login();
      const seen=await viewer.show(token);assert.equal(seen.status,200,seen.body);assert.match(seen.body,/Change approved/);
      // The record changes, so the approval no longer matches.
      f.sor.seed(A,'rec-EXAMPLE-42',{lifecycle_stage:'customer',owner:'changed-h11'});
      const changed=await outsider.show(token);
      assert.equal(unchanged.status,403,unchanged.body);
      assert.equal(changed.status,403,changed.body);
      assert.equal(changed.status,unchanged.status);
      assert.equal(changed.body,unchanged.body,'a person not permitted gets byte-identical answers in both states');
      const heading=b=>b.split('</style>').at(-1)??b;
      assert(!/approved/i.test(heading(unchanged.body)),'no decision outcome is shown');
      assert(!/approved/i.test(heading(changed.body)),'no decision outcome is shown after the record changes');
      for(const value of ['rec-EXAMPLE-42','new-owner','lifecycle_stage'])assert(!unchanged.body.includes(value),value);
    },
    // 170 (H12). read_record through an identifier that resolves to a record the
    // principal may not read (S78, S77). Finding P3. Off: read-alias-permission-denied.
    async function readRecordThroughUnreadableAlias() {
      for(const covered of [false,true]) {
        const f=covered?cov():setup(),mode=covered?'covered':'default';
        const open='rec-EXAMPLE-h12-open',openAlias='rec-EXAMPLE-h12-open-alias';
        const secret='rec-EXAMPLE-h12-secret',secretAlias='rec-EXAMPLE-h12-secret-alias';
        f.sor.permission(A,P,OP); // operation-level read, and no record-level denial for the open record
        f.sor.seed(A,open,{owner:'open-h12'});f.sor.merge(A,openAlias,open);
        f.sor.seed(A,secret,{owner:'secret-h12'});f.sor.recordPermission(A,P,secret,false,true);
        f.sor.merge(A,secretAlias,secret);
        await sdk(f,'server',async c=>{
          const read=async id=>JSON.stringify(await c.callTool({name:'read_record',arguments:{id}}));
          const absent=await read('rec-EXAMPLE-h12-absent'),unreadable=await read(secretAlias);
          assert.equal(unreadable,absent,mode+': an alias of an unreadable record is answered as an absent identifier');
          assert.equal(JSON.parse(JSON.parse(unreadable).content[0].text),null,mode+': the answer is null');
          assert(!unreadable.includes('secret-h12'),'no record content');
          // Section 2: the unreadable record itself, named directly, is
          // answered exactly as an absent identifier at record level and operation level.
          const refused=await read(secret);
          assert.equal(refused,absent,mode+': the unreadable record itself answers exactly as an absent identifier');
          assert.equal(JSON.parse(JSON.parse(refused).content[0].text),null,mode+': the answer is null');
          assert(!refused.includes('secret-h12'),'no record content');
          assert.deepEqual(JSON.parse(JSON.parse(await read(openAlias)).content[0].text),f.sor.get(A,open),mode+': a readable alias is still read');
        },{},{VA_PRECONDITIONS:covered?'1':''});
      }
    },
  ];
  const names=['Copy through a merged source','Approval page of a copy','State hash covers the set leaves only','Request key after its context expired','Approval expires inside its context','Next record after a grant','Record scope for query and copy','Earlier write outcome on the page','Request key on early refusals','Record values that cannot be serialized','Page for a person not permitted','Read through an unreadable alias'];
  return {tests,names};
}
