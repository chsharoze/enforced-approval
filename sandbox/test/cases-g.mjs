import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import crypto from 'node:crypto';
import { OP, QUERY, CREATE, COPY, changeObject } from '../src/core.mjs';
import { Issuer } from '../src/issuer.mjs';
import { readableTime } from '../src/presentation.mjs';
import { hash, jcs } from '../src/json.mjs';
const vectors=JSON.parse(readFileSync(new URL('../spec/vectors/vectors.json',import.meta.url)));
// Tests 97 to 146 of spec/CONFORMANCE.md, in order. A test that exercises a covered
// operation runs in the covered mode (the preconditions setting, as VA_PRECONDITIONS=1
// sets it for the runnable servers); the rest run against operations that are not covered.
export function cases({helpers:{setup,req,ask,browser,grant,concurrent},fixture,args,call,A,P,admin,ni,httpCall,sdk}) {
  // A covered-mode fixture: preconditions on, with the published HMAC test key (S61).
  const cov=(settings={})=>setup({preconditions:true,stateKey:vectors.state_manifest_hmac_key,...settings});
  const covered=()=>ni('covered operations are experimental in Draft 0.2 and the sandbox does not implement them');
  // A principal that may write but not read: a non-reader (S60).
  const nonReader=(f,operation=OP)=>f.sor.permission(A,P,operation,false,true);
  const pending=(f,status="status='pending'")=>f.core.db.prepare(`SELECT count(*) n FROM pending WHERE ${status}`).get().n;
  const contextRows=(f,key)=>f.core.db.prepare('SELECT * FROM contexts WHERE request_key=? ORDER BY rowid').all(key);
  const withoutClock=({retry_after,message,...rest})=>rest;
  const used=f=>f.core.db.prepare('SELECT count(*) n FROM used').get().n;
  const tests=[
    // 97. Refusals without hash for non-readers (S63, S68(1)).
    async function refusalsWithoutHash() {
      const noHash=(label,approval)=>{
        assert(!Object.hasOwn(approval,'change'),label+': no change');
        assert(!Object.hasOwn(approval,'change_hash'),label+': no change_hash');
      };
      const f=cov();nonReader(f);
      const r=req(f,'no-hash-97');
      const id=ask(f,r),b=browser(f);await b.login();await b.show(id);await b.decide(id,'deny');
      f.sor.seed(A,'rec-EXAMPLE-42',{lifecycle_stage:'changed',owner:'changed-97'});
      const denied=call(f,r);
      assert.equal(denied.approval.error,'approval_denied');
      const cancelled=call(f,{...req(f,'no-hash-97b'),inputResponses:{approve:{action:'decline'}}});
      assert.equal(cancelled.approval.error,'approval_cancelled');
      const k=cov({pendingCap:1});nonReader(k);
      ask(k,req(k,'cap-97a'));
      const limited=call(k,req(k,'cap-97b'));
      assert.equal(limited.approval.error,'approval_limit_reached');
      const g=cov();nonReader(g);
      for (const [label,inject] of [['conflict',()=>g.sor.db.prepare('DELETE FROM records WHERE account=? AND id=?').run(A,'rec-EXAMPLE-42')],['execution_failed',()=>{throw Error('write rejected');}]]) {
        const gr=req(g,'no-hash-97-'+label),gid=ask(g,gr),gb=browser(g);await gb.login();await gb.show(gid);await gb.decide(gid,'approve');
        g.sor.inject('before-write',inject);
        const out=call(g,gr);
        assert.equal(out.approval.error,label);
        noHash(label,out.approval);
      }
      const required=call(g,req(g,'no-hash-97c'));
      assert.equal(required.approval.error,'approval_required');
      for (const [label,approval] of [['approval_required',required.approval],['approval_denied',denied.approval],['approval_cancelled',cancelled.approval],['approval_limit_reached',limited.approval]]) noHash(label,approval);
      // The approval record and the audit record hold the hash (S68(1)).
      assert(g.core.db.prepare("SELECT 1 FROM pending WHERE context IS NOT NULL AND hash<>''").get(),'the approval record holds the change hash');
      assert(g.core.records().some(x=>x.action_detail?.change_hash),'the audit record holds the change hash');
    },
    // 98. Keyed state and manifest hashes (S61).
    function keyedStateHashes() {
      const key=vectors.state_manifest_hmac_key;
      const f=cov(); // a reader: the fixture principal may read the record
      const p=f.core.prepare(f.req());
      const entry=p.change.preconditions[0];
      // (a) the SHA-256 of the same input without the key is not state_hash
      const input={purpose:'enforced-approval/state_hash/2',audience:p.change.audience,account:A,operation:OP,record:'rec-EXAMPLE-42',state:{kind:'fields',value:{lifecycle_stage:'lead',owner:'user-EXAMPLE-3'}}};
      assert.notEqual(hash(input),entry.state_hash,'an unkeyed hash fails (a)');
      assert.equal(entry.state_hash,crypto.createHmac('sha256',Buffer.from(key,'hex')).update(jcs(input)).digest('base64url'),'HMAC-SHA-256 under the published test key');
      assert.equal(entry.state_hash,vectors.change_hash_vectors[11].change_object.preconditions[0].state_hash,'the value in V12');
      // (b) two records holding the same value have different state_hash
      f.sor.seed(A,'rec-EXAMPLE-98b',{lifecycle_stage:'lead',owner:'user-EXAMPLE-3'});
      const two=f.core.prepare(f.req({...args(),records:[{id:'rec-EXAMPLE-42',properties:{lifecycle_stage:'customer',owner:'user-EXAMPLE-7'}},{id:'rec-EXAMPLE-98b',properties:{lifecycle_stage:'customer',owner:'user-EXAMPLE-7'}}]}));
      assert.notEqual(two.change.preconditions[0].state_hash,two.change.preconditions[1].state_hash,'the record is bound into the hash (b)');
      // (c) two change objects that differ only in arguments have different manifest_hash
      const qa={objectType:'contact',filter:{lifecycle_stage:'lead'},set:{owner:'user-EXAMPLE-7'}};
      const m1=f.core.prepare(f.req(qa,{operation:QUERY})).change.resolved.manifest_hash;
      const m2=f.core.prepare(f.req({...qa,set:{owner:'user-EXAMPLE-8'}},{operation:QUERY})).change.resolved.manifest_hash;
      assert.notEqual(m1,m2,'the arguments are bound into the hash (c)');
    },
    // 99. Same answer for missing and existing records (S60, S64).
    function sameAnswerForMissing() {
      const f=setup();nonReader(f);
      const missing=call(f,f.req({...args(),records:[{id:'rec-EXAMPLE-99-missing',properties:{owner:'a'}}]}));
      const existing=call(f,f.req({...args(),records:[{id:'rec-EXAMPLE-42',properties:{owner:'a'}}]}));
      for (const r of [missing,existing]) {
        assert.equal(r.approval.error,'approval_required');
        assert(Object.hasOwn(r.approval,'change_hash'));
        assert(r.approval.change,'S63: change is always included for an operation that is not covered');
        assert(r.approval.approval_url);
      }
      assert.deepEqual(Object.keys(missing.approval).sort(),Object.keys(existing.approval).sort());
      assert.equal(missing.approval.message,existing.approval.message);
      assert.equal(missing.approval.operation,existing.approval.operation);
      assert.equal(missing.approval.audience,existing.approval.audience);
      assert.equal(f.count(),0);
    },
    // 100. No version or absent member (S62, S64). The reader clause speaks of
    // preconditions, which an operation that is not covered builds none of.
    function noVersionOrAbsent() {
      const f=setup();nonReader(f,CREATE);
      const exists=call(f,f.req({objectType:'contact',id:'rec-EXAMPLE-42',properties:{owner:'x'}},{operation:CREATE}));
      const free=call(f,f.req({objectType:'contact',id:'rec-EXAMPLE-100-new',properties:{owner:'x'}},{operation:CREATE}));
      for (const r of [exists,free]) {
        assert.equal(r.approval.error,'approval_required');
        assert(r.approval.change,'S63: change is always included for an operation that is not covered');
      }
      assert.deepEqual(Object.keys(exists.approval).sort(),Object.keys(free.approval).sort());
      assert.equal(exists.approval.message,free.approval.message);
      assert.equal(f.count(),0);
      // Reader: an operation that is not covered builds no entry of preconditions, so
      // none has a version or absent member (S62).
      assert(!f.core.prepare(f.req()).change.preconditions);
    },
    // 101. Conflict after approval (S64, S69(3)).
    async function conflictAfterApproval() {
      for (const conditional of [true,false]) {
        const f=setup();f.sor.conditional=conditional;nonReader(f);
        const r=f.req({...args(),records:[{id:'rec-EXAMPLE-101-gone',properties:{owner:'x'}}]});
        const id=ask(f,r),b=browser(f);await b.login();await b.show(id);await b.decide(id,'approve');
        const out=call(f,r);
        assert.equal(out.approval.error,'conflict',conditional+'');
        assert(Object.hasOwn(out.approval,'change_hash'));
        assert.equal(f.count(),0,'the write must not take effect');
        assert.equal(pending(f,"status='consumed'"),1,'the approval stays consumed');
        assert(!f.sor.get(A,'rec-EXAMPLE-101-gone'));
      }
      // S77: where the server sends nothing because one entry of a batch failed its
      // pre-write check, that entry is conflict and every other entry is not_sent.
      const f=setup();f.sor.conditional=false;
      const batch=f.req({...args(),records:[{id:'rec-EXAMPLE-42',properties:{owner:'kept'}},{id:'rec-EXAMPLE-101-missing',properties:{owner:'x'}}]});
      const id=ask(f,batch),b=browser(f);await b.login();await b.show(id);await b.decide(id,'approve');
      const out=call(f,batch);
      assert.equal(out.approval.error,'conflict');
      assert.equal(f.count(),0,'no entry of the batch was written');
      const outcome=f.core.records().find(x=>x.record_phase==='outcome');
      assert.deepEqual(outcome.action_detail.entries,[{id:'rec-EXAMPLE-42',outcome:'not_sent'},{id:'rec-EXAMPLE-101-missing',outcome:'conflict'}],JSON.stringify(outcome.action_detail.entries));
      assert(outcome.action_detail.entries.find(e=>e.id==='rec-EXAMPLE-42').outcome==='not_sent');
      assert(outcome.action_detail.entries.find(e=>e.id==='rec-EXAMPLE-101-missing').outcome==='conflict');
      assert.equal(f.sor.get(A,'rec-EXAMPLE-42').properties.owner,'user-EXAMPLE-3','the record the request names is untouched');
    },
    // 102. Signed receipts only (S66).
    function signedReceiptsOnly() {
      // A covered operation on a server that offers only signed receipts for it:
      // every request is approver_not_authorized with no change_hash, the same whether
      // or not the record exists, and without reading record state.
      const answers=[];
      for (const id of ['rec-EXAMPLE-42','rec-EXAMPLE-102-missing']) {
        const f=fixture({preconditions:true,stateKey:vectors.state_manifest_hmac_key});
        const out=call(f,f.req({...args(),records:[{id,properties:{owner:'x'}}]}));
        assert.equal(out.approval.error,'approver_not_authorized');
        assert(!Object.hasOwn(out.approval,'change_hash'),'no change_hash');
        assert.equal(f.sor.reads(),0,'without reading record state');
        assert.equal(f.count(),0);
        answers.push(out.approval);
      }
      assert.deepEqual(answers[0],answers[1],'the same whether or not the record exists');
      const g=fixture({preconditions:true,stateKey:vectors.state_manifest_hmac_key});
      const withReceipt=call(g,{...g.req(),receipt:vectors.receipts.person.jws});
      assert.equal(withReceipt.approval.error,'approver_not_authorized','a receipt presented for it is refused the same way');
      assert(!Object.hasOwn(withReceipt.approval,'change_hash'));
      // A server whose account allows no approver type for it in the server-issued profile.
      const h=cov();
      h.core.admin(admin,'settings',{operationTypes:{[OP]:[]}});
      for (const id of ['rec-EXAMPLE-42','rec-EXAMPLE-102-missing']) {
        const out=call(h,h.req({...args(),records:[{id,properties:{owner:'x'}}]}));
        assert.equal(out.approval.error,'approver_not_authorized');
        assert(!Object.hasOwn(out.approval,'change_hash'));
      }
    },
    // 103. Rejection by record state after approval (S65, S48).
    async function rejectionByRecordState() {
      const f=setup();
      f.sor.defineProperty('contact','owner',{restricted:true}); // the principal is not established to see every definition
      const r=req(f,'record-state');r.args.records[0].properties={owner:'x',not_a_defined_property:'bad'};
      const id=ask(f,r,'approval_required before approval, not invalid_input');
      const b=browser(f);await b.login();await b.show(id);assert.equal((await b.decide(id,'approve')).status,200);
      const out=call(f,r);
      assert.equal(out.approval.error,'execution_failed');
      assert(!JSON.stringify(out).includes('not_a_defined_property'),'the message names no record-state reason');
      assert(!JSON.stringify(out).includes('define'));
      assert.equal(f.count(),0);
      const outcome=f.core.records().find(x=>x.record_phase==='outcome');
      assert(outcome,'the audit record shows the failure');
      assert.equal(outcome.outcome,'failed_or_unknown');
    },
    // 104. No issuers for covered operations (S66).
    function noIssuersForCovered() {
      for (const nonreader of [false,true]) {
        const f=cov(); if (nonreader) nonReader(f);
        const out=call(f,req(f,'no-issuers-104'));
        assert.equal(out.approval.error,'approval_required');
        assert(!Object.hasOwn(out.approval,'issuers'),'the refusal lists no issuers');
        const receipt=call(f,{...req(f,'no-issuers-104'),receipt:vectors.receipts.person.jws});
        assert.equal(receipt.approval.error,'approver_not_authorized','a receipt presented for a covered operation is refused');
        assert(!Object.hasOwn(receipt.approval,'issuers'));
      }
      // On a server that offers only signed receipts for the operation, the same.
      const g=fixture({preconditions:true,stateKey:vectors.state_manifest_hmac_key});
      const out=call(g,g.req());
      assert.equal(out.approval.error,'approver_not_authorized');
      assert(!Object.hasOwn(out.approval,'issuers'));
    },
    // 105. Key rotation (S61).
    async function keyRotation() {
      const f=cov(),r=req(f,'rotation-105'),id=ask(f,r),b=browser(f);await b.login();await b.show(id);await b.decide(id,'approve');
      // The key is replaced and the previous key retired: the approved record no longer matches.
      f.core.admin(admin,'settings',{stateKey:crypto.randomBytes(32).toString('hex')});
      const out=call(f,r);
      assert.equal(out.approval.error,'approval_required','the approved record no longer matches');
      assert.equal(f.count(),0);
      assert.equal(f.core.db.prepare('SELECT count(*) n FROM used').get().n,0,'nothing was consumed');
    },
    // 106. Permission source undecided (S60).
    function permissionSourceUndecided() {
      const f=cov();
      // The permission source answers neither yes nor no for the read: the principal
      // is treated as a non-reader, as in test 97.
      f.sor.permission(A,P,OP,null,true);
      const out=call(f,req(f,'undecided-106'));
      assert.equal(out.approval.error,'approval_required');
      assert(!Object.hasOwn(out.approval,'change'),'no change');
      assert(!Object.hasOwn(out.approval,'change_hash'),'no change_hash');
      assert(out.approval.request_key,'request_key is carried');
    },
    // 107. Version token withdrawn (S62).
    function versionTokenWithdrawn() {
      const f=cov();
      const del=f.req({objectType:'contact',action:'delete',records:[{id:'rec-EXAMPLE-42'}]},{operation:'mcp:tools/call:delete_records'});
      const p1=f.core.prepare(del);
      assert.deepEqual(Object.keys(p1.change.preconditions[0]).sort(),['record','state_hash'],'the entry has record and state_hash only');
      // Milestone 1 (changed expectation). The line here was
      //   assert.notEqual(p2...state_hash,p1...state_hash,'a new token gives a new hash')
      // after a bump of the version counter alone. S62: "the server MAY use the `version`
      // kind only where the system of record changes the token on every write to that
      // record; otherwise, and where the server cannot establish this, it MUST use the
      // `fields` kind. A token qualifies only if every write to the record changes it to
      // a value it has not had before for that record, by any path and to any field,
      // including writes made by automation". The sandbox's counter does not qualify (a
      // record that is replaced or created again starts at 1 again), so a delete uses the
      // `fields` kind over every field of the record: every write that changes the
      // record gives a new hash, also one that leaves the counter where it was, and the
      // counter alone decides nothing. Off: delete-uses-version-token.
      f.sor.seed(A,'rec-EXAMPLE-42',{lifecycle_stage:'lead',owner:'changed-without-a-new-token'});
      assert.equal(f.sor.get(A,'rec-EXAMPLE-42').version,1,'this write left the version counter where it was');
      const p2=f.core.prepare(del);
      assert.notEqual(p2.change.preconditions[0].state_hash,p1.change.preconditions[0].state_hash,'a write gives a new hash, also where the token did not change');
      f.sor.db.prepare('UPDATE records SET version=version+1 WHERE account=? AND id=?').run(A,'rec-EXAMPLE-42');
      const p3=f.core.prepare(del);
      assert.equal(p3.change.preconditions[0].state_hash,p2.change.preconditions[0].state_hash,'the hash is over the record\'s fields, not over the token');
    },
    // 108. Missing record shown to the approver (S64, S53).
    async function missingRecordShown() {
      const f=setup();
      const missing=f.req({...args(),records:[{id:'rec-EXAMPLE-108-gone',properties:{owner:'x'}}]});
      const mid=ask(f,missing),b=browser(f);await b.login();
      const page=await b.show(mid);
      assert.equal(page.status,200);
      assert(page.body.includes('This record does not exist in the system of record.'),page.body.slice(0,400));
      const create=f.req({objectType:'contact',id:'rec-EXAMPLE-42',properties:{owner:'y'}},{operation:CREATE});
      const cid=ask(f,create);
      const cpage=await b.show(cid);
      assert(cpage.body.includes('A record with this identifier already exists in the system of record.'),cpage.body.slice(0,400));
      // S64: a create on a free identifier is not told that the record exists.
      const free=ask(f,f.req({objectType:'contact',id:'rec-EXAMPLE-108-free',properties:{owner:'z'}},{operation:CREATE}));
      const fpage=await b.show(free);assert.equal(fpage.status,200);
      assert(!fpage.body.includes('A record with this identifier already exists'),'a create on a free identifier must not be told it exists');
      assert(!fpage.body.includes('This record does not exist'),'a create on a free identifier is not a missing record');
      const p5=browser(f);await p5.login('test-person-5');
      const refused=await p5.show(mid);
      assert.equal(refused.status,403);
      for(const value of ['This record does not exist','rec-EXAMPLE-108-gone','owner'])assert(!refused.body.includes(value));
    },
    // 109. Version 2 only (Section 5, I5).
    function versionTwoOnly() {
      const f=fixture(),i=new Issuer(f.core);
      assert.equal(f.core.prepare(f.req()).change.v,2);
      const v2=changeObject({audience:f.core.settings().audience,account:A,principal:P,operation:OP,args:args()});
      const v1={...v2,v:1};
      assert.throws(()=>i.display(v1),/version/);
      assert.equal(i.display(v2).change.v,2);
    },
    // 110. Copied record value (S67, S4). Covered operation.
    function copiedRecordValue() {
      const f=cov();nonReader(f,COPY);
      f.sor.seed(A,'rec-EXAMPLE-110-source',{lifecycle_stage:'lead',owner:'secret-110'});f.sor.seed(A,'rec-EXAMPLE-110-target',{lifecycle_stage:'lead',owner:'target-110'});
      const r=f.req({objectType:'contact',source:'rec-EXAMPLE-110-source',target:'rec-EXAMPLE-110-target'},{operation:COPY});
      const first=call(f,r);assert.equal(first.approval.error,'approval_required');
      assert(!Object.hasOwn(first.approval,'change'),'the copied source value is not disclosed to a non-reader');
      assert(!Object.hasOwn(first.approval,'change_hash'));
      assert(!Object.hasOwn(r.args,'copied_owner'),'the copied member is absent from the client request');
      const keyChange=changeObject({...r,audience:f.core.settings().audience});
      const expected=f.core.requestKey(keyChange);assert.equal(first.approval.request_key,expected,'the request key is computed before the copy');
      const prepared=f.core.prepare(r);assert.equal(prepared.change.arguments.copied_owner,'secret-110');
      f.sor.seed(A,'rec-EXAMPLE-110-source',{lifecycle_stage:'lead',owner:'changed-110'});
      const repeat=call(f,r);assert.deepEqual(repeat,first,'the non-reader answer and context link stay identical after the source changes');
      const contexts=contextRows(f,expected);assert.equal(contexts.length,1,'one context for the stable request key');
      const open=f.core.db.prepare("SELECT * FROM pending WHERE context=? AND status='pending'").all(contexts[0].token);assert.equal(open.length,1,'one open record');
      assert.equal(JSON.parse(open[0].json).change.arguments.copied_owner,'changed-110','the open record is rebuilt from changed source state');
      assert.equal(f.count(),0);assert.equal(used(f),0);
    },
    // 111. Refusal stable while pending (S67, S68). Covered operation.
    async function refusalStableWhilePending() {
      const f=cov();nonReader(f);const r=req(f,'stable-111');
      const first=call(f,r);assert.equal(first.approval.error,'approval_required');
      const key=first.approval.request_key,token=first.approval.approval_url.split('/').at(-1);
      let contexts=contextRows(f,key);assert.equal(contexts.length,1);const ctx=contexts[0];
      const firstRecord=f.core.db.prepare("SELECT * FROM pending WHERE context=? AND status='pending'").get(ctx.token);assert(firstRecord);
      f.sor.seed(A,'rec-EXAMPLE-42',{lifecycle_stage:'changed-111',owner:'holder-111'});
      const repeat=call(f,r);assert.deepEqual(repeat,first,'the complete member set and link are unchanged');
      assert.equal(contextRows(f,key).length,1);assert.equal(pending(f,"status='pending'"),1);
      const h=cov();nonReader(h,'http:PATCH:/records');const body=req(h,'stable-http-111').args;
      const hfirst=await httpCall(h,{body});assert.equal(hfirst.status,403);
      h.sor.seed(A,'rec-EXAMPLE-42',{lifecycle_stage:'changed-http-111',owner:'holder-http-111'});
      const hrepeat=await httpCall(h,{body});
      assert.equal(hrepeat.status,hfirst.status);assert.deepEqual(hrepeat.headers,hfirst.headers);assert.equal(hrepeat.body,hfirst.body,'same HTTP body, status and headers');
      const hkey=JSON.parse(hfirst.body).approval.request_key;assert.equal(contextRows(h,hkey).length,1);assert.equal(pending(h,"status='pending'"),1);
      const b=browser(f);await b.login();const page=await b.show(token);assert.equal(page.status,200,page.body);
      assert(page.body.includes('changed-111')&&page.body.includes('holder-111'),'the page is built from changed record state');
      const old=f.core.db.prepare('SELECT * FROM pending WHERE id=?').get(firstRecord.id);assert.equal(old.status,'superseded');assert(old.hash.endsWith('#'+old.id),'the superseded record is kept');
      const open=f.core.db.prepare("SELECT * FROM pending WHERE context=? AND status='pending'").all(ctx.token);assert.equal(open.length,1,'exactly one open record exists');
      assert.equal(open[0].hash,f.core.prepare(r).change_hash,'the open record carries the changed state');
      assert.notEqual(open[0].id,firstRecord.id);
    },
    // 112. Query needs read permission (S72). Covered operation.
    function queryNeedsRead() {
      const f=cov({selectionLimit:2});
      for(const id of ['rec-EXAMPLE-42','rec-EXAMPLE-112-b','rec-EXAMPLE-112-c'])f.sor.seed(A,id,{lifecycle_stage:'lead',owner:'public-112'});
      const r=f.req({objectType:'contact',filter:{lifecycle_stage:'lead',owner:'secret-112'},set:{group:'after-112'}},{operation:QUERY});
      f.sor.fieldPermission(A,P,QUERY,'owner',false,'read');
      const before=f.sor.reads(),first=call(f,r);
      assert.deepEqual(first,{ok:false,approval:{error:'permission_denied'}});
      assert.equal(f.sor.reads(),before,'the step 1 refusal runs no query');
      for(const id of ['rec-EXAMPLE-42','rec-EXAMPLE-112-b','rec-EXAMPLE-112-c'])f.sor.seed(A,id,{lifecycle_stage:'lead',owner:'secret-112'});
      const changed=call(f,r);
      assert.deepEqual(changed,first,'the answer cannot depend on a guess about the unreadable field');
      assert.equal(f.sor.reads(),before,'even a selection over the limit is not evaluated');
      assert.equal(f.count(),0);assert.equal(pending(f),0);
      f.sor.fieldPermission(A,P,QUERY,'owner',true,'read');
      const permitted=f.req({objectType:'contact',filter:{lifecycle_stage:'archived'},set:{group:'after-112'}},{operation:QUERY});
      const reads=f.sor.reads(),admitted=call(f,permitted);
      assert.equal(admitted.approval.error,'approval_required');assert(admitted.approval.approval_url);
      assert(f.sor.reads()>reads,'an affirmatively readable domain reaches the query');
    },
    // 113. Limit does not depend on the change (S70, S27). Covered operation.
    function limitIndependent() {
      const f=cov({pendingCap:1});nonReader(f);
      const base=req(f,'cap-113'),tagged=tag=>({...base,args:{...base.args,change_tag:tag}}),a=tagged('a'),b=tagged('b');
      const first=call(f,a);assert.equal(first.approval.error,'approval_required');
      const key=first.approval.request_key,token=first.approval.approval_url.split('/').at(-1);assert.equal(contextRows(f,key).length,1);
      f.sor.seed(A,'rec-EXAMPLE-42',{lifecycle_stage:'changed-113',owner:'holder-113'});
      const repeat=call(f,a);assert.deepEqual(repeat,first,'the existing context answers a repeat, changed state does not re-apply the cap');
      const limited=call(f,b);assert.equal(limited.approval.error,'approval_limit_reached');assert.equal(limited.approval.open,1);assert.equal(limited.approval.limit,1);assert(Number.isInteger(limited.approval.retry_after));
      f.sor.seed(A,'rec-EXAMPLE-42',{lifecycle_stage:'changed-again-113',owner:'another-holder-113'});
      const again=call(f,b);assert.deepEqual(again,limited,'the other request key gets the same limit answer before and after the change');
      assert.equal(contextRows(f,key).length,1);assert.equal(contextRows(f,limited.approval.request_key).length,0,'a capped request opens no context');
      const open=f.core.db.prepare("SELECT * FROM pending WHERE context=? AND status='pending'").all(token);assert.equal(open.length,1,'only the existing context has an open record');
      assert.equal(pending(f),1);assert.equal(f.count(),0);assert.equal(used(f),0);
    },
    // 114. Denial is stable (S68(5), S70). Covered operation.
    async function denialStable() {
      const f=cov();nonReader(f);const r=req(f,'denial-114'),token=ask(f,r),ctx=f.pending.contextOf(token),key=ctx.request_key;
      const b=browser(f);await b.login();await b.show(token);assert.equal((await b.decide(token,'deny')).status,200);
      const first=call(f,r);assert.equal(first.approval.error,'approval_denied');assert.equal(first.approval.retry_after,ctx.expires-f.now());assert(!first.approval.approval_url);
      f.time(f.now()+13);f.sor.seed(A,'rec-EXAMPLE-42',{lifecycle_stage:'changed-114',owner:'holder-114'});
      const second=call(f,r);assert.equal(second.approval.error,'approval_denied');assert.equal(second.approval.retry_after,ctx.expires-f.now());
      assert.equal(first.approval.retry_after-second.approval.retry_after,13);assert.deepEqual(withoutClock(second.approval),withoutClock(first.approval));
      f.time(ctx.expires-1);const last=call(f,r);assert.equal(last.approval.error,'approval_denied');assert.equal(last.approval.retry_after,1);assert.equal(contextRows(f,key).length,1,'no new context while unexpired');
      assert.equal(pending(f),0);assert.equal(used(f),0);
      f.time(ctx.expires);const fresh=call(f,r);assert.equal(fresh.approval.error,'approval_required');assert.notEqual(fresh.approval.approval_url.split('/').at(-1),token);
      assert.equal(contextRows(f,key).length,2,'a fresh context is admitted only at expiry');
      // S30/S31 with S68(5), S70: a denial or a cancellation locks the change for at most
      // one hour, whatever the pending lifetime is, for a covered operation too. With a
      // two-hour pending lifetime the context outlives the lockout: after one hour a new
      // approval can be requested and the write runs, and the earlier denial is history.
      for (const [how,code] of [['deny','approval_denied'],['cancel','approval_cancelled']]) {
        const long=cov({pendingLifetime:7200,approverNotification:true}),lr=req(long,'lockout-covered-114-'+how),t0=long.now();
        const ltoken=ask(long,lr),lctx=long.pending.contextOf(ltoken);
        assert(lctx.expires-t0>=7200,'the fixture\'s context outlives one hour');
        if (how==='deny') {const lb=browser(long);await lb.login();await lb.show(ltoken);assert.equal((await lb.decide(ltoken,'deny')).status,200);assert.equal(call(long,lr).approval.error,'approval_denied');}
        else assert.equal(call(long,{...lr,inputResponses:{approve:{action:'decline'}}}).approval.error,'approval_cancelled');
        assert.equal(call(long,lr).approval.error,code,'the lockout holds at once');
        long.time(t0+3599);assert.equal(call(long,lr).approval.error,code,'the lockout still holds just before one hour');
        long.time(t0+3600);
        const reopened=call(long,lr);
        assert.equal(reopened.approval?.error,'approval_required','after one hour the denial no longer locks the change');
        assert(reopened.approval.approval_url,'a new approval can be requested');
        const lpage=browser(long);await lpage.login();await lpage.show(reopened.approval.approval_url.split('/').at(-1));
        assert.equal((await lpage.decide(reopened.approval.approval_url.split('/').at(-1),'approve')).status,200,'the reopened request can be approved');
        assert(call(long,lr).ok,'the write runs under the new approval');
        assert.equal(long.count(),1);
      }
    },
    // 115. Cancellation is stable (S68(5), S70). Covered operation.
    async function cancellationStable() {
      for(const action of ['decline','cancel']) {
        const f=cov();nonReader(f);const r=req(f,'cancellation-115-'+action),token=ask(f,r),ctx=f.pending.contextOf(token),key=ctx.request_key;
        const first=call(f,{...r,inputResponses:{approve:{action}}});assert.equal(first.approval.error,'approval_cancelled');assert.equal(first.approval.retry_after,ctx.expires-f.now());assert(!first.approval.approval_url);
        f.time(f.now()+17);f.sor.seed(A,'rec-EXAMPLE-42',{lifecycle_stage:'changed-115',owner:'holder-115'});
        const repeat=call(f,r);assert.equal(repeat.approval.error,'approval_cancelled');assert.equal(repeat.approval.retry_after,ctx.expires-f.now());
        assert.equal(first.approval.retry_after-repeat.approval.retry_after,17);assert.deepEqual(withoutClock(repeat.approval),withoutClock(first.approval));
        const accepted=call(f,{...r,inputResponses:{approve:{action:'accept'}}});assert.deepEqual(accepted,repeat,'accept cannot reopen a cancellation');
        f.time(ctx.expires-1);assert.equal(call(f,r).approval.retry_after,1);assert.equal(contextRows(f,key).length,1,'no new context while unexpired');
        f.time(ctx.expires);const fresh=call(f,r);assert.equal(fresh.approval.error,'approval_required');assert.notEqual(fresh.approval.approval_url.split('/').at(-1),token);
        assert.equal(contextRows(f,key).length,2);assert.equal(f.count(),0);assert.equal(used(f),0);
      }
    },
    // 116. Stale approval is not a write (S68(3)). Covered operation.
    async function staleApprovalNotAWrite() {
      const f=cov();nonReader(f);const r=req(f,'stale-116'),first=call(f,r);assert.equal(first.approval.error,'approval_required');
      const token=first.approval.approval_url.split('/').at(-1),b=browser(f);await b.login();await b.show(token);assert.equal((await b.decide(token,'approve')).status,200);
      f.sor.seed(A,'rec-EXAMPLE-42',{lifecycle_stage:'changed-116',owner:'holder-116'});
      const stale=call(f,r);assert.deepEqual(stale,first,'the answer after approval and state change is the one before approval');
      assert.equal(f.count(),0,'nothing was written');assert.equal(used(f),0,'nothing was consumed');
      const old=f.core.db.prepare("SELECT * FROM pending WHERE context=? AND status='stale'").get(token);assert(old,'the approved record is kept as stale');
      assert.equal(pending(f),1,'a new pending record exists in the same context');
      f.sor.seed(A,'rec-EXAMPLE-42',{lifecycle_stage:'lead',owner:'user-EXAMPLE-3'});
      const restored=call(f,r);assert.deepEqual(restored,first,'restoring state never revives the stale approval');
      assert.equal(f.count(),0,'the last repeat did not execute');assert.equal(used(f),0,'the last repeat consumed nothing');
      assert.equal(f.core.db.prepare('SELECT status FROM pending WHERE id=?').get(old.id).status,'stale');
    },
    // 117. Old approval page (S68(4), S43, S50). Covered operation.
    async function oldApprovalPage() {
      const f=cov(),r=req(f,'old-page-117'),token=ask(f,r),b=browser(f);await b.login();
      const oldPage=await b.show(token);assert.equal(oldPage.status,200);const oldId=/name="record" value="([a-f0-9]+)"/.exec(oldPage.body)?.[1];assert(oldId);
      const oldForm=new URLSearchParams({csrf:b.token(),decision:'approve',record:oldId}).toString();
      f.sor.seed(A,'rec-EXAMPLE-42',{lifecycle_stage:'changed-117',owner:'holder-117'});assert.equal(call(f,r).approval.error,'approval_required');
      const old=f.core.db.prepare('SELECT * FROM pending WHERE id=?').get(oldId);assert.equal(old.status,'superseded');
      const current=f.core.db.prepare("SELECT * FROM pending WHERE context=? AND status='pending'").get(token);assert(current&&current.id!==oldId);
      const beforeDecisions=f.core.records().filter(x=>x.record_phase==='decision').length;
      const stalePost=await b.send('POST','/approve/'+token,oldForm);assert.equal(stalePost.status,403,stalePost.body);
      assert(stalePost.body.includes('changed-117')&&stalePost.body.includes('holder-117'),'the old form is answered with the current request');
      assert(stalePost.body.includes('name="decision"'));
      assert.equal(f.core.db.prepare('SELECT count(*) n FROM page_decisions WHERE record=?').get(oldId).n,0,'the superseded record is not approved');
      assert.equal(f.core.records().filter(x=>x.record_phase==='decision').length,beforeDecisions,'no decision, denial or grant was recorded');
      assert.equal(f.core.db.prepare('SELECT status FROM pending WHERE id=?').get(current.id).status,'pending');
      const currentPage=await b.show(token);assert.equal(currentPage.status,200);
      const firstDecision=await b.decide(token,'approve');assert.equal(firstDecision.status,200,firstDecision.body);
      const decisions=f.core.db.prepare('SELECT count(*) n FROM page_decisions WHERE record=?').get(current.id).n;assert.equal(decisions,1);
      const auditDecisions=f.core.records().filter(x=>x.record_phase==='decision').length;
      const replay=await b.decide(token,'approve');assert.deepEqual(replay,firstDecision,'the identical decision POST returns the first result');
      assert.equal(f.core.db.prepare('SELECT count(*) n FROM page_decisions WHERE record=?').get(current.id).n,decisions,'no second decision row');
      assert.equal(f.core.records().filter(x=>x.record_phase==='decision').length,auditDecisions,'no second approval was recorded');
    },
    // 118. Grant closes the pending record (S68(3), S70, S50, S33 to S35).
    async function grantClosesPending() {
      const f=setup(),r=req(f,'sealed'),id=ask(f,r),b=browser(f);await b.login();await b.show(id);
      const done=await b.decide(id,'grant',{max_records:5,minutes:500/60});
      assert.equal(done.status,200,done.body);
      const sealed=await b.show(id);
      assert(sealed.body.includes('A standing grant was made from this change on'),'the record is no longer open');
      assert(!sealed.body.includes('name="decision"'));
      f.sor.seed(A,'rec-EXAMPLE-42',{lifecycle_stage:'changed',owner:'changed-118'}); // the record changes
      const out=call(f,r);
      assert(out.ok,'the identical retry executes under the grant');
      assert.equal(f.count(),1);
      const g=f.pending.grants.get(f.core.db.prepare('SELECT id FROM server_grants ORDER BY rowid DESC').get().id);
      assert.equal(g.charged,1);
      const page=await b.show(id);
      assert(page.body.includes('A standing grant was made from this change on'),'the old page shows the recorded grant');
      assert(!page.body.includes('name="decision"'),'and offers no decision');
    },
    // 119. One context under concurrency (S67). Covered operation.
    async function oneContextUnderConcurrency() {
      const f=cov();nonReader(f);const r=req(f,'concurrent-119');
      const first=await concurrent(f,[r,r],'before-get');
      assert.equal(first.length,2);for(const out of first){assert.equal(out.approval?.error,'approval_required',JSON.stringify(out));assert.deepEqual(out,first[0]);}
      const key=first[0].approval.request_key,contexts=contextRows(f,key);assert.equal(contexts.length,1,'simultaneous requests produce one context');const token=contexts[0].token;
      assert.equal(f.core.db.prepare("SELECT count(*) n FROM pending WHERE context=? AND status='pending'").get(token).n,1,'one open record after simultaneous first requests');
      const b=browser(f);await b.login();await b.show(token);assert.equal((await b.decide(token,'approve')).status,200);
      f.sor.seed(A,'rec-EXAMPLE-42',{lifecycle_stage:'changed-119',owner:'holder-119'});
      const second=await concurrent(f,[r,r],'before-get');
      assert.equal(second.length,2);for(const out of second){assert.equal(out.approval?.error,'approval_required',JSON.stringify(out));assert.deepEqual(out,second[0]);}
      assert.deepEqual(second[0],first[0],'the non-reader answer is also unchanged across the stale replacement');
      assert.equal(contextRows(f,key).length,1);assert.equal(f.core.db.prepare("SELECT count(*) n FROM pending WHERE context=? AND status='pending'").get(token).n,1,'one open record after the stale replacement');
      assert.equal(f.core.db.prepare("SELECT count(*) n FROM pending WHERE context=? AND status='stale'").get(token).n,1,'the approved record is stale');
      assert.equal(f.count(),0);assert.equal(used(f),0);assert(f.core.chainCheck().ok);
    },
    // 120. Identical request after consumption (S69(1), S69(2)).
    async function identicalRequestAfterConsumption() {
      for (const nonreader of [false,true]) {
        const f=cov(); if (nonreader) nonReader(f);
        const r=req(f,'repeat-120-'+nonreader),storedHash=f.core.prepare(r).change_hash;
        const token=ask(f,r),b=browser(f);await b.login();await b.show(token);await b.decide(token,'approve');
        assert(call(f,r).ok); assert.equal(f.count(),1);
        const before=call(f,r),key=before.result.request_key;
        // Someone else changes the record; the answer is the same as when it is unchanged.
        f.sor.seed(A,'rec-EXAMPLE-42',{lifecycle_stage:'changed-120',owner:'someone-else'});
        const after=call(f,r);
        assert(after.ok,JSON.stringify(after)); assert.equal(after.result.changed,1);
        const mark=after.result.recorded_outcome;
        assert.equal(mark.outcome,'success'); assert.equal(mark.sent_now,false);
        assert(mark.message.includes('earlier attempt'),mark.message);
        assert(mark.message.includes(readableTime(mark.at)),mark.message);
        assert(mark.message.includes('Nothing was sent now'),mark.message);
        assert.deepEqual(after,before);
        assert.equal(f.count(),1);assert.equal(used(f),1);assert.equal(pending(f),0);
        assert(!f.core.db.prepare("SELECT 1 FROM pending WHERE hash=? AND status IN ('pending','approved')").get(storedHash),'no new approval record was opened');
        const contexts=contextRows(f,key);assert.equal(contexts.length,1);assert.equal(contexts[0].status,'consumed');
        if(nonreader){assert(!Object.hasOwn(after.result,'change'));assert(!Object.hasOwn(after.result,'change_hash'));}
        else assert.equal(after.result.change_hash,storedHash);
      }
    },
    // 121. Repeat under a grant (S69(1), S34, S35): the identical request does not
    // execute and is not charged.
    async function repeatUnderGrant() {
      for (const nonreader of [false,true]) {
        const f=cov(); if (nonreader) nonReader(f);
        const {g}=await grant(f,req(f,'for-grant-121-'+nonreader));
        const r=req(f,'under-grant-121-'+nonreader),storedHash=f.core.prepare(r).change_hash;
        const first=call(f,r);
        assert(first.ok,JSON.stringify(first)); assert.equal(f.count(),1);
        f.sor.seed(A,'rec-EXAMPLE-42',{lifecycle_stage:'changed-121',owner:'someone-else'});
        const replay=call(f,r),key=replay.result.request_key;
        assert(replay.ok,JSON.stringify(replay)); assert.equal(replay.result.changed,1);
        assert.equal(replay.result.recorded_outcome.outcome,'success');
        assert(replay.result.recorded_outcome.message.includes('earlier attempt'));
        assert(replay.result.recorded_outcome.message.includes(readableTime(replay.result.recorded_outcome.at)));
        assert(replay.grant&&replay.grant.id===g.id,'the grant is still stated');
        assert.equal(f.count(),1,'not executed again');assert.equal(used(f),1);
        assert.equal(f.pending.grants.get(g.id).charged,1,'not charged again');
        const contexts=contextRows(f,key);assert.equal(contexts.length,1);
        assert.equal(f.core.db.prepare("SELECT count(*) n FROM pending WHERE context=? AND status='pending'").get(contexts[0].token).n,0,'the replay opens no approval record for this request');
        assert(!f.core.db.prepare("SELECT 1 FROM pending WHERE hash=? AND status IN ('pending','approved')").get(storedHash),'no new approval record was opened');
        assert.equal(contexts[0].status,'consumed');
        if(nonreader)assert(!Object.hasOwn(replay.result,'change_hash'));else assert.equal(replay.result.change_hash,storedHash);
      }
    },
    // 122. Distinguishing argument (S69(4)). Covered operation.
    async function distinguishingArgument() {
      const f=cov(),base=req(f,'distinguishing-122'),tagged=tag=>({...base,args:{...base.args,change_tag:tag}}),a=tagged('a'),b=tagged('b');
      const pa=f.core.prepare(a),pb=f.core.prepare(b),keyA=f.core.requestKey(pa.change),keyB=f.core.requestKey(pb.change);
      assert.notEqual(keyA,keyB,'the distinguishing argument changes the request key');assert.notEqual(pa.change_hash,pb.change_hash,'and the change hash');
      // Both intended writes carry the argument, at different values (S69(4)).
      const {g}=await grant(f,a);
      const first=call(f,a);assert(first.ok,JSON.stringify(first));assert.equal(f.count(),1);assert.equal(f.pending.grants.get(g.id).charged,1);
      const second=call(f,b);assert(second.ok,JSON.stringify(second),'the second tag still matches the same grant');assert.equal(f.count(),2);assert.equal(f.pending.grants.get(g.id).charged,2);
      const outcomes=f.core.db.prepare('SELECT request_key,change_hash FROM outcomes WHERE request_key IN (?,?) ORDER BY request_key').all(keyA,keyB);
      assert.equal(outcomes.length,2);assert.equal(new Set(outcomes.map(x=>x.change_hash)).size,2);assert(f.pending.grants.get(g.id).charged===2);
      assert(!Object.hasOwn(g.selectors,'change_tag'),'not a selector');assert(!g.fields.includes('change_tag'),'not a field');
      assert(!JSON.stringify(g.records??[]).includes('change_tag'),'not a record identifier');
      assert(!JSON.stringify({selectors:g.selectors,fields:g.fields}).includes('change_tag'));
      // Without a matching grant, the argument is optional and the ordinary flow applies.
      const h=cov(),without=call(h,req(h,'without-distinguishing-122'));
      assert(!Object.hasOwn(without.approval.change.arguments,'change_tag'),'the operation accepts its absence');
      assert.equal(without.approval.error,'approval_required');assert(without.approval.approval_url);assert(without.approval.request_key);
      assert.equal(h.count(),0);assert.equal(used(h),0);assert.equal(pending(h),1);
    },
    // 123. Unknown outcome (S69(3), S25).
    async function unknownOutcome() {
      for(const nonreader of [false,true]) {
        const f=cov();if(nonreader)nonReader(f);
        const r=req(f,'lost-outcome-'+nonreader),storedHash=f.core.prepare(r).change_hash;
        const token=ask(f,r),b=browser(f);await b.login();await b.show(token);await b.decide(token,'approve');
        f.sor.inject('after-write',()=>{throw Error('response lost');});
        // S25: "Where the outcome is unknown and the system of record offers no way to
        // treat a repeat as the same write, the server MUST NOT send the write again and
        // answers that the outcome is unknown." The first answer states it too, never
        // executing a write that did not run.
        const first=call(f,r);
        assert(first.ok,JSON.stringify(first.approval));
        assert.equal(first.result.outcome,'unknown');
        assert(!Object.hasOwn(first.result,'changed'));
        assert(first.result.message.includes('did not report whether it was made'));
        assert.equal(f.count(),1);assert.equal(used(f),1);
        // The system of record does not treat a repeat as the same write: the identical
        // request does not execute and is answered that the outcome is unknown.
        const replay=call(f,r);
        assert(replay.ok,JSON.stringify(replay));
        assert.equal(replay.result.recorded_outcome.outcome,'unknown');
        assert.equal(replay.result.recorded_outcome.sent_now,false);
        assert(replay.result.recorded_outcome.message.includes('not known'));
        assert(replay.result.recorded_outcome.message.includes('Nothing was sent now'));
        assert(replay.result.recorded_outcome.message.includes('change_tag'));
        assert(!Object.hasOwn(replay.result,'changed'));assert.equal(f.count(),1);assert.equal(pending(f),0);
        if(nonreader){assert(!Object.hasOwn(replay.result,'change'));assert(!Object.hasOwn(replay.result,'change_hash'));}
        else assert.equal(replay.result.change_hash,storedHash);
        f.sor.seed(A,'rec-EXAMPLE-42',{lifecycle_stage:'changed-123',owner:'x'});
        const replay2=call(f,r);assert.deepEqual(replay,replay2);
        // When the outcome is learned, the answer becomes the recorded one without
        // reading current record state to decide that change.
        f.core.learnOutcome(storedHash,{outcome:'success',changed:1});
        const learned=call(f,r);
        assert(learned.ok);assert.equal(learned.result.changed,1);
        assert.equal(learned.result.recorded_outcome.outcome,'success');
        assert(learned.result.recorded_outcome.message.includes(readableTime(learned.result.recorded_outcome.at)));
        assert.equal(f.count(),1);assert.equal(used(f),1);assert.equal(pending(f),0);
        // Where the system of record treats the keyed repeat as the same write and the
        // server sends it again, the answer says so and gives the recovered outcome.
        const g=cov();if(nonreader)nonReader(g);g.sor.idempotent=true;
        const gr=req(g,'keyed-lost-'+nonreader),grHash=g.core.prepare(gr).change_hash;
        const gid=ask(g,gr),gb=browser(g);await gb.login();await gb.show(gid);await gb.decide(gid,'approve');
        g.sor.inject('after-write',()=>{throw Error('response lost');});
        const keyedFirst=call(g,gr);
        assert(keyedFirst.ok,JSON.stringify(keyedFirst.approval));
        assert.equal(keyedFirst.result.outcome,'unknown','the first answer states the unknown outcome too');
        const recovered=call(g,gr);
        assert(recovered.ok,JSON.stringify(recovered));
        assert.equal(recovered.result.changed,1);
        assert.equal(recovered.result.recorded_outcome.outcome,'success');
        assert.equal(recovered.result.recorded_outcome.sent_now,false);
        assert.equal(recovered.result.recorded_outcome.sent_again,true);
        assert(recovered.result.recorded_outcome.message.includes('sent again'));
        assert(recovered.result.recorded_outcome.message.includes('earlier attempt'));
        assert(recovered.result.recorded_outcome.message.includes(readableTime(recovered.result.recorded_outcome.at)));
        assert.equal(g.count(),1,'the keyed repeat applies no additional write');assert.equal(used(g),1);assert.equal(pending(g),0);
        if(nonreader)assert(!Object.hasOwn(recovered.result,'change_hash'));else assert.equal(recovered.result.change_hash,grHash);
      }
    },
    // 124. Outcome of a consumed approval (S69, S64, S65, S68(6)). Covered operation.
    // S69, S65, S80: the answer to the identical request returns the recorded
    // outcome, marked as recorded earlier with its time; it opens no approval record, and
    // no open record of the context remains approvable. Off: covered-replay-executes.
    async function outcomeOfAConsumedApproval() {
      for(const nonreader of [false,true]) {
        for(const [label,inject] of [['conflict',()=>{throw Object.assign(Error('conflict'),{sorText:'rejected'});}],['execution_failed',()=>{throw Error('write rejected');}]]) {
          const f=cov();if(nonreader)nonReader(f);
          const r=req(f,'consumed-124-'+label+'-'+nonreader),storedHash=f.core.prepare(r).change_hash;
          const token=ask(f,r),b=browser(f);await b.login();await b.show(token);assert.equal((await b.decide(token,'approve')).status,200);
          f.sor.inject('before-write',inject);
          const first=call(f,r);assert.equal(first.approval?.error,label,label);
          assert.equal(f.count(),0,'the write did not take effect');
          const recordedAt=f.core.db.prepare('SELECT at FROM outcomes WHERE change_hash=?').get(storedHash).at;
          // The identical request is answered with the recorded outcome, marked as earlier.
          const replay=call(f,r);
          assert.equal(replay.approval?.error,label,'the identical request returns the recorded outcome');
          assert(replay.approval.recorded_outcome,'the recorded outcome is marked');assert.equal(replay.approval.recorded_outcome.outcome,label);
          assert.equal(replay.approval.recorded_outcome.at,recordedAt);assert.equal(replay.approval.recorded_outcome.sent_now,false);
          assert(replay.approval.message.includes(readableTime(recordedAt)),'the answer gives the recorded time');
          assert(replay.approval.message.includes('Nothing was sent now'),replay.approval.message);
          assert.equal(f.count(),0,'the repeat opens no approval record');
          assert.equal(used(f),1,'nothing else is consumed');
          // No open record of the context remains approvable.
          const ctx=f.pending.contextOf(token);
          assert.equal(ctx.status,'consumed');
          assert.equal(f.core.db.prepare("SELECT count(*) n FROM pending WHERE context=? AND status IN ('pending','approved')").get(token).n,0,'no open record of the context remains approvable');
          const page=await b.show(token);
          assert.equal(page.status,200,page.body);assert(!page.body.includes('name="decision"'),'the page offers no decision');
          if(nonreader){assert(!Object.hasOwn(replay.approval,'change'));assert(!Object.hasOwn(replay.approval,'change_hash'));}
          else assert.equal(replay.approval.change_hash,storedHash);
        }
      }
    },
    // 125. Consumed contexts do not count (S70, S27). Covered operation.
    async function consumedContextsDoNotCount() {
      const f=cov({pendingCap:1});nonReader(f);
      const base=req(f,'cap-125'),tagged=tag=>({...base,args:{...base.args,change_tag:tag}}),a=tagged('a'),b=tagged('b'),c=tagged('c');
      const first=call(f,a);assert.equal(first.approval.error,'approval_required');
      const tokenA=first.approval.approval_url.split('/').at(-1),keyA=first.approval.request_key;
      assert.equal(call(f,b).approval.error,'approval_limit_reached','another context is refused while A is open');
      const ab=browser(f);await ab.login();await ab.show(tokenA);assert.equal((await ab.decide(tokenA,'approve')).status,200);
      const executedA=call(f,a);assert(executedA.ok,JSON.stringify(executedA));assert.equal(f.pending.contextOf(tokenA).status,'consumed');
      const admittedB=call(f,b);assert.equal(admittedB.approval.error,'approval_required','consuming A releases its slot');
      const tokenB=admittedB.approval.approval_url.split('/').at(-1),keyB=admittedB.approval.request_key;
      const bb=browser(f);await bb.login();await bb.show(tokenB);assert.equal((await bb.decide(tokenB,'approve')).status,200);
      assert.equal(f.pending.contextOf(tokenB).status,'open','approval does not consume its context');
      const limitedC=call(f,c);assert.equal(limitedC.approval.error,'approval_limit_reached','an approved, unconsumed context still counts');assert.equal(limitedC.approval.open,1);
      const executedB=call(f,b);assert(executedB.ok,JSON.stringify(executedB));assert.equal(f.pending.contextOf(tokenB).status,'consumed');
      const admittedC=call(f,c);assert.equal(admittedC.approval.error,'approval_required','consuming B admits the request C had previously been refused');
      assert.equal(contextRows(f,keyA).length,1);assert.equal(contextRows(f,keyB).length,1);assert.equal(contextRows(f,admittedC.approval.request_key).length,1);
      assert.equal(f.count(),2);assert.equal(used(f),2);assert.equal(pending(f),1,'only C remains open');
    },
    // 126. Reader refusal (S63, S68). Covered operation.
    function readerRefusal() {
      const f=cov(),r=req(f,'reader-126'),first=call(f,r);
      assert.equal(first.approval.error,'approval_required');
      assert(Object.hasOwn(first.approval,'change'),'reader gets change');
      assert(Object.hasOwn(first.approval,'change_hash'),'reader gets change_hash');
      assert.deepEqual(first.approval.change,f.core.prepare(r).change);
      const key=first.approval.request_key,contexts=contextRows(f,key);assert.equal(contexts.length,1);
      assert.equal(f.core.db.prepare("SELECT count(*) n FROM pending WHERE context=? AND status='pending'").get(contexts[0].token).n,1);
      const repeat=call(f,r);assert.deepEqual(repeat,first);
      assert.equal(contextRows(f,key).length,1);
      assert.equal(f.core.db.prepare("SELECT count(*) n FROM pending WHERE context=? AND status='pending'").get(contexts[0].token).n,1,'a repeat opens no second record');
    },
    // 127. Same wording for unseen requests (S58, S70). Covered operation.
    async function sameWordingForUnseen() {
      const f=cov(),r=req(f,'unseen-127'),first=call(f,r),token=first.approval.approval_url.split('/').at(-1),ctx=f.pending.contextOf(token);
      const approver=browser(f);await approver.login();await approver.show(token);assert.equal((await approver.decide(token,'deny')).status,200);
      const b=browser(f);await b.login('test-person-5');
      const noOpen=await b.show(token);assert.equal(noOpen.status,403,noOpen.body);
      const unknown=await b.show('deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef');assert.equal(unknown.status,403,unknown.body);
      f.time(ctx.expires);const expired=await b.show(token);assert.equal(expired.status,403,expired.body);
      assert.equal(noOpen.body,unknown.body,'a live context with no open record reveals nothing to a person who may not see it');
      assert.equal(expired.body,unknown.body,'expired and unknown links use the same wording');
      assert.match(unknown.body,/This approval link is not valid or is no longer active/);
      for(const value of ['unseen-127','secret','rec-EXAMPLE-42','denied'])assert(!unknown.body.includes(value));
      assert.deepEqual(noOpen.headers,unknown.headers);assert.deepEqual(expired.headers,unknown.headers);
    },
    // 128. Grant status in a repeat (S68(2), S56). Covered operation.
    async function grantStatusInRepeat() {
      const f=cov();nonReader(f);const r=req(f,'repeat-128'),first=call(f,r);assert.equal(first.approval.error,'approval_required');
      f.sor.seed(A,'rec-EXAMPLE-128-other',{lifecycle_stage:'lead',owner:'user-EXAMPLE-3'});
      const other=f.req({...args(),records:[{id:'rec-EXAMPLE-128-other',properties:{lifecycle_stage:'customer',owner:'other-128'}}]});
      await grant(f,other,5,f.now()+500,'these_records');
      const repeat=call(f,r);assert.equal(repeat.approval.error,'approval_required');assert.equal(repeat.approval.grant_status,'outside');
      const {message:firstMessage,grant_status:firstGrantStatus,...firstRest}=first.approval,{message:repeatMessage,grant_status:repeatGrantStatus,...repeatRest}=repeat.approval;
      // S68(2), with S60(d)/S56: grant_status and its explanatory message are the permitted difference.
      assert.deepEqual(repeatRest,firstRest,'every other member, including the link and request key, is unchanged');
      assert(repeatMessage.startsWith(firstMessage),'the explanation is appended');assert.match(repeatMessage,/grant/i);assert.notEqual(repeatMessage,firstMessage);
    },
    // 129. Selection growth after consumption (S69, S29). Covered operation.
    async function selectionGrowth() {
      const f=cov({selectionLimit:3});f.core.db.prepare('DELETE FROM records WHERE account=?').run(A);
      for(const id of ['rec-EXAMPLE-129-1','rec-EXAMPLE-129-2','rec-EXAMPLE-129-3'])f.sor.seed(A,id,{lifecycle_stage:'lead'});
      const r=f.req({objectType:'contact',filter:{lifecycle_stage:'lead'},set:{owner:'selected-129'}},{operation:QUERY});
      const first=call(f,r);assert.equal(first.approval.error,'approval_required');
      const key=first.approval.request_key,storedHash=first.approval.change_hash,token=first.approval.approval_url.split('/').at(-1);
      const b=browser(f);await b.login();await b.show(token);assert.equal((await b.decide(token,'approve')).status,200);
      const executed=call(f,r);assert(executed.ok,JSON.stringify(executed));assert.equal(executed.result.changed,3);assert.equal(f.count(),3);assert.equal(used(f),1);
      const outcome=f.core.db.prepare('SELECT * FROM outcomes WHERE request_key=?').get(key);assert(outcome);
      f.sor.seed(A,'rec-EXAMPLE-129-4',{lifecycle_stage:'lead'});
      const replay=call(f,r);assert(replay.ok,JSON.stringify(replay));assert(!replay.approval,'not a selection-limit refusal');
      assert.equal(replay.result.request_key,key);assert.equal(replay.result.change_hash,storedHash);assert.equal(replay.result.changed,3);
      assert.equal(replay.result.recorded_outcome.outcome,'success');assert.equal(replay.result.recorded_outcome.at,outcome.at);assert.equal(replay.result.recorded_outcome.sent_now,false);
      assert.equal(f.count(),3,'the grown selection is not executed');assert.equal(used(f),1);assert.equal(pending(f),0);
      assert(!f.core.db.prepare('SELECT 1 FROM history WHERE record=?').get('rec-EXAMPLE-129-4'),'the fourth record has no history row');
      assert(!replay.result.recorded_outcome.message.includes('current record state'));
    },
    // 130. Replay is marked (S69(2)). Covered operation (the distinguishing argument).
    async function replayIsMarked() {
      for(const nonreader of [false,true]) {
        const f=cov();if(nonreader)nonReader(f);
        const r=req(f,'marked-130-'+nonreader),storedHash=f.core.prepare(r).change_hash,token=ask(f,r);
        const b=browser(f);await b.login();await b.show(token);assert.equal((await b.decide(token,'approve')).status,200);
        assert(call(f,r).ok);assert.equal(f.count(),1);assert.equal(used(f),1);
        const key=f.core.db.prepare('SELECT request_key FROM outcomes WHERE change_hash=?').get(storedHash).request_key;
        const stored=f.core.db.prepare('SELECT * FROM outcomes WHERE request_key=?').get(key);assert(stored);
        // A person sets the record back to its earlier values after the write.
        f.sor.seed(A,'rec-EXAMPLE-42',{lifecycle_stage:'lead',owner:'user-EXAMPLE-3'});
        const replay=call(f,r);assert(replay.ok,JSON.stringify(replay));assert.equal(f.count(),1);
        const mark=replay.result.recorded_outcome;assert(mark,'a client-visible member marks the recorded outcome');
        assert.equal(mark.outcome,'success');assert.equal(mark.at,stored.at);assert.equal(mark.sent_now,false);
        assert(mark.message.includes('outcome of an earlier attempt'),mark.message);
        assert(mark.message.includes(readableTime(mark.at)),mark.message);
        assert(mark.message.includes('Nothing was sent now'),mark.message);
        assert(mark.message.includes('new value of the change_tag argument'),mark.message);
        assert.equal(replay.result.changed,1);assert.equal(replay.result.request_key,key);
        if(nonreader){assert(!Object.hasOwn(replay.result,'change'));assert(!Object.hasOwn(replay.result,'change_hash'));}
        else assert.equal(replay.result.change_hash,storedHash,'the reader gets the stored change hash');
        f.sor.seed(A,'rec-EXAMPLE-42',{lifecycle_stage:'third-130',owner:'third-person-130'});
        const changed=call(f,r);assert.deepEqual(changed,replay,'the answer is the same whether or not the record changed');
        assert(!JSON.stringify(changed).includes('third-person-130'),'the replay does not describe current record state');
        assert.equal(f.count(),1);assert.equal(used(f),1);assert.equal(pending(f),0);
        const contexts=contextRows(f,key);assert.equal(contexts.length,1);assert.equal(contexts[0].status,'consumed');
      }
    },
    // 131. Unused approval is shown (S70, S50, S68(3)). Covered operation.
    async function unusedApprovalShown() {
      for(const retired of [false,true]) {
        const f=cov(),r=req(f,'unused-131-'+retired),token=ask(f,r),b=browser(f);await b.login();await b.show(token);assert.equal((await b.decide(token,'approve')).status,200);
        if(retired)f.core.admin(admin,'settings',{stateKey:crypto.randomBytes(32).toString('hex')});
        else f.sor.seed(A,'rec-EXAMPLE-42',{lifecycle_stage:'changed-131',owner:'holder-131'});
        assert.equal(call(f,r).approval.error,'approval_required');assert.equal(used(f),0);
        const page=await b.show(token);assert.equal(page.status,200,page.body);
        for(const words of ['earlier approval','not used','no longer matched'])assert(page.body.includes(words),page.body.slice(0,800));
        assert(page.body.includes('name="decision"'),'the current request is offered for a decision');
        if(!retired)assert(page.body.includes('changed-131')&&page.body.includes('holder-131'),'the current values are shown');
        const current=f.core.db.prepare("SELECT * FROM pending WHERE context=? AND status='pending'").get(token);assert(current);
        const old=f.core.db.prepare("SELECT * FROM pending WHERE context=? AND status='stale'").get(token);assert(old,'the earlier approval is retained as stale');
        assert.equal((await b.decide(token,'approve')).status,200);
        const decided=await b.show(token);assert.equal(decided.status,200,decided.body);assert(!decided.body.includes('name="decision"'),'a decided request offers no second decision');
      }
    },
    // 132. Repeat without a read (S68(3), S42). Covered operation.
    async function repeatWithoutRead() {
      const f=cov();nonReader(f);const r=req(f,'repeat-132'),first=call(f,r),token=first.approval.approval_url.split('/').at(-1);
      const firstRecord=f.core.db.prepare("SELECT * FROM pending WHERE context=? AND status='pending'").get(token);assert(firstRecord);
      f.sor.seed(A,'rec-EXAMPLE-42',{lifecycle_stage:'changed-132',owner:'snapshot-132'});
      const readsBefore=f.sor.reads(),repeat=call(f,r),readsAfter=f.sor.reads();assert.deepEqual(repeat,first);
      // S68(3) makes the read optional here; the observation is that this sandbox read
      // again, which is conforming, not a requirement that readsAfter===readsBefore.
      assert(readsAfter>=readsBefore);
      const b=browser(f);await b.login();const page=await b.show(token);assert.equal(page.status,200,page.body);
      assert(page.body.includes('changed-132')&&page.body.includes('snapshot-132'),'the first displayed page uses changed state');
      assert(!page.body.includes('user-EXAMPLE-3'),'the previously stored snapshot is not displayed');
      assert.equal(f.core.db.prepare('SELECT status FROM pending WHERE id=?').get(firstRecord.id).status,'superseded');
      const open=f.core.db.prepare("SELECT * FROM pending WHERE context=? AND status='pending'").all(token);assert.equal(open.length,1);
      assert.equal(open[0].hash,f.core.prepare(r).change_hash,'the open record was rebuilt from changed state');
    },
    // 133. Read is not skipped where it matters (S68(3), S30, S34). Covered operation.
    async function readNotSkipped() {
      const f=cov();nonReader(f);const r=req(f,'read-grant-133'),first=call(f,r);assert.equal(first.approval.error,'approval_required');
      const {g}=await grant(f,req(f,'grant-source-133'));assert(g.expires>f.now()&&g.revoked===null,'the grant is unexpired and unrevoked');
      const grantReads=f.sor.reads(),granted=call(f,r);assert(granted.ok,JSON.stringify(granted));assert(f.sor.reads()>grantReads,'a repeat with a grant reads record state');
      assert(granted.grant?.id===g.id);assert.equal(f.count(),1);assert.equal(f.pending.grants.get(g.id).charged,1);assert(f.core.db.prepare('SELECT status FROM contexts WHERE token=?').get(first.approval.approval_url.split('/').at(-1)).status==='consumed');
      const h=cov();nonReader(h);const hr=req(h,'read-displayed-133'),hfirst=call(h,hr),token=hfirst.approval.approval_url.split('/').at(-1);
      const hb=browser(h);await hb.login();await hb.show(token);const old=h.core.db.prepare("SELECT * FROM pending WHERE context=? AND status='pending'").get(token);
      h.sor.seed(A,'rec-EXAMPLE-42',{lifecycle_stage:'changed-133',owner:'holder-133'});const displayReads=h.sor.reads(),repeated=call(h,hr);
      // S68(2)/S68(3): the stored-refusal prohibition concerns the processing path.
      // It cannot require a different body, which S68(2) forbids for this non-reader.
      assert(h.sor.reads()>displayReads,'a repeat after display reads record state');assert.deepEqual(repeated,hfirst,'S68(2) keeps the non-reader answer identical during supersession');
      assert.equal(h.core.db.prepare('SELECT status FROM pending WHERE id=?').get(old.id).status,'superseded','S68(3) supersession was not missed');
      assert.equal(h.core.db.prepare("SELECT count(*) n FROM pending WHERE context=? AND status='pending'").get(token).n,1);assert.equal(h.count(),0);
      const k=cov();nonReader(k);const kr=req(k,'read-cancel-133'),kfirst=call(k,kr),ktoken=kfirst.approval.approval_url.split('/').at(-1);
      k.sor.seed(A,'rec-EXAMPLE-42',{lifecycle_stage:'changed-cancel-133',owner:'holder-cancel-133'});
      const cancelled=call(k,{...kr,inputResponses:{approve:{action:'cancel'}}});assert.equal(cancelled.approval.error,'approval_cancelled','S30 handles the cancel response');
      assert.notDeepEqual(cancelled,kfirst);assert.equal(k.count(),0);assert.equal(used(k),0);
      assert.equal(k.core.db.prepare('SELECT status FROM contexts WHERE token=?').get(ktoken).status,'cancelled');
      assert.equal(pending(k),0,'cancellation creates no replacement open record');
    },
    // 134. Approval of a change, not of a state (S71, S53).
    async function approvalOfChangeNotState() {
      const f=setup(),id=ask(f),b=browser(f);await b.login();
      const page=await b.show(id);
      assert(page.body.includes('You are approving the change exactly as requested'),page.body.slice(0,300));
      assert(page.body.includes('You are not approving the state of the record at the moment the write runs'));
      assert(page.body.includes("are the record's current values"),'current values are marked as current values');
      assert(page.body.includes('may change before the write runs'));
      assert(page.body.includes('were read when the request was made'),'old values are marked as read when the request was made');
      const p5=browser(f);await p5.login('test-person-5');
      assert.equal((await p5.show(id)).status,403,'current values are shown only to a person permitted to read them');
    },
    // 135. Repeat while in progress (S69(5)). Covered operation. The two requests
    // interleave on one server instance, which is where it knows the execution is running.
    async function repeatWhileInProgress() {
      const f=cov(),r=req(f,'in-progress-135'),{g}=await grant(f,r,3);
      let during;
      f.sor.inject('after-consume',()=>{during=call(f,r);});
      const outer=call(f,r);assert(outer.ok,JSON.stringify(outer));assert(during,'the first request was held after consumption');
      assert.equal(f.count(),1);assert.equal(f.pending.grants.get(g.id).charged,1);assert.equal(used(f),1);
      assert(during.ok,JSON.stringify(during));
      assert.equal(during.result.recorded_outcome.outcome,'in_progress');assert.notEqual(during.result.recorded_outcome.outcome,'unknown');
      assert.equal(during.result.recorded_outcome.sent_now,false);assert(!Object.hasOwn(during.result,'changed'),'this request sent nothing');
      assert(during.result.recorded_outcome.message.includes('still being carried out'),during.result.recorded_outcome.message);
      assert(during.result.recorded_outcome.message.includes('Ask again'),during.result.recorded_outcome.message);
      assert(during.result.recorded_outcome.message.includes('Nothing was sent now'));
      const key=during.result.request_key;assert(key,'the in-progress answer identifies the request key');
      assert.equal(pending(f),0,'the repeat opens no approval record');
      const contexts=contextRows(f,key);assert.equal(contexts.length,1);assert.equal(contexts[0].status,'consumed');
      const after=call(f,r);assert(after.ok);assert.equal(after.result.recorded_outcome.outcome,'success');
      assert.equal(f.count(),1);assert.equal(f.pending.grants.get(g.id).charged,1,'the third request is neither executed nor charged');assert.equal(used(f),1);
    },
    // 136. Approval within its context (S67). Covered operation.
    async function approvalWithinContext() {
      const f=cov({pendingLifetime:60}),r=req(f,'within-context-136'),token=ask(f,r),ctx=f.pending.contextOf(token),key=ctx.request_key;
      assert(f.now()+f.core.settings().maxLifetime>ctx.expires,'the approval lifetime would otherwise outlive its context');
      const b=browser(f);await b.login();await b.show(token);const decision=await b.decide(token,'approve');assert.equal(decision.status,200,decision.body);
      const approved=f.core.db.prepare("SELECT * FROM pending WHERE context=? AND status='approved'").get(token),claims=JSON.parse(approved.claims);
      assert.equal(claims.exp,ctx.expires,'the approval expires with its context');
      assert(decision.body.includes(readableTime(claims.exp)),'the decision page states the usable-until time');
      assert(call(f,r).ok);assert.equal(used(f),1);
      f.time(ctx.expires+1);const replay=call(f,r);
      assert(replay.ok,JSON.stringify(replay));assert.equal(replay.result.recorded_outcome.outcome,'success');assert(!replay.approval,'not a new approval request after expiry');
      let contexts=contextRows(f,key);assert.equal(contexts.length,1,'no new context while the consumed record is kept');assert.equal(contexts[0].status,'consumed');
      assert.equal(f.count(),1);assert.equal(used(f),1);assert.equal(pending(f),0);
      const fresh=call(f,{...r,args:{...r.args,change_tag:'after-context-expiry-136'}});assert.equal(fresh.approval.error,'approval_required','a different request key may open a context after expiry');
      assert.notEqual(fresh.approval.approval_url.split('/').at(-1),token);assert.equal(contextRows(f,fresh.approval.request_key).length,1);
      // An approved but unconsumed request cannot execute at the context's expiry.
      const h=cov({pendingLifetime:60}),hr=req(h,'unconsumed-context-136'),htoken=ask(h,hr),hctx=h.pending.contextOf(htoken);
      const hb=browser(h);await hb.login();await hb.show(htoken);assert.equal((await hb.decide(htoken,'approve')).status,200);
      h.time(hctx.expires);const unusable=call(h,hr);assert(!unusable.ok);assert(!unusable.result,'the expired approval does not execute');
      assert.equal(h.count(),0);assert.equal(used(h),0);
    },
    // 137. Earlier request shown (S69(4)). Covered operation.
    async function earlierRequestShown() {
      const f=cov();nonReader(f);const base=req(f,'earlier-137'),tagged=tag=>({...base,args:{...base.args,change_tag:tag}});
      const a=tagged('a'),atoken=ask(f,a),b=browser(f);await b.login();await b.show(atoken);assert.equal((await b.decide(atoken,'deny')).status,200);
      const denied=f.core.db.prepare("SELECT * FROM pending WHERE context=? AND status='denied'").get(atoken),claims=JSON.parse(denied.claims);
      const next=tagged('b'),btoken=ask(f,next),page=await b.show(btoken);assert.equal(page.status,200,page.body);
      assert(page.body.includes('An earlier request from this agent in this account, differing only in its change tag, was denied'),page.body.slice(0,1200));
      assert(page.body.includes(readableTime(claims.iat)),'the retained earlier denial includes its recorded time');
      assert(page.body.includes('name="decision"'),'the new pending request is offered for a decision');
      // Only requests equal after removing the distinguishing argument are siblings.
      const different=req(f,'different-owner-137');different.args={...different.args,change_tag:'c'};
      const dtoken=ask(f,different),unrelated=await b.show(dtoken);assert.equal(unrelated.status,200,unrelated.body);
      assert(!unrelated.body.includes('An earlier request from this agent in this account, differing only in its change tag'),'a request differing in another argument has no sibling notice');
    },
    // 138. Filter is a selector (S73, S34). Covered operation.
    async function filterIsSelector() {
      const f=cov();
      f.core.admin(admin,'settings',{grantConfig:{...f.core.settings().grantConfig,[A]:{...f.core.settings().grantConfig[A],[QUERY]:{maxRecords:10,maxSeconds:1000,anyRecord:true}}}});
      f.sor.seed(A,'rec-EXAMPLE-42',{lifecycle_stage:'lead',group:'q'});f.sor.seed(A,'rec-EXAMPLE-138-b',{lifecycle_stage:'lead',group:'q'});f.sor.seed(A,'rec-EXAMPLE-138-other',{lifecycle_stage:'customer',group:'other'});
      const r=f.req({objectType:'contact',filter:{lifecycle_stage:'lead'},set:{notes:'selected-138'}},{operation:QUERY});
      const other=f.req({objectType:'contact',filter:{group:'q'},set:{notes:'selected-138'}},{operation:QUERY});
      const firstSelection=f.core.prepare(r).records,otherSelection=f.core.prepare(other).records;
      assert.equal(firstSelection.length,2);assert.deepEqual(otherSelection,firstSelection,'the different filters select exactly the same records');
      const {g}=await grant(f,r,10,f.now()+500,'any_record');
      const executed=call(f,r);assert(executed.ok,JSON.stringify(executed));assert.equal(f.count(),2);assert.equal(f.pending.grants.get(g.id).charged,2);
      const changed=call(f,other);
      assert.equal(changed.approval.error,'approval_required','a different filter does not match even when its result is identical');
      assert.equal(changed.approval.change.resolved.count,2);assert.equal(f.count(),2,'the other filter wrote nothing');assert.equal(f.pending.grants.get(g.id).charged,2,'and was not charged');
      // S73's second sentence: an identical filter still has to satisfy these_records.
      const h=cov();
      h.core.admin(admin,'settings',{grantConfig:{...h.core.settings().grantConfig,[A]:{...h.core.settings().grantConfig[A],[QUERY]:{maxRecords:10,maxSeconds:1000,anyRecord:true}}}});
      h.sor.seed(A,'rec-EXAMPLE-42',{lifecycle_stage:'lead',group:'q'});h.sor.seed(A,'rec-EXAMPLE-138-b',{lifecycle_stage:'lead',group:'q'});
      const hr=h.req({objectType:'contact',filter:{lifecycle_stage:'lead'},set:{notes:'selected-138'}},{operation:QUERY});
      const {g:hg}=await grant(h,hr,10,h.now()+500,'these_records');assert.equal(hg.records.length,2);
      h.sor.seed(A,'rec-EXAMPLE-138-c',{lifecycle_stage:'lead',group:'q'});
      const outside=call(h,hr);assert.equal(outside.approval.error,'approval_required','the same filter still checks the resolved record set');
      assert.equal(outside.approval.change.resolved.count,3);assert.equal(h.count(),0);assert.equal(h.pending.grants.get(hg.id).charged,0);
    },
    // 139. Results carry no record content (S77).
    async function resultsCarryNoRecordContent() {
      const f=setup();nonReader(f);
      f.sor.seed(A,'rec-EXAMPLE-139',{owner:'secret-owner-139'});
      const r=f.req({objectType:'contact',id:'rec-EXAMPLE-139',properties:{owner:'new'}},{operation:CREATE});
      const id=ask(f,r),b=browser(f);await b.login();await b.show(id);await b.decide(id,'approve');
      const out=call(f,r);
      assert.equal(out.approval.error,'conflict','a create whose record exists is a conflict after consumption');
      assert(!JSON.stringify(out).includes('secret-owner-139'),'no record content in the refusal');
      assert(!JSON.stringify(out).includes('currently holds'),'no error text of the system of record');
      const replay=call(f,r);
      assert.equal(replay.approval.error,'conflict');
      assert(!JSON.stringify(replay).includes('secret-owner-139'),'no record content in the replayed outcome');
      // Under a grant, with the same rejection: a create whose record exists.
      const g=setup();nonReader(g);g.sor.seed(A,'rec-EXAMPLE-139b',{owner:'secret-owner-139b'});
      g.core.admin(admin,'settings',{grantConfig:{[A]:{[OP]:{maxRecords:10,maxSeconds:1000,anyRecord:true},[CREATE]:{maxRecords:10,maxSeconds:1000,anyRecord:true}}}});
      await grant(g,g.req({objectType:'contact',id:'rec-EXAMPLE-139g',properties:{owner:'seed'}},{operation:CREATE}));
      const gr=g.req({objectType:'contact',id:'rec-EXAMPLE-139b',properties:{owner:'new'}},{operation:CREATE});
      const gout=call(g,gr);
      assert.equal(gout.approval.error,'conflict');
      assert(!JSON.stringify(gout).includes('secret-owner-139b'));
      assert(!JSON.stringify(gout).includes('The system of record rejected'));
      assert.equal(g.sor.get(A,'rec-EXAMPLE-139b').properties.owner,'secret-owner-139b');
      // A successful write's result carries only what S77 permits.
      const h=setup();nonReader(h);
      const hr=req(h,'success-139'),hid=ask(h,hr),hb=browser(h);await hb.login();await hb.show(hid);await hb.decide(hid,'approve');
      const ok=call(h,hr);
      assert(ok.ok);
      assert.deepEqual(ok.result,{changed:1},'no value read from the system of record');
      assert(!JSON.stringify(ok).includes('The system of record accepted'));
    },
    // 140. Missing record under a record-scoped permission (S60).
    function recordScopedPermission() {
      const f=setup();nonReader(f);nonReader(f,CREATE);
      f.sor.recordWriteScope(A,P);
      f.sor.recordPermission(A,P,'rec-EXAMPLE-42',true,true);
      f.sor.recordPermission(A,P,'forbidden-record',true,false);
      const missing=call(f,f.req({...args(),records:[{id:'rec-EXAMPLE-140-missing',properties:{owner:'x'}}]}));
      const forbidden=call(f,f.req({...args(),records:[{id:'forbidden-record',properties:{owner:'x'}}]}));
      for (const r of [missing,forbidden]) {
        assert.equal(r.approval.error,'permission_denied');
        assert(!Object.hasOwn(r.approval,'change_hash'));
        assert(!r.approval.approval_url);
        assert.equal(r.approval.message,undefined);
      }
      assert.deepEqual(Object.keys(missing.approval).sort(),Object.keys(forbidden.approval).sort(),'identical apart from values taken from the request');
      assert.equal(f.count(),0);
      assert.equal(pending(f),0,'no approval record was created');
      // An in-scope update and a create still reach the approval flow.
      assert.equal(call(f,req(f,'in-scope')).approval.error,'approval_required');
      assert.equal(call(f,f.req({objectType:'contact',id:'rec-EXAMPLE-140-new',properties:{owner:'y'}},{operation:CREATE})).approval.error,'approval_required');
      // S78 with S60(c): an identifier that resolves to another record is treated as one
      // that names no record, so it gets the same step 1 refusal, even where the named
      // identifier itself carries a write permission.
      f.sor.seed(A,'rec-EXAMPLE-140-target',{owner:'x'});
      f.sor.recordPermission(A,P,'rec-EXAMPLE-140-from',true,true);
      f.sor.merge(A,'rec-EXAMPLE-140-from','rec-EXAMPLE-140-target');
      const resolved=call(f,f.req({...args(),records:[{id:'rec-EXAMPLE-140-from',properties:{owner:'x'}}]}));
      assert.equal(resolved.approval.error,'permission_denied','a resolved identifier is answered as a missing record');
      assert(!Object.hasOwn(resolved.approval,'change_hash'));
      assert.deepEqual(Object.keys(resolved.approval).sort(),Object.keys(missing.approval).sort());
      assert.equal(f.count(),0);
    },
    // 141. Absent record and failed read (S60(i), S67).
    function absentRecordAndFailedRead() {
      const f=setup();
      const out=call(f,f.req({...args(),records:[{id:'rec-EXAMPLE-141-missing',properties:{owner:'x'}}]}));
      assert.equal(out.approval.error,'approval_required','a record that does not exist is answered as any other change');
      assert(out.approval.approval_url);
      assert.equal(pending(f),1);
      const g=setup();
      g.sor.inject('before-get',()=>{throw Object.assign(Error('the system of record did not answer in time'),{code:'approval_unavailable'});});
      const failed=call(g,g.req());
      assert.equal(failed.approval.error,'approval_unavailable');
      assert.equal(g.count(),0);
      assert.equal(pending(g,"1=1"),0,'nothing was superseded, closed or consumed');
      assert.equal(used(g),0);
      // An ordinary error or timeout with no code is also answered approval_unavailable
      // before consumption (S60(i)).
      const h=setup();
      h.sor.inject('before-get',()=>{throw Error('connection to the system of record timed out');});
      const plain=call(h,h.req());
      assert.equal(plain.approval.error,'approval_unavailable','a plain read failure is not invalid_input');
      assert(!JSON.stringify(plain).includes('invalid_input'));
      assert.equal(h.count(),0);
      assert.equal(pending(h,"1=1"),0,'nothing was superseded, closed or consumed');
      assert.equal(used(h),0);
    },
    // 142. Other records close at consumption (S35, S68(6), S50).
    async function otherRecordsClose() {
      const f=setup(),r=req(f,'supersede-me'),id=ask(f,r);
      await grant(f,req(f,'for-supersede')); // a grant covering the same change
      const out=call(f,r);
      assert(out.ok,'the grant consumes the same change');
      assert.equal(f.count(),1);
      assert.equal(f.pending.get(id).status,'superseded','the person record is closed as superseded');
      const b=browser(f);await b.login();await b.list();
      const page=await b.show(id);
      assert(page.body.includes('This change already ran under another approval'),page.body.slice(0,300));
      assert(!page.body.includes('name="decision"'));
      const post=await b.decide(id,'approve');
      assert.equal(post.status,403,'approving its old page does nothing');
      assert(post.body.includes('already ran under another approval'));
      assert.equal(f.core.db.prepare('SELECT count(*) n FROM page_decisions WHERE record=?').get(id).n,0,'no decision was recorded for the superseded record');
      assert.equal(f.count(),1);
      // S35/S50: the supersession is one atomic step with the consumption. Where the
      // grant charge fails and the unit rolls back, the person's record is still pending.
      const h=setup(),hr=req(h,'charge-fails'),hid=ask(h,hr);
      const {g:hg}=await grant(h,req(h,'for-charge-fails'));
      h.sor.inject('before-grant-charge',()=>{const gr=h.pending.grants.get(hg.id);h.core.db.prepare('UPDATE server_grants SET charged=? WHERE id=?').run(gr.max_records,gr.id);});
      const failed=call(h,hr);
      assert.equal(failed.approval.error,'approval_required','the request is treated as one with no approved record');
      assert.equal(h.pending.get(hid).status,'pending','the person record is still pending after the rollback');
      assert(failed.approval.approval_url.endsWith('/approve/'+hid),'and its link is offered again');
      assert.equal(used(h),0);
      assert.equal(h.count(),0);
      assert.equal(h.pending.grants.get(hg.id).charged,0,'nothing was charged');
    },
    // 143. Identifier that resolves to another record (S78).
    async function identifierResolves() {
      // The system of record refuses the write itself.
      const f=setup();nonReader(f);
      f.sor.seed(A,'rec-EXAMPLE-143-from',{owner:'from-143'});f.sor.seed(A,'rec-EXAMPLE-143-target',{owner:'target-143'});
      const r=f.req({...args(),records:[{id:'rec-EXAMPLE-143-from',properties:{owner:'new'}}]});
      const id=ask(f,r),b=browser(f);await b.login();await b.show(id);await b.decide(id,'approve');
      f.sor.merge(A,'rec-EXAMPLE-143-from','rec-EXAMPLE-143-target');
      const out=call(f,r);
      assert.equal(out.approval.error,'conflict','answered as S64 provides after consumption');
      assert.equal(f.sor.get(A,'rec-EXAMPLE-143-target').properties.owner,'target-143','the other record does not change');
      assert(!f.core.db.prepare('SELECT 1 FROM history WHERE record=?').get('rec-EXAMPLE-143-target'));
      // Before consumption, a merged identifier and a missing one are answered alike for
      // a non-reader.
      const g=setup();nonReader(g);
      g.sor.seed(A,'rec-EXAMPLE-143b-from',{});g.sor.seed(A,'rec-EXAMPLE-143b-target',{});
      g.sor.merge(A,'rec-EXAMPLE-143b-from','rec-EXAMPLE-143b-target');
      const merged=call(g,g.req({...args(),records:[{id:'rec-EXAMPLE-143b-from',properties:{owner:'m'}}]}));
      const gone=call(g,g.req({...args(),records:[{id:'rec-EXAMPLE-143b-missing',properties:{owner:'m'}}]}));
      for (const x of [merged,gone]) {assert.equal(x.approval.error,'approval_required');assert(x.approval.change);}
      assert.deepEqual(Object.keys(merged.approval).sort(),Object.keys(gone.approval).sort());
      assert.equal(merged.approval.message,gone.approval.message);
      // The approval page states the resolution to a person permitted to see it and
      // offers no approval.
      const h=setup();h.sor.seed(A,'rec-EXAMPLE-143c-from',{});h.sor.seed(A,'rec-EXAMPLE-143c-target',{});
      const hr=req(h,'merge-143c');hr.args.records[0].id='rec-EXAMPLE-143c-from';
      const hid=ask(h,hr);
      h.sor.merge(A,'rec-EXAMPLE-143c-from','rec-EXAMPLE-143c-target');
      const hb=browser(h);await hb.login();
      const page=await hb.show(hid);
      assert(page.body.includes('rec-EXAMPLE-143c-from'),page.body.slice(0,300));
      assert(page.body.includes('rec-EXAMPLE-143c-target'),'the page states the resolution');
      assert(!page.body.includes('name="decision"'),'no approval is offered');
      assert(!page.body.includes('id="grant-terms"'),'no grant is offered');
      const post=await hb.decide(hid,'approve');
      assert.equal(post.status,403);
      assert.equal(h.core.db.prepare('SELECT count(*) n FROM page_decisions').get().n,0,'a decision posted to it records nothing');
      assert.equal(h.count(),0);
    },
    // 144. Identifier format (S77).
    async function identifierFormat() {
      const bad='x'.repeat(300); // over-long, outside the documented character set
      const f=setup();f.sor.conditional=false;
      f.sor.seed(A,'rec-EXAMPLE-144-from',{owner:'from'});f.sor.seed(A,bad,{owner:'bad'});
      const r=f.req({...args(),records:[{id:'rec-EXAMPLE-144-from',properties:{owner:'new'}}]});
      const id=ask(f,r),b=browser(f);await b.login();await b.show(id);await b.decide(id,'approve');
      f.sor.inject('before-write',()=>{f.sor.merge(A,'rec-EXAMPLE-144-from',bad);});
      const out=call(f,r);
      assert(out.ok,JSON.stringify(out.approval));
      const entry=out.result.entries?.[0];
      assert(entry,'a per-record result');
      assert.equal(entry.outcome,'misdirected');
      assert(!JSON.stringify(out).includes(bad),'the identifier does not appear in the result');
      assert(entry.identifier_withheld===true,'the result says it was withheld');
      const replay=call(f,r);
      assert(replay.ok);
      assert(!JSON.stringify(replay).includes(bad),'the identifier does not appear in a replayed outcome');
      assert.equal(replay.result.entries[0].identifier_withheld,true);
      assert(JSON.stringify(f.core.records().find(x=>x.record_phase==='outcome')).includes(bad),'the audit record holds the identifier the write was applied to');
      // S77: "An identifier returned by the system of record MUST be checked against a
      // format the server derives from that system's own identifier rules ... before it is
      // returned or placed in a message." The applied-to identifier is returned only where
      // this write created the record, the identifier conforms to the documented format,
      // and the principal may read that record (sandbox/README.md). A create that the store
      // applies to a new identifier created that record, so a conforming one is returned.
      const made=setup();made.sor.conditional=false;
      const cr=made.req({objectType:'contact',action:'create',records:[{id:'rec-FMT-144-from',properties:{owner:'made-144'}}]});
      const cid=ask(made,cr),cb=browser(made);await cb.login();await cb.show(cid);await cb.decide(cid,'approve');
      made.sor.inject('before-write',()=>{made.sor.merge(A,'rec-FMT-144-from','rec-FMT-144-target');});
      const created=call(made,cr);
      assert(created.ok,JSON.stringify(created.approval));
      const cEntry=created.result.entries?.[0];
      assert(cEntry,'a per-record result');assert.equal(cEntry.outcome,'misdirected');
      assert.equal(cEntry.applied_identifier,'rec-FMT-144-target','a conforming identifier the write created is returned');
      assert(!Object.hasOwn(cEntry,'identifier_withheld'));
      assert.equal(call(made,cr).result.entries[0].applied_identifier,'rec-FMT-144-target','and on the replay');
      // The same create applied to an identifier that is over-long is withheld (S77).
      const odd=setup();odd.sor.conditional=false;const oddId='y'.repeat(300);
      const or=odd.req({objectType:'contact',action:'create',records:[{id:'rec-FMT-144-odd',properties:{owner:'odd-made-144'}}]});
      const oid=ask(odd,or),ob=browser(odd);await ob.login();await ob.show(oid);await ob.decide(oid,'approve');
      odd.sor.inject('before-write',()=>{odd.sor.merge(A,'rec-FMT-144-odd',oddId);});
      const oddOut=call(odd,or);
      assert(oddOut.ok,JSON.stringify(oddOut.approval));
      assert.equal(oddOut.result.entries[0].identifier_withheld,true,'a non-conforming identifier is withheld');
      assert(!JSON.stringify(oddOut).includes(oddId));
      // A create applied to a record the principal may not read is withheld (S77).
      const hidden=setup();hidden.sor.conditional=false;
      hidden.sor.recordPermission(A,P,'rec-FMT-144-secret',false,true);
      const hr=hidden.req({objectType:'contact',action:'create',records:[{id:'rec-FMT-144-named',properties:{owner:'x-144'}}]});
      const hid=ask(hidden,hr),hb=browser(hidden);await hb.login();await hb.show(hid);await hb.decide(hid,'approve');
      hidden.sor.inject('before-write',()=>{hidden.sor.merge(A,'rec-FMT-144-named','rec-FMT-144-secret');});
      const shadow=call(hidden,hr);
      assert(shadow.ok,JSON.stringify(shadow.approval));
      assert.equal(shadow.result.entries[0].identifier_withheld,true,'an identifier of a record the principal may not read is withheld');
      assert(!JSON.stringify(shadow).includes('rec-FMT-144-secret'));
    },
    // 145. Recorded outcome for every guarded operation (S80, S14).
    async function recordedOutcome() {
      const f=setup();
      const r=req(f,'success-145');
      const sid=ask(f,r),sb=browser(f);await sb.login();await sb.show(sid);await sb.decide(sid,'approve');
      assert(call(f,r).ok);
      const replay=call(f,r);
      assert(replay.ok,JSON.stringify(replay.approval));
      assert.equal(replay.result.changed,1);
      const mark=replay.result.recorded_outcome;
      assert.equal(mark.outcome,'success');
      assert.equal(mark.sent_now,false);
      assert(mark.message.includes('outcome of an earlier attempt'),'the result identifies itself in its message');
      assert(mark.message.includes(readableTime(mark.at)),'with its recorded time');
      assert(mark.message.includes('Nothing was sent now'),'and says that nothing was sent now');
      assert.equal(f.count(),1);
      assert.equal(pending(f),0,'the replay opens no approval record');
      // After a write that failed.
      const g=setup();const fr=req(g,'failed-145');
      const id=ask(g,fr),b=browser(g);await b.login();await b.show(id);await b.decide(id,'approve');
      g.sor.inject('before-write',()=>{throw Error('write rejected');});
      assert.equal(call(g,fr).approval.error,'execution_failed');
      const replay2=call(g,fr);
      assert.equal(replay2.approval.error,'execution_failed');
      assert.equal(replay2.approval.recorded_outcome.outcome,'execution_failed');
      assert(replay2.approval.message.includes('Nothing was sent now'));
      assert(replay2.approval.message.includes('outcome of an earlier attempt'));
      assert(replay2.approval.message.includes(readableTime(replay2.approval.recorded_outcome.at)));
      assert(!Object.hasOwn(replay2.approval,'change'),'S63: only approval_required carries change');
      assert.equal(g.count(),0);
      // While the server knows the execution is still in progress, an identical request
      // is answered as in progress, sends nothing and opens no approval record (S80).
      const k=setup();const ir=req(k,'in-progress-145');
      const kid=ask(k,ir),kb=browser(k);await kb.login();await kb.show(kid);await kb.decide(kid,'approve');
      let during;
      k.sor.inject('before-write',()=>{during=call(k,ir);}); // the identical request, re-entrant during the write
      const outer=call(k,ir);
      assert(outer.ok,'the held execution completes');
      assert.equal(k.count(),1);
      assert(during.ok,JSON.stringify(during));
      assert.equal(during.result.recorded_outcome.outcome,'in_progress');
      assert.equal(during.result.recorded_outcome.sent_now,false);
      assert(!Object.hasOwn(during.result,'changed'),'this request sent nothing');
      assert(during.result.recorded_outcome.message.includes('still being carried out'),during.result.recorded_outcome.message);
      assert.equal(pending(k),0,'the repeat opens no approval record');
      const after=call(k,ir);
      assert(after.ok); assert.equal(after.result.recorded_outcome.outcome,'success','once complete, the repeat is answered with the recorded outcome');
      assert.equal(k.count(),1);
    },
    // 146. Redirected identifier on an operation that is not covered (S78, S77).
    async function redirectedIdentifier() {
      for (const how of ['person','grant']) {
        // The resolution exists before the read before the write: the write is not sent.
        const f=setup();f.sor.conditional=false;nonReader(f);
        f.sor.seed(A,'rec-EXAMPLE-146-from',{owner:'from'});f.sor.seed(A,'rec-EXAMPLE-146-target',{owner:'target-146'});
        const r=req(f,'merge-146-'+how);r.args.records[0].id='rec-EXAMPLE-146-from';
        if (how==='person') {const id=ask(f,r),b=browser(f);await b.login();await b.show(id);await b.decide(id,'approve');}
        else await grant(f,req(f,'for-grant-146-'+how));
        f.sor.merge(A,'rec-EXAMPLE-146-from','rec-EXAMPLE-146-target');
        const out=call(f,r);
        assert.equal(out.approval.error,'conflict','not sent after the read before the write finds the difference');
        assert.equal(f.sor.get(A,'rec-EXAMPLE-146-target').properties.owner,'target-146');
        assert(!f.core.db.prepare('SELECT 1 FROM history WHERE record=?').get('rec-EXAMPLE-146-target'));
        // The resolution appears only after that read: the entry's outcome is misdirected.
        const g=setup();g.sor.conditional=false;nonReader(g);
        g.sor.seed(A,'rec-EXAMPLE-146b-from',{owner:'from'});g.sor.seed(A,'rec-EXAMPLE-146b-target',{owner:'target-146b'});
        const r2=req(g,'merge-146b-'+how);r2.args.records[0].id='rec-EXAMPLE-146b-from';
        if (how==='person') {const id=ask(g,r2),b=browser(g);await b.login();await b.show(id);await b.decide(id,'approve');}
        else await grant(g,req(g,'for-grant-146b-'+how));
        g.sor.inject('before-write',()=>{g.sor.merge(A,'rec-EXAMPLE-146b-from','rec-EXAMPLE-146b-target');});
        const out2=call(g,r2);
        assert(out2.ok,JSON.stringify(out2.approval));
        const entry=out2.result.entries[0];
        assert.equal(entry.outcome,'misdirected');
        assert(!JSON.stringify(out2).includes('rec-EXAMPLE-146b-target'),'the other identifier is not returned to a non-reader');
        assert.equal(g.sor.get(A,'rec-EXAMPLE-146b-target').properties.owner,'merge-146b-'+how);
        const outcome=g.core.records().find(x=>x.record_phase==='outcome');
        assert(JSON.stringify(outcome).includes('rec-EXAMPLE-146b-target'),'the audit record holds the identifier the write was applied to');
        const replay=call(g,r2);
        assert(replay.ok,'a recorded misdirected is a result');
        assert.equal(replay.result.recorded_outcome.outcome,'misdirected');
        assert(!JSON.stringify(replay).includes('rec-EXAMPLE-146b-target'));
      }
    },
    // 147. Step 1 uses the full read model (S60(c), S60(a), S76). A principal that is a
    // reader at operation level but denied read on the record, or on a field the request
    // writes, gets the same step 1 refusal whether the record is present or absent.
    function fullReadModelAtStepOne() {
      const update=id=>({objectType:'contact',records:[{id,properties:{owner:'x'}}]});
      const same=(present,absent,label)=>{
        for(const r of [present,absent]){assert.equal(r.approval.error,'permission_denied',label);assert(!Object.hasOwn(r.approval,'change_hash'),label);}
        assert.equal(JSON.stringify(absent),JSON.stringify(present),label+': the whole answer is identical');
      };
      // Denied read and write on the record itself.
      const record=setup();record.sor.recordWriteScope(A,P);record.sor.recordPermission(A,P,'rec-EXAMPLE-147',false,false);
      record.sor.seed(A,'rec-EXAMPLE-147',{owner:'secret-147'});
      const recordPresent=call(record,record.req(update('rec-EXAMPLE-147')));
      record.sor.db.prepare('DELETE FROM records WHERE account=? AND id=?').run(A,'rec-EXAMPLE-147');
      const recordAbsent=call(record,record.req(update('rec-EXAMPLE-147')));
      same(recordPresent,recordAbsent,'record-level read denial');
      assert.equal(record.count(),0);assert.equal(pending(record),0);
      // Denied read on a field the request writes: under the write scope the record has
      // no write permission, so both cases are the same step 1 refusal.
      const field=setup();field.sor.recordWriteScope(A,P);field.sor.fieldPermission(A,P,OP,'/owner',false,'read');
      field.sor.seed(A,'rec-EXAMPLE-147-field',{owner:'secret-147'});
      const fieldPresent=call(field,field.req(update('rec-EXAMPLE-147-field')));
      field.sor.db.prepare('DELETE FROM records WHERE account=? AND id=?').run(A,'rec-EXAMPLE-147-field');
      const fieldAbsent=call(field,field.req(update('rec-EXAMPLE-147-field')));
      same(fieldPresent,fieldAbsent,'field-level read denial');
      assert.equal(field.count(),0);assert.equal(pending(field),0);
      // A reader of the whole record is not refused: S60(a) holds, so S64 applies.
      const reader=setup();reader.sor.recordWriteScope(A,P);reader.sor.recordPermission(A,P,'rec-EXAMPLE-147-ok',true,true);
      reader.sor.seed(A,'rec-EXAMPLE-147-ok',{owner:'x'});
      assert.equal(call(reader,reader.req(update('rec-EXAMPLE-147-ok'))).approval.error,'approval_required');
      reader.sor.db.prepare('DELETE FROM records WHERE account=? AND id=?').run(A,'rec-EXAMPLE-147-ok');
      assert.equal(call(reader,reader.req(update('rec-EXAMPLE-147-ok'))).approval.error,'approval_required','an absent record is not refused for a reader');
      assert.equal(reader.count(),0);
    },
    // 148. The kind of write comes from the operation, as declared, for step 1, prepare,
    // presentation and execution (S60(c), S65). delete_records declares no action.
    async function deleteByOperation() {
      const f=setup();f.sor.seed(A,'rec-EXAMPLE-148',{owner:'delete-me'});
      const r=f.req({objectType:'contact',records:[{id:'rec-EXAMPLE-148'}]},{operation:'mcp:tools/call:delete_records'});
      assert.equal(f.core.prepare(r).action,'delete','prepare reads the kind of write from the operation');
      const id=ask(f,r),b=browser(f);await b.login();
      const page=await b.show(id);assert.equal(page.status,200);
      assert(page.body.includes('Delete records'),'the operation is named for people');
      assert(page.body.includes('<dt>Action <small>(action)</small></dt><dd>delete</dd>'),'the page says delete');
      assert.equal((await b.decide(id,'approve')).status,200);
      const out=call(f,r);
      assert(out.ok,JSON.stringify(out));
      assert.equal(f.sor.get(A,'rec-EXAMPLE-148'),undefined,'the record is deleted');
      assert.deepEqual(f.sor.db.prepare('SELECT record,action FROM history').all().map(x=>({record:x.record,action:x.action})),[{record:'rec-EXAMPLE-148',action:'delete'}],'the write was a delete');
    },
    // 150. A non-string or missing record identifier follows from the request (S65).
    // Over the HTTP mapping it must be invalid_input before any read, identical whether
    // a record with the numeric identifier exists.
    async function nonStringIdentifiers() {
      const f=setup();
      const entry=id=>id===undefined?{properties:{owner:'x'}}:{id,properties:{owner:'x'}};
      for(const [label,id] of [['numeric',42],['missing',undefined]]){
        const body={objectType:'contact',records:[entry(id)]};
        f.sor.seed(A,'42',{owner:'existing-42'});
        const present=await httpCall(f,{body});
        f.sor.db.prepare('DELETE FROM records WHERE account=? AND id=?').run(A,'42');
        const absent=await httpCall(f,{body});
        for(const r of [present,absent]){
          assert.equal(r.status,403,label+' '+r.body);
          const approval=JSON.parse(r.body).approval;
          assert.equal(approval.error,'invalid_input',label);
          assert(!Object.hasOwn(approval,'change_hash'),label+' carries no change_hash');
          assert(!Object.hasOwn(approval,'approval_url'),label+' carries no approval link');
        }
        assert.equal(present.status,absent.status,label);
        assert.equal(present.body,absent.body,label+': identical whether a record "42" exists');
      }
      // The same entry reaches no approval flow in the in-process core.
      for(const id of [42,undefined]){
        const r=call(f,f.req({objectType:'contact',records:[entry(id)]}));
        assert.equal(r.approval.error,'invalid_input');
        assert(!Object.hasOwn(r.approval,'change_hash'));
      }
      assert.equal(f.count(),0);assert.equal(pending(f),0);
      // A string identifier still reaches the approval flow.
      assert.equal(call(f,f.req({objectType:'contact',records:[entry('rec-EXAMPLE-42')]})).approval.error,'approval_required');
    },
    // 151. A covered operation the default mode does not offer is refused with
    // approver_not_authorized, without reading record state and with no change_hash
    // (S66); the ordinary step 1 refusal comes first for a principal that may not write.
    function queryRefusedByS66() {
      const f=setup();
      const q=f.req({objectType:'contact',filter:{lifecycle_stage:'lead'},set:{owner:'x'}},{operation:QUERY});
      const reads=f.sor.reads(),r=call(f,q);
      assert.equal(r.approval.error,'approver_not_authorized');
      assert(!Object.hasOwn(r.approval,'change_hash'),'no change_hash');
      assert(!Object.hasOwn(r.approval,'approval_url'),'no approval link');
      assert.deepEqual(Object.keys(r.approval),['error']);
      assert.equal(f.sor.reads(),reads,'without reading record state');
      assert.equal(pending(f),0);assert.equal(f.count(),0);
      // The ordinary step 1 refusal precedes S66 for a principal that may not write.
      f.sor.permission(A,P,QUERY,true,false);
      assert.equal(call(f,q).approval.error,'permission_denied');
      // S66 with S72: with preconditions on but no server-issued profile (no approval
      // pages), the profile is not offered for the query, so S66's approver_not_authorized
      // is the answer for a principal that holds the write permission, before any S72
      // read-domain check. A principal whose read permission covers only part of the
      // domain is refused the same way, and the answer does not vary with record state.
      const g=fixture({preconditions:true,stateKey:vectors.state_manifest_hmac_key});
      assert(!g.core.pending,'this fixture offers no server-issued profile');
      g.sor.fieldPermission(A,P,QUERY,'/owner',false,'read');
      const gq=g.req({objectType:'contact',filter:{lifecycle_stage:'lead'},set:{owner:'x'}},{operation:QUERY});
      const coveredReads=g.sor.reads(),refused=call(g,gq);
      assert.equal(refused.approval.error,'approver_not_authorized','S66 precedes the S72 domain check when the profile is not offered');
      assert.deepEqual(Object.keys(refused.approval),['error']);
      assert.equal(g.sor.reads(),coveredReads,'without reading record state');
      g.sor.seed(A,'rec-EXAMPLE-151-lead',{lifecycle_stage:'lead'});
      assert.deepEqual(call(g,gq),refused,'the answer does not depend on the selection');
      assert.equal(g.count(),0);
    },
    // 152. An entry's properties must be an object (S65). Over PATCH /records a null
    // properties value is refused before preparing, and no stored record can hold null.
    async function nullProperties() {
      const f=setup();
      const body={objectType:'contact',records:[{id:'rec-EXAMPLE-42',properties:null}]};
      const r=await httpCall(f,{body});
      assert.equal(r.status,403,r.body);
      const approval=JSON.parse(r.body).approval;
      assert.equal(approval.error,'invalid_input');
      assert(!Object.hasOwn(approval,'change_hash'));
      assert(!Object.hasOwn(approval,'approval_url'));
      assert.deepEqual(f.sor.get(A,'rec-EXAMPLE-42').properties,{lifecycle_stage:'lead',owner:'user-EXAMPLE-3'},'the record is untouched');
      assert.equal(call(f,f.req(body)).approval.error,'invalid_input','the in-process core refuses it too');
      // No stored record can hold null properties, including through a direct write.
      assert.throws(()=>f.sor.write(A,[{id:'rec-EXAMPLE-42',properties:null}],'update','contact'),/invalid_input/);
      assert.equal(f.sor.db.prepare("SELECT count(*) n FROM records WHERE properties='null'").get().n,0);
      assert.equal(f.count(),0);assert.equal(pending(f),0);
      // A later update of the same record is not state-dependent on a broken record.
      assert.equal(call(f,f.req({objectType:'contact',records:[{id:'rec-EXAMPLE-42',properties:{owner:'ok'}}]})).approval.error,'approval_required');
    },
    // 153. read_record with field-level read denials (S60, S76, S77). A field the
    // permission model denies is absent from the record and listed in `withheld`. The
    // list names every denied field of the object type, so it does not disclose whether
    // the record holds a value for it; nothing is listed when nothing is denied.
    async function readRecordFieldDenials() {
      const f=fixture();
      f.sor.seed(A,'rec-FIELD-153',{owner:'secret-owner-153',lifecycle_stage:'lead',notes:'notes-153'});
      f.sor.seed(A,'rec-FIELD-153-empty',{lifecycle_stage:'lead'});
      f.sor.fieldPermission(A,P,OP,'/owner',false,'read');
      await sdk(f,'organization',async c=>{
        const read=id=>c.callTool({name:'read_record',arguments:{id}});
        const withValue=await read('rec-FIELD-153'),withoutValue=await read('rec-FIELD-153-empty');
        assert(!withValue.isError,JSON.stringify(withValue));
        const body=JSON.parse(withValue.content[0].text),empty=JSON.parse(withoutValue.content[0].text);
        assert.equal(body.properties.owner,undefined,'a denied field is not returned');
        assert(!JSON.stringify(body).includes('secret-owner-153'),'no denied value appears');
        assert(Array.isArray(body.withheld),'the unreadable field is flagged');
        assert(body.withheld.includes('/owner'),JSON.stringify(body.withheld));
        assert.equal(body.properties.lifecycle_stage,'lead','the readable fields are returned');
        assert.equal(body.properties.notes,'notes-153');
        assert.equal(empty.properties.owner,undefined);
        assert(Array.isArray(empty.withheld),'the flag is present for a record without a value too');
        assert.deepEqual(empty.withheld,body.withheld,'the flag does not depend on record state');
        // Nothing denied: the record is unchanged and no flag appears.
        f.sor.fieldPermission(A,P,OP,'/owner',true,'read');
        const full=await read('rec-FIELD-153');
        assert(!full.isError,JSON.stringify(full));
        const whole=JSON.parse(full.content[0].text);
        assert(!Object.hasOwn(whole,'withheld'),'no withheld member when nothing is denied');
        assert.deepEqual(whole,f.sor.get(A,'rec-FIELD-153'),'a full reader sees the record unchanged');
      });
    },
  ];
  const names=['Refusals without hash for non-readers','Keyed state and manifest hashes','Same answer for missing and existing records','No version or absent member','Conflict after approval','Signed receipts only','Rejection by record state after approval','No issuers for covered operations','Key rotation','Permission source undecided','Version token withdrawn','Missing record shown to the approver','Version 2 only','Copied record value','Refusal stable while pending','Query needs read permission','Limit does not depend on the change','Denial is stable','Cancellation is stable','Stale approval is not a write','Old approval page','Grant closes the pending record','One context under concurrency','Identical request after consumption','Repeat under a grant','Distinguishing argument','Unknown outcome','Outcome of a consumed approval','Consumed contexts do not count','Reader refusal','Same wording for unseen requests','Grant status in a repeat','Selection growth after consumption','Replay is marked','Unused approval is shown','Repeat without a read','Read is not skipped where it matters','Approval of a change, not of a state','Repeat while in progress','Approval within its context','Earlier request shown','Filter is a selector','Results carry no record content','Missing record under a record-scoped permission','Absent record and failed read','Other records close at consumption','Identifier that resolves to another record','Identifier format','Recorded outcome for every guarded operation','Redirected identifier on an operation that is not covered','Full read model at step 1','Delete as declared by the operation','Non-string record identifiers refused','Query refused by S66 in the default mode','Null properties refused','Read with field-level denials'];
  return {tests,names};
}
