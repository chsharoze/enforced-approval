import assert from 'node:assert/strict';
import { OP, QUERY, CREATE, mcpResult } from '../src/core.mjs';
import { anyWarning, formatTime, readableTime, shapeWords } from '../src/presentation.mjs';
export function cases({helpers:{setup,req,ask,browser,grant},call,A}) {
  const person={id:'test-person',authenticated:true},live=(f,g)=>f.pending.grants.get(g.id);
  function status(f,r,expected,word) {const count=f.count(),out=call(f,r);assert.equal(out.approval?.error,'approval_required');assert.equal(out.approval.grant_status,expected);assert(out.approval.message.toLowerCase().includes(word));assert.equal(f.count(),count);return out;}
  const tests=[
    async function anyWarningTest() {
      for(const shape of ['any_record','these_records']) {
        const f=setup(),{page,done,g}=await grant(f,req(f),5,f.now()+500,shape);assert(page.body.includes('These records only'));assert(page.body.includes('Any record you may change'));assert(page.body.includes(anyWarning));assert(page.body.includes('Fixed records for this choice:'));
        assert(done.body.includes(shapeWords(shape)));if(shape==='any_record'){assert(done.body.includes(anyWarning));assert(!done.body.includes('Fixed records'));assert(!done.body.includes('rec-EXAMPLE-42'));assert(!Object.hasOwn(g,'records'));}
        else {assert(!done.body.includes(anyWarning));assert(done.body.includes('rec-EXAMPLE-42'));}
      }
    },
    async function undefinedProperty() {
      const f=setup(),r=req(f);r.args.records[0].properties.not_a_defined_property='never-defined';const before=f.core.db.prepare('SELECT count(*) n FROM pending').get().n;
      const check=()=>{const result=call(f,r);assert.equal(result.approval.error,'invalid_input');assert(!result.approval.approval_url);assert.equal(f.count(),0);assert.equal(f.core.db.prepare('SELECT count(*) n FROM pending').get().n,before);};check();
      const change={...f.core.prepare(req(f)).change,arguments:r.args};assert.equal(f.pending.grants.offer(change,person),undefined);assert(!f.pending.grants.match(change));
      const {g}=await grant(f);const pending=f.core.db.prepare('SELECT count(*) n FROM pending').get().n;const out=call(f,r);assert.equal(out.approval.error,'invalid_input');assert.equal(f.core.db.prepare('SELECT count(*) n FROM pending').get().n,pending);assert.equal(live(f,g).charged,0);assert.equal(f.count(),0);
      assert.throws(()=>f.sor.write(A,r.args.records,'update','contact'),/invalid_input/);assert.equal(f.count(),0);
      const q=setup({preconditions:true});
      for(const operation of [QUERY,CREATE]) {const x=operation===QUERY?q:f;const args=operation===QUERY?{objectType:'contact',filter:{},set:{not_a_defined_property:'bad'}}:{objectType:'contact',id:'no-created',properties:{not_a_defined_property:'bad'}};assert.equal(call(x,x.req(args,{operation})).approval.error,'invalid_input');}
      const nested=req(f);nested.args.records[0].properties={profile:{undefined_child:'bad'}};assert.equal(call(f,nested).approval.error,'invalid_input');
      for(const property of ['owner','lifecycle_stage','notes','email','phone','company'])assert(f.sor.defined('contact',{[property]:'v'}));assert(!f.sor.defined('deal',{phone:'v'}));
    },
    async function noGrantReason() {
      const none=setup(),no=call(none,req(none));assert.equal(no.approval.error,'approval_required');assert(!Object.hasOwn(no.approval,'grant_status'));
      const used=setup(),{g:ug}=await grant(used,req(used),1);assert(call(used,req(used)).ok);status(used,req(used,'beyond-limit'),'used_up','used up');assert.equal(live(used,ug).charged,1);
      const exp=setup(),{g:eg}=await grant(exp,req(exp),5,exp.now()+60);exp.time(eg.expires);status(exp,req(exp,'after-expiry'),'expired','expired');assert.equal(live(exp,eg).charged,0);
      const rev=setup(),{g:rg,b:rb}=await grant(rev);assert.equal((await rb.revoke(rg.id)).status,200);status(rev,req(rev,'after-revoke'),'revoked','revoked');
      const outside=setup(),{g:og}=await grant(outside,req(outside),5,outside.now()+500,'these_records');const field=req(outside,'outside-field');field.args.records[0].properties.notes='not covered';status(outside,field,'outside','field');outside.sor.seed(A,'new-record',{});const record=req(outside,'outside-record');record.args.records[0].id='new-record';status(outside,record,'outside','record');assert.equal(live(outside,og).charged,0);
      const other=call(outside,{...req(outside),principal:'agent-EXAMPLE-other'});assert(!Object.hasOwn(other.approval,'grant_status'));
      const mixed=setup(),{g:old,b:oldBrowser}=await grant(mixed),wide=req(mixed,'newest');wide.args.records[0].properties.notes='newer';const {g:newest}=await grant(mixed,wide,5,mixed.now()+120);await oldBrowser.revoke(old.id);mixed.time(newest.expires);status(mixed,req(mixed,'newest-reason'),'expired','expired');
    },
    async function readablePages() {
      const f=setup(),{g,id:approvalId,b,page,done}=await grant(f);for(const label of ['Operation','Account','Agent','Record:','Field','Old value','New value'])assert(page.body.includes(label),label);assert(page.body.includes('user-EXAMPLE-3'));assert(page.body.includes('new-owner'));assert(page.body.includes('<details>'));assert(page.body.includes('name="minutes"'));assert(!page.body.includes('name="expires"'));assert(page.body.includes('Allowed maximum: 10 records'));assert(page.body.includes('Allowed maximum: 16 minutes 40 seconds'));assert(done.body.includes(readableTime(g.expires)));assert(done.body.includes(readableTime(g.made_at)));assert(!done.body.includes(formatTime(g.expires)),'one time form only (S57)');assert(!done.body.includes(String(g.expires)));
      // Duration retries remain the same decision even after time advances.
      f.time(f.now()+2);const again=await b.decide(approvalId,'grant',{max_records:5,minutes:500/60});assert.equal(again.status,200);assert.equal(again.body,done.body);assert.equal(f.core.db.prepare('SELECT count(*) n FROM server_grants').get().n,1);
      for(const [state,charged,expires,revoked] of [['used up',5,g.expires,null],['expired',0,f.now(),null],['revoked',0,g.expires,f.now()],['active',0,g.expires,null]]) {
        f.core.db.prepare('UPDATE server_grants SET charged=?,revoked=? WHERE id=?').run(charged,revoked,g.id);if(state==='expired')f.time(g.expires);else f.time(g.made_at+2);
        const listed=await b.list();assert.equal(listed.status,200);assert(listed.body.includes('<table>'));for(const label of ['Fields','Shape','State','Records used','Records remaining','Made at','Expires at'])assert(listed.body.includes(label),label);assert(listed.body.includes('<td>'+state+'</td>'));assert(listed.body.includes(readableTime(g.expires)));assert(listed.body.includes(readableTime(g.made_at)));assert(!listed.body.includes(formatTime(g.expires)),'one time form only (S57)');assert.equal((listed.body.match(/<button>Revoke<\/button>/g)??[]).length,state==='active'?1:0);assert(!listed.body.includes(String(g.expires)));
      }
      const h=setup(),id=ask(h),hb=browser(h);await hb.login();await hb.show(id);const approved=await hb.decide(id,'approve');assert(approved.body.includes(readableTime(h.now()+300)));
      const q=setup(),qid=ask(q),qb=browser(q);await qb.login();await qb.show(qid);assert.equal((await qb.decide(qid,'grant',{shape:'any_record',max_records:5,minutes:0})).status,403);assert.equal((await qb.decide(qid,'grant',{shape:'any_record',max_records:5,minutes:17})).status,403);
      const legacy=await qb.send('POST','/approve/'+qid,new URLSearchParams({csrf:qb.token(),decision:'grant',shape:'any_record',max_records:5,expires:q.now()+500}));assert.equal(legacy.status,403);
    },
    async function wording() {for(const shape of ['these_records','any_record']) {const f=setup(),{g}=await grant(f,req(f),5,f.now()+500,shape),out=mcpResult(call(f,req(f))),text=out.content.filter(c=>c.type==='text').map(c=>c.text).join('\n');for(const phrase of ['grant','standing permission','not an approval of this one change',g.id,shapeWords(shape),'records remaining: 4 records',formatTime(g.expires)])assert(text.includes(phrase),text);assert(!text.includes(String(g.expires)));}}
  ];
  return {tests,names:['Any-record warning','Undefined property','Why no grant applied','Readable pages','Grant wording']};
}
