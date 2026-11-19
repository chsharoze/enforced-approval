import assert from 'node:assert/strict';
import { OP } from '../src/core.mjs';
import { anyWarning, formatTime, plural, readableTime, shapeWords } from '../src/presentation.mjs';
// Tests 89 to 92 of spec/CONFORMANCE.md.
export function cases({helpers:{setup,req,ask,browser,grant},call,A,sdk}) {
  const live=(f,g)=>f.pending.grants.get(g.id);
  const newest=f=>f.pending.grants.get(f.core.db.prepare('SELECT id FROM server_grants ORDER BY rowid DESC').get().id);
  const tests=[
    // 89. Words, not identifiers (S57).
    async function wordsNotIdentifiers() {
      const f=setup(),r=req(f,'labels');r.args.records[0].properties.uncovered='value';
      const id=ask(f,r),b=browser(f);
      const shell=await b.send('GET','/approve/'+id);
      assert.match(shell.body,/<title>Sign in \| Approval sandbox<\/title>/,shell.body.slice(0,200));
      await b.login();
      const page=await b.show(id);
      assert.match(page.body,/<title>Review change \| Approval sandbox<\/title>/);
      // The operation and each field carry a name for people, technical identifier secondary.
      assert(page.body.includes('Update records <small>(mcp:tools/call:manage_records)</small>'),page.body);
      assert(page.body.includes('Object type <small>(objectType)</small>'));
      assert(page.body.includes('Action <small>(action)</small>'));
      assert(page.body.includes('Lifecycle stage <small>(/lifecycle_stage)</small>'));
      assert(page.body.includes('Owner <small>(/owner)</small>'));
      assert(page.body.includes('Uncovered <small>(/uncovered)</small>'),'an unmapped defined property falls back to a tidied name');
      // The value beside the minutes input is labelled as the latest possible expiry, the maximum.
      assert(page.body.includes('Latest possible expiry'));
      assert(page.body.includes('maximum expiry you may choose'));
      assert(page.body.includes(readableTime(f.now()+1000)),'the maximum expiry in readable form');
      assert(!page.body.includes(formatTime(f.now()+1000)),'pages show one time form only (S57)');
      // The confirmation states the expiry actually set, the record limit and the shape in words.
      const done=await b.decide(id,'grant',{max_records:5,minutes:500/60});
      assert.equal(done.status,200,done.body);
      assert.match(done.body,/<title>Grant created \| Approval sandbox<\/title>/);
      assert(done.body.includes(readableTime(f.now()+500)),'the expiry actually set');
      assert(done.body.includes('Record limit'));
      assert(done.body.includes(shapeWords('any_record')));
      assert(done.body.includes(anyWarning),'the any-record warning is repeated');
      // Grants list: state in words, remaining only for active grants, its own title.
      const g=newest(f);
      const listed=await b.list();
      assert.match(listed.body,/<title>Your grants \| Approval sandbox<\/title>/);
      assert(listed.body.includes(`<td>${plural(g.max_records-g.charged)}</td>`),'an active grant shows its remaining count');
      for(const [state,charged,revoked,atExpiry] of [['used up',5,null,false],['expired',0,null,true],['revoked',0,g.made_at,false]]) {
        f.core.db.prepare('UPDATE server_grants SET charged=?,revoked=? WHERE id=?').run(charged,revoked,g.id);
        if(atExpiry)f.time(g.expires);else f.time(g.made_at+2);
        const row=await b.list();
        assert(row.body.includes(`<td>${state}</td>`),state);
        assert(row.body.includes('<td>-</td>'),state+' must not show a remaining count as usable');
      }
      // Each remaining page has its own title.
      const approvedId=ask(f,req(f,'approve-title'));await b.show(approvedId);
      assert.match((await b.decide(approvedId,'approve')).body,/<title>Change approved \| Approval sandbox<\/title>/);
      const deniedId=ask(f,req(f,'deny-title'));await b.show(deniedId);
      assert.match((await b.decide(deniedId,'deny')).body,/<title>Change denied \| Approval sandbox<\/title>/);
      const revokeId=ask(f,req(f,'revoke-title'));await b.show(revokeId);
      await b.decide(revokeId,'grant',{max_records:5,minutes:500/60});
      assert.match((await b.revoke(newest(f).id)).body,/<title>Grant revoked \| Approval sandbox<\/title>/);
      const missing=await b.send('GET','/approve/'+'e'.repeat(48));
      assert.equal(missing.status,403);
      assert.match(missing.body,/<title>Problem \| Approval sandbox<\/title>/);
    },
    // 90. Readable errors (S58).
    async function readableErrors() {
      const f=setup(),id=ask(f),b=browser(f);await b.login();
      const isPage=(r,heading)=>{assert([403,404,426].includes(r.status),r.status);assert.equal(r.headers['content-type'],'text/html; charset=utf-8',r.headers['content-type']);assert(r.body.includes('<h1>'),'a heading in plain words');assert(r.body.includes('What to do next'),'one line on what to do next');assert(r.body.toLowerCase().includes(heading),r.body);assert(r.body.includes('</html>'),'never an empty body');assert(!r.body.includes('new-owner'),'no record data on an error page');assert.match(r.headers['content-security-policy'],/frame-ancestors 'none'/);assert.equal(r.headers['cache-control'],'no-store');assert.equal(r.headers['referrer-policy'],'same-origin');};
      isPage(await b.send('GET','/approve/'+'d'.repeat(48)),'not valid or is no longer active'); // an unknown link (S58 wording)
      await b.show(id);assert.equal((await b.decide(id,'approve')).status,200);
      isPage(await b.decide(id,'deny'),'already recorded'); // a second decision
      const forged=ask(f,req(f,'forgery'));
      isPage(await b.send('POST','/approve/'+forged,new URLSearchParams({decision:'approve'})),'not sent from this page'); // a failed forgery check
      const p2=browser(f);await p2.login('test-person-2');const protectedId=ask(f,req(f,'no-permission'));
      assert.equal((await p2.show(protectedId)).status,200);
      isPage(await p2.decide(protectedId,'approve'),'not permitted'); // a person without permission
      const limited=ask(f,req(f,'bad-limit'));await b.show(limited);
      isPage(await b.decide(limited,'grant',{max_records:99,minutes:500/60}),'outside what is allowed'); // a bad limit
      isPage(await b.decide(limited,'grant',{max_records:5,minutes:17}),'outside what is allowed'); // a bad expiry
      f.time(f.pending.get(limited).expires);
      isPage(await b.show(limited),'not valid or is no longer active'); // an expired link (S58 wording)
    },
    // 91. Invalid input names its cause (S3, S48).
    async function invalidInputReason() {
      const f=setup(),r=req(f);r.args.records[0].properties.not_a_defined_property='never-defined';
      const out=call(f,r);
      assert.equal(out.approval.error,'invalid_input');
      assert.deepEqual(out.approval.invalid,['/not_a_defined_property']);
      assert(out.approval.message.includes('not_a_defined_property'),out.approval.message);
      assert(!Object.hasOwn(out.approval,'change_hash'));
      assert(!Object.hasOwn(out.approval,'approval_url'));
      const nested=req(f);nested.args.records[0].properties={profile:{undefined_child:'bad'}};
      const nestedOut=call(f,nested);
      assert.equal(nestedOut.approval.error,'invalid_input');assert.deepEqual(nestedOut.approval.invalid,['/profile/undefined_child']);assert(nestedOut.approval.message.includes('/profile/undefined_child'));
      for(const [args,word] of [[[],'not a JSON object'],[{x:'\ud800'},'lone surrogate'],[{x:9007199254740993},'number']]) {
        const res=call(f,f.req(args));
        assert.equal(res.approval.error,'invalid_input');assert(res.approval.message.includes(word),res.approval.message);
        assert(!Object.hasOwn(res.approval,'change_hash'));assert(!Object.hasOwn(res.approval,'approval_url'));
      }
      for(const [raw,word] of [['{"x":1,"x":2}','duplicate member name'],['{"x":9007199254740993}','safe range']]) {
        const res=call(f,f.req({},{rawArguments:raw}));
        assert.equal(res.approval.error,'invalid_input');assert(res.approval.message.includes(word),res.approval.message);
      }
    },
    // 92. Reason on the elicitation (S56).
    async function elicitationReason() {
      const f=setup(),{g}=await grant(f,req(f,'under-grant'),1,f.now()+500);
      assert(call(f,req(f,'under-grant')).ok);assert.equal(live(f,g).charged,1);
      const beyond=req(f,'beyond');
      const refusal=call(f,beyond);
      assert.equal(refusal.approval.error,'approval_required');assert.equal(refusal.approval.grant_status,'used_up');
      await sdk(f,'server',async(client,elicited)=>{
        const result=await client.callTool({name:'manage_records',arguments:structuredClone(beyond.args)});
        assert(elicited.length>0,'a URL mode elicitation was sent');
        assert.match(elicited[0].message,/used up/i,JSON.stringify(elicited[0]));
        assert.equal(elicited[0].message,JSON.parse(result.content[0].text).message,'the elicitation text is the refusal message');
      });
    },
  ];
  return {tests,names:['Words, not identifiers','Readable error pages','Invalid input names its cause','Reason on the elicitation']};
}
