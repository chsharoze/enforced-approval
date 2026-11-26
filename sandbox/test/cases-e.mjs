import assert from 'node:assert/strict';
import { OP } from '../src/core.mjs';
import { readableTime, formatTime } from '../src/presentation.mjs';
// Tests 93 to 95 of spec/CONFORMANCE.md.
export function cases({helpers:{setup,req,ask,browser,grant},call,A,sdk}) {
  const tests=[
    // 93. Decided links (S50).
    async function decidedLinks() {
      const f=setup(),b=browser(f);await b.login();
      const aId=ask(f,req(f,'approve-one'));await b.show(aId);assert.equal((await b.decide(aId,'approve')).status,200);
      const dId=ask(f,req(f,'deny-one'));await b.show(dId);assert.equal((await b.decide(dId,'deny')).status,200);
      const {id:gId}=await grant(f,req(f,'grant-one'));
      const decided=await b.show(aId);
      assert.equal(decided.status,200);
      assert.match(decided.body,/<title>Change approved \| Approval sandbox<\/title>/,decided.body.slice(0,200));
      assert(decided.body.includes('This change was approved on'),decided.body);
      assert(decided.body.includes(readableTime(f.now())),'the decision time in readable form');
      assert(decided.body.includes(readableTime(f.now()+300)),'until when the approval can be used');
      assert(!decided.body.includes(formatTime(f.now()+300)),'pages show one time form only (S57)');
      assert(!decided.body.includes('name="decision"'),'no decision form on a decided link');
      assert(!decided.body.includes('Review the saved change'),'the change is not presented as open');
      assert(!decided.body.includes('Old value'),'old values are not shown as current');
      assert(!decided.body.includes('id="grant-terms"'),'no grant form on a decided link');
      const denied=await b.show(dId);
      assert.match(denied.body,/<title>Change denied \| Approval sandbox<\/title>/);
      assert(denied.body.includes('This change was denied on'));
      assert(denied.body.includes('It will not run.'));
      assert(!denied.body.includes('name="decision"'));
      const granted=await b.show(gId);
      assert.match(granted.body,/<title>Grant created \| Approval sandbox<\/title>/);
      assert(granted.body.includes('A standing grant was made from this change on'));
      assert(granted.body.includes('/grants'),'a link to the grants page');
      assert(!granted.body.includes('name="decision"'));
      // An approval that has already run says so, and no longer offers its use window.
      assert(call(f,req(f,'approve-one')).ok);
      const used=await b.show(aId);
      assert.match(used.body,/<title>Change approved \| Approval sandbox<\/title>/);
      assert(used.body.includes('This change was approved on'));
      assert(used.body.includes('already been used'));
      assert(!used.body.includes('It can be used until'));
    },
    // 94. Error wording (S58).
    async function errorWording() {
      const f=setup(),b=browser(f);await b.login();
      const aId=ask(f,req(f,'a'));await b.show(aId);assert.equal((await b.decide(aId,'approve')).status,200);
      const dId=ask(f,req(f,'d'));await b.show(dId);assert.equal((await b.decide(dId,'deny')).status,200);
      const eId=ask(f,req(f,'expired-link')); // created before any grant, so it needs approval
      const {id:gId}=await grant(f,req(f,'g'));
      // A second decision to each decided record says which decision stands (403 is fine).
      for(const [id,decision,title,sentence] of [[aId,'deny','Change approved','This change was approved on'],[dId,'approve','Change denied','This change was denied on'],[gId,'deny','Grant created','A standing grant was made from this change on']]) {
        const second=await b.decide(id,decision);
        assert.equal(second.status,403,second.status+' '+second.body.slice(0,160));
        assert.match(second.body,new RegExp('<title>'+title+' \\| Approval sandbox</title>'),second.body.slice(0,200));
        assert(second.body.includes('A decision was already recorded'),second.body);
        assert(second.body.includes(sentence),second.body);
      }
      // After a denial the page never tells the person to send the request again.
      assert(!/send the (request|same request) again/i.test((await b.decide(dId,'approve')).body));
      // An invented link and an expired one get the same page, which fits an unknown link.
      const unknown=await b.send('GET','/approve/'+'0'.repeat(48));
      assert.equal(unknown.status,403);
      f.time(f.pending.get(eId).expires);
      const expired=await b.send('GET','/approve/'+eId);
      assert.equal(expired.status,403);
      for(const r of [unknown,expired]) {
        assert(r.body.includes('This approval link is not valid or is no longer active'),r.body.slice(0,160));
        assert(r.body.includes('Ask the assistant to request the change again if it is still needed.'),r.body.slice(0,160));
        assert(!/expired/i.test(r.body),'nothing on the page reveals whether the link ever existed');
      }
      assert.equal(unknown.body,expired.body,'unknown and expired links get the same page');
    },
    // 95. Messages for people (S59).
    async function messagesForPeople() {
      const members=['approval_url','grant_status','retry_after','change_hash','approval_receipt','max_records','manifest_hash','selection_limit','approver_types'];
      const scan=(m,label)=>{assert(typeof m==='string'&&m.trim().length>0,label+' has a message');for(const name of members)assert(!m.includes(name),label+' must not name the member '+name+': '+m);return m;};
      const f=setup(),first=call(f,req(f,'no-grant-yet'));
      assert.equal(first.approval.error,'approval_required');
      const plain=scan(first.approval.message,'approval_required');
      assert(plain.includes("This change needs a person's approval."),'the new wording: '+plain);
      assert(plain.includes('Open the approval page'));
      assert(plain.includes('Nothing needs to be copied or pasted back'));
      assert(!plain.includes('Approval page: '),'the core refusal carries no link; the transport adds it only without an elicitation');
      // Every other refusal message avoids protocol member names too.
      const d=setup(),dId=ask(d,req(d,'denied-change')),db=browser(d);await db.login();await db.show(dId);await db.decide(dId,'deny');
      const deniedMessage=scan(call(d,req(d,'denied-change')).approval.message,'approval_denied');
      assert(deniedMessage.includes('about '),'the duration is a plain duration for people');
      assert(/\(until \d{2}:\d{2} UTC\)/.test(deniedMessage),'with the absolute moment alongside it');
      assert(!/\b\d+ seconds?\b/.test(deniedMessage),'no bare seconds count in the message (S59)');
      const c=setup();scan(call(c,{...req(c),inputResponses:{approve:{action:'decline'}}}).approval.message,'approval_cancelled');
      const cap=setup({pendingCap:1});ask(cap,req(cap,'cap-first'));const limited=call(cap,req(cap,'cap-second'));
      assert.equal(limited.approval.error,'approval_limit_reached');
      assert(scan(limited.approval.message,'approval_limit_reached').includes('about '),'the duration is plain words, not a raw count');
      const iv=setup(),bad=req(iv,'invalid');bad.args.records[0].properties.never_defined='x';
      const invalid=call(iv,bad);assert.equal(invalid.approval.error,'invalid_input');scan(invalid.approval.message,'invalid_input');
      const u=setup();await grant(u,req(u),1);assert(call(u,req(u)).ok);scan(call(u,req(u,'beyond')).approval.message,'used-up grant reason');
      const e=setup(),{g:eg}=await grant(e,req(e),5,e.now()+60);e.time(eg.expires);scan(call(e,req(e,'later')).approval.message,'expired grant reason');
      const rv=setup(),{g:rg,b:rb}=await grant(rv);assert.equal((await rb.revoke(rg.id)).status,200);scan(call(rv,req(rv,'after')).approval.message,'revoked grant reason');
      const out=setup(),{g:og}=await grant(out,req(out),5,out.now()+500,'these_records');out.sor.seed(A,'another-record',{});
      const outside=req(out,'outside-record');outside.args.records[0].id='another-record';scan(call(out,outside).approval.message,'outside grant reason');
      // With an elicitation the message says to open the approval page and never carries the link.
      await sdk(f,'server',async(client,elicited)=>{
        const fresh=req(f,'elicited-change');
        const result=await client.callTool({name:'manage_records',arguments:structuredClone(fresh.args)});
        assert(elicited.length>0,'a URL mode elicitation was sent');
        scan(elicited[0].message,'the elicitation message');
        assert(elicited[0].message.includes('Open the approval page'),elicited[0].message);
        assert(!elicited[0].message.includes('/approve/'),'the elicitation message does not repeat the link');
        assert(String(elicited[0].url).startsWith('http'),'the link travels in the elicitation, not the message');
        const refusal=JSON.parse(result.content[0].text);
        assert.equal(elicited[0].message,refusal.message,'the elicitation text is the refusal message');
        assert(!refusal.message.includes('Approval page: '));
      });
      // Without an elicitation the refusal message includes the link itself.
      await sdk(f,'server',async(client,elicited)=>{
        const fresh=req(f,'unelicited-change');
        const result=await client.callTool({name:'manage_records',arguments:structuredClone(fresh.args)});
        assert.equal(elicited.length,0,'no elicitation was declared');
        const refusal=JSON.parse(result.content[0].text);
        assert.equal(refusal.error,'approval_required');
        scan(refusal.message,'a refusal without an elicitation');
        assert(refusal.message.includes('Approval page: '+refusal.approval_url),refusal.message);
      },{});
      // The HTTP mapping has no elicitation, so its refusal message carries the link too.
      const h=setup(),hb=browser(h);
      const patch=await hb.send('PATCH','/records',JSON.stringify(req(h,'http-change').args));
      assert.equal(patch.status,403);
      const body=JSON.parse(patch.body);
      assert.equal(body.approval.error,'approval_required');
      scan(body.approval.message,'the HTTP mapping');
      assert(body.approval.message.includes('Approval page: '+body.approval.approval_url),body.approval.message);
    },
  ];
  return {tests,names:['Decided links','Error wording','Messages for people']};
}
