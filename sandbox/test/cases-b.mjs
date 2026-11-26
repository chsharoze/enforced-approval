import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import crypto from 'node:crypto';
import { OP, QUERY, CREATE, mcpResult } from '../src/core.mjs';
export function cases({helpers:{setup,req,ask,browser,grant,concurrent},call,A,admin}) {
  const person={id:'test-person',authenticated:true},live=(f,g)=>f.pending.grants.get(g.id);
  const grants=f=>f.core.db.prepare('SELECT count(*) n FROM server_grants').get().n;
  const token=body=>/name="csrf" value="([a-f0-9]+)"/.exec(body)?.[1];
  const tests=[
    async function authority() {
      const f=setup(),{g}=await grant(f),r=req(f,'forbidden');r.args.records[0].id='forbidden-record';ask(f,r);assert.equal(live(f,g).charged,0);
      f.sor.permission(A,person.id,OP,true,false);ask(f,req(f,'lost-operation'));assert.equal(live(f,g).charged,0);
      f.sor.permission(A,person.id,OP);f.sor.inject('before-grant-charge',()=>f.sor.recordPermission(A,person.id,'rec-EXAMPLE-42',true,false));ask(f,req(f,'lost-in-transaction'));assert.equal(live(f,g).charged,0);assert.equal(f.count(),0);
      const h=setup(),{g:hg}=await grant(h);h.sor.fieldPermission(A,person.id,OP,'/owner',false);ask(h,req(h,'lost-field'));assert.equal(live(h,hg).charged,0);
      const k=setup(),parent=req(k);parent.args.records[0].properties={profile:null};const {g:kg}=await grant(k,parent);k.sor.seed(A,'rec-EXAMPLE-42',{profile:{secret:'protected'}});k.sor.fieldPermission(A,person.id,OP,'/profile/secret',false);ask(k,parent);assert.equal(live(k,kg).charged,0);assert.equal(k.count(),0);
    },
    async function oneExecution() {
      // Draft 0.2 test 69: the replay returns the recorded outcome while the server holds
      // it (S80), charged once.
      const f=setup(),r=req(f,'lost-response'),{g}=await grant(f,r);assert(call(f,r).ok);const n=f.count(),charged=live(f,g).charged;
      const replay=call(f,r);assert(replay.ok);assert.equal(replay.result.recorded_outcome.outcome,'success');assert.equal(f.count(),n);assert.equal(live(f,g).charged,charged);
      // Draft 0.2 (S69, covered operation): the identical request after consumption is
      // answered with the recorded outcome and is not charged again; a new write to the
      // same record is sent with a new value of the distinguishing argument (S69(4))
      // and then runs under the grant.
      const h=setup({preconditions:true}),hr=req(h,'stateful'),{g:hg}=await grant(h,hr);const first=h.core.prepare(hr).change_hash;assert(call(h,hr).ok);const second=h.core.prepare(hr).change_hash;assert.notEqual(second,first,'S28: a changed record gives a different hash');
      const identical=call(h,hr);assert(identical.ok,JSON.stringify(identical));assert.equal(identical.result.recorded_outcome.outcome,'success');assert.equal(h.count(),1);assert.equal(live(h,hg).charged,1);
      const fresh=req(h,'stateful');fresh.args.change_tag='second-write';assert(call(h,fresh).ok,JSON.stringify(call(h,fresh)));assert.equal(h.count(),2);assert.equal(live(h,hg).charged,2);
      // Two independently prepared calls with one hash share the same atomic identity.
      const k=setup(),{g:kg}=await grant(k);const both=await concurrent(k,[req(k,'same-hash'),req(k,'same-hash')]);assert.equal(both.filter(r=>r.ok).length,2);assert.equal(both.filter(r=>r.ok&&!r.result?.recorded_outcome).length,1,'exactly one executed');assert.equal(k.count(),1);assert.equal(live(k,kg).charged,1);
    },
    async function oneUnit() {
      const f=setup(),{g}=await grant(f),r=req(f,'charge-fails');f.sor.inject('grant-charge',()=>{assert.equal(f.core.db.prepare("SELECT count(*) n FROM pending WHERE status='approved'").get().n,1);throw Error('injected charge failure');});
      ask(f,r);assert.equal(f.count(),0);assert.equal(live(f,g).charged,0);assert.equal(f.core.db.prepare("SELECT count(*) n FROM pending WHERE status IN ('approved','consumed')").get().n,0);assert.equal(f.core.db.prepare('SELECT count(*) n FROM used').get().n,0);assert(!f.core.records().some(r=>r.record_phase==='consumption'));
    },
    async function selectors() {
      const docs=readFileSync('README.md','utf8');assert(docs.includes('objectType')&&docs.includes('action')&&docs.includes('selectors'));
      const f=setup(),r=req(f,'unknown-kind',{operation:'mcp:tools/call:run_cleanup'});f.core.admin(admin,'settings',{grantConfig:{[A]:{[r.operation]:{maxRecords:10,maxSeconds:1000,anyRecord:true}}}});r.args={records:r.args.records};const id=ask(f,r),b=browser(f);await b.login();assert(!(await b.show(id)).body.includes('id="grant-terms"'));assert.equal((await b.decide(id,'grant',{max_records:2,expires:f.now()+100})).status,403);
    },
    async function leaves() {
      const f=setup(),r=req(f);r.args.records[0].properties={profile:{name:'A'}};const {g,page}=await grant(f,r);
      assert.deepEqual(g.fields,['/profile/name']);assert(page.body.includes('/profile/name'));assert(!g.fields.includes('/profile'));
      for(const properties of [{profile:{email:'x'}},{profile:'replace-parent'},{profile:{name:'B',email:'x'}}]) {const changed=req(f);changed.args.records[0].properties=properties;ask(f,changed);}
      assert.equal(live(f,g).charged,0);assert.equal(f.count(),0);
      const flat=setup(),{g:fg}=await grant(flat);const child=req(flat);child.args.records[0].properties={owner:{id:'new-child'}};ask(flat,child);assert.equal(live(flat,fg).charged,0);
      assert(readFileSync('README.md','utf8').includes('JSON Pointer'));
    },
    async function finiteLimits() {
      const f=setup(),original=f.core.settings();for(const value of [undefined,null,'',0,-1,'unlimited',Infinity,-Infinity,NaN,{},Number.MAX_VALUE])for(const key of ['maxRecords','maxSeconds']) {
        const cfg={maxRecords:10,maxSeconds:1000,anyRecord:true,[key]:value};assert.throws(()=>f.core.admin(admin,'settings',{grantConfig:{[A]:{[OP]:cfg}}}));assert.deepEqual(f.core.settings(),original);
      }
      f.core.admin(admin,'settings',{grantConfig:{}});const b=browser(f);await b.login();assert(!(await b.show(ask(f))).body.includes('id="grant-terms"'));assert(readFileSync('README.md','utf8').includes('100 records/3600s'));
    },
    async function declines() {const f=setup(),{g}=await grant(f);for(const action of ['decline','cancel']) {const r=req(f,'no-record-'+action),hash=f.core.prepare(r).change_hash;assert(!f.core.db.prepare('SELECT 1 FROM pending WHERE hash=?').get(hash));const result=call(f,{...r,inputResponses:{approve:{action}}});assert.equal(result.approval.error,'approval_cancelled');assert(!f.core.db.prepare('SELECT 1 FROM pending WHERE hash=?').get(hash));assert.equal(live(f,g).charged,0);assert.equal(f.count(),0);}
      const used=req(f,'already-consumed');assert(call(f,used).ok);for(const action of ['decline','cancel'])assert.equal(call(f,{...used,inputResponses:{approve:{action}}}).approval.error,'approval_cancelled');const replay=call(f,used);assert(replay.ok,'the replay returns the recorded outcome (S80)');assert.equal(replay.result.recorded_outcome.outcome,'success');assert.equal(live(f,g).charged,1);assert.equal(f.count(),1);
    },
    async function finality() {
      const f=setup(),id=ask(f),b=browser(f);await b.login();await b.show(id);const first=await b.decide(id,'approve'),before=f.core.records().length;
      assert.equal(first.status,200);assert.equal((await b.decide(id,'deny')).status,403);assert.equal((await b.decide(id,'grant',{max_records:5,expires:f.now()+500})).status,403);const replay=await b.decide(id,'approve');assert.equal(replay.status,200);assert.equal(replay.body,first.body);assert.equal(f.core.records().length,before);assert.equal(grants(f),0);assert.equal(f.pending.get(id).status,'approved');
      const h=setup(),{id:hid,b:hb,done}=await grant(h),n=h.core.records().length;const again=await hb.decide(hid,'grant',{max_records:5,expires:h.now()+500});assert.equal(again.status,200);assert.equal(again.body,done.body);assert.equal(grants(h),1);assert.equal(h.core.records().length,n);assert.equal((await hb.decide(hid,'approve')).status,403);assert.equal((await hb.decide(hid,'deny')).status,403);
      const k=setup(),kid=ask(k);for(const s of ['race-a','race-b'])k.pending.page(kid,person,s);const race=await concurrent(k,[{decision:true,id:kid,approve:true,session:'race-a'},{decision:true,id:kid,approve:false,session:'race-b'}]);assert.equal(race.filter(r=>r.decision).length,1);assert.equal(race.filter(r=>r.refused).length,1);assert.equal(k.core.records().filter(r=>r.record_phase==='decision').length,1);
      const m=setup(),{g:mg}=await grant(m),mr=req(m,'person-before-consumption');m.sor.inject('before-consume',()=>{const mid=m.core.db.prepare('SELECT id FROM pending WHERE hash=?').get(m.core.prepare(mr).change_hash).id;m.pending.page(mid,person,'racing-person');m.pending.decide(mid,person,true,'racing-person');});assert(call(m,mr).ok);assert.equal(live(m,mg).charged,0);assert.equal(m.core.records().find(r=>r.record_phase==='consumption').action_detail.approver_type,'person');assert.equal(m.count(),1);
      assert(call(f,req(f)).ok);assert.equal((await b.decide(id,'approve')).status,403);const expired=setup(),eid=ask(expired),eb=browser(expired);await eb.login();await eb.show(eid);expired.time(expired.pending.get(eid).expires);assert.equal((await eb.decide(eid,'deny')).status,403);
    },
    async function inert() {
      const f=setup(),bad='<script>globalThis.pwned=1</script>',image='"><img src=x onerror=globalThis.pwned=1>',r=req(f);r.args.records[0]={id:image,properties:{[bad]:image,owner:bad}};f.sor.defineProperty('contact',bad);f.sor.seed(A,image,{});const id=ask(f,r),b=browser(f);await b.login();const p=await b.show(id);assert.equal(p.status,200);
      for(const raw of ['<script>','<img','onerror=globalThis.pwned=1>'])assert(!p.body.includes(raw),p.body);assert(p.body.includes('&lt;script&gt;'));assert(p.body.includes('&lt;img'));assert(p.body.includes('&quot;'));assert.match(p.headers['content-security-policy'],/script-src 'none'/);assert.match(p.headers['content-security-policy'],/default-src 'none'/);
      for(const response of [await b.list(),await b.decide(id,'deny'),await b.send('POST','/signin','')])assert.match(response.headers['content-security-policy'],/script-src 'none'/);
    },
    async function signin() {
      // S58/S79: the sandbox's fake sign-in names a test person. The secret is generated
      // by the server (or taken from VA_SIGNIN_SECRET) and printed on the operator's
      // console only; a missing or wrong secret is answered exactly like any other
      // failed sign-in, and no session is created.
      const secret='signin-secret-'+crypto.randomUUID(),previous=process.env.VA_SIGNIN_SECRET;
      process.env.VA_SIGNIN_SECRET=secret;
      try {
        const f=setup(),id=ask(f),b=browser(f),first=await b.show(id),old=first.headers['set-cookie'].split(';')[0],csrf=token(first.body);
        assert.match(first.body,/name="secret"/,'the sign-in form has a secret field');
        for(const [data,headers] of [[{person:person.id},{cookie:old}],[{person:person.id,csrf:'wrong'},{cookie:old}],[{person:person.id,csrf},{cookie:old,origin:'https://evil.example'}]]) {const refused=await b.send('POST','/signin',new URLSearchParams(data),headers);assert.equal(refused.status,403);assert(!refused.headers['set-cookie']);}
        // A missing secret creates no session and shows no record state.
        const missing=await b.send('POST','/signin',new URLSearchParams({person:person.id,csrf}),{cookie:old});
        assert.equal(missing.status,403,'a missing secret is refused');assert(!missing.headers['set-cookie'],'a failed sign-in sets no session cookie');
        const missingPage=await b.send('GET','/approve/'+id,'',{cookie:old});
        assert(!missingPage.body.includes('new-owner'),'a failed sign-in does not reveal record state');
        // A wrong secret is the same failure, and the same answer as any failed sign-in.
        const wrong=await b.send('POST','/signin',new URLSearchParams({person:person.id,csrf,secret:'wrong'}),{cookie:old});
        const unknown=await b.send('POST','/signin',new URLSearchParams({person:'test-person-9',csrf,secret}),{cookie:old});
        assert.equal(wrong.status,403,'a wrong secret is refused');assert(!wrong.headers['set-cookie']);
        assert.equal(unknown.status,403,'an unknown person is refused');
        assert.equal(wrong.body,unknown.body,'a wrong secret gets the same answer as any failed sign-in');
        // The right secret works.
        const signed=await b.send('POST','/signin',new URLSearchParams({person:person.id,csrf,secret,next:'https://evil.example/steal'}),{cookie:old});assert.equal(signed.status,303);assert.equal(signed.headers.location,'/approve/'+id);const fresh=signed.headers['set-cookie'].split(';')[0];assert.notEqual(fresh,old);assert(!(await b.send('GET','/approve/'+id,'',{cookie:old})).body.includes('new-owner'));assert((await b.send('GET','/approve/'+id,'',{cookie:fresh})).body.includes('new-owner'));
        const c=browser(f),start=await c.send('GET','/signin?next=https://evil.example'),pc=start.headers['set-cookie'].split(';')[0];const result=await c.send('POST','/signin',new URLSearchParams({person:person.id,csrf:token(start.body),secret,next:'/not-generated'}),{cookie:pc});assert.equal(result.status,303);assert.equal(result.headers.location,'/grants');
        // The secret never appears in any HTTP answer or header.
        for(const r of [first,missing,missingPage,wrong,unknown,signed,await b.send('GET','/approve/'+id,'',{cookie:fresh})])
          assert(!String(r.body).includes(secret)&&!JSON.stringify(r.headers??{}).includes(secret),'the secret never appears in an HTTP answer or header');
      } finally { if(previous===undefined)delete process.env.VA_SIGNIN_SECRET; else process.env.VA_SIGNIN_SECRET=previous; }
    },
    async function viewing() {
      const f=setup(),id=ask(f);for(const name of ['test-person-4','test-person-5']) {const b=browser(f);await b.login(name);const r=await b.show(id);assert.equal(r.status,403);for(const value of ['rec-EXAMPLE-42','new-owner','lifecycle_stage'])assert(!r.body.includes(value));}
      const b=browser(f);await b.login();assert((await b.show(id)).body.includes('new-owner'));f.sor.recordPermission(A,person.id,'rec-EXAMPLE-42',false,true);assert.equal((await b.show(id)).status,403);
    },
    async function referrer() {const f=setup(),id=ask(f),b=browser(f);for(const r of [await b.show(id),await b.login(),await b.show(id),await b.list(),await b.decide(id,'deny'),await b.send('POST','/approve/'+id,'')])assert.equal(r.headers['referrer-policy'],'same-origin');},
    async function offeredShapes() {
      const f=setup(),cfg=enabled=>({grantConfig:{[A]:{[OP]:{maxRecords:10,maxSeconds:1000,anyRecord:enabled},[CREATE]:{maxRecords:10,maxSeconds:1000,anyRecord:false}}}});f.core.admin(admin,'settings',cfg(false));const id=ask(f),b=browser(f);await b.login();const one=await b.show(id);assert(one.body.includes('These records'));assert(!one.body.includes('Any record'));assert(one.body.includes('rec-EXAMPLE-42'));assert.equal((await b.decide(id,'grant',{max_records:5,expires:f.now()+500,shape:'any_record'})).status,403);assert.equal(grants(f),0);
      f.core.admin(admin,'settings',cfg(true));assert.equal((await b.decide(id,'grant',{max_records:5,expires:f.now()+500,shape:'any_record'})).status,403);const both=await b.show(id);assert(both.body.includes('These records')&&both.body.includes('Any record'));const granted=await b.decide(id,'grant',{max_records:5,expires:f.now()+500,shape:'these_records'});assert.equal(granted.status,200);assert(granted.body.includes('these_records'));assert.equal(grants(f),1);
      const cr=f.req({objectType:'contact',id:'new-created',properties:{owner:'created'}},{operation:CREATE}),cid=ask(f,cr);assert(!(await b.show(cid)).body.includes('id="grant-terms"'));f.core.admin(admin,'settings',{grantConfig:{[A]:{[CREATE]:{maxRecords:10,maxSeconds:1000,anyRecord:true}}}});const createPage=await b.show(cid);assert(createPage.body.includes('Any record'));assert(!createPage.body.includes('These records'));assert.equal((await b.decide(cid,'grant',{shape:'these_records',max_records:5,expires:f.now()+500})).status,403);assert.equal((await b.decide(cid,'grant',{shape:'any_record',max_records:5,expires:f.now()+500})).status,200);assert(call(f,cr).ok);
    },
    async function theseRecords() {
      const f=setup(),{g}=await grant(f,req(f),5,f.now()+500,'these_records');assert.deepEqual(g.records,['rec-EXAMPLE-42']);assert(call(f,req(f,'same-record')).ok);f.sor.seed(A,'another-record',{});const other=req(f,'other');other.args.records[0].id='another-record';ask(f,other);const mixed=req(f,'mixed');mixed.args.records.push(other.args.records[0]);ask(f,mixed);assert.equal(f.count(),1);assert.equal(live(f,g).charged,1);
      const q=setup({preconditions:true});q.core.admin(admin,'settings',{grantConfig:{[A]:{[QUERY]:{maxRecords:10,maxSeconds:1000,anyRecord:true}}}});for(const id of ['q1','q2','q3'])q.sor.seed(A,id,{group:'q'});const qr=q.req({objectType:'contact',filter:{group:'q'},set:{owner:'query'}},{operation:QUERY}),{g:qg}=await grant(q,qr,5,q.now()+500,'these_records');assert.deepEqual(qg.records,['q1','q2','q3']);q.sor.seed(A,'q4',{group:'q'});ask(q,qr);assert.equal(q.count(),0);assert.equal(live(q,qg).charged,0);
    },
    async function statedShape() {for(const shape of ['these_records','any_record']) {const f=setup(),{g}=await grant(f,req(f),5,f.now()+500,shape),out=mcpResult(call(f,req(f)));assert(out.content.some(c=>c.type==='text'&&c.text.includes(g.id)&&c.text.includes(shape)));for(const phase of ['consumption','outcome'])assert.equal(f.core.records().find(r=>r.record_phase===phase).action_detail.grant_shape,shape);assert.equal(live(f,g).shape,shape);}},
    async function retention() {const f=setup(),r=req(f,'retained'),{g}=await grant(f,r,5,f.now()+900);assert(call(f,r).ok);f.time(g.expires-1);f.pending.cleanup();const replay=call(f,r);assert(replay.ok,'the replay returns the recorded outcome (S80)');assert.equal(replay.result.recorded_outcome.outcome,'success');assert.equal(f.count(),1);assert.equal(live(f,g).charged,1);assert.equal(f.core.db.prepare("SELECT count(*) n FROM pending WHERE status='consumed'").get().n,1);}
  ];
  return {tests,names:['Authority at use','One change, one execution','One unit','Selectors','Leaf field names','Finite limits','Declines never match','Decision finality','Inert output','Sign-in','Who may view','Referrer','Shapes offered','These records','Shape is stated','Retention']};
}
