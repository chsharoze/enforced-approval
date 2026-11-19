import { Worker } from 'node:worker_threads';
import assert from 'node:assert/strict';
import { Readable } from 'node:stream';
import { createHandler } from '../src/http.mjs';
import { ServerIssued } from '../src/server-issued.mjs';
import { OP, QUERY, CREATE, mcpResult } from '../src/core.mjs';
import { readableTime } from '../src/presentation.mjs';
export function cases({fixture,args,call,A,P,OTHER,admin,na}) {
  function setup(settings={}) {
    const f=fixture(settings);f.core.admin(admin,'settings',{grantConfig:{[A]:{[OP]:{maxRecords:10,maxSeconds:1000,anyRecord:true},[CREATE]:{maxRecords:10,maxSeconds:1000,anyRecord:false}}},pageAdministrators:{[A]:['test-admin']}});
    for(const op of [OP,QUERY,OTHER,'mcp:tools/call:run_cleanup']) {f.sor.permission(A,'test-person-2',op,true,false);f.sor.permission(A,'test-person-3',op);}
    f.sor.member(A,'test-admin');f.sor.permission('acct-EXAMPLE-0002','test-person-4',OP);f.sor.member(A,'test-person-4',false);f.sor.permission(A,'test-person-5',OP);f.sor.fieldPermission(A,'test-person-5',OP,'/owner',false,'read');f.sor.seed(A,'forbidden-record',{owner:'protected'});f.sor.recordPermission(A,'test-person','forbidden-record',true,false);f.pending=new ServerIssued(f.core);return f;
  }
  const req=(f,owner='new-owner',extra={})=>f.req({...args(),records:[{id:'rec-EXAMPLE-42',properties:{lifecycle_stage:'customer',owner}}]},extra);
  function ask(f,r=req(f)) {const n=f.count(),out=call(f,r);assert.equal(out.ok,false,JSON.stringify(out));assert.equal(out.approval.error,'approval_required',JSON.stringify(out));assert.equal(f.count(),n);assert(out.approval.approval_url);return out.approval.approval_url.split('/').at(-1);}
  function browser(f) {
    const handler=createHandler({core:f.core,sor:f.sor,account:A,principal:P,pending:f.pending});let cookie='',csrf='';
    const b={async send(method,url,data='',headers={}) {
      const request=Readable.from([String(data)]);Object.assign(request,{method,url,headers:{...(f.pending.baseURL.startsWith('https:')?{'x-forwarded-proto':'https'}:{}),...(cookie?{cookie}:{}),...headers},rawHeaders:[]});let status,h,body;
      await handler(request,{writeHead(s,v){status=s;h=v;},end(v){body=String(v);}});return {status,headers:h,body};
    },async login(person='test-person') {const first=await b.send('GET','/grants');cookie=first.headers['set-cookie'].split(';')[0];const pre=/name="csrf" value="([a-f0-9]+)"/.exec(first.body)?.[1];const r=await b.send('POST','/signin',new URLSearchParams({person,csrf:pre}));assert.equal(r.status,303);cookie=r.headers['set-cookie'].split(';')[0];return r;},
    async show(id,suffix='') {const r=await b.send('GET','/approve/'+id+suffix);const c=/name="csrf" value="([a-f0-9]+)"/.exec(r.body)?.[1];if(c)csrf=c;return r;},
    decide(id,decision,more={}) {more={...more};if(Object.hasOwn(more,'expires')){more.minutes=(more.expires-f.now())/60;delete more.expires;}return b.send('POST','/approve/'+id,new URLSearchParams({csrf,decision,...(decision==='grant'?{shape:'any_record'}:{}),...more}));},
    async list() {const r=await b.send('GET','/grants');const c=/name="csrf" value="([a-f0-9]+)"/.exec(r.body)?.[1];if(c)csrf=c;return r;},
    revoke(id) {return b.send('POST','/grants/'+id+'/revoke',new URLSearchParams({csrf}));},token:()=>csrf,cookie:()=>cookie};return b;
  }
  async function grant(f,r=req(f),limit=5,expires=f.now()+500,shape='any_record') {
    const id=ask(f,r),b=browser(f);await b.login();const page=await b.show(id);assert.equal(page.status,200);const done=await b.decide(id,'grant',{max_records:limit,expires,shape});assert.equal(done.status,200,done.body);
    const g=f.pending.grants.get(f.core.db.prepare('SELECT id FROM server_grants ORDER BY rowid DESC').get().id);return {g,id,b,page,done};
  }
  async function concurrent(f,requests) {
    const gate=new SharedArrayBuffer(4),word=new Int32Array(gate);
    const code=`const {parentPort,workerData:d}=require('node:worker_threads');
      (async()=>{const {Sor}=await import(d.root+'src/sor.mjs'),{Core}=await import(d.root+'src/core.mjs'),{ServerIssued}=await import(d.root+'src/server-issued.mjs');
        const sor=new Sor(d.db),core=new Core(sor,{adminCredential:d.admin,now:()=>d.now}),pending=new ServerIssued(core);
        const ready=()=>{parentPort.postMessage({ready:true});Atomics.wait(new Int32Array(d.gate),0,0,10000);};let result;
        if(d.req.decision){ready();try{result={decision:pending.decide(d.req.id,{id:'test-person',authenticated:true},d.req.approve,d.req.session)};}catch(e){result={refused:e.message};}}
        else if(d.req.revoke){ready();pending.grants.revoke(d.req.account,d.req.revoke,{id:'test-person',authenticated:true});result={revoked:true};}
        else {sor.inject('before-consume',ready);result=core.handle(d.req);}
        sor.close();parentPort.postMessage({result});})().catch(e=>{throw e;});`;
    const workers=requests.map(req=>new Worker(code,{eval:true,workerData:{root:new URL('../',import.meta.url).href,db:f.db,admin,now:f.now(),req,gate}}));
    let waiting=0;const results=workers.map(w=>new Promise((resolve,reject)=>{w.on('error',reject);w.on('exit',c=>{if(c)reject(Error('worker exited '+c));});w.on('message',m=>{if(m.ready&&++waiting===workers.length){Atomics.store(word,0,1);Atomics.notify(word,0);}if(m.result)resolve(m.result);});}));
    try{return await Promise.all(results);}finally{await Promise.all(workers.map(w=>w.terminate()));}
  }
  const count=f=>f.core.db.prepare('SELECT count(*) n FROM server_grants').get().n;
  const covered=(f,g)=>f.pending.grants.get(g.id);
  const tests=[
    async function create() {
      const f=setup(),r=f.req(),id=ask(f,r),b=browser(f);await b.login();const page=await b.show(id);
      for(const term of [P,A,OP,'objectType','contact','action','update','lifecycle_stage','owner'])assert(page.body.includes(term),term);
      assert.match(page.body,/name="max_records"/);assert.match(page.body,/name="minutes"/);
      for(const field of ['principal','account','operation','selectors','fields'])assert(!page.body.includes('name="'+field+'"'));
      for(const terms of [{max_records:11,expires:f.now()+500},{max_records:5,expires:f.now()+1001},{max_records:5,expires:f.now()+500,principal:'attacker'}])assert.equal((await b.decide(id,'grant',terms)).status,403);
      const p2=browser(f);await p2.login('test-person-2');assert.doesNotMatch((await p2.show(id)).body,/id="grant-terms"/);assert.equal((await p2.decide(id,'grant',{max_records:5,expires:f.now()+500})).status,403);
      f.sor.fieldPermission(A,'test-person',OP,'owner',false);assert.doesNotMatch((await b.show(id)).body,/id="grant-terms"/);assert.equal((await b.decide(id,'grant',{max_records:5,expires:f.now()+500})).status,403);f.sor.fieldPermission(A,'test-person',OP,'owner',true);await b.show(id);
      f.core.admin(admin,'settings',{grantConfig:{[A]:{[OP]:{maxRecords:10,maxSeconds:1000,anyRecord:true},['mcp:tools/call:run_cleanup']:{maxRecords:10,maxSeconds:1000,anyRecord:true}}}});
      for(const operation of [OTHER,'mcp:tools/call:run_cleanup']) {const other=ask(f,{...r,operation,...(operation.endsWith('run_cleanup')?{args:{}}:{})});assert.doesNotMatch((await b.show(other)).body,/id="grant-terms"/);}
      for(const altered of [{...r,inputResponses:{approve:{action:'accept',content:{grant:{max_records:1000}}}}},{...r,args:{...r.args,grant:{max_records:1000}}},{...r,args:{...r.args,confirmation:'CONFIRMED'},inputResponses:{approve:{action:'accept',content:{confirmation:'CONFIRMED',grant:true}}}}]) {call(f,altered);assert.equal(count(f),0);assert.equal(f.count(),0);}
      const done=await b.decide(id,'grant',{max_records:5,expires:f.now()+500});assert.equal(done.status,200);assert.equal(f.count(),0);assert.equal(f.pending.get(id).status,'pending');const g=f.pending.grants.get(f.core.db.prepare('SELECT id FROM server_grants').get().id);assert.equal(g.charged,0);
      assert(call(f,r).ok);assert.equal(covered(f,g).charged,1);assert.equal(f.count(),1);
    },
    async function match() {
      const f=setup(),{g}=await grant(f);f.sor.seed(A,'other-record',{});
      const changed=f.req({...args(),records:[{id:'other-record',properties:{lifecycle_stage:'other',owner:'another'}}]});const out=call(f,changed);assert(out.ok);assert(!out.approval);assert.equal(f.count(),1);assert.equal(covered(f,g).charged,1);
      for(const r of [{...req(f,'p2'),principal:'agent-EXAMPLE-other'},{...req(f,'acct2'),account:'acct-EXAMPLE-0002'},{...req(f,'op2'),operation:OTHER},{...req(f,'selector'),args:{...req(f,'selector').args,action:'delete'}},{...req(f,'type'),args:{...req(f,'type').args,objectType:'company'}}])ask(f,r);
      assert.equal(f.count(),1);assert.equal(covered(f,g).charged,1);
      f.core.admin(admin,'settings',{audience:'https://different.example'});ask(f,req(f,'audience'));assert.equal(covered(f,g).charged,1);
    },
    async function fieldCover() {const f=setup(),{g}=await grant(f),r=req(f);r.args.records[0].properties.extra='uncovered';ask(f,r);assert.equal(covered(f,g).charged,0);},
    async function limit() {
      const f=setup(),{g}=await grant(f);f.core.db.prepare('UPDATE server_grants SET charged=4 WHERE id=?').run(g.id);
      const two=req(f,'two');two.args.records.push(structuredClone(two.args.records[0]));ask(f,two);assert.equal(covered(f,g).charged,4);
      const rs=await concurrent(f,['one-a','one-b'].map(v=>req(f,v)));assert.equal(rs.filter(r=>r.ok).length,1);assert.equal(rs.filter(r=>r.approval?.error==='approval_required').length,1);assert.equal(f.count(),1);assert.equal(covered(f,g).charged,5);assert(f.core.chainCheck().ok);
      const q=setup();q.core.admin(admin,'settings',{grantConfig:{[A]:{[QUERY]:{maxRecords:10,maxSeconds:1000,anyRecord:true}}}});for(const id of ['q1','q2','q3'])q.sor.seed(A,id,{group:'q'});
      const qr=q.req({objectType:'contact',filter:{group:'q'},set:{owner:'q-owner'}},{operation:QUERY}),{g:qg}=await grant(q,qr);assert(call(q,qr).ok);assert.equal(q.count(),3);assert.equal(covered(q,qg).charged,3);
      const h=setup(),{g:hg}=await grant(h);h.sor.inject('before-consume',()=>h.core.db.prepare('UPDATE server_grants SET charged=5 WHERE id=?').run(hg.id));ask(h,req(h,'late'));assert.equal(h.count(),0);assert.equal(covered(h,hg).charged,5);assert.equal(h.core.db.prepare('SELECT count(*) n FROM used').get().n,0);
      const k=setup(),{g:kg}=await grant(k),saved=k.core.audit;k.core.audit=function(phase,...rest){if(phase==='consumption'){this.audit=saved;throw Error('injected audit failure');}return saved.call(this,phase,...rest);};assert.equal(call(k,req(k)).approval.error,'approval_unavailable');assert.equal(k.count(),0);assert.equal(covered(k,kg).charged,0);assert.equal(k.core.db.prepare('SELECT count(*) n FROM used').get().n,0);
      const m=setup(),{g:mg}=await grant(m),wide=req(m,'wide');wide.args.records[0].properties.extra='x';const {g:second}=await grant(m,wide);m.sor.inject('before-consume',()=>m.pending.grants.revoke(A,mg.id,{id:'test-person',authenticated:true}));assert(call(m,req(m,'alternate')).ok);assert.equal(covered(m,mg).charged,0);assert.equal(covered(m,second).charged,1);
    },
    async function expiry() {
      const f=setup(),{g}=await grant(f);f.time(g.expires-1);assert(call(f,req(f,'before')).ok);f.time(g.expires);ask(f,req(f,'exact'));assert.equal(f.count(),1);assert.equal(covered(f,g).charged,1);
      const h=setup(),{g:hg}=await grant(h);h.sor.inject('before-consume',()=>h.time(hg.expires));ask(h,req(h,'transaction-expiry'));assert.equal(covered(h,hg).charged,0);assert.equal(h.count(),0);
    },
    async function revoke() {
      const f=setup(),{g,b}=await grant(f);assert(call(f,req(f,'before-revoke')).ok);assert((await b.list()).body.includes(g.id));
      const p3=browser(f);await p3.login('test-person-3');await p3.show(ask(f,req(f,'uncovered-p3',{operation:OTHER})));assert(!(await p3.list()).body.includes(g.id));assert.equal((await p3.revoke(g.id)).status,403);
      const a=browser(f);await a.login('test-admin');assert((await a.list()).body.includes(g.id));assert.equal((await a.revoke(g.id)).status,200);ask(f,req(f,'after-revoke'));assert.equal(f.count(),1);assert.equal(covered(f,g).charged,1);assert.equal(f.sor.get(A,'rec-EXAMPLE-42').properties.owner,'before-revoke');
      const h=setup(),{g:hg,b:hb}=await grant(h);assert.equal((await hb.revoke(hg.id)).status,200);ask(h,req(h,'creator-revoked'));
      const race=setup(),{g:rg}=await grant(race),[written,revoked]=await concurrent(race,[req(race,'parallel-revoke'),{account:A,revoke:rg.id}]);assert(revoked.revoked);
      const records=race.core.records(),revocationIndex=records.findIndex(r=>r.outcome==='revoked');assert(revocationIndex>=0);
      if(written.ok){assert.equal(race.count(),1);assert.equal(covered(race,rg).charged,1);const consumptionIndex=records.findIndex(r=>r.record_phase==='consumption');assert(consumptionIndex>=0&&consumptionIndex<revocationIndex);}
      else {assert.equal(written.approval.error,'approval_required');assert.equal(race.count(),0);assert.equal(covered(race,rg).charged,0);}
      assert(race.core.chainCheck().ok);ask(race,req(race,'after-parallel-revoke'));
      const k=setup(),{g:kg}=await grant(k);k.sor.inject('before-consume',()=>k.pending.grants.revoke(A,kg.id,{id:'test-person',authenticated:true}));ask(k,req(k,'racing-revocation'));assert.equal(covered(k,kg).charged,0);
      const l=setup(),{g:lg}=await grant(l);l.sor.inject('after-consume',()=>{assert.equal(covered(l,lg).charged,1);l.pending.grants.revoke(A,lg.id,{id:'test-person',authenticated:true});});assert(call(l,req(l,'charged-first')).ok);assert.equal(l.count(),1);ask(l,req(l,'later'));
    },
    async function audit() {const f=setup(),{g}=await grant(f);assert(call(f,req(f)).ok);for(const phase of ['consumption','outcome']){const row=f.core.records().find(r=>r.record_phase===phase);assert(row);assert.equal(row.action_detail.approver_type,'grant');assert.equal(row.action_detail.grant_id,g.id);assert.equal(row.action_detail.approver_id,'test-person');}assert(f.core.chainCheck().ok);},
    async function resultText() {const f=setup(),{g}=await grant(f);const out=mcpResult(call(f,req(f)));const text=out.content.filter(c=>c.type==='text').map(c=>c.text).join('\n');for(const value of ['under grant',g.id,'records remaining: 4',new Date(g.expires*1000).toISOString()+' UTC'])assert(text.includes(value),text);const failed=req(f,'failing');f.sor.inject('before-write',()=>{throw Error('write rejected');});const error=mcpResult(call(f,failed));assert(error.isError);assert(error.content.some(c=>c.type==='text'&&c.text.includes(g.id)&&c.text.includes('records remaining: 3')));assert.equal(covered(f,g).charged,2);},
    async function unclassified() {const f=setup(),{g}=await grant(f);const top=req(f,'top');top.args.undocumented='x';ask(f,top);const nested=req(f,'nested');nested.args.records[0].undocumented='x';ask(f,nested);assert.equal(covered(f,g).charged,0);},
    async function denialFirst() {for(const decision of ['deny','decline']) {const f=setup(),r=req(f,'blocked'),id=ask(f,r),b=browser(f);await b.login();await b.show(id);if(decision==='deny')assert.equal((await b.decide(id,'deny')).status,200);else assert.equal(call(f,{...r,inputResponses:{approve:{action:'decline'}}}).approval.error,'approval_cancelled');const {g}=await grant(f,req(f,'create-grant'));const out=call(f,r);assert.equal(out.approval.error,decision==='deny'?'approval_denied':'approval_cancelled');assert(!out.approval.approval_url);assert.equal(f.count(),0);assert.equal(covered(f,g).charged,0);}
      const h=setup(),{g:hg}=await grant(h),r=req(h,'racing-cancel');h.sor.inject('before-consume',()=>{assert.equal(call(h,{...r,inputResponses:{approve:{action:'decline'}}}).approval.error,'approval_cancelled');});assert.equal(call(h,r).approval.error,'approval_cancelled');assert.equal(h.count(),0);assert.equal(covered(h,hg).charged,0);
    },
    async function session() {
      const f=setup(),id=ask(f),b=browser(f);
      for(const headers of [{},{authorization:'Bearer '+P},{cookie:'va_session='+id}]) {const page=await b.send('GET','/approve/'+id,'',headers);assert(!page.body.includes('new-owner'));assert(!page.body.includes(P));assert.equal((await b.send('POST','/approve/'+id,new URLSearchParams({decision:'approve',csrf:id}),headers)).status,403);}
      assert.equal(f.pending.get(id).status,'pending');await b.login();await b.show(id);f.time(f.now()+2);assert.equal((await b.decide(id,'approve')).status,200);const record=f.core.records().find(r=>r.action_detail.outcome==='approved')??f.core.records().find(r=>r.record_phase==='decision');assert.equal(record.principal,'test-person');assert(record.action_detail.displayed_at<record.action_detail.decided_at);
    },
    async function csrf() {
      const f=setup(),{g,b}=await grant(f),id=ask(f,req(f,'csrf',{operation:OTHER}));await b.show(id);const gr=req(f,'grant-csrf');gr.args.records[0].properties.extra='x';const gid=ask(f,gr); // covered already: use extra field to force a pending record
      await b.show(gid);
      for(const [url,fields] of [['/approve/'+id,{decision:'approve'}],['/approve/'+gid,{decision:'grant',max_records:5,minutes:500/60}],['/grants/'+g.id+'/revoke',{}]]) {
        const before=f.core.records().length;
        for(const [token,headers] of [[undefined,{}],['wrong',{}],[b.token(),{origin:'https://evil.example'}]]) {const data={...fields,...(token===undefined?{}:{csrf:token})};assert.equal((await b.send('POST',url,new URLSearchParams(data),headers)).status,403);}
        assert.equal(f.core.records().length,before);assert.equal(count(f),1);assert.equal(covered(f,g).revoked,null);assert.equal(f.pending.get(id).status,'pending');assert.equal(f.pending.get(gid).status,'pending');
      }
    },
    async function framing() {const f=setup(),id=ask(f),b=browser(f);const responses=[await b.show(id),await b.login(),await b.show(id),await b.list(),await b.decide(id,'approve')];for(const r of responses)assert.match(r.headers['content-security-policy'],/frame-ancestors 'none'/);return na('All page/decision headers forbid framing; actual embedding at another origin requires a browser and is not exercised in-process.');},
    async function transport() {const f=setup();f.pending.baseURL='https://approval.example';const id=ask(f),b=browser(f),before=f.core.records().length;
      for(const [method,url] of [['GET','/approve/'+id],['GET','/grants'],['POST','/approve/'+id],['POST','/grants/abc/revoke'],['POST','/signin']]) {const r=await b.send(method,url,'',{ 'x-forwarded-proto':'http'});assert.equal(r.status,426);assert(!r.body.includes('new-owner'));}assert.equal(f.core.records().length,before);assert.equal((await b.send('GET','/approve/'+id,'',{'x-forwarded-proto':''})).status,426);
      for(const r of [await b.show(id),await b.login(),await b.show(id),await b.decide(id,'approve'),await b.list()]){assert.equal(r.headers['cache-control'],'no-store');assert.equal(r.headers['strict-transport-security'],'max-age=31536000');}return na('Trusted loopback headers and HTTPS-origin HSTS/no-store are checked; no TLS tunnel or public plaintext endpoint is available to establish end-to-end transport.');},
    async function stored() {const f=setup(),id=ask(f),b=browser(f);await b.login();const page=await b.show(id,'?owner=FORGED&summary=FORGED#FORGED');assert.equal(page.status,200);assert(page.body.includes('new-owner'));assert(!page.body.includes('FORGED'));},
    async function displayed() {
      const f=setup(),id=ask(f),other=ask(f,req(f,'other')),b=browser(f);await b.login();await b.show(id);
      const p3=browser(f);await p3.login('test-person-3');await p3.show(other);assert.equal((await p3.decide(id,'approve')).status,403);
      assert.equal((await b.decide(other,'approve')).status,403);
      const second=browser(f);await second.login();await second.show(other);assert.equal((await second.decide(id,'approve')).status,403);
      f.time(f.now()+3);assert.equal((await b.decide(id,'approve')).status,200);const row=f.core.records().find(r=>r.record_phase==='decision');assert.equal(row.action_detail.decided_at-row.action_detail.displayed_at,3);
    },
    async function identifiers() {const f=setup({pendingCap:1100}),ids=[];for(let i=0;i<1000;i++){const r=f.core.handle(req(f,'identifier-'+i));assert.equal(r.approval?.error,'approval_required');ids.push(r.approval.approval_url.split('/').at(-1));}assert.equal(new Set(ids).size,1000);assert(ids.every(id=>/^[a-f0-9]{48}$/.test(id)));assert(new Set(ids.map(id=>id.slice(0,8))).size>990);const b=browser(f);await b.login();const mutated=(ids[0][0]==='a'?'b':'a')+ids[0].slice(1);assert.equal((await b.show(mutated)).status,403);const unauth=browser(f);assert(!(await unauth.show(ids[0])).body.includes('identifier-0'));assert.equal((await unauth.decide(ids[0],'approve')).status,403);},
    async function messages() {const messages=[];for(const decision of ['approve','deny','grant']){const f=setup(),id=ask(f),b=browser(f);await b.login();await b.show(id);const out=await b.decide(id,decision,{...(decision==='grant'?{max_records:5,expires:f.now()+500}:{})});assert.equal(out.status,200);messages.push(out.body);if(decision==='approve'){assert.match(out.body,/Approved/);assert(out.body.includes(readableTime(f.now()+300)),'the use window in the single page time form');}if(decision==='deny')assert.match(out.body,/Denied/);if(decision==='grant')for(const value of ['Granted',P,A,OP,'owner','Record limit','5 records','Records remaining',readableTime(f.now()+500)])assert(out.body.includes(value),value);}assert.equal(new Set(messages).size,3);}
  ];
  return {helpers:{setup,req,ask,browser,grant,concurrent},tests,names:['Create server grant','Match server grant','Field coverage','Server grant limit','Server grant expiry','Server grant revocation','Grant audit type','Grant result text','Unclassified grant input','Denial/cancellation precede grants','Page session','Page request forgery','Page framing','Page transport/cache','Stored rendering','Session display binding','Approval identifiers','Decision messages']};
}
