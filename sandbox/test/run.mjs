import { cases as casesC } from './cases-c.mjs';
import { cases as casesD } from './cases-d.mjs';
import { cases as casesE } from './cases-e.mjs';
import { cases as casesF } from './cases-f.mjs';
import { cases as casesB } from './cases-b.mjs';
import { cases as casesA } from './cases-a.mjs';
import assert from 'node:assert/strict';
import { readFileSync, writeFileSync, mkdtempSync, rmSync } from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { Readable } from 'node:stream';
import { createHandler } from '../src/http.mjs';
import { Sor } from '../src/sor.mjs';
import { Core, OP, QUERY, CREATE, ISSUER, changeObject, hash, mcpResult } from '../src/core.mjs';
import { sign, jwk, parseReceipt, privateKey } from '../src/receipt.mjs';
import { parseJSON, jcs } from '../src/json.mjs';
import { Issuer } from '../src/issuer.mjs';
import { ServerIssued } from '../src/server-issued.mjs';
import { Client } from '@modelcontextprotocol/client';
import { StdioClientTransport } from '@modelcontextprotocol/client/stdio';
const vectors=JSON.parse(readFileSync(new URL('../spec/vectors/vectors.json',import.meta.url)));
const V=vectors.change_hash_vectors, A=V[0].change_object.account, P=V[0].change_object.principal, OTHER='mcp:tools/call:delete_records';
const args=()=>structuredClone(V[0].request_arguments), admin=crypto.randomUUID();
let fixtures=[];
function fixture(settings={}) {
  const dir=mkdtempSync(path.resolve('.va-test-')), db=path.join(dir,'test.sqlite'); let clock=vectors.now;
  const sor=new Sor(db), options={adminCredential:admin,now:()=>clock,settings}; const core=new Core(sor,options);
  for (const account of [A,'acct-EXAMPLE-0002']) for (const principal of [P,'agent-EXAMPLE-other','test-person']) for (const operation of [OP,OTHER,QUERY,CREATE,'mcp:tools/call:run_cleanup','http:PATCH:/records']) sor.permission(account,principal,operation);
  sor.seed(A,'rec-EXAMPLE-42',{lifecycle_stage:'lead',owner:'user-EXAMPLE-3'});
  sor.seed('acct-EXAMPLE-0002','rec-EXAMPLE-42',{});
  for (const account of [A,'acct-EXAMPLE-0002']) core.admin(admin,'issuer',{account,issuer:ISSUER,keys:[jwk],operations:[OP,OTHER,QUERY,CREATE,'mcp:tools/call:run_cleanup'],types:['person','grant','policy'],cachedAt:clock});
  const f={dir,db,sor,core,options,now:()=>clock,time:n=>{clock=n;},req:(a=args(),extra={})=>({account:A,principal:P,operation:OP,args:a,...extra}),count:()=>f.sor.count()};
  fixtures.push(f);return f;
}
function call(f,req=f.req()) {
  const before=f.core.records().length; const r=f.core.handle(req);
  if (!r.ok) {
    assert.equal(f.core.records().at(-1).action_detail.error,r.approval.error);
    assert(f.core.records().length>before);assert(!Object.hasOwn(r,'result'));
    if (req.receipt) assert(!JSON.stringify(r).includes(req.receipt));
    if (req.receipt && typeof req.receipt==='string') assert(!JSON.stringify(f.core.records()).includes(req.receipt));
  }
  return r;
}
function err(f,r,code,before=0) {assert.equal(r.ok,false,JSON.stringify(r));assert.equal(r.approval.error,code);assert.equal(f.count(),before);}
function claims(f,req=f.req(),extra={}) {return {...vectors.receipts.person.claims,jti:crypto.randomUUID(),iat:f.now(),exp:f.now()+300,change_hash:f.core.prepare(req).change_hash,...extra};}
function token(f,req=f.req(),extra={}) {return sign(claims(f,req,extra));}
function approved(f,req=f.req(),extra={}) {return {...req,receipt:token(f,req,extra)};}
function grant(f,req=f.req(),g={}) {return approved(f,req,{approver:{type:'grant',id:'test-person'},grant:{id:'g1',max_records:50,expires:f.now()+1000,...g}});}
function issuer(f) {return new Issuer(f.core);}
function person() {return {id:'test-person',authenticated:true};}
function na(reason) {return {status:'NOT AUTOMATED',reason};}
async function sdk(f,mode,fn,capabilities={elicitation:{url:{},form:{}}},env={}) {
  const c=new Client({name:'conformance',version:'1'},{capabilities,versionNegotiation:{mode:{pin:'2026-07-28'}}});
  let elicited=[]; if (capabilities.elicitation) c.setRequestHandler('elicitation/create',async req=>{elicited.push(req.params);return {action:'accept'};});
  const transport=new StdioClientTransport({command:process.execPath,args:[path.resolve('src/mcp-server.mjs')],env:{...process.env,VA_DB:f.db,VA_ADMIN:admin,VA_MODE:mode,VA_NOW:String(f.now()),VA_ACCOUNT:A,VA_PRINCIPAL:P,...env},stderr:'pipe'});
  let logs='';transport.stderr?.on('data',b=>{logs+=b;});
  try {await c.connect(transport);return await fn(c,elicited,()=>logs);} finally {await c.close();}
}

async function httpCall(f, {method='PATCH',url='/records',body=args(),rawHeaders=[],headers={},cookie}={}) {
  const req=Readable.from([typeof body==='string'?body:JSON.stringify(body)]);Object.assign(req,{method,url,rawHeaders,headers:{...headers,...(cookie?{cookie}: {})}});
  let status, responseHeaders, payload;
  await createHandler({core:f.core,sor:f.sor,account:A,principal:P,pending:f.core.pending})(req,{writeHead(s,h){status=s;responseHeaders=h;},end(b){payload=b;}});
  return {status,headers:responseHeaders,body:payload};
}

function vectorAssertions() {
  for (const v of V) {
    const c=v.change_object;
    const built=changeObject({audience:c.audience,account:c.account,principal:c.principal,operation:c.operation,args:v.request_arguments??{},approvalFields:[...v.approval_fields,'/approval_receipt'],preconditions:c.preconditions,resolved:c.resolved});
    assert.equal(hash(built),v.change_hash,v.name);assert.equal(jcs(built),v.canonical,v.name);
    const f=fixture({audience:c.audience,preconditions:!!c.preconditions});
    if (c.resolved) {f.core.db.prepare('DELETE FROM records WHERE account=?').run(c.account);for(const id of ['rec-EXAMPLE-11','rec-EXAMPLE-12','rec-EXAMPLE-13'])f.sor.seed(c.account,id,{lifecycle_stage:'lead'});}
    const prepared=f.core.prepare(f.req(v.request_arguments??{},{account:c.account,principal:c.principal,operation:c.operation}));
    assert.equal(prepared.change_hash,v.change_hash,'server prepare '+v.name);assert.deepEqual(prepared.change,c);
  }
}
async function test01() {
  vectorAssertions(); const f=fixture();const r=call(f);err(f,r,'approval_required');assert.equal(r.approval.change_hash,V[0].change_hash);assert.deepEqual(r.approval.change,V[0].change_object);
  const wire=mcpResult(r);assert.deepEqual(JSON.parse(wire.content[0].text),wire._meta['com.example.approval/refusal']);
  await sdk(f,'organization',async c=>{const r=await c.callTool({name:'manage_records',arguments:args()});assert(r.isError);assert.deepEqual(JSON.parse(r.content[0].text),r._meta['com.example.approval/refusal']);assert.equal(r._meta['com.example.approval/refusal'].change_hash,V[0].change_hash);});
}
function test02() {for (const confirmation of ['CONFIRMED','WAIVED']) {const f=fixture(),r=call(f,f.req({...args(),confirmation}));err(f,r,'approval_required');assert.equal(r.approval.change_hash,V[0].change_hash);}}
function test03() {for (const confirmation of ['CONFIRMED','WAIVED']) {const f=fixture();const r=call(f,{...f.req({...args(),confirmation}),receipt:vectors.receipts.person.jws});assert.deepEqual(r,{ok:true,result:{changed:1}});assert.equal(f.count(),1);}}
async function test04() {
  const f=fixture();assert(call(f,{...f.req(),receipt:vectors.receipts.person.jws}).ok);assert.equal(f.count(),1);
  assert.deepEqual(f.sor.get(A,'rec-EXAMPLE-42').properties,args().records[0].properties);
  const [consumption,outcome]=f.core.records();assert.equal(consumption.record_phase,'consumption');assert.equal(outcome.action_detail.authorization_record_id,consumption.record_id);assert.equal(outcome.action_detail.approver_type,'person');assert(f.core.chainCheck().ok);
  const g=fixture(),req=g.req();const receipt=token(g,req);const r=call(g,g.req({...args(),approval_receipt:receipt}));assert(r.ok);assert.equal(g.count(),1);assert.equal(g.core.prepare(g.req({...args(),approval_receipt:receipt})).change_hash,V[0].change_hash);
  const argWire=fixture();await sdk(argWire,'organization',async c=>{const receipt=token(argWire);const result=await c.callTool({name:'manage_records',arguments:{...args(),approval_receipt:receipt}});assert(!result.isError);assert.equal(argWire.count(),1);});
  const h=fixture();await sdk(h,'organization',async(c,_,logs)=>{const receipt=token(h);assert(!(await c.callTool({name:'manage_records',arguments:args(),_meta:{'com.example.approval/receipt':receipt}})).isError);assert.equal(h.count(),1);assert(!logs().includes(receipt));});
}
function test05() {const f=fixture(),req=approved(f);assert(call(f,req).ok);err(f,call(f,req),'approval_used',1);}
async function test06() {
  const f=fixture(),sor2=new Sor(f.db),c2=new Core(sor2,f.options),req=approved(f);
  try {const rs=await Promise.all(Array.from({length:20},(_,i)=>Promise.resolve().then(()=>i%2?c2.handle(req):call(f,req))));assert.equal(rs.filter(r=>r.ok).length,1);assert.equal(f.count(),1);} finally {sor2.close();}
  return na('20 calls across two SQLite connections pass; synchronous in-process dispatch does not exercise simultaneous processes or every deployment instance.');
}
function test07() {
  const f=fixture(),req=approved(f);assert(call(f,req).ok);f.sor.close();f.sor=new Sor(f.db);f.core=new Core(f.sor,f.options);err(f,call(f,req),'approval_used',1);
  // No cleanup of used identifiers is implemented. Verify retention at the maximum lifetime boundary.
  const req2=approved(f);assert(call(f,req2).ok);f.time(f.now()+299);err(f,call(f,req2),'approval_used',2);
}
function test08() {const f=fixture();err(f,call(f,{...f.req(V[3].request_arguments),receipt:vectors.receipts.person.jws}),'approval_mismatch');}
function test09() {const f=fixture();assert(call(f,{...f.req(V[2].request_arguments),receipt:vectors.receipts.person.jws}).ok);assert.equal(f.count(),1);}
function test10() {
  const f=fixture();err(f,call(f,{...f.req(args(),{operation:OTHER}),receipt:vectors.receipts.person.jws}),'approval_mismatch');
  const base='http:PATCH:/records';const req=f.req(args(),{operation:base}),receipt=token(f,req);
  const variants=['http:POST:/records','http:PATCH:/other','http:PATCH:/records?x=1'];f.core.admin(admin,'issuer',{account:A,issuer:ISSUER,keys:[jwk],operations:[OP,OTHER,base,...variants],types:['person']});
  for (const operation of variants) {f.sor.permission(A,P,operation);err(f,call(f,{...req,operation,receipt}),'approval_mismatch');}
}
function test11() {const f=fixture();err(f,call(f,{...f.req(args(),{account:'acct-EXAMPLE-0002'}),receipt:vectors.receipts.person.jws}),'approval_mismatch');}
function test12() {const f=fixture();err(f,call(f,{...f.req(args(),{principal:'agent-EXAMPLE-other'}),receipt:vectors.receipts.person.jws}),'approval_mismatch');}
function test13() {const f=fixture(),r=call(f,f.req(args(),{meta:{account:'x',audience:'x',principal:'x',change_hash:'x'}}));err(f,r,'approval_required');assert.equal(r.approval.change_hash,V[0].change_hash);}
function test14() {const f=fixture();err(f,call(f,{...approved(f),effects:{'x-write-mode':'replace'}}),'invalid_input');}
function test15() {const f=fixture();err(f,call(f,{...f.req(),receipt:vectors.receipts.wrong_audience.jws}),'approval_invalid');}
function test16() {
  for (const extra of [{iat:vectors.now-900,exp:vectors.now-600},{iat:vectors.now-361,exp:vectors.now-61},{iat:vectors.now+61,exp:vectors.now+300},{exp:vectors.now+301},{iat:vectors.now-300,exp:vectors.now}]) {const f=fixture();err(f,call(f,approved(f,f.req(),extra)),'approval_expired');}
  const f=fixture();f.core.admin(admin,'settings',{skew:60});assert(call(f,approved(f,f.req(),{iat:f.now()+30,exp:f.now()+300})).ok);assert.equal(f.count(),1);
}
function test17() {const f=fixture();err(f,call(f,{...f.req(V[3].request_arguments),receipt:vectors.receipts.tampered_payload.jws}),'approval_invalid');}
function test18() {
  const f=fixture();const c=claims(f);
  for (const receipt of [sign(c,{alg:'EdDSA',kid:'unknown',typ:'approval-receipt+jwt'}),sign({...c,iss:'https://unregistered.example'}),sign(c,undefined,crypto.generateKeyPairSync('ed25519').privateKey)]) err(f,call(f,{...f.req(),receipt}),'approval_invalid');
  f.core.admin(admin,'removeIssuer',{account:A,issuer:ISSUER});f.core.admin(admin,'issuer',{account:'acct-EXAMPLE-0002',issuer:ISSUER,keys:[jwk],operations:[OP],types:['person']});err(f,call(f,{...f.req(),receipt:sign(c)}),'approval_invalid');
}
function test19() {
  const f=fixture(),c=claims(f),header={alg:'EdDSA',kid:jwk.kid,typ:'approval-receipt+jwt'};
  const raw=(h,p)=>{const input=Buffer.from(h).toString('base64url')+'.'+Buffer.from(p).toString('base64url');return input+'.'+crypto.sign(null,Buffer.from(input),privateKey).toString('base64url');};
  const invalid=['','a.b','@@.@@.@@',raw(JSON.stringify(header),'[]'),raw(JSON.stringify(header),JSON.stringify(c).replace('{','{"jti":"duplicate",')),raw(JSON.stringify(header),'{"iat":9007199254740993}'),sign({...c,exp:String(c.exp)}),sign({...c,iat:c.exp}),sign({...c,grant:{}}),sign({...c,policy:{}}),sign({...c,approver:{type:'person',id:''}}),sign({...c,approver:{type:'grant',id:'x'},grant:{id:'g',max_records:0,expires:f.now()+10}}),sign({...c,approver:{type:'policy',id:'x'},policy:{id:'p',version_hash:5}}),'x'.repeat(8193),'not-a-listed-format'];
  for (const key of Object.keys(c)) {const cc={...c};delete cc[key];invalid.push(sign(cc));}
  for (const h of [{...header,typ:'JWT'},{...header,alg:'none'},{...header,alg:'HS256'},{...header,alg:'ES256'},...['jwk','jku','x5u','x5c','crit'].map(k=>({...header,[k]:'x'}))]) {
    if (h.alg==='HS256') {const input=Buffer.from(JSON.stringify(h)).toString('base64url')+'.'+Buffer.from(JSON.stringify(c)).toString('base64url');const publicKey=crypto.createPublicKey({key:jwk,format:'jwk'}).export({format:'pem',type:'spki'});invalid.push(input+'.'+crypto.createHmac('sha256',publicKey).update(input).digest('base64url'));}
    else if (h.alg==='ES256') invalid.push(sign(c,h,crypto.generateKeyPairSync('ec',{namedCurve:'P-256'}).privateKey));
    else invalid.push(sign(c,h));
  }
  for (const receipt of invalid) err(f,call(f,{...f.req(),receipt}),'approval_invalid');
  // Unknown claims are ignored, including nested unknown members.
  assert(call(f,approved(f,f.req(),{unknown:'ignored',approver:{type:'person',id:'p',extra:'ignored'}})).ok);assert.equal(f.count(),1);
}
async function test20() {
  const f=fixture(),valid=token(f);
  for (const [a,b] of [[valid,'bad'],['bad',valid]]) {
    err(f,call(f,f.req(args(),{meta:{'a/receipt':a,'b/receipt':b}})),'approval_invalid');
    err(f,call(f,f.req({...args(),approval_receipt:a},{meta:{'com.example.approval/receipt':b}})),'approval_invalid');
    err(f,call(f,f.req(args(),{receipt:[a,b]})),'approval_invalid');err(f,call(f,f.req(args(),{receipt:a+','+b})),'approval_invalid');
  }
  for (const tokens of [[valid,'bad'],['bad',valid]]) {
    const result=await httpCall(f,{rawHeaders:['Approval-Receipt',tokens[0],'Approval-Receipt',tokens[1]],headers:{'approval-receipt':tokens.join(', ')}});
    assert.equal(result.status,403);assert.equal(result.headers['content-type'],'application/problem+json');assert.equal(JSON.parse(result.body).approval.error,'approval_invalid');
    const joined=await httpCall(f,{rawHeaders:['Approval-Receipt',tokens.join(',')],headers:{'approval-receipt':tokens.join(',')}});assert.equal(JSON.parse(joined.body).approval.error,'approval_invalid');
  }
  await sdk(f,'organization',async c=>{const r=await c.callTool({name:'manage_records',arguments:{...args(),approval_receipt:valid},_meta:{'com.example.approval/receipt':'bad'}});assert.equal(JSON.parse(r.content[0].text).error,'approval_invalid');});assert.equal(f.count(),0);
  const capped=fixture({pendingCap:1});new ServerIssued(capped.core);askForApproval(capped);
  const before=capped.core.db.prepare('SELECT count(*) n FROM pending').get().n;
  const httpLimit=await httpCall(capped),approval=JSON.parse(httpLimit.body).approval;
  assert.equal(httpLimit.status,429);assert.equal(httpLimit.headers['content-type'],'application/problem+json');
  assert.equal(approval.error,'approval_limit_reached');retryAfter(capped,approval);
  assert.equal(httpLimit.headers['retry-after'],String(approval.retry_after));
  assert.equal(approval.open,1);assert.equal(approval.limit,1);assert(!Object.hasOwn(approval,'approval_url'));
  assert.equal(capped.core.db.prepare('SELECT count(*) n FROM pending').get().n,before);assert.equal(capped.count(),0);

}
function test21() {
  const f=fixture();for (const a of [[],{x:'\ud800'},{x:9007199254740993}]) {const r=call(f,f.req(a));err(f,r,'invalid_input');assert(!('change_hash' in r.approval));}
  for (const rawArguments of ['{"x":1,"x":2}','{"x":9007199254740993}']) {const r=call(f,f.req({}, {rawArguments}));err(f,r,'invalid_input');assert(!('change_hash' in r.approval));}
  assert.equal(call(f,f.req({x:0.1})).approval.error,'approval_required');assert.throws(()=>parseJSON('{"x":{"a":1,"a":2}}'));assert.equal(parseJSON('{"x":0.1}').x,0.1);
}
function test22() {for (const type of ['policy','grant']) {const f=fixture();f.core.admin(admin,'settings',{approverTypes:['person']});err(f,call(f,{...f.req(),receipt:vectors.receipts[type].jws}),'approver_not_authorized');}}
function test23() {for (const [operations,types] of [[[OTHER],['person']],[[OP],['policy']]]) {const f=fixture();f.core.admin(admin,'issuer',{account:A,issuer:ISSUER,keys:[jwk],operations,types});err(f,call(f,{...f.req(),receipt:vectors.receipts.person.jws}),'approver_not_authorized');}}
function test24() {for (const type of ['policy','grant']) {const f=fixture();assert(call(f,{...f.req(),receipt:vectors.receipts[type].jws}).ok);assert.equal(f.count(),1);const r=f.core.records()[0];assert.equal(r.action_detail.approver_type,type);assert(type==='policy'?r.action_detail.policy.id:r.action_detail.grant_id);assert(f.core.chainCheck().ok);}}
async function test25() {
  const f=fixture();f.core.db.prepare('INSERT INTO grants VALUES(?,?,?,?,?,?)').run(A,ISSUER,'g1',50,f.now()+1000,49);
  const two=f.req({...args(),records:[args().records[0],args().records[0]]}),req=grant(f,two);err(f,call(f,req),'grant_exceeded');assert.equal(f.core.db.prepare('SELECT charged FROM grants').get().charged,49);assert.equal(f.core.db.prepare('SELECT count(*) n FROM used').get().n,0);
  const one=grant(f),another=grant(f,f.req(V[3].request_arguments));const rs=await Promise.all([Promise.resolve().then(()=>call(f,one)),Promise.resolve().then(()=>call(f,another))]);assert.equal(rs.filter(r=>r.ok).length,1);assert.equal(f.count(),1);assert.equal(f.core.db.prepare('SELECT charged FROM grants').get().charged,50);
  const g=fixture();g.core.db.exec("CREATE TRIGGER fail_audit BEFORE INSERT ON audit WHEN json_extract(NEW.json,'$.record_phase')='consumption' BEGIN SELECT RAISE(ABORT,'injected'); END;");err(g,call(g,grant(g)),'approval_unavailable');assert.equal(g.core.db.prepare('SELECT count(*) n FROM used').get().n,0);assert.equal(g.core.db.prepare('SELECT count(*) n FROM grants').get().n,0);
}
function test26() {const f=fixture();assert(call(f,grant(f)).ok);for (const g of [{max_records:51},{expires:f.now()+1001}]) err(f,call(f,grant(f,f.req(),g)),'grant_exceeded',1);err(f,call(f,grant(f,f.req(),{id:'expired',expires:f.now()})),'grant_exceeded',1);}
function test27() {
  const f=fixture();const req=f.req({...args(),records:[args().records[0],args().records[0]]});assert(call(f,grant(f,req)).ok);assert.equal(f.count(),2);assert.equal(f.core.db.prepare('SELECT charged FROM grants').get().charged,2);
  f.sor.inject('before-write',()=>{throw Error('failure');});err(f,call(f,grant(f)),'execution_failed',2);assert.equal(f.core.db.prepare('SELECT charged FROM grants').get().charged,3);
  const unknown=f.req({},{operation:'mcp:tools/call:run_cleanup'});err(f,call(f,grant(f,unknown)),'grant_exceeded',2);
}
function test28() {const f=fixture(),req=approved(f);f.sor.inject('before-write',()=>{throw Error('failure');});err(f,call(f,req),'execution_failed');err(f,call(f,req),'approval_used');}
async function test29() {
  const f=fixture(),req=approved(f);f.sor.inject('after-write',()=>{throw Error('response lost');});err(f,call(f,req),'execution_failed',1);err(f,call(f,req),'approval_used',1);
  const g=fixture(),receipt=token(g);
  await sdk(g,'organization',async c=>{await assert.rejects(c.callTool({name:'manage_records',arguments:args(),_meta:{'com.example.approval/receipt':receipt}}));},{elicitation:{url:{}}},{VA_TEST_FAULT:'crash-after-consume'});
  assert.equal(g.count(),0);assert.deepEqual(g.core.records().map(r=>r.record_phase),['consumption']);
  await sdk(g,'organization',async c=>{const r=await c.callTool({name:'manage_records',arguments:args(),_meta:{'com.example.approval/receipt':receipt}});assert.equal(JSON.parse(r.content[0].text).error,'approval_used');});assert.equal(g.count(),0);
}
function test30() {for (const unavailable of ['store','registry','keys']) {const f=fixture();if(unavailable==='keys')f.time(f.now()+3601);f.core.unavailable[unavailable]=true;err(f,call(f,approved(f)),'approval_unavailable');}}
function test31() {const f=fixture(),req=approved(f);f.sor.permission(A,P,OP,true,false);err(f,call(f,req),'permission_denied');assert.equal(f.core.db.prepare('SELECT count(*) n FROM used').get().n,0);}
function test32() {for (const extra of [{skipApproval:true},{dryRun:false},{approval_required:false},{'com.example.approval/refusal':{error:'approval_required'}}]) {const f=fixture();err(f,call(f,f.req({...args(),...extra},{meta:extra})),'approval_required');assert.equal(call(f,f.req(args(),{meta:extra})).approval.change_hash,V[0].change_hash);}}
function test33() {
  const f=fixture();for (const req of [f.req(),{...f.req(),receipt:'not-a-receipt~malformed~value'},f.req([],{}),{...f.req(),receipt:vectors.receipts.expired.jws}]) call(f,req);
  assert.equal(f.core.records().length,4);assert(f.core.chainCheck().ok);
  const row=f.core.db.prepare('SELECT * FROM audit WHERE seq=2').get();const r=JSON.parse(row.json);r.outcome='tampered';f.core.db.prepare('UPDATE audit SET json=? WHERE seq=2').run(JSON.stringify(r));assert.deepEqual(f.core.chainCheck(),{ok:false,seq:2});
  f.core.db.prepare('UPDATE audit SET json=? WHERE seq=2').run(row.json);f.core.db.prepare('DELETE FROM audit WHERE seq=2').run();assert.equal(f.core.chainCheck().ok,false);
}
async function test34() {
  const f=fixture(),p=new ServerIssued(f.core);const r=call(f);err(f,r,'approval_required');assert(r.approval.approval_url);
  for (const extra of [{inputResponses:{approve:{action:'accept'}}},{inputResponses:{approve:{action:'accept',content:{confirm:true}}}},{meta:{requestState:'forged'}},{args:{...args(),confirmation:'CONFIRMED'}}]) err(f,call(f,{...f.req(),...extra}),'approval_required');
  await sdk(f,'server',async(c,elicited)=>{const r=await c.callTool({name:'manage_records',arguments:args()});assert( elicited.length>0);assert.equal(elicited[0].mode,'url');assert(r.isError);assert.equal(JSON.parse(r.content[0].text).error,'approval_required');});assert.equal(f.count(),0);
  await sdk(f,'server',async(c,elicited)=>{const r=await c.callTool({name:'manage_records',arguments:args()});assert.equal(elicited.length,0);assert(JSON.parse(r.content[0].text).approval_url);},{});
}
function test35() {const f=fixture(),p=new ServerIssued(f.core);const r=call(f);const id=r.approval.approval_url.split('/').at(-1);p.page(id,person());p.decide(id,person(),true);err(f,call(f,f.req(V[3].request_arguments)),'approval_required');err(f,call(f,f.req(args(),{principal:'agent-EXAMPLE-other'})),'approval_required');assert(call(f).ok);assert.equal(f.count(),1);err(f,call(f),'approval_used',1);}
function test36() {const f=fixture(),p=new ServerIssued(f.core);const id=call(f).approval.approval_url.split('/').at(-1);assert.throws(()=>p.decide(id,{id:'nobody',authenticated:true},true),/permission/);assert.throws(()=>p.decide(id,{id:'test-person',authenticated:false},true));err(f,call(f),'approval_required');}
function test37() {
  const f=fixture({pendingCap:2}),p=new ServerIssued(f.core);assert(f.core.settings().pendingLifetime<=3600);const id=call(f).approval.approval_url.split('/').at(-1);f.time(f.now()+601);assert.throws(()=>p.decide(id,person(),true),/expired/);for (let i=0;i<5;i++) call(f,f.req({...args(),nonce:i}));assert.equal(f.core.db.prepare("SELECT count(*) n FROM pending WHERE expires>? AND status='pending'").get(f.now()).n,2);assert.equal(f.count(),0);
  limitRefusal(f,f.req({...args(),nonce:'beyond-cap'}),2);
  // The approval expires independently, before the pending record itself does.
  const g=fixture(),pending=new ServerIssued(g.core),req=g.req();
  const approvalId=call(g,req).approval.approval_url.split('/').at(-1);
  const record=pending.get(approvalId);g.time(g.now()+37);pending.page(approvalId,person());
  const decision=pending.decide(approvalId,person(),true),claims=JSON.parse(pending.get(approvalId).claims);
  assert.equal(decision.usable_until,claims.exp);
  assert.equal(claims.exp,Math.min(record.expires,g.now()+g.core.settings().maxLifetime));
  assert(claims.exp<record.expires,'fixture must distinguish approval expiry from pending expiry');
  for(const now of [claims.exp,claims.exp+1]) {
    g.time(now);err(g,call(g,req),'approval_expired');
    assert.equal(g.core.db.prepare('SELECT count(*) n FROM used').get().n,0);
  }
}
async function test38() {
  const f=fixture(),initial=f.core.settings();
  for (const [action,data] of [['issuer',{account:A,issuer:ISSUER,keys:[]}],['removeIssuer',{account:A,issuer:ISSUER}],['settings',{approverTypes:['policy']}],['settings',{maxLifetime:99999}],['settings',{guardedOperations:[]}],['settings',{grantConfig:{[A]:{[OTHER]:{maxRecords:99999,maxSeconds:99999}}}}],['settings',{pageAdministrators:{[A]:[P]}}]]) assert.throws(()=>f.core.admin(P,action,data),/permission/);
  await sdk(f,'organization',async c=>{for (const name of ['manage_records','update_by_query','create_record','delete_records','read_record']) {const r=await c.callTool({name,arguments:{...args(),id:'not-a-record',adminAction:'settings',maxLifetime:99999,issuer:ISSUER,keys:[],guardedOperations:[],grantConfig:{[A]:{[OTHER]:{maxRecords:99999,maxSeconds:99999}}},pageAdministrators:{[A]:[P]}}});if(name!=='read_record')assert(r.isError);}});
  assert.deepEqual(f.core.settings(),initial);assert.equal(f.count(),0);assert.equal(f.core.db.prepare('SELECT count(*) n FROM issuers').get().n,2);
}
function test39() {
  const f=fixture();assert(f.core.settings().keyCacheSeconds<=86400);assert(f.core.settings().removalSeconds<=3600);
  assert.throws(()=>f.core.admin(admin,'issuer',{account:A,issuer:'https://other.example',keys:[jwk],operations:[OP],types:['person']}),/key already/);
  for(let i=0;i<100;i++) err(f,call(f,{...f.req(),receipt:sign(claims(f),{alg:'EdDSA',kid:'unknown-'+i,typ:'approval-receipt+jwt'})}),'approval_invalid');assert.equal(f.core.db.prepare('SELECT refreshes FROM issuers').get().refreshes,1);
  const sor2=new Sor(f.db),c2=new Core(sor2,f.options);
  try {const req=approved(f);f.core.admin(admin,'issuer',{account:A,issuer:ISSUER,keys:[],operations:[OP],types:['person']});err(f,call(f,req),'approval_invalid');assert.equal(c2.handle(req).approval.error,'approval_invalid');f.core.admin(admin,'removeIssuer',{account:A,issuer:ISSUER});assert.equal(c2.handle(req).approval.error,'approval_invalid');}finally{sor2.close();}
  return na('Cache bounds, refresh throttling and immediate revocation pass on two connections; every instance in a deployment cannot be exercised here.');
}
function test40() {
  const f=fixture({preconditions:true}),i=issuer(f),req=f.req(),p=f.core.prepare(req),display=i.display(p.change,{current:p.current,summary:'FAKE',change_hash:'wrong'});assert.deepEqual(display.change,p.change);assert(!JSON.stringify(display).includes('FAKE'));const receipt=i.decide(display,person(),true);assert.equal(parseReceipt(receipt).claims.change_hash,p.change_hash);
  assert.throws(()=>i.display(p.change,{current:{'rec-EXAMPLE-42':{wrong:1}}}));
  const q=fixture();for(const id of ['11','12','13'])q.sor.seed(A,'rec-EXAMPLE-'+id,{lifecycle_stage:'lead'});const qi=issuer(q),qp=q.core.prepare(q.req(V[12].request_arguments,{operation:QUERY}));assert.throws(()=>qi.display(qp.change,{records:['fake']}));
}
function test41() {const f=fixture(),i=issuer(f);assert.deepEqual(i.request(f.core.prepare(f.req()).change),{error:'person_action_required'});assert.equal(f.core.db.prepare('SELECT count(*) n FROM decisions').get().n,0);const d=i.display(f.core.prepare(f.req()).change);assert.throws(()=>i.decide(d,{id:'nobody',authenticated:true},true));assert.throws(()=>i.decide(d,{...person(),authenticated:false},true));f.time(f.now()+2);const r=parseReceipt(i.decide(d,person(),true)).claims,record=i.decision(ISSUER,r.jti);assert.equal(record.displayed_at,vectors.now);assert.equal(record.decided_at,vectors.now+2);}
function test42() {
  const f=fixture(),i=issuer(f),terms={...vectors.grant_example,id:'issuer-grant',max_records:1};const display=i.displayGrant(terms);assert.throws(()=>i.createGrant(display,person(),false));assert.throws(()=>i.underGrant(terms.id,V[0].change_object));i.createGrant(display,person(),true);
  for(const key of ['principal','audience','account','operation'])assert.throws(()=>i.underGrant(terms.id,{...V[0].change_object,[key]:'different'}));
  const c=structuredClone(V[0].change_object);c.arguments.records[0].properties={forbidden:'x'};assert.throws(()=>i.underGrant(terms.id,c));f.time(terms.not_before-1);assert.throws(()=>i.underGrant(terms.id,V[0].change_object));f.time(terms.expires);assert.throws(()=>i.underGrant(terms.id,V[0].change_object));f.time(vectors.now);assert.equal(parseReceipt(i.underGrant(terms.id,V[0].change_object)).claims.approver.type,'grant');assert.throws(()=>i.underGrant(terms.id,V[0].change_object));
}
function test43() {const f=fixture(),i=issuer(f),c=V[0].change_object;assert.throws(()=>i.underPolicy('p',c));assert.throws(()=>i.registerPolicy(P,'p','v1',()=>true));i.registerPolicy(admin,'p','v1',change=>change.arguments.action==='update');const r=parseReceipt(i.underPolicy('p',c,{agentFacts:{action:'delete'}})).claims;assert.deepEqual(r.policy,{id:'p',version_hash:hash('v1')});assert.equal(r.approver.type,'policy');const d={...c,arguments:{action:'delete'}};assert.throws(()=>i.underPolicy('p',d,{agentFacts:{action:'update'}}));}
function test44() {const f=fixture(),i=issuer(f),display=i.display(V[0].change_object);const yes=parseReceipt(i.decide(display,person(),true)).claims;assert.equal(i.decision(ISSUER,yes.jti).decision,'approved');const no=i.decide(display,person(),false);assert.equal(i.decision(ISSUER,no.receipt_id).decision,'denied');assert.equal(i.decision('https://wrong.example',yes.jti),undefined);assert.throws(()=>i.createGrant(i.displayGrant({...vectors.grant_example,id:'denied-grant'}),person(),false),e=>{assert.equal(i.decision(ISSUER,e.receipt_id).decision,'denied');return true;});}
function test45() {
  const f=fixture({preconditions:true}),p=f.core.prepare(f.req());assert.equal(p.change_hash,V[11].change_hash);const r=call(f);assert.equal(hash(r.approval.current['rec-EXAMPLE-42']),r.approval.change.preconditions[0].state_hash);
  const req=approved(f);f.sor.seed(A,'rec-EXAMPLE-42',{lifecycle_stage:'changed',owner:'new'});err(f,call(f,req),'approval_mismatch');assert.notDeepEqual(call(f).approval.change.preconditions,p.change.preconditions);
  const c=f.req({id:'new-record',objectType:'contact',properties:{name:'n'}},{operation:CREATE}),cr=approved(f,c);f.sor.seed(A,'new-record',{name:'other'});err(f,call(f,cr),'conflict');
  const g=fixture({preconditions:true}),gone=approved(g);g.core.db.prepare('DELETE FROM records WHERE account=? AND id=?').run(A,'rec-EXAMPLE-42');err(g,call(g,gone),'conflict');
  const h=fixture({preconditions:true}),hr=approved(h);h.sor.inject('before-write',()=>{h.core.db.prepare('UPDATE records SET version=version+1 WHERE account=?').run(A);});err(h,call(h,hr),'conflict');
  const k=fixture({preconditions:true});k.sor.permission(A,P,OP,false,true);const hidden=call(k);assert(!('current'in hidden.approval));assert.equal(k.count(),0);
}
function queryFixture() {const f=fixture();f.core.db.prepare('DELETE FROM records WHERE account=?').run(A);for(const id of ['11','12','13'])f.sor.seed(A,'rec-EXAMPLE-'+id,{lifecycle_stage:'lead'});return f;}
function test46() {
  const f=queryFixture(),req=f.req(V[12].request_arguments,{operation:QUERY});const r=call(f,req);assert.equal(r.approval.change_hash,V[12].change_hash);assert.equal(hash(r.approval.records),r.approval.change.resolved.manifest_hash);
  assert(call(f,grant(f,req)).ok);assert.equal(f.count(),3);assert.equal(f.core.db.prepare('SELECT charged FROM grants').get().charged,3);assert.deepEqual(f.core.db.prepare('SELECT record FROM history ORDER BY record').all().map(x=>x.record),r.approval.records);
  const g=queryFixture(),qr=g.req(V[12].request_arguments,{operation:QUERY}),approvedQuery=approved(g,qr);g.sor.seed(A,'rec-EXAMPLE-14',{lifecycle_stage:'lead'});err(g,call(g,approvedQuery),'approval_mismatch');
  const h=queryFixture(),qh=h.req(V[12].request_arguments,{operation:QUERY}),hr=approved(h,qh);h.sor.inject('before-write',()=>h.sor.seed(A,'rec-EXAMPLE-14',{lifecycle_stage:'lead'}));assert(call(h,hr).ok);assert.equal(h.count(),3);assert(!h.core.db.prepare('SELECT 1 FROM history WHERE record=?').get('rec-EXAMPLE-14'));
  const k=queryFixture();k.core.admin(admin,'settings',{selectionLimit:2});err(k,call(k,k.req(V[12].request_arguments,{operation:QUERY})),'selection_limit');
}
function test47() {const f=fixture();f.sor.seed(A,'second',{});const a=args();a.records.push({id:'second',properties:{owner:'changed'}});const req=approved(f,f.req(a));f.sor.inject('before-record:second',()=>{throw Error('record rejected');});err(f,call(f,req),'execution_failed',1);err(f,call(f,req),'approval_used',1);const subset=f.req({...a,records:[a.records[1]]});err(f,call(f,{...subset,receipt:req.receipt}),'approval_mismatch',1);assert(call(f,approved(f,subset)).ok);assert.equal(f.count(),2);assert.equal(f.core.db.prepare("SELECT count(*) n FROM history WHERE record='second'").get().n,1);}
// Tests 48/49 use actual page handlers with in-memory HTTP messages, never sockets.
function askForApproval(f,req=f.req()) {
  const result=call(f,req);err(f,result,'approval_required');
  assert.equal(typeof result.approval.approval_url,'string');
  return result.approval.approval_url.split('/').at(-1);
}
function retryAfter(f,approval,minimum=1) {
  assert(Object.hasOwn(approval,'retry_after'),approval.error+' must carry retry_after');
  assert(Number.isInteger(approval.retry_after) && approval.retry_after>=minimum && approval.retry_after<=f.core.settings().pendingLifetime,'retry_after must be an integer within the pending lifetime');
}
function limitRefusal(f,req,expectedOpen=f.core.settings().pendingCap) {
  const before=f.core.db.prepare('SELECT count(*) n FROM pending').get().n;
  const result=call(f,req);err(f,result,'approval_limit_reached');
  const a=result.approval;
  assert.equal(a.open,expectedOpen);assert.equal(a.limit,f.core.settings().pendingCap);
  assert(Number.isInteger(a.open) && Number.isInteger(a.limit));retryAfter(f,a);
  assert.equal(typeof a.message,'string');assert(a.message.trim().length>0);
  assert(!Object.hasOwn(a,'approval_url'),'a capped request must not offer an approval link');
  assert.equal(f.core.db.prepare('SELECT count(*) n FROM pending').get().n,before,'a capped request must not create a record');
  return result;
}
function terminalRefusal(f,req,code) {
  const result=call(f,req);err(f,result,code);
  assert(!Object.hasOwn(result.approval,'approval_url'),'terminal refusal must not offer an approval link');
  const record=f.core.db.prepare('SELECT id FROM pending WHERE hash=?').get(result.approval.change_hash);
  retryAfter(f,result.approval,record?1:0);
  return result;
}
async function decideOnPage(f,id,decision) {
  const handler=createHandler({core:f.core,sor:f.sor,account:A,principal:P,pending:f.core.pending});
  async function request(method,url,body='',headers={}) {
    const req=Readable.from([String(body)]);Object.assign(req,{method,url,headers,rawHeaders:[]});
    let status,responseHeaders,text;
    await handler(req,{writeHead(s,h){status=s;responseHeaders=h;},end(value){text=value;}});
    return {status,headers:responseHeaders,body:text};
  }
  const url='/approve/'+id;
  const first=await request('GET',url);const preCookie=first.headers['set-cookie'].split(';')[0];
  const preToken=/name="csrf" value="([a-f0-9]+)"/.exec(first.body)?.[1];
  const login=await request('POST','/signin',new URLSearchParams({person:'test-person',csrf:preToken}),{cookie:preCookie});
  assert.equal(login.status,303);assert.equal(login.headers.location,url);
  const cookie=login.headers['set-cookie'].split(';')[0];
  const display=await request('GET',url,'',{cookie});assert.equal(display.status,200);
  const csrf=/name="csrf" value="([a-f0-9]+)"/.exec(display.body)?.[1];assert(csrf);
  const result=await request('POST',url,new URLSearchParams({csrf,decision}),{cookie});
  assert.equal(result.status,200);assert.equal(f.count(),0);
  return result;
}
function test48() {
  for(const action of ['decline','cancel']) {
    const f=fixture(),p=new ServerIssued(f.core),req=f.req(),id=askForApproval(f,req);
    p.page(id,person());const approval=p.decide(id,person(),true),record=p.get(id);
    terminalRefusal(f,{...req,inputResponses:{approve:{action}}},'approval_cancelled');
    assert.equal(p.get(id).status,'cancelled');assert.equal(p.get(id).expires,record.expires);
    assert.equal(f.core.db.prepare('SELECT count(*) n FROM used').get().n,0);
    // Both a neutral retry and a client "accept" must preserve the cancellation.
    for(const now of [f.now(),approval.usable_until+1,record.expires-1]) {
      f.time(now);terminalRefusal(f,req,'approval_cancelled');
      terminalRefusal(f,{...req,inputResponses:{approve:{action:'accept'}}},'approval_cancelled');
      assert.equal(f.core.db.prepare('SELECT count(*) n FROM pending').get().n,1);
      assert.equal(p.get(id).status,'cancelled');
    }
    f.time(record.expires);const freshId=askForApproval(f,req);
    assert.notEqual(freshId,id);assert.equal(p.get(freshId).status,'pending');assert.equal(f.count(),0);
  }
  for(const action of ['decline','cancel']) {
    const f=fixture();new ServerIssued(f.core);
    terminalRefusal(f,f.req(args(),{inputResponses:{approve:{action}}}),'approval_cancelled');
    assert.equal(f.core.db.prepare('SELECT count(*) n FROM pending').get().n,0,'a veto without a record must not create one');
  }
  const f=fixture({pendingCap:3}),p=new ServerIssued(f.core);
  const changed=i=>f.req({...args(),records:[{...args().records[0],properties:{...args().records[0].properties,owner:'cap-owner-'+i}}]});
  for(let i=0;i<3;i++) {
    const req=changed(i),id=askForApproval(f,req);
    terminalRefusal(f,{...req,inputResponses:{approve:{action:'decline'}}},'approval_cancelled');
    terminalRefusal(f,req,'approval_cancelled');assert.equal(p.get(id).status,'cancelled');
  }
  for(let i=3;i<7;i++) {
    limitRefusal(f,changed(i),3);
  }
  assert.equal(f.core.db.prepare('SELECT count(*) n FROM pending WHERE principal=? AND expires>?').get(P,f.now()).n,3);
  // The cap belongs to the principal, rather than globally blocking other principals.
  askForApproval(f,{...changed(7),principal:'agent-EXAMPLE-other'});
  assert.equal(f.count(),0);
}
async function test49() {
  const f=fixture({pendingCap:1}),p=new ServerIssued(f.core),req=f.req(),id=askForApproval(f,req);
  const denied=await decideOnPage(f,id,'deny'),record=p.get(id);
  assert.match(denied.body,/\bdenied\b/i);assert.doesNotMatch(denied.body,/\bapproved\b/i);
  assert.equal(record.status,'denied');
  const g=fixture();new ServerIssued(g.core);
  const approved=await decideOnPage(g,askForApproval(g),'approve');
  assert.match(approved.body,/\bapproved\b/i);assert.doesNotMatch(approved.body,/\bdenied\b/i);
  assert.notEqual(denied.body,approved.body,'denial and approval must have distinct page messages');
  terminalRefusal(f,req,'approval_denied');
  terminalRefusal(f,{...req,inputResponses:{approve:{action:'decline'}}},'approval_denied');
  terminalRefusal(f,req,'approval_denied');
  // Neither cancel nor accept may override a denial, even after an approval would have expired.
  for(const action of ['cancel','accept']) terminalRefusal(f,{...req,inputResponses:{approve:{action}}},'approval_denied');
  const blocked=f.req({...args(),records:[{...args().records[0],properties:{owner:'changed-after-denial'}}]});
  limitRefusal(f,blocked,1);
  f.time(record.expires-1);terminalRefusal(f,req,'approval_denied');
  assert.equal(p.get(id).status,'denied');assert.equal(p.get(id).expires,record.expires);
  assert.equal(f.core.db.prepare('SELECT count(*) n FROM used').get().n,0);
  f.time(record.expires);const freshId=askForApproval(f,req);
  assert.notEqual(freshId,id);assert.equal(p.get(freshId).status,'pending');assert.equal(f.count(),0);
}
const tests=[test01,test02,test03,test04,test05,test06,test07,test08,test09,test10,test11,test12,test13,test14,test15,test16,test17,test18,test19,test20,test21,test22,test23,test24,test25,test26,test27,test28,test29,test30,test31,test32,test33,test34,test35,test36,test37,test38,test39,test40,test41,test42,test43,test44,test45,test46,test47,test48,test49];
const names=['Missing receipt','Approval field without receipt','Approval field with receipt','Valid receipt','Replay','Concurrent replay','Restart and expiry','Changed argument','Reordered members','Other tool and HTTP target','Other account','Other principal','Untrusted target metadata','Outside inputs','Wrong audience','Times','Tampered payload','Keys','Malformed receipts','Two receipts','Unsafe input','Approver type','Issuer scope','Recorded approver','Grant limit and atomic rollback','Fixed grant terms','Counting','Execution failure','Unknown outcome','Unavailable','Ordinary permissions','No opt-out','Audit and chain tampering','Connection cannot approve','Approved change only','Approver permission','Pending cap and expiry','Administrative settings','Key freshness','Issuer object and proofs','Person action and timing','Grant terms','Registered policy','Decision lookup','Stale and conditional writes','Resolved query','Partial batch failure','Client decline and sticky cancellation','Sticky page denial'];
const additions=casesA({fixture,args,call,A,P,OTHER,admin,na});tests.push(...additions.tests);names.push(...additions.names);
const stage10=casesB({helpers:additions.helpers,call,A,admin});tests.push(...stage10.tests);names.push(...stage10.names);
const stage11=casesC({helpers:additions.helpers,call,A});tests.push(...stage11.tests);names.push(...stage11.names);
const stage12=casesD({helpers:additions.helpers,call,A,sdk});tests.push(...stage12.tests);names.push(...stage12.names);
const stage13=casesE({helpers:additions.helpers,call,A,sdk});tests.push(...stage13.tests);names.push(...stage13.names);
const stage14=casesF({helpers:additions.helpers,call,A});tests.push(...stage14.tests);names.push(...stage14.names);
const rows=[];
for(let n=0;n<tests.length;n++) {
  let status='PASS',reason='';
  try {const r=await tests[n]();if(r){status=r.status;reason=r.reason;}}
  catch(e){status='FAIL';reason=e.message.replace(/\s+/g,' ').slice(0,450);if(process.env.VA_DEBUG)console.error(e.stack);}
  finally {for(const f of fixtures){try{f.sor.close();}catch{}rmSync(f.dir,{recursive:true,force:true});}fixtures=[];}
  rows.push({number:n+1,name:names[n],status,reason});
}
const counts=Object.fromEntries(['PASS','FAIL','NOT AUTOMATED'].map(s=>[s,rows.filter(r=>r.status===s).length]));
const summary=`SUMMARY: PASS=${counts.PASS} FAIL=${counts.FAIL} NOT AUTOMATED=${counts['NOT AUTOMATED']}`;
const report=['| Test | Short name | Status | Reason |','|---|---|---|---|',...rows.map(r=>`| ${r.number} | ${r.name} | ${r.status} | ${r.reason.replaceAll('|','\\|')} |`),'',summary,''].join('\n');
console.log(report);if(process.env.VA_REPORT!=='0')writeFileSync('RESULTS.md',report);if(counts.FAIL)process.exitCode=1;
