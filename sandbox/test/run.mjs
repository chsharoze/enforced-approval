import { cases as casesC } from './cases-c.mjs';
import { cases as casesD } from './cases-d.mjs';
import { cases as casesE } from './cases-e.mjs';
import { cases as casesF } from './cases-f.mjs';
import { cases as casesG } from './cases-g.mjs';
import { cases as casesH } from './cases-h.mjs';
import { cases as casesI } from './cases-i.mjs';
import { cases as casesJ } from './cases-j.mjs';
import { cases as casesK } from './cases-k.mjs';
import { cases as casesL } from './cases-l.mjs';
import { cases as casesB } from './cases-b.mjs';
import { cases as casesA } from './cases-a.mjs';
import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import { once } from 'node:events';
import { readFileSync, writeFileSync, mkdtempSync, rmSync } from 'node:fs';
import path from 'node:path';
import net from 'node:net';
import crypto from 'node:crypto';
import { Readable } from 'node:stream';
import { createHandler } from '../src/http.mjs';
import { Sor } from '../src/sor.mjs';
import { Core, OP, QUERY, CREATE, COPY, ISSUER, changeObject, hash, mcpResult } from '../src/core.mjs';
import { sign, jwk, parseReceipt, privateKey } from '../src/receipt.mjs';
import { parseJSON, jcs } from '../src/json.mjs';
import { Issuer } from '../src/issuer.mjs';
import { ServerIssued } from '../src/server-issued.mjs';
import { Client, StreamableHTTPClientTransport } from '@modelcontextprotocol/client';
import { StdioClientTransport } from '@modelcontextprotocol/client/stdio';
const vectors=JSON.parse(readFileSync(new URL('../spec/vectors/vectors.json',import.meta.url)));
// The conformance runner owns the configuration of every server it starts (a fresh fixture
// per test, with its own settings and time). A start setting taken from the environment
// would leak into those spawned stdio and page servers and forge a run that is not the
// documented one, and the run would then overwrite RESULTS.md with it. Refuse such a run
// with a clear message rather than producing a misleading RESULTS.md. VA_REPORT=0 is the
// documented way to run without writing RESULTS.md; VA_MUTATE selects an Off hook.
const START_VARS=['VA_PRECONDITIONS','VA_PENDING_LIFETIME','VA_PENDING_CAP','VA_SELECTION_LIMIT','VA_RETENTION_FLOOR','VA_MAX_LIFETIME','VA_SKEW','VA_GRANT_CHARGE_LIMIT','VA_GRANT_SECONDS_LIMIT','VA_KEY_CACHE','VA_APPROVER_NOTIFICATION','VA_APPROVER_MODEL','VA_PRINCIPAL_MODEL','VA_NOW','VA_DB','VA_MODE','VA_ACCOUNT','VA_PRINCIPAL','VA_TEST_ISSUER','VA_ADMIN','VA_BASE_URL','VA_SIGNIN_SECRET','VA_EDGE_MARKER','VA_LOG'];
if (process.env.VA_RUNNER_ALLOW_START_VARS!=='1') {
  const leaked=START_VARS.filter(name=>process.env[name]!==undefined);
  if (leaked.length) {
    console.error(`refusing to run: the environment sets start settings ${leaked.join(', ')}. ` +
      'The runner configures each server it starts; a setting from the environment would leak ' +
      'into the spawned servers and make a run that is not the documented one. Unset these ' +
      'variables (use VA_REPORT=0 to run without writing RESULTS.md).');
    process.exit(2);
  }
}
const V=vectors.change_hash_vectors, A=V[0].change_object.account, P=V[0].change_object.principal, OTHER='mcp:tools/call:delete_records';
const args=()=>structuredClone(V[0].request_arguments), admin=crypto.randomUUID();
// S79: the HTTP mapping takes the connector's path token. The in-process handler reads it
// from the environment, so the runner sets one before any handler is created.
const PATH_TOKEN='va-runner-path-token-0123456789abcdef';
process.env.VA_PATH_TOKEN ||= PATH_TOKEN;
let fixtures=[];
function fixture(settings={}) {
  const dir=mkdtempSync(path.resolve('.va-test-')), db=path.join(dir,'test.sqlite'); let clock=vectors.now;
  const sor=new Sor(db), options={adminCredential:admin,now:()=>clock,settings}; const core=new Core(sor,options);
  for (const account of [A,'acct-EXAMPLE-0002']) for (const principal of [P,'agent-EXAMPLE-other','test-person']) for (const operation of [OP,OTHER,QUERY,CREATE,'mcp:tools/call:run_cleanup','http:PATCH:/records']) sor.permission(account,principal,operation);
  if(settings.preconditions)for(const account of [A,'acct-EXAMPLE-0002'])for(const principal of [P,'agent-EXAMPLE-other','test-person'])sor.permission(account,principal,COPY);
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
function ni(reason) {return {status:'NOT IMPLEMENTED',reason};}
async function sdk(f,mode,fn,capabilities={elicitation:{url:{},form:{}}},env={}) {
  const c=new Client({name:'conformance',version:'1'},{capabilities,versionNegotiation:{mode:{pin:'2026-07-28'}}});
  let elicited=[]; if (capabilities.elicitation) c.setRequestHandler('elicitation/create',async req=>{elicited.push(req.params);return {action:'accept'};});
  const transport=new StdioClientTransport({command:process.execPath,args:[path.resolve('src/mcp-server.mjs')],env:{...process.env,VA_DB:f.db,VA_ADMIN:admin,VA_MODE:mode,VA_NOW:String(f.now()),VA_ACCOUNT:A,VA_PRINCIPAL:P,VA_TEST_ISSUER:'1',...env},stderr:'pipe'});
  let logs='';transport.stderr?.on('data',b=>{logs+=b;});
  try {await c.connect(transport);return await fn(c,elicited,()=>logs);} finally {await c.close();}
}

async function httpCall(f, {method='PATCH',url='/records',body=args(),rawHeaders=[],headers={},cookie,authorization=`Bearer ${process.env.VA_PATH_TOKEN}`}={}) {
  const req=Readable.from([typeof body==='string'?body:JSON.stringify(body)]);Object.assign(req,{method,url,rawHeaders,headers:{...(authorization?{authorization}:{}),...headers,...(cookie?{cookie}: {})}});
  let status, responseHeaders, payload;
  await createHandler({core:f.core,sor:f.sor,account:A,principal:P,pending:f.core.pending})(req,{writeHead(s,h){status=s;responseHeaders=h;},end(b){payload=b;}});
  return {status,headers:responseHeaders,body:payload};
}

function vectorAssertions() {
  for (const v of V) {
    const c=v.change_object;
    const built=changeObject({audience:c.audience,account:c.account,principal:c.principal,operation:c.operation,args:v.request_arguments??{},approvalFields:[...v.approval_fields,'/approval_receipt'],preconditions:c.preconditions,resolved:c.resolved});
    assert.equal(hash(built),v.change_hash,v.name);assert.equal(jcs(built),v.canonical,v.name);
    if (c.preconditions || c.resolved) continue; // covered operations (S61) are not implemented by the sandbox
    const f=fixture({audience:c.audience,preconditions:!!c.preconditions});
    if (c.resolved) {f.core.db.prepare('DELETE FROM records WHERE account=?').run(c.account);for(const id of ['rec-EXAMPLE-11','rec-EXAMPLE-12','rec-EXAMPLE-13'])f.sor.seed(c.account,id,{lifecycle_stage:'lead'});}
    const prepared=f.core.prepare(f.req(v.request_arguments??{},{account:c.account,principal:c.principal,operation:c.operation}));
    assert.equal(prepared.change_hash,v.change_hash,'server prepare '+v.name);assert.deepEqual(prepared.change,c);
  }
}
async function test01() {
  vectorAssertions(); const f=fixture();const r=call(f);err(f,r,'approval_required');assert.equal(r.approval.change_hash,V[0].change_hash);assert.deepEqual(r.approval.change,V[0].change_object);
  const wire=mcpResult(r);assert.deepEqual(JSON.parse(wire.content[0].text),wire._meta['org.enforcedapproval/refusal']);
  await sdk(f,'organization',async c=>{const r=await c.callTool({name:'manage_records',arguments:args()});assert(r.isError);assert.deepEqual(JSON.parse(r.content[0].text),r._meta['org.enforcedapproval/refusal']);assert.equal(r._meta['org.enforcedapproval/refusal'].change_hash,V[0].change_hash);});
}
function test02() {for (const confirmation of ['CONFIRMED','WAIVED']) {const f=fixture(),r=call(f,f.req({...args(),confirmation}));err(f,r,'approval_required');assert.equal(r.approval.change_hash,V[0].change_hash);}}
function test03() {for (const confirmation of ['CONFIRMED','WAIVED']) {const f=fixture();const r=call(f,{...f.req({...args(),confirmation}),receipt:vectors.receipts.person.jws});assert.deepEqual(r,{ok:true,result:{changed:1}});assert.equal(f.count(),1);}}
async function test04() {
  const f=fixture();assert(call(f,{...f.req(),receipt:vectors.receipts.person.jws}).ok);assert.equal(f.count(),1);
  assert.deepEqual(f.sor.get(A,'rec-EXAMPLE-42').properties,args().records[0].properties);
  const [consumption,outcome]=f.core.records();assert.equal(consumption.record_phase,'consumption');assert.equal(outcome.action_detail.authorization_record_id,consumption.record_id);assert.equal(outcome.action_detail.approver_type,'person');assert(f.core.chainCheck().ok);
  const g=fixture(),req=g.req();const receipt=token(g,req);const r=call(g,g.req({...args(),approval_receipt:receipt}));assert(r.ok);assert.equal(g.count(),1);assert.equal(g.core.prepare(g.req({...args(),approval_receipt:receipt})).change_hash,V[0].change_hash);
  const argWire=fixture();await sdk(argWire,'organization',async c=>{const receipt=token(argWire);const result=await c.callTool({name:'manage_records',arguments:{...args(),approval_receipt:receipt}});assert(!result.isError);assert.equal(argWire.count(),1);});
  const h=fixture();await sdk(h,'organization',async(c,_,logs)=>{const receipt=token(h);assert(!(await c.callTool({name:'manage_records',arguments:args(),_meta:{'org.enforcedapproval/receipt':receipt}})).isError);assert.equal(h.count(),1);assert(!logs().includes(receipt));});
}
// Draft 0.2 test 5: the replay returns the recorded outcome while the server holds it (S80).
function test05() {const f=fixture(),req=approved(f);assert(call(f,req).ok);const replay=call(f,req);assert(replay.ok);assert.equal(replay.result.changed,1);assert.equal(replay.result.recorded_outcome.outcome,'success');assert.equal(replay.result.recorded_outcome.sent_now,false);assert(replay.result.recorded_outcome.message.includes('Nothing was sent now'));assert.equal(f.count(),1);}
async function test06() {
  const f=fixture(),sor2=new Sor(f.db),c2=new Core(sor2,f.options),req=approved(f);
  try {const rs=await Promise.all(Array.from({length:20},(_,i)=>Promise.resolve().then(()=>i%2?c2.handle(req):call(f,req))));assert.equal(rs.filter(r=>r.ok).length,20);assert.equal(rs.filter(r=>r.result?.recorded_outcome?.outcome==='success').length,19);assert.equal(f.count(),1);} finally {sor2.close();}
  return na('20 calls across two SQLite connections pass; synchronous in-process dispatch does not exercise simultaneous processes or every deployment instance.');
}
function test07() {
  const f=fixture(),req=approved(f);assert(call(f,req).ok);f.sor.close();f.sor=new Sor(f.db);f.core=new Core(f.sor,f.options);const replay=call(f,req);assert(replay.ok);assert.equal(replay.result.recorded_outcome.outcome,'success');assert.equal(f.count(),1);
  // No cleanup of used identifiers is implemented. Verify retention at the maximum lifetime boundary.
  const req2=approved(f);assert(call(f,req2).ok);f.time(f.now()+299);const replay2=call(f,req2);assert(replay2.ok);assert.equal(replay2.result.recorded_outcome.outcome,'success');assert.equal(f.count(),2);
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
  // Signed receipts Section 4: `policy.inputs` is "an array of objects, each with `ref` and
  // `hash`". A keyed object in its place, a non-array, an entry missing a member, an entry
  // with an extra member and an empty ref are each refused (S7).
  const policyClaims={...c,approver:{type:'policy',id:'p'},policy:{id:'p',version_hash:'h'}};
  for (const inputs of [{risk:{ref:'r',hash:'h'}},'x',[{ref:'r'}],[{ref:'r',hash:'h',extra:'x'}],[{ref:'',hash:'h'}]])
    invalid.push(sign({...policyClaims,policy:{...policyClaims.policy,inputs}}));
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
    err(f,call(f,f.req({...args(),approval_receipt:a},{meta:{'org.enforcedapproval/receipt':b}})),'approval_invalid');
    err(f,call(f,f.req(args(),{receipt:[a,b]})),'approval_invalid');err(f,call(f,f.req(args(),{receipt:a+','+b})),'approval_invalid');
  }
  for (const tokens of [[valid,'bad'],['bad',valid]]) {
    const result=await httpCall(f,{rawHeaders:['Approval-Receipt',tokens[0],'Approval-Receipt',tokens[1]],headers:{'approval-receipt':tokens.join(', ')}});
    assert.equal(result.status,403);assert.equal(result.headers['content-type'],'application/problem+json');assert.equal(JSON.parse(result.body).approval.error,'approval_invalid');
    const joined=await httpCall(f,{rawHeaders:['Approval-Receipt',tokens.join(',')],headers:{'approval-receipt':tokens.join(',')}});assert.equal(JSON.parse(joined.body).approval.error,'approval_invalid');
  }
  await sdk(f,'organization',async c=>{const r=await c.callTool({name:'manage_records',arguments:{...args(),approval_receipt:valid},_meta:{'org.enforcedapproval/receipt':'bad'}});assert.equal(JSON.parse(r.content[0].text).error,'approval_invalid');});assert.equal(f.count(),0);
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
  for (const rawArguments of ['{"x":1,"x":2}','{"x":9007199254740993}','{"x":9007199254740993.0}','{"x":9.007199254740993e15}']) {const r=call(f,f.req({}, {rawArguments}));err(f,r,'invalid_input');assert(!('change_hash' in r.approval));}
  for (const rawArguments of ['{"x":9007199254740993.0}','{"x":9.007199254740993e15}']) {const r=call(f,f.req({}, {rawArguments}));assert(r.approval.message.includes('safe range'),r.approval.message);}
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
// Draft 0.2 (S80): the replay returns the recorded outcome, here a recorded failure.
function test28() {const f=fixture(),req=approved(f);f.sor.inject('before-write',()=>{throw Error('failure');});err(f,call(f,req),'execution_failed');const replay=call(f,req);assert.equal(replay.approval.error,'execution_failed');assert.equal(replay.approval.recorded_outcome.outcome,'execution_failed');assert(replay.approval.message.includes('Nothing was sent now'));assert.equal(f.count(),0);}
async function test29() {
  const f=fixture(),req=approved(f);f.sor.inject('after-write',()=>{throw Error('response lost');});
  // S25/S64/S77: the write was sent and its response was lost, so the outcome is not
  // known. It is recorded as unknown and answered as unknown — a result, never
  // execution_failed, which says the write did not run.
  const first=call(f,req);
  assert(first.ok,'a lost response is answered as an unknown outcome, not execution_failed: '+JSON.stringify(first.approval));
  assert.equal(first.result.outcome,'unknown');
  assert(!Object.hasOwn(first.result,'changed'),'no count is claimed for an unknown outcome');
  assert.equal(f.count(),1,'the write ran once');
  const recorded=f.core.records().find(x=>x.record_phase==='outcome');
  assert.equal(recorded.outcome,'unknown','the outcome is recorded as unknown');
  assert(f.core.chainCheck().ok,true);
  // Draft 0.2 (S80/S25): the outcome is unknown, so the replay says so and writes nothing.
  const replay=call(f,req);assert(replay.ok,JSON.stringify(replay));assert.equal(replay.result.recorded_outcome.outcome,'unknown');assert.equal(replay.result.recorded_outcome.sent_now,false);assert.equal(f.count(),1);
  const g=fixture(),receipt=token(g);
  await sdk(g,'organization',async c=>{await assert.rejects(c.callTool({name:'manage_records',arguments:args(),_meta:{'org.enforcedapproval/receipt':receipt}}));},{elicitation:{url:{}}},{VA_TEST_FAULT:'crash-after-consume'});
  assert.equal(g.count(),0);assert.deepEqual(g.core.records().map(r=>r.record_phase),['consumption']);
  await sdk(g,'organization',async c=>{const r=await c.callTool({name:'manage_records',arguments:args(),_meta:{'org.enforcedapproval/receipt':receipt}});const body=JSON.parse(r.content[0].text);assert(!r.isError);assert.equal(body.recorded_outcome.outcome,'unknown');assert.equal(g.count(),0);});assert.equal(g.count(),0);
}
function test30() {for (const unavailable of ['store','registry','keys']) {const f=fixture();if(unavailable==='keys')f.time(f.now()+3601);f.core.unavailable[unavailable]=true;err(f,call(f,approved(f)),'approval_unavailable');}}
function test31() {const f=fixture(),req=approved(f);f.sor.permission(A,P,OP,true,false);err(f,call(f,req),'permission_denied');assert.equal(f.core.db.prepare('SELECT count(*) n FROM used').get().n,0);}
function test32() {for (const extra of [{skipApproval:true},{dryRun:false},{approval_required:false},{'org.enforcedapproval/refusal':{error:'approval_required'}}]) {const f=fixture();err(f,call(f,f.req({...args(),...extra},{meta:extra})),'approval_required');assert.equal(call(f,f.req(args(),{meta:extra})).approval.change_hash,V[0].change_hash);}}
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
// Draft 0.2 (S80): retrying the original request returns the recorded success; only a
// different change needs a new approval.
function test35() {const f=fixture(),p=new ServerIssued(f.core);const r=call(f);const id=r.approval.approval_url.split('/').at(-1);p.page(id,person());p.decide(id,person(),true);err(f,call(f,f.req(V[3].request_arguments)),'approval_required');err(f,call(f,f.req(args(),{principal:'agent-EXAMPLE-other'})),'approval_required');assert(call(f).ok);assert.equal(f.count(),1);const replay=call(f);assert(replay.ok);assert.equal(replay.result.recorded_outcome.outcome,'success');assert.equal(f.count(),1);}
function test36() {const f=fixture(),p=new ServerIssued(f.core);const id=call(f).approval.approval_url.split('/').at(-1);assert.throws(()=>p.decide(id,{id:'nobody',authenticated:true},true),/permission/);assert.throws(()=>p.decide(id,{id:'test-person',authenticated:false},true));err(f,call(f),'approval_required');}
function test37() {
  const f=fixture({pendingCap:2}),p=new ServerIssued(f.core);assert(f.core.settings().pendingLifetime<=3600);const id=call(f).approval.approval_url.split('/').at(-1);
  // The pending lifetime is the registry's default of 3600 seconds (S27's at most 1 hour);
  // one second past it the record has expired and takes no decision.
  f.time(f.now()+f.core.settings().pendingLifetime+1);assert.throws(()=>p.decide(id,person(),true),/expired/);for (let i=0;i<5;i++) call(f,f.req({...args(),nonce:i}));assert.equal(f.core.db.prepare("SELECT count(*) n FROM pending WHERE expires>? AND status='pending'").get(f.now()).n,2);assert.equal(f.count(),0);
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
  // I1 names an operation that is not covered; a covered one has no issuer (S66).
  const f=fixture(),i=issuer(f),req=f.req(),p=f.core.prepare(req),display=i.display(p.change,{current:p.current,summary:'FAKE',change_hash:'wrong'});assert.deepEqual(display.change,p.change);assert(!JSON.stringify(display).includes('FAKE'));const receipt=i.decide(display,person(),true);assert.equal(parseReceipt(receipt).claims.change_hash,p.change_hash);
  // The Draft 0.1 clause that the issuer checks current against the change is withdrawn
  // (S66); a covered change object (here an update by query, which uses resolved) is refused.
  const q=fixture();for(const id of ['11','12','13'])q.sor.seed(A,'rec-EXAMPLE-'+id,{lifecycle_stage:'lead'});const qi=issuer(q),qp=q.core.prepare(q.req(V[12].request_arguments,{operation:QUERY}));assert.throws(()=>qi.display(qp.change,{records:['fake']}));
}
function test41() {const f=fixture(),i=issuer(f);assert.deepEqual(i.request(f.core.prepare(f.req()).change),{error:'person_action_required'});assert.equal(f.core.db.prepare('SELECT count(*) n FROM decisions').get().n,0);const d=i.display(f.core.prepare(f.req()).change);assert.throws(()=>i.decide(d,{id:'nobody',authenticated:true},true));assert.throws(()=>i.decide(d,{...person(),authenticated:false},true));f.time(f.now()+2);const r=parseReceipt(i.decide(d,person(),true)).claims,record=i.decision(ISSUER,r.jti);assert.equal(record.displayed_at,vectors.now);assert.equal(record.decided_at,vectors.now+2);}
function test42() {
  const f=fixture(),i=issuer(f),terms={...vectors.grant_example,id:'issuer-grant',max_records:1};const display=i.displayGrant(terms);assert.throws(()=>i.createGrant(display,person(),false));assert.throws(()=>i.underGrant(terms.id,V[0].change_object));i.createGrant(display,person(),true);
  for(const key of ['principal','audience','account','operation'])assert.throws(()=>i.underGrant(terms.id,{...V[0].change_object,[key]:'different'}));
  const c=structuredClone(V[0].change_object);c.arguments.records[0].properties={forbidden:'x'};assert.throws(()=>i.underGrant(terms.id,c));f.time(terms.not_before-1);assert.throws(()=>i.underGrant(terms.id,V[0].change_object));f.time(terms.expires);assert.throws(()=>i.underGrant(terms.id,V[0].change_object));f.time(vectors.now);assert.equal(parseReceipt(i.underGrant(terms.id,V[0].change_object)).claims.approver.type,'grant');assert.throws(()=>i.underGrant(terms.id,V[0].change_object));
}
// Draft 0.2 test 43: the receipt records a registered input beyond the change object by
// reference and hash; changing the input changes the recorded hash, and a new model
// version changes the recorded reference (I4).
function test43() {const f=fixture(),i=issuer(f),c=V[0].change_object;assert.throws(()=>i.underPolicy('p',c));assert.throws(()=>i.registerPolicy(P,'p','v1',()=>true));i.registerPolicy(admin,'p','v1',change=>change.arguments.action==='update');const r=parseReceipt(i.underPolicy('p',c,{agentFacts:{action:'delete'}})).claims;assert.deepEqual(r.policy,{id:'p',version_hash:hash('v1')});assert.equal(r.approver.type,'policy');const d={...c,arguments:{action:'delete'}};assert.throws(()=>i.underPolicy('p',d,{agentFacts:{action:'update'}}));
  const inputs={risk:{ref:'risk-source',value:()=>'low'},quota:{ref:'quota-source',value:()=>({remaining:5})}};
  i.registerPolicy(admin,'inputs','v1',()=>true,inputs);
  const first=parseReceipt(i.underPolicy('inputs',c)).claims;
  assert.equal(first.policy.id,'inputs');assert.equal(first.policy.version_hash,hash('v1'));
  // Signed receipts profile Section 4: "optionally `inputs`: an array of objects, each with
  // `ref` and `hash`, for the inputs I4 allows." The receipt carries that shape, not a
  // keyed object.
  assert(Array.isArray(first.policy.inputs),'policy.inputs is an array');
  assert.deepEqual(first.policy.inputs.map(x=>x.ref).sort(),['quota-source','risk-source']);
  for (const x of first.policy.inputs) {assert.deepEqual(Object.keys(x).sort(),['hash','ref'],'each input carries exactly ref and hash');assert.equal(typeof x.hash,'string');}
  assert.deepEqual(first.policy.inputs.find(x=>x.ref==='risk-source').hash,hash('low'));
  assert.deepEqual(first.policy.inputs.find(x=>x.ref==='quota-source').hash,hash({remaining:5}));
  inputs.risk.value=()=>'high'; // change one source so the computed value changes
  const second=parseReceipt(i.underPolicy('inputs',c)).claims;
  assert.notEqual(second.policy.inputs.find(x=>x.ref==='risk-source').hash,first.policy.inputs.find(x=>x.ref==='risk-source').hash,'the recorded hash changes');
  assert.equal(second.policy.inputs.find(x=>x.ref==='quota-source').hash,first.policy.inputs.find(x=>x.ref==='quota-source').hash,'the unchanged input keeps its hash');
  i.registerPolicy(admin,'inputs','v2',()=>true,inputs); // change the model version
  const third=parseReceipt(i.underPolicy('inputs',c)).claims;
  assert.notEqual(third.policy.version_hash,first.policy.version_hash,'the recorded reference changes');}
function test44() {const f=fixture(),i=issuer(f),display=i.display(V[0].change_object);const yes=parseReceipt(i.decide(display,person(),true)).claims;assert.equal(i.decision(ISSUER,yes.jti).decision,'approved');const no=i.decide(display,person(),false);assert.equal(i.decision(ISSUER,no.receipt_id).decision,'denied');assert.equal(i.decision('https://wrong.example',yes.jti),undefined);assert.throws(()=>i.createGrant(i.displayGrant({...vectors.grant_example,id:'denied-grant'}),person(),false),e=>{assert.equal(i.decision(ISSUER,e.receipt_id).decision,'denied');return true;});}
async function test45() {
  // Draft 0.2 (S28, S61, S64, S68(3)): the server-issued profile, a principal that may
  // read the record, the covered mode with the published HMAC test key.
  const {setup,req,ask,browser}=additions.helpers;
  const cov=()=>setup({preconditions:true,stateKey:vectors.state_manifest_hmac_key});
  const used=f=>f.core.db.prepare('SELECT count(*) n FROM used').get().n;
  const approve=async(f,r)=>{const id=ask(f,r),b=browser(f);await b.login();await b.show(id);await b.decide(id,'approve');};
  // Obtain an approval for an update, change the record, then send the approved request.
  const f=cov(),r=req(f);
  const first=call(f,r);assert.equal(first.approval.error,'approval_required');
  // The state_hash in the preconditions of the first refusal, before the record is
  // changed, equals the value in V12, computed with the HMAC test key.
  assert.equal(first.approval.change.preconditions[0].state_hash,V[11].change_object.preconditions[0].state_hash,'the value in V12');
  await approve(f,r);
  f.sor.seed(A,'rec-EXAMPLE-42',{lifecycle_stage:'changed',owner:'new'});
  const stale=call(f,r);
  assert.equal(stale.approval.error,'approval_required','no write, no consumption, approval_required');
  assert(stale.approval.change&&stale.approval.change_hash,'carrying the fresh change object and change hash');
  assert.equal(stale.approval.change.preconditions[0].state_hash,f.core.prepare(r).change.preconditions[0].state_hash,'the fresh change object');
  assert.equal(f.count(),0,'no write');assert.equal(used(f),0,'no consumption');
  assert(f.core.db.prepare("SELECT 1 FROM pending WHERE status='stale'").get(),'the approved record is kept as stale');
  // Approve a create, create the record by another path, then send the approved request:
  // a conflict refusal before approval is accepted but not required.
  const g=cov(),gc=g.req({objectType:'contact',action:'create',records:[{id:'rec-EXAMPLE-45',properties:{owner:'n'}}]});
  await approve(g,gc);
  g.sor.seed(A,'rec-EXAMPLE-45',{owner:'other'});
  const gout=call(g,gc);
  assert(['approval_required','conflict'].includes(gout.approval.error),'conflict before approval is accepted but not required: '+gout.approval.error);
  assert.equal(g.count(),0,'no write');assert.equal(used(g),0,'no consumption');
  // Delete a record with an approved update, then send it: the same rule applies.
  const h=cov(),hr=req(h);await approve(h,hr);
  h.core.db.prepare('DELETE FROM records WHERE account=? AND id=?').run(A,'rec-EXAMPLE-42');
  const hout=call(h,hr);
  assert(['approval_required','conflict'].includes(hout.approval.error),'the same rule applies: '+hout.approval.error);
  assert.equal(h.count(),0,'no write');assert.equal(used(h),0,'no consumption');
  // Where the system of record supports conditional writes, force a change between
  // verification and the write: expect no write.
  const k=cov(),kr=req(k);await approve(k,kr);
  k.sor.inject('before-write',()=>{k.core.db.prepare('UPDATE records SET version=version+1 WHERE account=?').run(A);});
  err(k,call(k,kr),'conflict');assert.equal(k.count(),0,'no write');
}
async function test46() {
  // Draft 0.2 (S19, S29, S61, S68(3), S69(4)): the server-issued profile, a reader.
  const {setup,ask,browser,grant}=additions.helpers;
  const covq=()=>{const f=setup({preconditions:true,stateKey:vectors.state_manifest_hmac_key});f.core.db.prepare('DELETE FROM records WHERE account=?').run(A);for(const id of ['11','12','13'])f.sor.seed(A,'rec-EXAMPLE-'+id,{lifecycle_stage:'lead'});f.core.admin(admin,'settings',{grantConfig:{...f.core.settings().grantConfig,[A]:{...f.core.settings().grantConfig?.[A],[QUERY]:{maxRecords:10,maxSeconds:1000,anyRecord:true}}}});return f;};
  const used=f=>f.core.db.prepare('SELECT count(*) n FROM used').get().n;
  const query=f=>f.req(structuredClone(V[12].request_arguments),{operation:QUERY});
  // Approve an update by query that selects 3 records (vector V13).
  const f=covq(),qr=query(f);
  const first=call(f,qr);assert.equal(first.approval.error,'approval_required');
  // manifest_hash, computed as S61 defines with the HMAC test key over the approved
  // arguments and the three selected records, equals the value in V13.
  assert.equal(first.approval.change.resolved.manifest_hash,V[12].change_object.resolved.manifest_hash,'the value in V13');
  const {g}=await grant(f,qr);
  // Send the approved request: exactly those 3 records change and a grant is charged 3.
  assert(call(f,qr).ok);assert.equal(f.count(),3);assert.equal(f.pending.grants.get(g.id).charged,3);
  assert.deepEqual(f.core.db.prepare('SELECT record FROM history ORDER BY record').all().map(x=>x.record),['rec-EXAMPLE-11','rec-EXAMPLE-12','rec-EXAMPLE-13']);
  // With a fresh approval for a request that has a new value of the distinguishing
  // argument (S69(4)), add a fourth matching record before sending.
  const g2=covq(),qr2=g2.req({...structuredClone(V[12].request_arguments),change_tag:'second-selection'},{operation:QUERY});
  const id2=ask(g2,qr2),b2=browser(g2);await b2.login();await b2.show(id2);await b2.decide(id2,'approve');
  g2.sor.seed(A,'rec-EXAMPLE-14',{lifecycle_stage:'lead'});
  const out2=call(g2,qr2);
  assert.equal(out2.approval.error,'approval_required');
  assert(out2.approval.change&&out2.approval.change_hash,'carrying the fresh change object and change hash');
  assert.equal(out2.approval.change.resolved.count,4,'the selection grew');
  assert.equal(g2.count(),0,'no write');assert.equal(used(g2),0,'the approval is not consumed');
  // Add a matching record between verification and the write: it is not changed.
  const h=covq(),qh=query(h);
  const id3=ask(h,qh),b3=browser(h);await b3.login();await b3.show(id3);await b3.decide(id3,'approve');
  h.sor.inject('before-write',()=>h.sor.seed(A,'rec-EXAMPLE-15',{lifecycle_stage:'lead'}));
  assert(call(h,qh).ok);assert.equal(h.count(),3);assert(!h.core.db.prepare('SELECT 1 FROM history WHERE record=?').get('rec-EXAMPLE-15'),'the added record is not changed');
  // A selection over the server's limit is refused.
  const k=covq();k.core.admin(admin,'settings',{selectionLimit:2});
  err(k,call(k,query(k)),'selection_limit');
}
function test47() {const f=fixture();f.sor.seed(A,'second',{});const a=args();a.records.push({id:'second',properties:{owner:'changed'}});const req=approved(f,f.req(a));f.sor.inject('before-record:second',()=>{throw Error('record rejected');});
  // S17, S77: a request whose entries partly succeed has the result outcome
  // `partial`, a result not a refusal, with each entry's outcome; `execution_failed` is only
  // for a request in which no entry succeeded. The first entry wrote; the second did not.
  const partial=call(f,req);assert(partial.ok,'a partial result is a result, not a refusal: '+JSON.stringify(partial.approval));assert.equal(partial.result.outcome,'partial');assert.equal(partial.result.changed,1);assert.deepEqual(partial.result.entries.map(e=>e.outcome),['success','execution_failed']);assert.equal(f.count(),1,'only the first entry was written');
  // S80: the replay returns the recorded partial, never a second write.
  const replay=call(f,req);assert(replay.ok,JSON.stringify(replay));assert.equal(replay.result.outcome,'partial');assert.equal(replay.result.recorded_outcome.outcome,'partial');assert.equal(f.count(),1);
  const subset=f.req({...a,records:[a.records[1]]});err(f,call(f,{...subset,receipt:req.receipt}),'approval_mismatch',1);assert(call(f,approved(f,subset)).ok);assert.equal(f.count(),2);assert.equal(f.core.db.prepare("SELECT count(*) n FROM history WHERE record='second'").get().n,1);}
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
  const login=await request('POST','/signin',new URLSearchParams({person:'test-person',csrf:preToken,secret:f.core.signinSecret??''}),{cookie:preCookie});
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
  // S30 (item 12): a cancellation locks the change for at most one hour, whatever the
  // pending lifetime is. With a two-hour pending lifetime the record outlives the lockout:
  // after one hour a new approval can be requested, while the record still exists.
  const long=fixture({pendingLifetime:7200,approverNotification:true});new ServerIssued(long.core);
  const lreq=long.req(),lrecordId=askForApproval(long,lreq);
  terminalRefusal(long,{...lreq,inputResponses:{approve:{action:'decline'}}},'approval_cancelled');
  terminalRefusal(long,lreq,'approval_cancelled');
  long.time(long.now()+3599);terminalRefusal(long,lreq,'approval_cancelled');
  long.time(long.now()+1);
  const lfresh=askForApproval(long,lreq);
  assert.notEqual(lfresh,lrecordId,'after one hour a cancellation no longer locks the change');
  assert.equal(long.count(),0);
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
  // S31 (item 12): a denial locks the change for at most one hour, whatever the pending
  // lifetime is. A two-hour pending record outlives the lockout, and after one hour a new
  // approval can be requested.
  const long=fixture({pendingLifetime:7200,approverNotification:true}),lp=new ServerIssued(long.core);
  const lreq=long.req(),lrecordId=askForApproval(long,lreq);
  lp.page(lrecordId,person());lp.decide(lrecordId,person(),false);
  terminalRefusal(long,lreq,'approval_denied');
  long.time(long.now()+3599);terminalRefusal(long,lreq,'approval_denied');
  long.time(long.now()+1);
  const lfresh=askForApproval(long,lreq);
  assert.notEqual(lfresh,lrecordId,'after one hour a denial no longer locks the change');
  assert.equal(long.count(),0);
}
// Draft 0.2 test 50: read_record checks read permission on the identifier and treats an
// identifier that resolves to a record the principal may not read as one that names no
// record (S78, S60, S77). Section 2: a record the principal may not read is
// answered exactly as an absent identifier (`null`), at record and operation level, so the
// read cannot be used as an oracle on which records exist.
async function test50() {
  const f=fixture();
  f.sor.seed(A,'rec-SECRET-50',{owner:'secret-owner-50',notes:'confidential-50'});
  f.sor.recordPermission(A,P,'rec-SECRET-50',false,true);
  f.sor.merge(A,'rec-ALIAS-50','rec-SECRET-50');
  f.sor.seed(A,'rec-OPEN-50',{owner:'open-owner-50'});
  f.sor.merge(A,'rec-OPEN-ALIAS-50','rec-OPEN-50');
  await sdk(f,'organization',async c=>{
    const read=id=>c.callTool({name:'read_record',arguments:{id}});
    const denied=await read('rec-SECRET-50'),aliased=await read('rec-ALIAS-50'),absent=await read('rec-ABSENT-50');
    assert.deepEqual(JSON.parse(denied.content[0].text),null,'a record the principal may not read is answered as an absent identifier');
    assert(!denied.isError);
    assert.equal(JSON.stringify(denied),JSON.stringify(absent),'the denied record answers exactly as an absent identifier');
    assert.deepEqual(JSON.parse(aliased.content[0].text),null,'an alias of a record the principal may not read is answered as an absent identifier');
    assert(!aliased.isError);
    assert.equal(JSON.stringify(aliased),JSON.stringify(absent),'the alias answers exactly as an absent identifier');
    for(const answer of [denied,aliased])assert(!JSON.stringify(answer).includes('secret-owner-50'),'no record content');
    assert.deepEqual(JSON.parse(absent.content[0].text),null,'an identifier that names no record is answered as before');
    const open=await read('rec-OPEN-ALIAS-50');
    assert(!open.isError);assert.equal(JSON.parse(open.content[0].text).properties.owner,'open-owner-50','a readable alias is still read');
  });
}
// Organization mode takes the operator's issuer public key in VA_ISSUER_PUBLIC_KEY. The
// built-in test key is accepted only with VA_TEST_ISSUER=1, and organization mode
// refuses to start with neither (stdio and connector both exit non-zero).
async function test51() {
  const base=()=>{const e={...process.env};delete e.VA_TEST_ISSUER;delete e.VA_ISSUER_PUBLIC_KEY;return e;};
  const f=fixture();
  const env={...base(),VA_ADMIN:admin,VA_MODE:'organization',VA_DB:f.db,VA_NOW:String(f.now()),VA_SIGNIN_SECRET:'org-refusal'};
  const stdio=spawnSync(process.execPath,[path.resolve('src/mcp-server.mjs')],{cwd:process.cwd(),env,encoding:'utf8',input:'',timeout:15000});
  assert(stdio.status!==0&&stdio.status!==null,`organization stdio starts without an issuer key: ${stdio.status} ${stdio.signal} ${stdio.stderr}`);
  assert(/VA_ISSUER_PUBLIC_KEY/.test(stdio.stderr)&&/VA_TEST_ISSUER/.test(stdio.stderr),'the stdio refusal names the key variable and the test flag: '+stdio.stderr);
  const webEnv={...base(),VA_ADMIN:admin,VA_MODE:'organization',VA_DB:path.join(f.dir,'org.sqlite'),VA_LOG:path.join(f.dir,'org.log'),VA_PATH_TOKEN:'t'.repeat(24),VA_BASE_URL:'http://127.0.0.1:1',PORT:'0',VA_NOW:String(f.now()),VA_SIGNIN_SECRET:'org-refusal'};
  const connector=spawnSync(process.execPath,[path.resolve('src/mcp-http.mjs')],{cwd:process.cwd(),env:webEnv,encoding:'utf8',input:'',timeout:15000});
  assert(connector.status!==0&&connector.status!==null,`the connector starts without an issuer key: ${connector.status} ${connector.signal} ${connector.stderr}`);
  assert(/VA_ISSUER_PUBLIC_KEY/.test(connector.stderr)&&/VA_TEST_ISSUER/.test(connector.stderr),'the connector refusal names the key variable and the test flag: '+connector.stderr);
  // The built-in test key is accepted with VA_TEST_ISSUER=1.
  const testIssuer=fixture();
  await sdk(testIssuer,'organization',async c=>{
    const r=await c.callTool({name:'manage_records',arguments:args(),_meta:{'org.enforcedapproval/receipt':vectors.receipts.person.jws}});
    assert(!r.isError,JSON.stringify(r));
  },{}, {VA_TEST_ISSUER:'1',VA_ISSUER_PUBLIC_KEY:''});
  assert.equal(testIssuer.count(),1);
  // With the operator's key set and VA_TEST_ISSUER unset, the built-in key is refused
  // and a receipt signed by the operator's key works.
  const operator=fixture();
  const {publicKey,privateKey:operatorPrivate}=crypto.generateKeyPairSync('ed25519');
  const operatorJwk={...publicKey.export({format:'jwk'}),kid:'operator-key-1',alg:'EdDSA',use:'sig'};
  await sdk(operator,'organization',async c=>{
    const denied=await c.callTool({name:'manage_records',arguments:args(),_meta:{'org.enforcedapproval/receipt':vectors.receipts.person.jws}});
    assert.equal(denied.isError,true,'the built-in test key is refused without VA_TEST_ISSUER=1');
    assert.equal(denied._meta['org.enforcedapproval/refusal']?.error,'approval_invalid');
    const claims={...vectors.receipts.person.claims,jti:crypto.randomUUID(),iat:operator.now(),exp:operator.now()+300};
    const receipt=sign(claims,{alg:'EdDSA',kid:'operator-key-1',typ:'approval-receipt+jwt'},operatorPrivate);
    const ok=await c.callTool({name:'manage_records',arguments:args(),_meta:{'org.enforcedapproval/receipt':receipt}});
    assert(!ok.isError,JSON.stringify(ok));
  },{}, {VA_ISSUER_PUBLIC_KEY:JSON.stringify(operatorJwk),VA_TEST_ISSUER:''});
  assert.equal(operator.count(),1);
}
// A real connector process on a loopback port, for the restart and secret checks.
async function freePort() {
  const s=net.createServer(); await new Promise((resolve,reject)=>{s.once('error',reject);s.listen(0,'127.0.0.1',resolve);});
  const p=s.address().port; await new Promise(r=>s.close(r)); return p;
}
async function startConnector(db, extra={}) {
  const port=await freePort(), base=`http://127.0.0.1:${port}`, token=crypto.randomBytes(24).toString('hex');
  const env={...process.env,VA_ADMIN:admin,VA_DB:db,VA_LOG:path.join(path.dirname(db),'connector.log'),PORT:String(port),VA_BASE_URL:base,VA_PATH_TOKEN:token,NODE_NO_WARNINGS:'1',...extra};
  const child=spawn(process.execPath,[path.resolve('src/mcp-http.mjs')],{cwd:process.cwd(),env,stdio:['ignore','pipe','pipe']});
  let stderr=''; child.stderr.on('data',b=>{stderr+=b;});
  await new Promise((resolve,reject)=>{
    const timer=setTimeout(()=>reject(Error('connector startup timeout: '+stderr)),10000);
    child.once('exit',code=>{clearTimeout(timer);reject(Error('connector exited '+code+': '+stderr));});
    child.stdout.on('data',b=>{if(String(b).includes('MCP HTTP listening')){clearTimeout(timer);resolve();}});
  });
  return {base,token,child,stderr:()=>stderr};
}
async function stopConnector(c) {
  if(c.child.exitCode!==null||c.child.signalCode!==null)return;
  const exit=once(c.child,'exit'); c.child.kill('SIGTERM'); const timer=setTimeout(()=>c.child.kill('SIGKILL'),2000);
  await exit; clearTimeout(timer);
}
// 155. A withheld field's change must not be observable through read_record (S76, S60).
async function test52() {
  const f=fixture();
  f.sor.fieldPermission(A,P,OP,'/notes',false,'read');
  f.sor.seed(A,'rec-WITHHELD-155',{owner:'owner-155',notes:'secret-155'});
  await sdk(f,'organization',async c=>{
    const read=async()=>JSON.parse((await c.callTool({name:'read_record',arguments:{id:'rec-WITHHELD-155'}})).content[0].text);
    const first=await read();
    f.sor.write(A,[{id:'rec-WITHHELD-155',properties:{notes:'secret-155-changed'}}],'update','contact');
    const second=await read();
    assert.equal(JSON.stringify(second),JSON.stringify(first),'the two answers are byte-identical after only a withheld field changes');
    assert(!Object.hasOwn(first,'version'),'version is withheld while a field is withheld');
    assert.deepEqual(first.withheld,['/notes']);
    assert.equal(first.properties.owner,'owner-155');
    assert(!JSON.stringify(first).includes('secret-155'),'no denied value is returned');
    f.sor.write(A,[{id:'rec-WITHHELD-155',properties:{owner:'owner-155-changed'}}],'update','contact');
    const third=await read();
    assert.notEqual(JSON.stringify(third),JSON.stringify(second),'a readable field change is still visible');
    assert.equal(third.properties.owner,'owner-155-changed');
  });
  const plain=fixture(); plain.sor.seed(A,'rec-PLAIN-155',{owner:'owner',notes:'notes'});
  await sdk(plain,'organization',async c=>{
    const answer=JSON.parse((await c.callTool({name:'read_record',arguments:{id:'rec-PLAIN-155'}})).content[0].text);
    assert(Number.isInteger(answer.version),'without a denial the record is returned unchanged');
    assert(!Object.hasOwn(answer,'withheld'));
    assert.deepEqual(answer,plain.sor.get(A,'rec-PLAIN-155'));
  });
}
// 156. The stdio server never prints the sign-in secret; the page-serving connector does.
async function test53() {
  const secret='stdio-never-prints-1f4c';
  const f=fixture();
  await sdk(f,'organization',async(c,_,logs)=>{
    await c.callTool({name:'read_record',arguments:{id:'rec-EXAMPLE-42'}});
    assert(!logs().includes(secret),'the stdio server printed the sign-in secret: '+logs());
  },{},{VA_SIGNIN_SECRET:secret});
  const dir=mkdtempSync(path.resolve('.va-secret-')),db=path.join(dir,'test.sqlite');
  try {
    const connector=await startConnector(db,{VA_SIGNIN_SECRET:secret});
    try {
      assert(connector.stderr().includes('Sandbox sign-in secret: '+secret),'the connector did not print the secret: '+connector.stderr());
    } finally { await stopConnector(connector); }
  } finally { rmSync(dir,{recursive:true,force:true}); }
}
// 157. A restart does not re-grant the default permissions (S76).
async function test54() {
  const dir=mkdtempSync(path.resolve('.va-restart-')),db=path.join(dir,'test.sqlite');
  try {
    const first=await startConnector(db); await stopConnector(first);
    const sor=new Sor(db);
    const granted=sor.can(A,P,OP,'read');
    sor.permission(A,P,OP,false,true);
    sor.close();
    assert.equal(granted,true,'the fresh start granted the default read permission');
    const second=await startConnector(db);
    try {
      const c=new Client({name:'restart',version:'1'},{capabilities:{},versionNegotiation:{mode:{pin:'2026-07-28'}}});
      await c.connect(new StreamableHTTPClientTransport(new URL(second.base+'/mcp/'+second.token)));
      try {
        const r=await c.callTool({name:'read_record',arguments:{id:'rec-EXAMPLE-42'}});
        // Section 2: a record the principal may not read is answered as an
        // absent identifier (`null`), which is still a non-reader, not as content.
        assert.deepEqual(JSON.parse(r.content[0].text),null,'the principal is still a non-reader after the restart');
      } finally { await c.close(); }
    } finally { await stopConnector(second); }
    const after=new Sor(db); const still=after.can(A,P,OP,'read'); after.close();
    assert.equal(still,false,'the restart did not restore the read permission');
  } finally { for(const s of ['','-wal','-shm']) rmSync(db+s,{force:true}); rmSync(dir,{recursive:true,force:true}); }
}
// 158. The HTTP mapping requires its bearer token: 401, no read and no record otherwise.
async function test55() {
  const f=fixture();
  const handler=createHandler({core:f.core,sor:f.sor,account:A,principal:P,pending:f.core.pending});
  const send=async authorization=>{
    const headers=authorization?{authorization}:{};
    const req=Readable.from([JSON.stringify(args())]);Object.assign(req,{method:'PATCH',url:'/records',headers,rawHeaders:[]});
    let status,responseHeaders,payload;
    await handler(req,{writeHead(s,h){status=s;responseHeaders=h;},end(b){payload=b;}});
    return {status,headers:responseHeaders,body:payload};
  };
  const reads=f.sor.reads(),records=f.core.records().length;
  for(const [label,authorization] of [['missing',undefined],['wrong','Bearer wrong-'+'0'.repeat(24)]]) {
    const r=await send(authorization);
    assert.equal(r.status,401,label+' token: '+r.status);
    assert(!String(r.body).includes('new-owner'),label+' token read nothing');
  }
  assert.equal(f.sor.reads(),reads,'nothing was read without the token');
  assert.equal(f.core.records().length,records,'no approval refusal was recorded without the token');
  const right=await send('Bearer '+process.env.VA_PATH_TOKEN);
  assert.equal(right.status,403);
  assert.equal(JSON.parse(right.body).approval.error,'approval_required');
}
const tests=[test01,test02,test03,test04,test05,test06,test07,test08,test09,test10,test11,test12,test13,test14,test15,test16,test17,test18,test19,test20,test21,test22,test23,test24,test25,test26,test27,test28,test29,test30,test31,test32,test33,test34,test35,test36,test37,test38,test39,test40,test41,test42,test43,test44,test45,test46,test47,test48,test49];
const names=['Missing approval','Approval field does nothing without an approval','Approval field does nothing with an approval','Valid approval runs once','Replay','Concurrent replay','Replay after restart and near expiry','Changed argument','Reordered members','Other tool','Other account','Other principal','Client-supplied target','Input outside the change object','Wrong audience','Times','Tampered payload','Keys','Malformed receipt fails closed','Two receipts','Unsafe input','Approver type not allowed','Issuer scope','Policy and grant are recorded as such','Grant limit','Grant terms are fixed','Counting','Execution failure','Unknown outcome','Unavailable','An approval is not a permission','No opt-out','Refusals are recorded and leak nothing','The connection cannot approve','Approved change only','Approver permission','Pending records','Settings are administrative','Key freshness','Issuer object and proofs','Person action and timing','Grant terms','Registered policy','Decision lookup','Stale approval','Update by query','Partial batch failure','Client decline','Denial'];
const additions=casesA({fixture,args,call,A,P,OTHER,admin,na});tests.push(...additions.tests);names.push(...additions.names);
const stage10=casesB({helpers:additions.helpers,call,A,admin});tests.push(...stage10.tests);names.push(...stage10.names);
const stage11=casesC({helpers:additions.helpers,call,A});tests.push(...stage11.tests);names.push(...stage11.names);
const stage12=casesD({helpers:additions.helpers,call,A,sdk});tests.push(...stage12.tests);names.push(...stage12.names);
const stage13=casesE({helpers:additions.helpers,call,A,sdk});tests.push(...stage13.tests);names.push(...stage13.names);
const stage14=casesF({helpers:additions.helpers,call,A});tests.push(...stage14.tests);names.push(...stage14.names);
const stage15=casesG({helpers:additions.helpers,fixture,args,call,A,P,admin,ni,httpCall,sdk});tests.push(...stage15.tests);names.push(...stage15.names);
// The sandbox's own tests start at 147. casesG's last six are 147 to 152, and this one,
// which was formerly inserted at 50 and shifted every later number, follows them at 153.
tests.push(test50);names.push('Read through a merged alias');
tests.push(test51);names.push('Organization issuer key');
tests.push(test52,test53,test54,test55);
names.push('Read with a withheld field does not leak','Stdio never prints the sign-in secret','Restart keeps the operator\'s denials','HTTP mapping requires its token');
// Covered-mode tests added after the cold read; registered after the tests above, which
// keeps their own numbers and puts these at 159 to 170.
const stage16=casesH({helpers:additions.helpers,args,call,A,P,admin,sdk});tests.push(...stage16.tests);names.push(...stage16.names);
// Milestone 1 (root-cause refactor): the corrected readings of requirements and the key
// protection of each new single function, at 171 to 189.
const stage17=casesI({helpers:additions.helpers,fixture,call,A,P,admin,httpCall,sdk});tests.push(...stage17.tests);names.push(...stage17.names);
// CONFORMANCE.md tests 190 to 199: the settings registry, the deployment record and S90.
const stage18=casesK({helpers:additions.helpers,fixture,call,A,P,admin,sdk});tests.push(...stage18.tests);names.push(...stage18.names);
// Milestone 2 sandbox tests, renumbered from 190 to 197 to 200 to 208 because 190 to 199
// are CONFORMANCE.md's settings tests.
const stage19=casesJ({helpers:additions.helpers,fixture,call,A,P,admin,sdk});tests.push(...stage19.tests);names.push(...stage19.names);
// Release-fix tests, from 209: one per release-fix item that changes behaviour.
const stage20=casesL({helpers:additions.helpers,fixture,call,A,P,admin,sdk});tests.push(...stage20.tests);names.push(...stage20.names);
// The number of a test is its registration position. Every test CONFORMANCE.md numbers must
// be at that position with that short name, so a test inserted or removed anywhere before it
// makes this check fail instead of silently shifting every later number.
function conformanceCheck() {
  const md=readFileSync(new URL('../../CONFORMANCE.md',import.meta.url),'utf8');
  const entries=new Map();
  for(const line of md.split('\n')) {
    const m=/^(\d+)\.\s+(?:\*\*(.+?)\.?\*\*)?/.exec(line.trim());
    if(!m) continue;
    const number=Number(m[1]); if(number>199) continue;
    entries.set(number,m[2]?m[2].replace(/\.$/,''):undefined);
  }
  const problems=[];
  for(const [number,title] of entries) {
    if(number>tests.length) {problems.push(`CONFORMANCE.md test ${number} is not registered`);continue;}
    const registered=names[number-1];
    if(title!==undefined && registered!==title) problems.push(`test ${number}: registered "${registered}", CONFORMANCE.md says "${title}"`);
  }
  if(problems.length) throw Error('CONFORMANCE.md numbering: '+problems.join('; '));
}
conformanceCheck();
const rows=[];
for(let n=0;n<tests.length;n++) {
  let status='PASS',reason='';
  try {const r=await tests[n]();if(r){status=r.status;reason=r.reason;}}
  catch(e){status='FAIL';reason=e.message.replace(/\s+/g,' ').slice(0,450);if(process.env.VA_DEBUG)console.error(e.stack);}
  finally {for(const f of fixtures){try{f.sor.close();}catch{}rmSync(f.dir,{recursive:true,force:true});}fixtures=[];}
  rows.push({number:n+1,name:names[n],status,reason});
}
const counts=Object.fromEntries(['PASS','FAIL','NOT AUTOMATED','NOT IMPLEMENTED'].map(s=>[s,rows.filter(r=>r.status===s).length]));
const summary=`SUMMARY: PASS=${counts.PASS} FAIL=${counts.FAIL} NOT AUTOMATED=${counts['NOT AUTOMATED']} NOT IMPLEMENTED=${counts['NOT IMPLEMENTED']}`;
const report=['| Test | Short name | Status | Reason |','|---|---|---|---|',...rows.map(r=>`| ${r.number} | ${r.name} | ${r.status} | ${r.reason.replaceAll('|','\\|')} |`),'',summary,''].join('\n');
console.log(report);if(process.env.VA_REPORT!=='0')writeFileSync('RESULTS.md',report);if(counts.FAIL)process.exitCode=1;
