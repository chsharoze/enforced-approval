// Real loopback only. No tunnel, public service, or external network is used.
import { Client, StreamableHTTPClientTransport } from '@modelcontextprotocol/client';
import { spawn, spawnSync } from 'node:child_process';
import { once } from 'node:events';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { DatabaseSync } from 'node:sqlite';
import net from 'node:net';
import crypto from 'node:crypto';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
const root=fileURLToPath(new URL('..',import.meta.url));
const dir=mkdtempSync(path.join(root,'.va-http-'));
const vectors=JSON.parse(readFileSync(path.join(root,'spec/vectors/vectors.json')));
const receipt=vectors.receipts.person.jws;
let n=0,bad=0,notRun=false;
function check(name,ok,detail='') {n++;if(!ok)bad++;console.log((ok?'ok   ':'FAIL ')+name+(!ok?' '+detail:''));}
async function port() {
  const s=net.createServer();await new Promise((resolve,reject)=>{s.once('error',reject);s.listen(0,'127.0.0.1',resolve);});
  const p=s.address().port;await new Promise(resolve=>s.close(resolve));return p;
}
async function start(mode,revision='2026-07-28',env0={}) {
  const p=await port(),base=`http://127.0.0.1:${p}`,token=crypto.randomBytes(24).toString('hex');
  const id=crypto.randomUUID(),db=path.join(dir,id+'.sqlite'),log=path.join(dir,id+'.log');
  const env={...process.env,VA_ADMIN:crypto.randomUUID(),VA_PATH_TOKEN:token,VA_DB:db,VA_LOG:log,PORT:String(p),VA_BASE_URL:base,VA_SIGNIN_SECRET:'e2e-http-signin-secret',NODE_NO_WARNINGS:'1',...env0};
  // VA_MUTATE is left in place: this suite is the killing suite for
  // tls-refusal-unrecorded, whose hook is in the connector (mcp-http.mjs).
  delete env.VA_MODE;delete env.VA_TEST_FAULT;delete env.VA_NOW;
  if(mode)env.VA_MODE=mode;
  if(mode==='organization')env.VA_NOW=String(vectors.now);
  const child=spawn(process.execPath,[path.join(root,'src/mcp-http.mjs')],{cwd:root,env,stdio:['ignore','pipe','pipe']});
  let stderr='';child.stderr.on('data',b=>{stderr+=b;});
  await new Promise((resolve,reject)=>{
    const timer=setTimeout(()=>{child.kill('SIGKILL');reject(Error('HTTP startup timeout: '+stderr));},10000);
    child.once('exit',code=>{clearTimeout(timer);reject(Error('HTTP server exited '+code+': '+stderr));});
    child.once('error',e=>{clearTimeout(timer);reject(e);});
    child.stdout.on('data',b=>{if(String(b).includes('MCP HTTP listening')){clearTimeout(timer);resolve();}});
  });
  const database=new DatabaseSync(db,{readOnly:true});
  const client=new Client({name:'e2e-http-'+revision,version:'1.2.3'},{capabilities:{elicitation:{url:{}}},versionNegotiation:{mode:revision==='2026-07-28'?{pin:revision}:'legacy'}});
  const f={base,endpoint:base+'/mcp/'+token,client,db,log,env,child,
    count:()=>database.prepare('SELECT count(*) n FROM history').get().n,
    audit:()=>database.prepare('SELECT json FROM audit ORDER BY seq').all().map(r=>JSON.parse(r.json)),
    lines:()=>readFileSync(log,'utf8').trim().split('\n').filter(Boolean).map(s=>JSON.parse(s)),
    async stop(){await client.close().catch(()=>{});const exit=once(child,'exit');child.kill('SIGTERM');const timer=setTimeout(()=>child.kill('SIGKILL'),2000);await exit;clearTimeout(timer);database.close();},
    async connect(){await client.connect(new StreamableHTTPClientTransport(new URL(f.endpoint)));},
  };
  return f;
}
async function browser(f,url,decision,extra={}) {
  const next=new URL(url).pathname;
  const first=await fetch(url),signinPage=await first.text(),preCookie=(first.headers.get('set-cookie')??'').split(';')[0],preCsrf=/name="csrf" value="([a-f0-9]+)"/.exec(signinPage)?.[1];
  const signed=await fetch(f.base+'/signin',{method:'POST',headers:{cookie:preCookie},redirect:'manual',body:new URLSearchParams({person:'test-person',csrf:preCsrf,secret:f.env.VA_SIGNIN_SECRET})});
  const cookie=(signed.headers.get('set-cookie')??'').split(';')[0];
  const page=await(await fetch(url,{headers:{cookie}})).text();
  const csrf=/name="csrf" value="([a-f0-9]+)"/.exec(page)?.[1];
  // S68(4): for a covered operation the page's form names the displayed record; a real
  // browser posts it back, so the driver does the same.
  const record=/name="record" value="([a-f0-9]+)"/.exec(page)?.[1];
  const done=await fetch(url,{method:'POST',headers:{cookie},body:new URLSearchParams({csrf,decision,...(record?{record}:{}),...extra})});
  const doneText=await done.text();
  return {signinPage,page,doneText,status:done.status,cookie,csrf};
}
const args=owner=>({objectType:'contact',action:'update',records:[{id:'rec-EXAMPLE-42',properties:{lifecycle_stage:'customer',owner}}]});
async function serverIssued() {
  const f=await start();let mode='accept-only';const seen=[];
  try {
    for(const suffix of ['/mcp','/mcp/wrong','/mcp/'+f.env.VA_PATH_TOKEN+'/extra','/mcp-other'])check('wrong MCP path is 404: '+suffix.replace(f.env.VA_PATH_TOKEN,'TOKEN'),(await fetch(f.base+suffix)).status===404);
    f.client.setRequestHandler('elicitation/create',async req=>{const item={...req.params};seen.push(item);if(mode!=='accept-only')item.pageInfo=await browser(f,req.params.url,mode);return {action:'accept'};});
    await f.connect();check('HTTP negotiated 2026-07-28',f.client.getNegotiatedProtocolVersion()==='2026-07-28');
    const call=owner=>f.client.callTool({name:'manage_records',arguments:args(owner),_meta:{'test/marker':'full metadata'}});
    const first=await call('user-EXAMPLE-7');check('accept without visiting: no write',f.count()===0 && first.isError);
    check('URL elicitation uses the same origin',seen[0]?.mode==='url' && seen[0]?.url?.startsWith(f.base+'/approve/'));
    mode='approve';const approved=await call('user-EXAMPLE-7');
    check('approve on the page: exactly one write',!approved.isError && f.count()===1);
    const info=seen.at(-1)?.pageInfo;
    check('approval page asks for sign-in',/sign-in/i.test(info?.signinPage??''));
    check('approval page shows old and new values',/user-EXAMPLE-3/.test(info?.page??'') && /user-EXAMPLE-7/.test(info?.page??''));
    check('approval POST succeeds',info?.status===200);
    // Draft 0.2 (S80): an identical request after consumption is answered with the
    // recorded outcome and does not execute; no new approval is opened.
    const seenCount=seen.length;mode='accept-only';const repeat=await call('user-EXAMPLE-7');
    const repeatOutcome=(()=>{try{return JSON.parse(repeat.content?.find(c=>c.type==='text')?.text??'{}').recorded_outcome;}catch{return undefined;}})();
    check('an identical request after consumption is answered with the recorded outcome and does not execute (S80)',f.count()===1 && seen.length===seenCount && repeat.isError!==true && repeatOutcome?.outcome==='success' && repeatOutcome?.sent_now===false,JSON.stringify(repeat).slice(0,200));
    mode='deny';const denied=await call('user-EXAMPLE-9');check('deny: no write',f.count()===1 && denied.isError && seen.at(-1)?.pageInfo?.status===200);
    // A grant made on the page, and grant_status on the tools/call log line when present.
    mode='accept-only';
    const grantArgs=args('user-EXAMPLE-g1');
    const needing=await f.client.callTool({name:'manage_records',arguments:grantArgs});
    const grantUrl=seen.at(-1)?.url;
    check('a covered change asks for approval before any grant exists',needing.isError && !!grantUrl,String(needing.isError));
    const confirmed=await browser(f,grantUrl,'grant',{shape:'any_record',max_records:'1',minutes:'10'});
    check('grant confirmation page shows the terms and a readable expiry',confirmed.status===200 && /Granted future changes/.test(confirmed.doneText) && /Record limit/.test(confirmed.doneText) && /\d{1,2} [A-Z][a-z]{2} \d{4}, \d{2}:\d{2} UTC/.test(confirmed.doneText),confirmed.status+' '+confirmed.doneText.slice(0,120));
    const ran=await f.client.callTool({name:'manage_records',arguments:grantArgs});
    check('the retried change runs under the grant',!ran.isError && f.count()===2,JSON.stringify(ran).slice(0,120));
    const exhausted=await f.client.callTool({name:'manage_records',arguments:args('user-EXAMPLE-g2')});
    const exhaustedRefusal=JSON.parse(exhausted.content?.find(c=>c.type==='text')?.text ?? '{}');
    check('an exhausted grant gets the normal approval with its reason',exhausted.isError && exhaustedRefusal.error==='approval_required' && exhaustedRefusal.grant_status==='used_up',JSON.stringify(exhaustedRefusal).slice(0,160));
    // Log original wire arguments, including fields that the read schema strips.
    await f.client.callTool({name:'read_record',arguments:{id:'rec-EXAMPLE-42',approval_receipt:receipt,copy:receipt,nested:{value:'copied:'+receipt},ordinaryVersion:'1.2.3'},_meta:{'org.enforcedapproval/receipt':receipt,'test/nested':{copied:receipt},'test/malformed/receipt':'not-a-real-receipt','io.modelcontextprotocol/clientInfo':{name:'not-a-real-receipt',version:'0'}},inputResponses:{probe:{action:'accept',content:{approval_receipt:receipt}}}});
    try{await f.client.callTool({name:'not_a_tool',arguments:{kept:'full original arguments'}});}catch{}
    const lines=f.lines(),calls=lines.filter(l=>l.event==='tools/call');
    check('the tools/call log line carries grant_status when present',calls.some(l=>l.grant_status==='used_up')&&calls.every(l=>l.outcome!=='executed'||l.grant_status===undefined));
    check('log has the client capabilities line',lines.some(l=>l.event==='client' && l.protocol_revision==='2026-07-28' && l.client_info?.name==='e2e-http-2026-07-28' && l.client_info?.version==='1.2.3' && l.capabilities?.elicitation?.url));
    check('log retains complete tool arguments and metadata',calls.some(l=>l.tool==='manage_records' && JSON.stringify(l.arguments)===JSON.stringify(args('user-EXAMPLE-7')) && l._meta['test/marker']==='full metadata' && l._meta['io.modelcontextprotocol/clientCapabilities']?.elicitation?.url));
    check('log records input_required, refused, executed', ['input_required','refused:approval_required','executed'].every(o=>calls.some(l=>l.outcome===o)));
    check('log includes calls rejected before a tool handler',calls.some(l=>l.tool==='not_a_tool' && l.arguments.kept==='full original arguments' && l.outcome.startsWith('refused:')));
    const redacted=calls.find(l=>l.tool==='read_record' && l.arguments.approval_receipt!==undefined);
    check('receipt fields, copies and inputResponses are lengths',redacted?.arguments.approval_receipt===receipt.length && redacted.arguments.copy===receipt.length && redacted.arguments.nested.value===receipt.length+7 && redacted.arguments.ordinaryVersion==='1.2.3' && redacted._meta['org.enforcedapproval/receipt']===receipt.length && redacted._meta['test/nested'].copied===receipt.length && redacted.inputResponses.probe.content.approval_receipt===receipt.length);
    check('malformed receipt copies in client info are redacted',!readFileSync(f.log,'utf8').includes('not-a-real-receipt') && lines.some(l=>l.event==='client' && l.client_info?.name==='not-a-real-receipt'.length));
    check('request log contains no receipt value',!readFileSync(f.log,'utf8').includes(receipt));
    check('all tool log events have time and protocol revision',calls.every(l=>!Number.isNaN(Date.parse(l.time)) && l.protocol_revision==='2026-07-28'));
  } finally {await f.stop();}
}
async function organization(revision) {
  const f=await start('organization',revision,{VA_TEST_ISSUER:'1'});
  try {
    await f.connect();check(revision+' organization HTTP negotiated '+revision,f.client.getNegotiatedProtocolVersion()===revision);
    const req={name:'manage_records',arguments:vectors.change_hash_vectors[0].request_arguments,_meta:{'org.enforcedapproval/receipt':receipt}};
    const required=await f.client.callTool({name:req.name,arguments:req.arguments});check(revision+' organization requires receipt',required.isError && f.count()===0);
    const approved=await f.client.callTool(req);
    if (process.env.VA_PRECONDITIONS==='1') {
      // S66: a covered operation cannot be approved through an organization's issuer;
      // a receipt presented for it is refused, with no change_hash, and nothing runs.
      const refOf=x=>x?._meta?.['org.enforcedapproval/refusal'];
      check(revision+' organization receipt refused for a covered operation (S66)',approved.isError===true && refOf(approved)?.error==='approver_not_authorized' && !Object.hasOwn(refOf(approved)??{},'change_hash') && f.count()===0,JSON.stringify(approved).slice(0,240));
      const replay=await f.client.callTool(req);
      check(revision+' organization replay refuses the receipt the same way (S66)',replay.isError===true && refOf(replay)?.error==='approver_not_authorized' && f.count()===0,JSON.stringify(replay).slice(0,240));
    } else {
      check(revision+' organization receipt executes once',!approved.isError && f.count()===1);
      // Draft 0.2 (S80): the replay returns the recorded outcome and executes nothing.
      const replay=await f.client.callTool(req);check(revision+' organization replay returns the recorded outcome without executing again',!replay.isError && f.count()===1 && JSON.parse(replay.content?.find(c=>c.type==='text')?.text ?? '{}').recorded_outcome?.outcome==='success',JSON.stringify(replay).slice(0,240));
    }
    const log=f.lines();check(revision+' capabilities logged',log.some(l=>l.event==='client' && l.protocol_revision===revision && l.client_info?.name==='e2e-http-'+revision && l.capabilities?.elicitation?.url));
    check(revision+' receipt lengths logged without token',log.some(l=>l.event==='tools/call' && l._meta?.['org.enforcedapproval/receipt']===receipt.length) && !readFileSync(f.log,'utf8').includes(receipt));
  } finally {await f.stop();}
}
// S79: behind an https public origin the agent's MCP endpoint and the HTTP request path
// refuse a plain client connection, execute nothing, record the event and report it to
// the account's administrators.
async function tlsRequired() {
  const f=await start(null,'2026-07-28',{VA_BASE_URL:'https://tunnel.example.invalid'});
  try {
    const mcp=await fetch(f.endpoint,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({jsonrpc:'2.0',id:1,method:'tools/list'})});
    check('the agent MCP endpoint refuses plain HTTP behind an https origin',mcp.status===426,String(mcp.status));
    check('the refusal answer is unchanged (S79)',mcp.status===426 && (await mcp.text())==='TLS required');
    // S79: the event is recorded in the audit store and reported, with the account's
    // administrators, on the existing request log.
    const events=f.audit();
    check('a refused plain-HTTP request is recorded once (S79)',events.length===1 && events[0].record_phase==='security' && events[0].action_detail?.event==='plain_http' && events[0].action_detail?.reason==='tls_required' && events[0].outcome==='disclosed',JSON.stringify(events).slice(0,400));
    check('the recorded event is reported to an administrator (S79)',(events[0]?.action_detail?.administrators??[]).includes('test-admin') && f.lines().some(l=>l.event==='security' && l.reason==='tls_required' && (l.administrators??[]).includes('test-admin')),JSON.stringify(f.lines()).slice(0,400));
    const patch=await fetch(f.base+'/records',{method:'PATCH',headers:{'content-type':'application/json'},body:JSON.stringify({objectType:'contact',action:'update',records:[{id:'rec-EXAMPLE-42',properties:{owner:'tls'}}]})});
    check('the agent HTTP endpoint refuses plain HTTP behind an https origin',patch.status===426,String(patch.status));
    check('each refused plain-HTTP request is recorded (S79)',f.audit().length===2,JSON.stringify(f.audit()).slice(0,400));
    check('nothing was written behind a refused plain connection',f.count()===0);
  } finally {await f.stop();}
}
try {
  // No listener or database should be started by these invalid configurations.
  for(const token of [undefined,'too-short']) {
    const env={...process.env,VA_ADMIN:crypto.randomUUID(),VA_LOG:path.join(dir,'invalid.log')};if(token)env.VA_PATH_TOKEN=token;else delete env.VA_PATH_TOKEN;
    const result=spawnSync(process.execPath,[path.join(root,'src/mcp-http.mjs')],{cwd:root,env,encoding:'utf8',timeout:10000});
    check('startup rejects '+(token?'short':'missing')+' path token',result.status!==0 && /VA_PATH_TOKEN/.test(result.stderr));
  }
  await serverIssued();await organization('2026-07-28');await organization('2025-11-25');await tlsRequired();
} catch(e) {
  if(['EPERM','EACCES'].includes(e.code)) {notRun=true;console.error('HTTP E2E: NOT RUN (loopback TCP is blocked: '+e.code+')');process.exitCode=1;}
  else {check('unexpected HTTP E2E error',false,e.stack);process.exitCode=1;}
} finally {rmSync(dir,{recursive:true,force:true});}
if(!notRun)console.log(`HTTP E2E: ${n-bad} of ${n} passed`);if(bad)process.exitCode=1;
