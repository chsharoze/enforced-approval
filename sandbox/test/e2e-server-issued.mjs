// End-to-end check of the server-issued profile with real HTTP: an MCP client over
// stdio, the approval page over 127.0.0.1, one shared database. Needs to open a local
// port, so it is not part of test/run.mjs. Usage: node test/e2e-server-issued.mjs
import { Client } from '@modelcontextprotocol/client';
import { StdioClientTransport } from '@modelcontextprotocol/client/stdio';
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import { DatabaseSync } from 'node:sqlite';
import { Sor } from '../src/sor.mjs';
import { Core, OP } from '../src/core.mjs';
import { fileURLToPath } from 'node:url';
const here = fileURLToPath(new URL('..', import.meta.url));
const PORT = 8799, BASE = `http://127.0.0.1:${PORT}`, db = here + `e2e-${process.pid}.sqlite`, pageLog = here + `e2e-pages-${process.pid}.log`;
const PATH_TOKEN = 'e2e-server-issued-path-token';
const env = { ...process.env, VA_ADMIN: 'e2e-admin', VA_MODE: 'server', VA_DB: db, PORT: String(PORT), VA_BASE_URL: BASE, VA_LOG: pageLog, VA_SIGNIN_SECRET: 'e2e-server-issued-secret', VA_PATH_TOKEN: PATH_TOKEN, NODE_NO_WARNINGS: '1' };
let n = 0, bad = 0;
const check = (name, ok, detail = '') => { n++; if (!ok) bad++; console.log((ok ? 'ok   ' : 'FAIL ') + name + (ok ? '' : '  ' + detail)); };
const web = spawn('node', [here + 'src/http.mjs'], { cwd: here, env, stdio: 'ignore' });
await new Promise(r => setTimeout(r, 700));

async function approveInBrowser(url, decision,shape='any_record',minutes=10,maxRecords='5') {
  const path = new URL(url).pathname;
  const first = await fetch(url);
  const signinPage = await first.text();
  const preCookie=(first.headers.get('set-cookie')??'').split(';')[0],preCsrf=/name="csrf" value="([a-f0-9]+)"/.exec(signinPage)?.[1];
  const s = await fetch(BASE + '/signin', { method: 'POST', headers:{cookie:preCookie},redirect: 'manual', body: new URLSearchParams({ person: 'test-person', csrf:preCsrf, secret: env.VA_SIGNIN_SECRET }) });
  const cookie = (s.headers.get('set-cookie') ?? '').split(';')[0];
  const page = await (await fetch(url, { headers: { cookie } })).text();
  const csrf = /name="csrf" value="([a-f0-9]+)"/.exec(page)?.[1];
  const before=count();
  // S68(4): for a covered operation the page's form names the displayed record; a real
  // browser posts it back, so the driver does the same.
  const record=/name="record" value="([a-f0-9]+)"/.exec(page)?.[1];
  const payload=new URLSearchParams({csrf,decision,...(record?{record}:{}),...(decision==='grant'?{shape,max_records:maxRecords,minutes:String(minutes)}:{})});
  const done=await fetch(url,{method:'POST',headers:{cookie},body:payload}),doneText=await done.text();let replay;
  if(decision==='grant'){const before=grantCount(),again=await fetch(url,{method:'POST',headers:{cookie},body:payload});replay={status:again.status,text:await again.text(),noNewGrant:grantCount()===before};}
  return { signinPage, page, status: done.status, doneText,cookie,csrf,noWrite:count()===before,replay };
}
let mode = 'approve', seen = [];
const client = new Client({ name: 'e2e', version: '0' }, { capabilities: { elicitation: { url: {} } }, versionNegotiation: { mode: { pin: '2026-07-28' } } });
client.setRequestHandler('elicitation/create', async req => {
  seen.push(req.params);
  if (mode !== 'accept-only') { const r = await approveInBrowser(req.params.url, mode === 'approve-then-decline' ? 'approve' : mode==='grant-these'?'grant':mode,mode==='grant-these'?'these_records':'any_record'); seen.at(-1).pageInfo = r; }
  return { action: mode === 'approve-then-decline' ? 'decline' : 'accept' };
});
await client.connect(new StdioClientTransport({ command: 'node', args: [here + 'src/mcp-server.mjs'], cwd: here, env }));
const database=new DatabaseSync(db,{readOnly:true});
const count=()=>database.prepare('SELECT count(*) n FROM history').get().n;
const grantCount=()=>database.prepare('SELECT count(*) n FROM server_grants').get().n;
function configureAny(enabled) {const sor=new Sor(db);try {const core=new Core(sor,{adminCredential:env.VA_ADMIN});core.admin(env.VA_ADMIN,'settings',{grantConfig:{...core.settings().grantConfig,['acct-EXAMPLE-0001']:{[OP]:{maxRecords:100,maxSeconds:3600,anyRecord:enabled}}}});}finally{sor.close();}}
function configureSettings(patch) {const sor=new Sor(db);try {const core=new Core(sor,{adminCredential:env.VA_ADMIN});core.admin(env.VA_ADMIN,'settings',patch);}finally{sor.close();}}
const call = async (name, args) => { try { return await client.callTool({ name, arguments: args }); } catch (e) { return { thrown: e?.message }; } };
const read = async () => JSON.parse((await call('read_record', { id: 'rec-EXAMPLE-42' })).content[0].text);
const args = owner => ({ objectType: 'contact', action: 'update', records: [{ id: 'rec-EXAMPLE-42', properties: { lifecycle_stage: 'customer', owner } }] });
try {
  const v0 = (await read()).version;
  mode = 'accept-only';
  const a = await call('manage_records', args('user-EXAMPLE-7'));
  check('accept without visiting the page: no write', (await read()).version === v0, JSON.stringify(a).slice(0, 200));
  check('a URL mode elicitation was sent', seen[0]?.mode === 'url' && seen[0]?.url?.startsWith(BASE + '/approve/'), JSON.stringify(seen[0]));
  mode = 'approve';
  const b = await call('manage_records', args('user-EXAMPLE-7'));
  const r1 = await read();
  check('approve on the page, retry runs', !b.isError && r1.version === v0 + 1 && (r1.properties ?? r1).owner === 'user-EXAMPLE-7', JSON.stringify(b).slice(0, 300) + JSON.stringify(r1));
  const info = seen.at(-1)?.pageInfo;
  check('page asks for sign-in first', /sign-in/i.test(info?.signinPage ?? ''));
  check('page shows old and new values', /user-EXAMPLE-3/.test(info?.page ?? '') && /user-EXAMPLE-7/.test(info?.page ?? ''), (info?.page ?? '').slice(0, 200));
  mode = 'accept-only';
  await call('manage_records', args('user-EXAMPLE-7'));
  check('same change again needs a new approval', (await read()).version === v0 + 1);
  mode = 'deny';
  const d = await call('manage_records', args('user-EXAMPLE-9'));
  check('deny on the page: no write', (await read()).version === v0 + 1, JSON.stringify(d).slice(0, 200));
  const ref = x => x?._meta?.['org.enforcedapproval/refusal'];
  check('after deny the retry says approval_denied, with no new link', ref(d)?.error === 'approval_denied' && !ref(d)?.approval_url, JSON.stringify(ref(d) ?? d).slice(0, 240));
  const approveText = seen.find(s => /Approved/.test(s.pageInfo?.doneText ?? ''))?.pageInfo.doneText, denyText = seen.at(-1)?.pageInfo?.doneText ?? '';
  check('page text differs for approve and deny', /Denied/.test(denyText) && !!approveText && approveText !== denyText, denyText.slice(0, 120));
  mode = 'approve-then-decline';
  const e = await call('manage_records', args('user-EXAMPLE-11'));
  check('approve on the page then decline in the client: no write', (await read()).version === v0 + 1 && ref(e)?.error === 'approval_cancelled', JSON.stringify(ref(e) ?? e).slice(0, 240));
  mode = 'accept-only';
  const g = await call('manage_records', args('user-EXAMPLE-11'));
  check('the declined approval stays cancelled: no write and no new link', (await read()).version === v0 + 1 && ref(g)?.error === 'approval_cancelled' && !ref(g)?.approval_url, JSON.stringify(ref(g) ?? g).slice(0, 200));
  const d2 = await call('manage_records', args('user-EXAMPLE-9'));
  check('the denial is still in force afterwards', ref(d2)?.error === 'approval_denied' && !ref(d2)?.approval_url, JSON.stringify(ref(d2) ?? d2).slice(0, 200));
  mode='grant';const beforeGrant=count(),promptsBefore=seen.length;
  const under=await call('manage_records',args('grant-first')),grantPage=seen.at(-1)?.pageInfo;
  const text=x=>x.content?.filter(c=>c.type==='text').map(c=>c.text).join('\n')??'';
  const grantId=/Ran under grant ([a-f0-9]+)/.exec(text(under))?.[1];
  check('grant creation on the page performs no write',grantPage?.status===200 && grantPage.noWrite && /Granted future changes/.test(grantPage.doneText));
  check('retry runs under grant without a new elicitation',!under.isError && count()===beforeGrant+1 && seen.length===promptsBefore+1 && !!grantId,text(under));
  const promptCount=seen.length,second=await call('manage_records',args('grant-second'));
  check('same fields and another value run without a prompt',!second.isError && seen.length===promptCount && count()===beforeGrant+2);
  check('grant result includes id, remaining allowance and expiry',text(second).includes(grantId) && /records remaining: 3 records; expires: \d{4}-\d{2}-\d{2}T[^ ]+ UTC/.test(text(second)),JSON.stringify(second).slice(0,700));
  mode='accept-only';const outside=args('grant-outside');outside.records[0].properties.uncovered='x';const extra=await call('manage_records',outside);
  check('uncovered field gets normal approval and no write',ref(extra)?.error==='approval_required' && count()===beforeGrant+2 && seen.length>promptCount);
  check('outside grant reason identifies the field',ref(extra)?.grant_status==='outside' && /field/.test(ref(extra)?.message??''));
  const scopeWarning='This grant covers these fields on every record you may change, not only the records shown.';
  check('any-record warning is visible in the choice and confirmation',grantPage.page.includes(scopeWarning)&&grantPage.doneText.includes(scopeWarning));
  check('grant form uses minutes and labelled record values',/name="minutes"/.test(grantPage.page)&&!/name="expires"/.test(grantPage.page)&&['Old value','New value','Operation','Account','Agent'].every(t=>grantPage.page.includes(t)));
  check('grant result calls out standing permission and UTC expiry',text(second).includes('standing permission, not an approval of this one change')&&text(second).includes('Any record you may change')&&/\d{4}-\d{2}-\d{2}T[^ ]+ UTC/.test(text(second)));
  const listing=await fetch(BASE+'/grants',{headers:{cookie:grantPage.cookie}}),listText=await listing.text();
  check('creator lists grant on the page',listing.status===200 && listText.includes(grantId));
  const revoked=await fetch(BASE+'/grants/'+grantId+'/revoke',{method:'POST',headers:{cookie:grantPage.cookie},body:new URLSearchParams({csrf:grantPage.csrf})});
  check('creator revokes grant on the page',revoked.status===200 && /revoked/i.test(await revoked.text()));
  const beforeRevokePrompt=seen.length,after=await call('manage_records',args('grant-after-revoke'));
  check('next call after revocation gets normal approval',ref(after)?.error==='approval_required' && count()===beforeGrant+2 && seen.length>beforeRevokePrompt);
  check('revoked grant reason is explicit',ref(after)?.grant_status==='revoked'&&/revoked/.test(ref(after)?.message??''));
  configureAny(false);mode='grant-these';const beforeThese=count(),fixed=await call('manage_records',args('these-first')),fixedPage=seen.at(-1)?.pageInfo;
  check('these-records grant is offered with any-record disabled',fixedPage?.page.includes('These records')&&!fixedPage.page.includes('Any record')&&!fixed.isError && count()===beforeThese+1,text(fixed));
  check('replayed grant request returns first result without another grant',fixedPage?.replay?.status===200 && fixedPage.replay.noNewGrant && fixedPage.replay.text===fixedPage.doneText);
  const seenFixed=seen.length,fixedAgain=await call('manage_records',args('these-second'));
  check('these-records grant covers second write to the same record',!fixedAgain.isError && seen.length===seenFixed && count()===beforeThese+2 && text(fixedAgain).includes('these_records'));
  mode='accept-only';const otherArgs=args('these-outside');otherArgs.records[0].id='rec-EXAMPLE-43';const otherRecord=await call('manage_records',otherArgs);
  check('these-records grant refuses another record',ref(otherRecord)?.error==='approval_required' && count()===beforeThese+2);
  check('outside grant reason identifies the record',ref(otherRecord)?.grant_status==='outside'&&/record/.test(ref(otherRecord)?.message??''));
  check('these-records confirmation lists its limit without an any-record warning',fixedPage.doneText.includes('rec-EXAMPLE-42')&&!fixedPage.doneText.includes(scopeWarning));
  configureAny(true);const wider=await approveInBrowser(ref(otherRecord).approval_url,'grant','any_record');
  check('any-record option appears only after administrative enablement',wider.page.includes('These records')&&wider.page.includes('Any record')&&wider.status===200);
  check('any-record grant replay creates nothing new',wider.replay?.status===200 && wider.replay.noNewGrant && wider.replay.text===wider.doneText);
  const anyResult=await call('manage_records',otherArgs);check('enabled any-record grant covers the other record',!anyResult.isError && count()===beforeThese+3 && text(anyResult).includes('any_record'));
  const evil=args('<script>globalThis.pwned=1</script>');evil.records[0].properties['markup-field']='"><img src=x onerror=globalThis.pwned=1>';
  const evilResult=await call('manage_records',evil),escaped=await approveInBrowser(ref(evilResult).approval_url,'deny');
  check('script and image payloads are shown as escaped text',escaped.status===200 && escaped.page.includes('&lt;script&gt;') && escaped.page.includes('&lt;img') && !escaped.page.includes('<script>') && !escaped.page.includes('<img') && count()===beforeThese+3);
  const beforeInvalid=count(),undefinedArgs=args('undefined');undefinedArgs.records[0].properties.never_defined='bad';const invalid=await call('manage_records',undefinedArgs);
  check('undefined property is invalid before any approval',ref(invalid)?.error==='invalid_input'&&!ref(invalid)?.approval_url&&count()===beforeInvalid);
  for(let i=0;i<4;i++){const r=args('exhaust-'+i);r.records[0].id='rec-EXAMPLE-43';const out=await call('manage_records',r);check('covered write charges remaining any-record allowance '+i,!out.isError);}
  const over=args('past-limit');over.records[0].id='rec-EXAMPLE-43';const exhausted=await call('manage_records',over);
  check('exhausted grant reason is explicit',ref(exhausted)?.error==='approval_required'&&ref(exhausted)?.grant_status==='used_up'&&/used up/.test(ref(exhausted)?.message??''));
  const brief=await approveInBrowser(ref(exhausted).approval_url,'grant','any_record',1/60);check('one-second duration grant is created with a readable expiry',brief.status===200&&/\d{1,2} [A-Z][a-z]{2} \d{4}, \d{2}:\d{2} UTC/.test(brief.doneText),brief.doneText.slice(0,160));
  await new Promise(r=>setTimeout(r,1200));const later=args('after-brief-expiry');later.records[0].id='rec-EXAMPLE-43';const expired=await call('manage_records',later);
  check('expired grant reason is explicit',ref(expired)?.error==='approval_required'&&ref(expired)?.grant_status==='expired'&&/expired/.test(ref(expired)?.message??''));
  const table=await(await fetch(BASE+'/grants',{headers:{cookie:brief.cookie}})).text();
  check('grants table shows all four states and record counts',table.includes('<table>')&&['active','used up','expired','revoked'].every(t=>table.includes('<td>'+t+'</td>'))&&table.includes('Records used')&&table.includes('Records remaining'));
  check('grants table offers revoke only for the active grant',(table.match(/<button>Revoke<\/button>/g)??[]).length===1);
  const times=[...table.matchAll(/<time>([^<]+)<\/time>/g)].map(m=>m[1]);check('all listed times use the single readable page form',times.length>=8&&times.every(t=>/^\d{1,2} [A-Z][a-z]{2} \d{4}, \d{2}:\d{2} UTC$/.test(t))&&!times.some(t=>/^\d{4}-\d{2}-\d{2}T/.test(t)),JSON.stringify(times));
  check('grant confirmation states the readable expiry actually set',/\d{1,2} [A-Z][a-z]{2} \d{4}, \d{2}:\d{2} UTC/.test(brief.doneText)&&!brief.doneText.includes('undefined'),brief.doneText.slice(0,120));
  check('grant confirmation repeats the any-record warning',brief.doneText.includes(scopeWarning));
  // S58: error pages are readable pages (S58), over real HTTP.
  const unknown=await fetch(BASE+'/approve/'+'0'.repeat(48),{headers:{cookie:brief.cookie}});
  const unknownText=await unknown.text();
  check('unknown approval link is a readable error page',unknown.status===403&&(unknown.headers.get('content-type')??'').startsWith('text/html')&&/<h1>/.test(unknownText)&&/What to do next/.test(unknownText)&&/not valid or is no longer active/i.test(unknownText)&&!/expired/i.test(unknownText),unknown.status+' '+unknownText.slice(0,120));
  check('error pages keep every security header',(unknown.headers.get('content-security-policy')??'').includes("frame-ancestors 'none'")&&(unknown.headers.get('content-security-policy')??'').includes("script-src 'none'")&&unknown.headers.get('cache-control')==='no-store'&&unknown.headers.get('referrer-policy')==='same-origin',JSON.stringify(Object.fromEntries(unknown.headers)));
  const sampleId=new URL(ref(exhausted).approval_url).pathname.split('/').at(-1);
  const forged=await fetch(BASE+'/approve/'+sampleId,{method:'POST',headers:{cookie:brief.cookie},body:new URLSearchParams({decision:'approve'})});
  const forgedText=await forged.text();
  check('a failed forgery check is a readable error page',forged.status===403&&(forged.headers.get('content-type')??'').startsWith('text/html')&&/not sent from this page/.test(forgedText)&&/What to do next/.test(forgedText),forged.status+' '+forgedText.slice(0,120));
  // One page log line per page request, with kind, id prefix, status and error code.
  const rawLog=fs.readFileSync(pageLog,'utf8');
  const pageLines=rawLog.trim().split('\n').filter(Boolean).map(s=>JSON.parse(s)).filter(l=>l.event==='page');
  check('page log has one line per page request',pageLines.length>10&&pageLines.every(l=>l.method&&typeof l.status==='number'&&!Number.isNaN(Date.parse(l.time))),String(pageLines.length));
  check('page log names the kind of page',pageLines.some(l=>l.page==='approve'&&l.method==='GET'&&l.status===200)&&pageLines.some(l=>l.page==='signin'&&l.method==='POST'&&l.status===303)&&pageLines.some(l=>l.page==='grants'&&l.status===200)&&pageLines.some(l=>l.page==='revoke'&&l.status===200));
  check('page log ids are the first 8 characters of the identifier',pageLines.some(l=>l.id===sampleId.slice(0,8))&&pageLines.every(l=>l.id===undefined||/^[a-f0-9]{8}$/.test(l.id)));
  check('page log carries the internal error code for errors',pageLines.some(l=>l.status===403&&typeof l.error==='string'&&l.error.length>0));
  check('page log holds no cookies, tokens or form values',!rawLog.includes('va_session')&&!rawLog.includes(brief.csrf)&&!rawLog.includes('test-person'),rawLog.slice(0,200));

  // Decided links show their outcome (S50), unknown and expired
  // links get the same wording (S58), and messages avoid member names (S59). Every s13
  // change targets rec-EXAMPLE-43, which no earlier standing grant covers; changes made
  // after the s13 grant also set an uncovered field so that grant cannot match them.
  mode='accept-only';
  configureSettings({pendingCap:50}); // earlier flows leave pending records that count against the principal
  const otherArgs13=(owner,extra={})=>({objectType:'contact',action:'update',records:[{id:'rec-EXAMPLE-43',properties:{lifecycle_stage:'customer',owner,...extra}}]});
  const linkA=ref(await call('manage_records',otherArgs13('s13-approve')))?.approval_url;
  const doneA=await approveInBrowser(linkA,'approve');
  const pageA=await(await fetch(linkA,{headers:{cookie:doneA.cookie}})).text();
  check('an approved link shows its outcome page, not the form',/<title>Change approved \| Approval sandbox<\/title>/.test(pageA)&&/This change was approved on/.test(pageA)&&/It can be used until/.test(pageA)&&!/name="decision"/.test(pageA)&&!/Review the saved change/.test(pageA),pageA.slice(0,200));
  const secondA=await fetch(linkA,{method:'POST',headers:{cookie:doneA.cookie},body:new URLSearchParams({csrf:doneA.csrf,decision:'deny'})});
  const secondAText=await secondA.text();
  check('a second decision after approve says which decision stands',secondA.status===403&&/<title>Change approved \| Approval sandbox<\/title>/.test(secondAText)&&/This change was approved on/.test(secondAText),secondA.status+' '+secondAText.slice(0,160));
  const linkD=ref(await call('manage_records',otherArgs13('s13-deny')))?.approval_url;
  const doneD=await approveInBrowser(linkD,'deny');
  const pageD=await(await fetch(linkD,{headers:{cookie:doneD.cookie}})).text();
  check('a denied link shows its outcome page',/<title>Change denied \| Approval sandbox<\/title>/.test(pageD)&&/This change was denied on/.test(pageD)&&/It will not run\./.test(pageD)&&!/name="decision"/.test(pageD),pageD.slice(0,200));
  const secondD=await fetch(linkD,{method:'POST',headers:{cookie:doneD.cookie},body:new URLSearchParams({csrf:doneD.csrf,decision:'approve'})});
  const secondDText=await secondD.text();
  check('a second decision after deny never says to send the request again',secondD.status===403&&/<title>Change denied \| Approval sandbox<\/title>/.test(secondDText)&&/This change was denied on/.test(secondDText)&&!/send the (request|same request) again/i.test(secondDText),secondD.status+' '+secondDText.slice(0,160));
  const linkG=ref(await call('manage_records',otherArgs13('s13-grant')))?.approval_url;
  const doneG=await approveInBrowser(linkG,'grant','any_record');
  const pageG=await(await fetch(linkG,{headers:{cookie:doneG.cookie}})).text();
  check('a grant-decided link shows its outcome page with the grants link',/<title>Grant created \| Approval sandbox<\/title>/.test(pageG)&&/A standing grant was made from this change on/.test(pageG)&&/\/grants/.test(pageG)&&!/name="decision"/.test(pageG),pageG.slice(0,200));
  // S59: with an elicitation the message says to open the approval page and never carries
  // the link; without one (the HTTP mapping) the message includes the link itself.
  const withPrompt=await call('manage_records',otherArgs13('s13-message',{notes:'uncovered'}));
  const afterPrompt=seen.at(-1);
  check('the elicitation message says to open the approval page and carries no link',afterPrompt?.mode==='url'&&afterPrompt.message.includes('Open the approval page')&&!afterPrompt.message.includes('/approve/')&&!afterPrompt.message.includes('Approval page: '),String(afterPrompt?.message));
  check('a refusal that followed an elicitation does not repeat the link',ref(withPrompt)?.message===afterPrompt?.message,String(ref(withPrompt)?.message));
  const httpRefusal=await fetch(BASE+'/records',{method:'PATCH',headers:{authorization:'Bearer '+PATH_TOKEN},body:JSON.stringify(otherArgs13('s13-http',{notes:'uncovered'}))});
  const httpJson=JSON.parse(await httpRefusal.text());
  check('the HTTP mapping puts the approval link in the message itself',httpRefusal.status===403&&httpJson.approval?.error==='approval_required'&&httpJson.approval.message.includes('Approval page: '+httpJson.approval.approval_url),JSON.stringify(httpJson.approval).slice(0,240));
  check('no refusal or elicitation message names a protocol member',[afterPrompt?.message,ref(withPrompt)?.message,httpJson.approval?.message].every(m=>!['approval_url','grant_status','retry_after','change_hash'].some(n=>String(m).includes(n))),String(afterPrompt?.message));
  // S58: an invented link and an expired one get the same page.
  const unknown13=await fetch(BASE+'/approve/'+'2'.repeat(48),{headers:{cookie:doneA.cookie}});
  const unknown13Text=await unknown13.text();
  configureSettings({pendingLifetime:1});
  const linkE=ref(await call('manage_records',otherArgs13('s13-expired',{notes:'uncovered'})))?.approval_url;
  await new Promise(r=>setTimeout(r,1300));
  const expired13=await fetch(linkE,{headers:{cookie:doneA.cookie}});
  const expired13Body=await expired13.text();
  check('an expired link and an invented link get the same page',unknown13.status===403&&expired13.status===403&&unknown13Text.includes('This approval link is not valid or is no longer active')&&expired13Body.includes('This approval link is not valid or is no longer active')&&unknown13Text===expired13Body,unknown13.status+' '+expired13.status+' '+expired13Body.slice(0,160));
  check('neither page reveals whether the link ever existed',!/expired/i.test(unknown13Text)&&!/expired/i.test(expired13Body)&&unknown13Text.includes('Ask the assistant to request the change again if it is still needed.'),unknown13Text.slice(0,200));

  // The grant outcome page describes the state when viewed (S50),
  // counts are pluralized, pages carry a single time form, and no message holds a bare
  // seconds count. pendingLifetime returns to 600 because the decided-links block set it to 1.
  configureSettings({pendingLifetime:600});
  const link14=ref(await call('manage_records',otherArgs13('s14-grant',{company:'s14'})))?.approval_url;
  const done14=await approveInBrowser(link14,'grant','any_record');
  const page14=await(await fetch(link14,{headers:{cookie:done14.cookie}})).text();
  check('the grant outcome page before use says it has not been used yet',/A standing grant was made from this change on/.test(page14)&&/It has not been used yet\./.test(page14)&&!/This change ran under that grant/.test(page14)&&!/The grant did not approve this change/.test(page14),page14.slice(0,240));
  const under14=await call('manage_records',otherArgs13('s14-grant',{company:'s14'}));
  check('the change shown on the link runs under the grant made from it',!under14.isError,text(under14));
  const used14=await(await fetch(link14,{headers:{cookie:done14.cookie}})).text();
  check('the grant outcome page after use says the change ran under that grant',/This change ran under that grant on/.test(used14)&&!/It has not been used yet/.test(used14),used14.slice(0,240));
  const linkP=ref(await call('manage_records',otherArgs13('s14-single',{email:'one@example.com'})))?.approval_url;
  const doneP=await approveInBrowser(linkP,'grant','any_record',10,'1');
  const runP=await call('manage_records',otherArgs13('s14-single',{email:'one@example.com'}));
  const tableP=await(await fetch(BASE+'/grants',{headers:{cookie:doneP.cookie}})).text();
  check('counts are pluralized everywhere they are shown',doneP.status===200&&/Record limit/.test(doneP.doneText)&&doneP.doneText.includes('1 record')&&!doneP.doneText.includes('1 records')&&/<td>1 of 1 record<\/td>/.test(tableP),doneP.doneText.slice(0,200)+' | '+tableP.slice(0,400));
  check('pages use the single readable time form',[page14,used14,done14.doneText,doneP.doneText,tableP].every(t=>!/\d{4}-\d{2}-\d{2}T/.test(t))&&/\d{1,2} [A-Z][a-z]{2} \d{4}, \d{2}:\d{2} UTC/.test(doneP.doneText),doneP.doneText.slice(0,200));
  const denial14=ref(await call('manage_records',otherArgs13('s13-deny')));
  const messageTexts=[...seen.map(s=>s.message),...[d,e,g,d2,exhausted,expired,after,otherRecord,extra,withPrompt,invalid,denial14].map(r=>ref(r)?.message),httpJson.approval?.message].map(m=>String(m??''));
  check('no refusal or elicitation message contains a bare seconds count',messageTexts.every(m=>!/\b\d+ seconds?\b/.test(m)),messageTexts.find(m=>/\b\d+ seconds?\b/.test(m))??'');

} finally {
  await client.close().catch(() => {}); database.close();web.kill();
  for (const s of ['', '-wal', '-shm']) fs.rmSync(db + s, { force: true });
  fs.rmSync(pageLog,{ force: true });
}
console.log(`\nE2E: ${n - bad} of ${n} passed`);
process.exit(bad ? 1 : 0);
