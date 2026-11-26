import { document, approvalPage, grantConfirmation, grantsPage, outcomePage, outcomeTitle, resolutionPage } from './pages.mjs';
import { readableTime } from './presentation.mjs';
import http from 'node:http';
import crypto from 'node:crypto';
import path from 'node:path';
import { appendFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';
import { mutated } from './core.mjs';
import { runtime } from './runtime.mjs';

// S79: the client's scheme comes from the server's own socket or from a configured,
// trusted edge marker. A header the client can send is never trusted to accept.
export function clientScheme(req) {
  if (mutated('trust-client-forwarded-proto')) return req.socket?.encrypted || req.headers['x-forwarded-proto'] === 'https' ? 'https' : 'http';
  if (req.socket?.encrypted) return 'https';
  const edge = process.env.VA_EDGE_MARKER;
  if (edge) {
    const eq = edge.indexOf('=');
    if (eq > 0 && req.headers[edge.slice(0, eq).toLowerCase()] === edge.slice(eq + 1)) return 'https';
  }
  return 'http';
}

// S79: a request that reached the server over a plain client connection is refused and
// never executed; a credential it carried is treated as disclosed. The event is recorded
// in the audit store and reported on the server's request log, the existing
// operator-facing channel, addressed to the account's configured page administrators.
export function recordDisclosure(r, {channel, operation, credential}) {
  let administrators=[];
  try { administrators=r.core.settings().pageAdministrators?.[r.account]??[]; } catch {}
  const detail={event:'plain_http',reason:'tls_required',channel,credential,administrators};
  let record_id;
  try { record_id=r.core.audit('security',{principal:r.principal,operation},{...detail},'disclosed'); } catch {}
  return {...detail,event:'security',outcome:'disclosed',...(record_id?{record_id}:{})};
}
export function createHandler(r) {
  const sessions=new Map(),origin=new URL(r.pending?.baseURL??process.env.VA_BASE_URL??'http://127.0.0.1:8787').origin;
  const secure={'content-security-policy':"default-src 'none'; script-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",'cache-control':'no-store','referrer-policy':'same-origin',...(origin.startsWith('https:')?{'strict-transport-security':'max-age=31536000'}:{})};
  const random=()=>crypto.randomBytes(24).toString('hex');
  // S79: the HTTP mapping acts as the configured principal, so it takes the connector's
  // path token (VA_PATH_TOKEN) as a bearer credential. It is compared in constant time;
  // without it the request is refused before any record is read and no approval record
  // is opened.
  const pathToken=process.env.VA_PATH_TOKEN;
  const tokenMatches=req=>{
    const given=/^Bearer (.+)$/.exec(String(req.headers.authorization??''))?.[1];
    if(!pathToken||given===undefined)return false;
    const a=Buffer.from(given,'utf8'),b=Buffer.from(pathToken,'utf8');
    if(a.length!==b.length){crypto.timingSafeEqual(b,b);return false;}
    return crypto.timingSafeEqual(a,b);
  };
  const cookie=id=>`va_session=${id}; HttpOnly; SameSite=Strict; Path=/${origin.startsWith('https:')?'; Secure':''}`;
  // The fake sign-in takes a secret the server generated (or the operator set). It is
  // compared in constant time and never leaves the operator's console: no page, HTTP
  // answer or log line carries it.
  const signinSecret=r.core?.signinSecret;
  const secretMatches=given=>{
    if(!signinSecret)return false;
    const a=Buffer.from(String(given??''),'utf8'),b=Buffer.from(String(signinSecret),'utf8');
    if(a.length!==b.length){crypto.timingSafeEqual(b,b);return false;}
    return crypto.timingSafeEqual(a,b);
  };
  // S58: plain-words error pages. The internal code goes to the page log, never the page.
  // S58: an unknown link and an expired one get the same wording, which fits
  // an unknown link and does not reveal whether the link ever existed.
  const explain=e=>{const m=String(e?.message??'');
    if(m==='expired'||m==='expired or consumed'||m==='expired or decided')return mutated('unknown-link-says-expired')
      ?['This approval link has expired','Ask the assistant to request the change again, then open the new link it gives you.']
      :['This approval link is not valid or is no longer active','Ask the assistant to request the change again if it is still needed.'];
    if(m==='first decision is final')return ['A decision was already recorded for this change','The first decision stands and nothing further can be decided here.'];
    if(m==='change must be displayed to this session')return ['This change was not displayed to you in this session','Open the approval link, review the change on the page, then decide.'];
    if(m==='permission_denied')return ['You are not permitted to approve this change','Ask a person who has the needed permission in this account to review it.'];
    if(m==='record resolved')return ['This change can no longer be decided','The record it names now refers to another record in the system of record. If the change is still needed, ask the assistant to request it again.'];
    if(m==='invalid anti-forgery token or origin')return ['The form was not sent from this page','Go back to the page, reload it and try again.'];
    if(m==='grant limits'||m==='invalid duration')return ['The limit or expiry is outside what is allowed','Go back and choose a smaller record limit or a shorter expiry, then try again.'];
    if(m==='shape not offered on this page')return ['That choice of records was not offered on this page','Go back and choose among the options the page shows.'];
    if(m==='grant terms are fixed')return ['The grant terms cannot be changed','Go back and use the form exactly as the page shows it.'];
    if(m==='sign-in required')return ['You need to sign in first','Open the approval link or the grants page and sign in, then try again.'];
    if(m==='unknown test person')return ['That sign-in name is not known here','Go back and sign in with one of the sandbox\'s test names.'];
    if(m==='invalid decision')return ['That decision is not one this page offers','Go back to the approval page and use Approve, Deny or Create standing grant.'];
    if(m==='method')return ['That request method is not supported on this page','Go back and use the page as it was shown.'];
    if(m==='body too large')return ['That request was too large','Go back and try again with a smaller request.'];
    return ['Something went wrong','Go back to the page you came from, reload it and try again.'];
  };
  // Page request log (S57/S58 work): one line per page request, no cookies, tokens or form values.
  const logFile=process.env.VA_LOG?path.resolve(process.env.VA_LOG):null;
  if(logFile&&!logFile.startsWith(process.cwd()+path.sep))throw Error('VA_LOG must be inside this directory');
  const pageLog=logFile?(entry)=>{try{appendFileSync(logFile,JSON.stringify({time:new Date().toISOString(),event:'page',...entry})+'\n');}catch{}}:null;
  return async(req,res)=>{
    let kind='other',itemId='',errorCode,session;
    const send=(status,type,body,headers={})=>{res.writeHead(status,{'content-type':type,...secure,...headers});res.end(body);if(pageLog)pageLog({method:req.method,page:kind,...(itemId?{id:itemId.slice(0,8)}:{}),status,...(status>=400&&errorCode?{error:errorCode}:{})});};
    const html=(s,title='Review change',headers={})=>send(200,'text/html; charset=utf-8',document(s,title),headers);
    try {
      let body='';for await(const b of req){body+=b;if(body.length>65536)throw Error('body too large');}
      const url=new URL(req.url,origin),pathname=url.pathname;
      const match=/^\/approve\/([a-f0-9-]+)$/.exec(pathname),revoke=/^\/grants\/([a-f0-9]+)\/revoke$/.exec(pathname);
      kind=match?'approve':pathname==='/signin'?'signin':pathname==='/grants'?'grants':revoke?'revoke':'other';itemId=match?.[1]??revoke?.[1]??'';
      const sid=/\bva_session=([a-f0-9]+)/.exec(req.headers.cookie??'')?.[1];session=sessions.get(sid);
      if(!session&&mutated('page-session-from-url')&&match)session={id:match[1],person:{id:'test-person',authenticated:true},csrf:match[1]};
      if(origin.startsWith('https:')&&clientScheme(req)!=='https') {
        if(!mutated('tls-refusal-unrecorded')) {
          const disclosure=recordDisclosure(r,{channel:'page',operation:'page:'+kind,credential:req.headers.cookie?'cookie':req.headers.authorization?'authorization':req.headers['approval-receipt']?'receipt':'none'});
          if(pageLog)pageLog(disclosure);
        }
        return problemResponse(426,'tls_required','This page needs a secure connection','Open it over HTTPS, or through the organization\'s secure tunnel, and try again.');
      }
      const f=new URLSearchParams(body),csrf=()=>{if(!session||f.get('csrf')!==session.csrf||(req.headers.origin&&req.headers.origin!==origin))throw Error('invalid anti-forgery token or origin');};
      if(pathname==='/signin'&&req.method==='POST') {
        csrf();const name=f.get('person');
        // A missing or wrong secret is the same failed sign-in as an unknown name: the
        // same page, no session, and no record state.
        const knownName=['test-person','test-person-2','test-person-3','test-person-4','test-person-5','test-admin'].includes(name);
        if(!knownName||!(mutated('signin-secret-ignored')||secretMatches(f.get('secret'))))throw Error('unknown test person');
        const next=mutated('signin-open-return')?(f.get('next')??session.returnTo):session.returnTo;
        const id=mutated('signin-keeps-session')?session.id:random();sessions.delete(session.id);
        sessions.set(id,{id,person:{id:name,authenticated:true},csrf:random(),returnTo:session.returnTo});
        return send(303,'text/html; charset=utf-8',document('<h1>Signed in</h1><p>You are signed in. If the next page does not open, go back to the assistant and use its link again.</p>','Sign in'),{'set-cookie':cookie(id),location:next});
      }
      if((match||pathname==='/grants'||pathname==='/signin'||revoke)&&r.pending) {
        if(!session?.person) {
          if(req.method!=='GET')throw Error('sign-in required');
          const stored=match&&(r.pending.get(match[1])??r.pending.contextOf(match[1]));const returnTo=stored?'/approve/'+match[1]:'/grants';
          if(!session){const id=random();session={id,csrf:random(),person:null,returnTo};sessions.set(id,session);}else session.returnTo=returnTo;
          return html(`<h1>Fake sandbox sign-in</h1><form method="post" action="/signin"><input type="hidden" name="csrf" value="${session.csrf}"><input name="person" value="test-person"><input type="password" name="secret" autocomplete="current-password" placeholder="Sign-in secret"><button>Sign in</button></form>`,'Sign in',{'set-cookie':cookie(session.id)});
        }
        if(req.method==='POST'&&!mutated('page-no-csrf'))csrf();
        if(revoke) {
          if(req.method!=='POST')throw Error('method');r.pending.grants.revoke(r.account,revoke[1],session.person);return html('<h1>Grant revoked</h1><p>Grant revoked. Future changes need approval.</p>','Grant revoked');
        }
        if(pathname==='/grants') {
          if(req.method!=='GET')throw Error('method');const grants=r.pending.grants.list(r.account,session.person);
          return html(grantsPage(grants,r.core.now(),session.csrf),'Your grants');
        }
        if(!match)throw Error('method');
        // S53/S58/S70: "S58 on an unknown or expired link also covers a
        // valid token whose context has no open record, for a person not permitted to
        // see the request." A signed-in person who may not see the request behind a token
        // gets exactly the unknown-link page, for GET and POST, whatever state the token
        // is in: this check comes before anything that depends on that state. The text
        // states it for covered operations; the sandbox applies the same, least
        // disclosing answer to operations that are not covered (AMBIGUITIES.md).
        if(!r.pending.visible(match[1],session.person))throw Error('expired');
        if(req.method==='POST') {
          if(!['approve','deny','grant'].includes(f.get('decision')))throw Error('invalid decision');
          // S50/S58: a decided record takes no second, different decision; the page says
          // which decision stands. An identical retry keeps its stored first result below.
          // S68(4): for a covered operation the decision names the record the page
          // displayed, and is refused when that record is no longer open.
          const contextToken=!r.pending.get(match[1])&&r.pending.contextOf(match[1])?match[1]:null;
          // S70/S68(4) (cold read, finding 9): in an open context the decision that
          // stands is the named record's own. A grant made from an earlier record of
          // the context is history and does not stop a decision on its new record.
          const standing=contextToken?r.pending.standingFor(contextToken,f.get('record')):r.pending.outcome(match[1]);
          if(standing&&f.get('decision')!==standing.kind&&!mutated('error-page-hides-decision'))throw Object.assign(Error('first decision is final'),{standing});
          if(f.get('decision')==='grant') {
            if([...f.keys()].some(k=>!['csrf','decision','max_records','minutes','shape','record'].includes(k)))throw Error('grant terms are fixed');
            const g=contextToken
              ?r.pending.decideNamed(contextToken,f.get('record'),session.person,(id)=>r.pending.createGrantMinutes(id,session.person,Number(f.get('max_records')),Number(f.get('minutes')),session.id,f.get('shape')))
              :r.pending.createGrantMinutes(match[1],session.person,Number(f.get('max_records')),Number(f.get('minutes')),session.id,f.get('shape'));
            return html(grantConfirmation(g),'Grant created');
          }
          const d=contextToken
            ?r.pending.decideNamed(contextToken,f.get('record'),session.person,(id)=>r.pending.decide(id,session.person,f.get('decision')==='approve',session.id))
            :r.pending.decide(match[1],session.person,f.get('decision')==='approve',session.id);
          // S70: the page after an approval of a covered operation says that the
          // approval is not used if the record changes before the request is sent again.
          const staleNote=contextToken?'<p>This approval is not used if the record changes before the request is sent again.</p>':'';
          return html(d.approved?`<h1>Change approved</h1><p>Approved. Go back to the assistant and continue. The change will run once. This approval can be used until ${readableTime(d.usable_until)}.</p>${staleNote}`:'<h1>Change denied</h1><p>Denied. The change will not run.</p>',d.approved?'Change approved':'Change denied');
        }
        if(req.method!=='GET')throw Error('method');
        // S50: a record that is no longer pending shows its recorded outcome, never a
        // decision form, never the change as open. A context token renders through the
        // context, which applies supersession and staleness first (S68(3)).
        const isContext=!r.pending.get(match[1])&&r.pending.contextOf(match[1]);
        const standing=mutated('decided-link-shows-form')||isContext?undefined:r.pending.outcome(match[1]);
        if(standing)return html(outcomePage(standing),outcomeTitle(standing));
        const d=r.pending.page(match[1],session.person,session.id);
        if(d.contextOutcome)return html(outcomePage(d.contextOutcome),outcomeTitle(d.contextOutcome));
        // S78: a page for a record that resolves to another record states the resolution
        // and offers no approval or grant.
        if(d.resolution)return html(resolutionPage(d),'Change not available');
        return html(approvalPage({...d,now:r.core.now()},session.csrf),'Review change');
      }
      if(pathname.startsWith('/records')&&req.method==='PATCH') {
        if(!mutated('http-mapping-unauthenticated')&&!tokenMatches(req)) {
          errorCode='unauthorized';
          return send(401,'application/problem+json',JSON.stringify({type:'https://enforcedapproval.org/problems/unauthorized',title:'unauthorized'}));
        }
        // The mapping hands the core what it received: the body as text (so duplicate
        // member names and integers beyond 2^53-1 are still visible, S3), every receipt
        // header, and every header that would change what the write does (S4). The one
        // shapeRequest in the core parses and refuses; nothing is parsed here.
        const tokens=req.rawHeaders.filter((_,i)=>i%2===0).filter(k=>k.toLowerCase()==='approval-receipt');
        const result=r.core.handle({account:r.account,principal:r.principal,operation:`http:${req.method}:${req.url}`,rawArguments:body,receipt:tokens.length>1?[]:req.headers['approval-receipt'],effects:Object.fromEntries(Object.entries(req.headers).filter(([k])=>k.startsWith('x-write-')))});
        if(!result.ok){errorCode=result.approval.error;return problem(result);}return send(200,'application/json',JSON.stringify(result.result));
      }
      errorCode='not_found';return problemResponse(404,'not_found','There is no page at this address','Go back to the assistant and use one of the links it gives you.');
      function problem(result){const e=result.approval.error;
        // S59: the HTTP mapping has no elicitation, so the refusal message carries the link itself.
        if(e==='approval_required'&&result.approval.approval_url)result.approval.message+=' Approval page: '+result.approval.approval_url;
        send(e==='approval_unavailable'?503:e==='approval_limit_reached'?429:e==='conflict'?409:e==='execution_failed'?500:403,'application/problem+json',JSON.stringify({type:'https://enforcedapproval.org/problems/refusal',title:e,approval:result.approval}),e==='approval_limit_reached'?{'retry-after':String(result.approval.retry_after)}:{});
      }
      function problemResponse(status,code,heading,next){errorCode=code;send(status,'text/html; charset=utf-8',document(`<h1>${heading}</h1><p><strong>What to do next:</strong> ${next}</p>`,'Problem'));}
    }catch(e){
      if(mutated('page-error-bare-response'))return send(403,'text/plain',e.message);
      // S50/S58: a decision that cannot be recorded because one already stands returns
      // the outcome page saying which decision stands.
      const decidedId=e?.standing?undefined:/^\/approve\/([a-f0-9-]+)$/.exec(req.url??'')?.[1];
      let standing=e?.standing;
      if(!standing&&decidedId&&r.pending&&['first decision is final','expired or decided','expired or consumed'].includes(String(e?.message))&&!mutated('error-page-hides-decision'))standing=r.pending.outcome(decidedId)??r.pending.contextOutcome?.(decidedId);
      if(standing&&!mutated('error-page-hides-decision')){errorCode='first decision is final';return send(403,'text/html; charset=utf-8',document(outcomePage(standing,true),outcomeTitle(standing)));}
      // S68(4): a decision that names a record which is no longer the context's open
      // record records nothing and shows the current request.
      if(String(e?.message)==='request changed'&&decidedId&&r.pending&&session?.person) {
        try {
          const d=r.pending.page(decidedId,session.person,session.id);
          if(d&&!d.contextOutcome&&!d.resolution){errorCode='request changed';return send(403,'text/html; charset=utf-8',document(approvalPage({...d,now:r.core.now()},session.csrf),'Review change'));}
          // S67/S50 (finding 8): where the context holds no open record, as after an
          // approval expired unused, the page shows the outcome it holds now.
          if(d?.contextOutcome){errorCode='request changed';return send(403,'text/html; charset=utf-8',document(outcomePage(d.contextOutcome),outcomeTitle(d.contextOutcome)));}
        }catch{}
      }
      const [heading,next]=explain(e);errorCode=String(e?.message??'unknown');return send(403,'text/html; charset=utf-8',document(`<h1>${heading}</h1><p><strong>What to do next:</strong> ${next}</p>`,'Problem'));
    }
  };
}
if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href) {
  // This entry point serves the approval pages, so its operator console gets the sign-in
  // secret once at start.
  const r=runtime();
  console.error(`Sandbox sign-in secret: ${r.core.signinSecret}`);
  // The HTTP mapping acts as the configured principal, so this entry point needs the same
  // bearer token the connector uses. When the operator did not set one it is generated
  // here and printed once on this console.
  if(!process.env.VA_PATH_TOKEN) {
    const token=crypto.randomBytes(32).toString('base64url');
    process.env.VA_PATH_TOKEN=token;
    console.error(`Sandbox HTTP mapping token: ${token}`);
  }
  http.createServer(createHandler(r)).listen(Number(process.env.PORT??8787),'127.0.0.1');
}
