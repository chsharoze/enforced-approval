import { document, approvalPage, grantConfirmation, grantsPage, outcomePage, outcomeTitle } from './pages.mjs';
import { readableTime } from './presentation.mjs';
import http from 'node:http';
import crypto from 'node:crypto';
import path from 'node:path';
import { appendFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';
import { parseJSON } from './json.mjs';
import { mutated } from './core.mjs';
import { runtime } from './runtime.mjs';

export function createHandler(r) {
  const sessions=new Map(),origin=new URL(r.pending?.baseURL??process.env.VA_BASE_URL??'http://127.0.0.1:8787').origin;
  const secure={'content-security-policy':"default-src 'none'; script-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",'cache-control':'no-store','referrer-policy':'same-origin',...(origin.startsWith('https:')?{'strict-transport-security':'max-age=31536000'}:{})};
  const random=()=>crypto.randomBytes(24).toString('hex');
  const cookie=id=>`va_session=${id}; HttpOnly; SameSite=Strict; Path=/${origin.startsWith('https:')?'; Secure':''}`;
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
    let kind='other',itemId='',errorCode;
    const send=(status,type,body,headers={})=>{res.writeHead(status,{'content-type':type,...secure,...headers});res.end(body);if(pageLog)pageLog({method:req.method,page:kind,...(itemId?{id:itemId.slice(0,8)}:{}),status,...(status>=400&&errorCode?{error:errorCode}:{})});};
    const html=(s,title='Review change',headers={})=>send(200,'text/html; charset=utf-8',document(s,title),headers);
    try {
      let body='';for await(const b of req){body+=b;if(body.length>65536)throw Error('body too large');}
      const url=new URL(req.url,origin),pathname=url.pathname;
      const match=/^\/approve\/([a-f0-9-]+)$/.exec(pathname),revoke=/^\/grants\/([a-f0-9]+)\/revoke$/.exec(pathname);
      kind=match?'approve':pathname==='/signin'?'signin':pathname==='/grants'?'grants':revoke?'revoke':'other';itemId=match?.[1]??revoke?.[1]??'';
      const sid=/\bva_session=([a-f0-9]+)/.exec(req.headers.cookie??'')?.[1];let session=sessions.get(sid);
      if(!session&&mutated('page-session-from-url')&&match)session={id:match[1],person:{id:'test-person',authenticated:true},csrf:match[1]};
      if(origin.startsWith('https:')&&!req.socket?.encrypted&&req.headers['x-forwarded-proto']!=='https')return problemResponse(426,'tls_required','This page needs a secure connection','Open it over HTTPS, or through the organization\'s secure tunnel, and try again.');
      const f=new URLSearchParams(body),csrf=()=>{if(!session||f.get('csrf')!==session.csrf||(req.headers.origin&&req.headers.origin!==origin))throw Error('invalid anti-forgery token or origin');};
      if(pathname==='/signin'&&req.method==='POST') {
        csrf();const name=f.get('person');if(!['test-person','test-person-2','test-person-3','test-person-4','test-person-5','test-admin'].includes(name))throw Error('unknown test person');
        const next=mutated('signin-open-return')?(f.get('next')??session.returnTo):session.returnTo;
        const id=mutated('signin-keeps-session')?session.id:random();sessions.delete(session.id);
        sessions.set(id,{id,person:{id:name,authenticated:true},csrf:random(),returnTo:session.returnTo});
        return send(303,'text/html; charset=utf-8',document('<h1>Signed in</h1><p>You are signed in. If the next page does not open, go back to the assistant and use its link again.</p>','Sign in'),{'set-cookie':cookie(id),location:next});
      }
      if((match||pathname==='/grants'||pathname==='/signin'||revoke)&&r.pending) {
        if(!session?.person) {
          if(req.method!=='GET')throw Error('sign-in required');
          const stored=match&&r.pending.get(match[1]);const returnTo=stored?'/approve/'+stored.id:'/grants';
          if(!session){const id=random();session={id,csrf:random(),person:null,returnTo};sessions.set(id,session);}else session.returnTo=returnTo;
          return html(`<h1>Fake sandbox sign-in</h1><form method="post" action="/signin"><input type="hidden" name="csrf" value="${session.csrf}"><input name="person" value="test-person"><button>Sign in</button></form>`,'Sign in',{'set-cookie':cookie(session.id)});
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
        if(req.method==='POST') {
          if(!['approve','deny','grant'].includes(f.get('decision')))throw Error('invalid decision');
          // S50/S58: a decided record takes no second, different decision; the page says
          // which decision stands. An identical retry keeps its stored first result below.
          const standing=r.pending.outcome(match[1]);
          if(standing&&f.get('decision')!==standing.kind&&!mutated('error-page-hides-decision'))throw Object.assign(Error('first decision is final'),{standing});
          if(f.get('decision')==='grant') {
            if([...f.keys()].some(k=>!['csrf','decision','max_records','minutes','shape'].includes(k)))throw Error('grant terms are fixed');
            const g=r.pending.createGrantMinutes(match[1],session.person,Number(f.get('max_records')),Number(f.get('minutes')),session.id,f.get('shape'));
            return html(grantConfirmation(g),'Grant created');
          }
          const d=r.pending.decide(match[1],session.person,f.get('decision')==='approve',session.id);
          return html(d.approved?`<h1>Change approved</h1><p>Approved. Go back to the assistant and continue. The change will run once. This approval can be used until ${readableTime(d.usable_until)}.</p>`:'<h1>Change denied</h1><p>Denied. The change will not run.</p>',d.approved?'Change approved':'Change denied');
        }
        if(req.method!=='GET')throw Error('method');
        // S50: a record that is no longer pending shows its recorded outcome, never a
        // decision form, never the change as open.
        const standing=mutated('decided-link-shows-form')?undefined:r.pending.outcome(match[1]);
        if(standing)return html(outcomePage(standing),outcomeTitle(standing));
        const d=r.pending.page(match[1],session.person,session.id);
        return html(approvalPage({...d,now:r.core.now()},session.csrf),'Review change');
      }
      if(pathname.startsWith('/records')&&req.method==='PATCH') {
        let args;try{args=parseJSON(body);}catch{errorCode='invalid_input';return problem(r.core.refusal({account:r.account,principal:r.principal,operation:`http:${req.method}:${req.url}`},'invalid_input'));}
        const tokens=req.rawHeaders.filter((_,i)=>i%2===0).filter(k=>k.toLowerCase()==='approval-receipt');
        const result=r.core.handle({account:r.account,principal:r.principal,operation:`http:${req.method}:${req.url}`,args,receipt:tokens.length>1?[]:req.headers['approval-receipt'],effects:Object.fromEntries(Object.entries(req.headers).filter(([k])=>k.startsWith('x-write-')))});
        if(!result.ok){errorCode=result.approval.error;return problem(result);}return send(200,'application/json',JSON.stringify(result.result));
      }
      errorCode='not_found';return problemResponse(404,'not_found','There is no page at this address','Go back to the assistant and use one of the links it gives you.');
      function problem(result){const e=result.approval.error;
        // S59: the HTTP mapping has no elicitation, so the refusal message carries the link itself.
        if(e==='approval_required'&&result.approval.approval_url)result.approval.message+=' Approval page: '+result.approval.approval_url;
        send(e==='approval_unavailable'?503:e==='approval_limit_reached'?429:403,'application/problem+json',JSON.stringify({type:'urn:example:enforced-approval',title:e,approval:result.approval}),e==='approval_limit_reached'?{'retry-after':String(result.approval.retry_after)}:{});
      }
      function problemResponse(status,code,heading,next){errorCode=code;send(status,'text/html; charset=utf-8',document(`<h1>${heading}</h1><p><strong>What to do next:</strong> ${next}</p>`,'Problem'));}
    }catch(e){
      if(mutated('page-error-bare-response'))return send(403,'text/plain',e.message);
      // S50/S58: a decision that cannot be recorded because one already stands returns
      // the outcome page saying which decision stands.
      const decidedId=e?.standing?undefined:/^\/approve\/([a-f0-9-]+)$/.exec(req.url??'')?.[1];
      let standing=e?.standing;
      if(!standing&&decidedId&&r.pending&&['first decision is final','expired or decided','expired or consumed'].includes(String(e?.message))&&!mutated('error-page-hides-decision'))standing=r.pending.outcome(decidedId);
      if(standing&&!mutated('error-page-hides-decision')){errorCode='first decision is final';return send(403,'text/html; charset=utf-8',document(outcomePage(standing,true),outcomeTitle(standing)));}
      const [heading,next]=explain(e);errorCode=String(e?.message??'unknown');return send(403,'text/html; charset=utf-8',document(`<h1>${heading}</h1><p><strong>What to do next:</strong> ${next}</p>`,'Problem'));
    }
  };
}
if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href)http.createServer(createHandler(runtime())).listen(Number(process.env.PORT??8787),'127.0.0.1');
