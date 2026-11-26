import { leaves } from './fields.mjs';
import { plural, readableTime, shapeWords, anyWarning, grantState, stateWords, operationName, selectorName, fieldName } from './presentation.mjs';
import { actionFor, mutated } from './core.mjs';
export const escape=s=>mutated('page-renders-markup')?String(s):String(s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const text=v=>v===undefined?'Not set':v===null?'None':typeof v==='string'?v:JSON.stringify(v);
const list=values=>`<ul>${values.map(v=>`<li>${escape(text(v))}</li>`).join('')}</ul>`;
const listH=values=>`<ul>${values.map(v=>`<li>${v}</li>`).join('')}</ul>`;
const line=(name,value)=>`<div class="line"><dt>${escape(name)}</dt><dd>${escape(text(value))}</dd></div>`;
const lineH=(name,valueHTML)=>`<div class="line"><dt>${escape(name)}</dt><dd>${valueHTML}</dd></div>`;
const lineT=(nameHTML,value)=>`<div class="line"><dt>${nameHTML}</dt><dd>${escape(text(value))}</dd></div>`;
const named=(readable,technical)=>`${escape(readable)} <small>(${escape(technical)})</small>`;
// S57: one time form on the pages. The ISO form is permitted only inside
// the collapsed "Raw saved change" details, which carry no timestamps.
const when=epoch=>`<time>${escape(readableTime(epoch))}</time>`;
const pointer=(value,path)=>path.slice(1).split('/').map(k=>k.replaceAll('~1','/').replaceAll('~0','~')).reduce((v,k)=>v?.[k],value);
const warning=()=>mutated('any-record-no-warning')?'':`<p class="warning">${escape(anyWarning)}</p>`;
const hidden=csrf=>`<input type="hidden" name="csrf" value="${csrf}">`;
const terms=g=>`<dl>${lineH('Operation',named(operationName(g.operation),g.operation))}${line('Account',g.account)}${line('Agent',g.principal)}${line('Audience',g.audience)}${g.selectors?Object.entries(g.selectors).map(([k,v])=>lineT(named(selectorName(k),k),v)).join(''):''}<div class="line"><dt>Fields</dt><dd>${listH(g.fields.map(f=>named(fieldName(f),f)))}</dd></div></dl>`;
export function document(body,title='Review change') {
  return `<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${escape(title)} | Approval sandbox</title><style>body{font:16px/1.5 system-ui,sans-serif;color:#17212b;background:#f5f7fa;margin:0}main{max-width:1080px;margin:2rem auto;padding:2rem;background:white;border:1px solid #d7dfe7;border-radius:10px}h1,h2,h3{line-height:1.2}.line{display:grid;grid-template-columns:minmax(8rem,12rem) 1fr;gap:1rem;padding:.4rem 0}dt{font-weight:650}dd{margin:0;overflow-wrap:anywhere}ul{margin:.25rem 0;padding-left:1.3rem}fieldset,article{border:1px solid #ccd5df;border-radius:6px;padding:1rem;margin:1rem 0}.scope-choice{padding:.75rem 0}.scope-details{display:none}.scope-choice input:checked~.scope-details{display:block}.warning{background:#fff5d6;border-left:4px solid #ab7200;padding:.75rem}label{display:block;margin:.6rem 0}input[type=number]{width:9rem;padding:.4rem;margin:0 .5rem}button{font:inherit;padding:.5rem 1rem;margin:.3rem;border:1px solid #6d8295;border-radius:5px;background:#eef4fb;cursor:pointer}details{margin:1rem 0}pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#f5f7fa;padding:1rem}.table-wrap{overflow:auto}table{border-collapse:collapse;width:100%;font-size:.9rem}th,td{border-bottom:1px solid #d7dfe7;text-align:left;vertical-align:top;padding:.7rem}time{white-space:nowrap}small{color:#5b6b7a;font-size:.85em}@media(max-width:600px){main{margin:0;padding:1rem}.line{grid-template-columns:1fr;gap:0}}</style><main>${body}</main></html>`;
}
export function approvalPage(d,csrf) {
  // S70/S53 (cold read, finding 1): for a covered copy the field the request sets is
  // the target's owner and its new value is the value copied from the source. Both are
  // part of what the open record is bound to, so the page shows them as the change,
  // with the source they come from, not only inside the raw saved change.
  const copy=d.copy&&!mutated('copy-page-hides-copied-value')?d.copy:null;
  const a=d.change.arguments,offer=d.grantOffer,action=actionFor(d.change.operation,a),entries=copy?[{id:copy.target,properties:{owner:a.copied_owner??null}}]:a.records??(d.records??(a.id?[a.id]:[])).map(id=>({id,properties:a.set??a.properties??{}}));
  const copyNotice=copy?`<p class="notice">The new owner is copied from record ${escape(copy.source)}: it is that record's current owner. It is part of what this approval is bound to.${copy.sourceMissing?' That record does not exist in the system of record, so no owner is copied.':''}</p>`:'';
  const notice=d.notices??{};
  const noticeFor=id=>mutated('page-hides-record-state-notices')?'':notice[id]==='missing'?'<p class="notice">This record does not exist in the system of record.</p>':notice[id]==='exists'?'<p class="notice">A record with this identifier already exists in the system of record.</p>':'';
  const changes=entries.map(e=>`<article><h3>Record: ${escape(e.id)}</h3>${noticeFor(e.id)}${copyNotice}${leaves(e.properties??{}).map(field=>`<dl>${lineH('Field',named(fieldName(field),field))}${line('Old value',pointer(d.current?.[e.id],field))}${line('New value',pointer(e.properties,field))}</dl>`).join('')||'<p>No fields are being set.</p>'}</article>`).join('');
  // S71: "For an operation that is not covered, the approval page MUST say that the
  // approval is for the change as requested and not for the state of the record when
  // the write runs." The old values were captured when the request was made, so the
  // label says that; they "MUST be marked as current values that may change before the
  // write". S70: for a covered operation the page shows what the approval is bound to,
  // and says so.
  // S70: "Any record value the page shows that the open record is not
  // bound to MUST be marked as not part of what the approval is bound to." A query's open
  // record is bound to the records the query selects (`resolved`: their identifiers and
  // count), not to the values those records hold, so the page says exactly that.
  const query=!!d.change.resolved&&!mutated('query-page-claims-values-bound');
  const scope=mutated('page-silent-on-change-vs-state')?'':d.covered
    ?(query
      ?'<p class="approval-scope">You are approving the change exactly as requested below, bound to the selection shown: which records the query selects and how many. If the selection changes before the request is sent again, this approval is not used. The values those records hold are not part of what this approval is bound to and may change before the write runs.</p>'
      :'<p class="approval-scope">You are approving the change exactly as requested below, bound to the record state shown: whether each record exists and the current values shown. If the record changes before the request is sent again, this approval is not used.</p>')
    :'<p class="approval-scope">You are approving the change exactly as requested below. You are not approving the state of the record at the moment the write runs: the record may change before then.</p>';
  const currentNote=mutated('page-silent-on-change-vs-state')?'':d.covered
    ?(query
      ?'<p>Values shown as old values are the records\' current values as they were read for this page. They are not part of what this approval is bound to and may change before the write runs.</p>'
      :'<p>Values shown as old values are the record\'s current values. They are part of what this approval is bound to.</p>')
    :mutated('page-old-values-unmarked')
      ?'<p>Values shown as old values are the record\'s current values. They may change before the write runs and are not part of the approved change.</p>'
      :'<p>Values shown as old values are the record\'s current values as they were read when the request was made. They may change before the write runs and are not part of the approved change.</p>';
  // S70: an earlier approval that was closed as stale is told to the approver.
  const staleNotice=d.staleNotice&&!mutated('covered-page-silent-on-unused-approval')?'<p class="warning">An earlier approval of this request was not used, because it no longer matched the record. The current request is shown below for a decision.</p>':'';
  // S69(4): an earlier request that differs only in the distinguishing argument.
  // S69(3) (cold read, finding 11): a consumed earlier request is described by the
  // outcome recorded for its write. "Already ran" is said only of a recorded success;
  // where the outcome is not known the page says so.
  const SIBLING_WORDS={denied:'was denied',cancelled:'was declined in the client',consumed:'already ran'};
  const siblingWords=s=>{
    const on=s.at?` on ${readableTime(s.at)}`:'';
    if(s.status!=='consumed'||s.outcome===undefined||s.outcome==='success')return `${SIBLING_WORDS[s.status]??s.status}${on}.`;
    if(s.outcome==='unknown')return `was approved and its write was sent${on}, but the outcome of that earlier write is not known. It may or may not have taken effect.`;
    if(s.outcome==='in_progress')return 'was approved and its write is still being carried out.';
    if(s.outcome==='conflict')return `was approved${on}, but its write was not made because it no longer fitted the records.`;
    if(s.outcome==='misdirected')return `was approved and its write took effect${on}, but on a record other than the one it named.`;
    return `was approved${on}, but its write could not be carried out.`;
  };
  const siblingNotices=(d.siblings??[]).map(s=>`<p class="notice">An earlier request from this agent in this account, differing only in its change tag, ${siblingWords(s)}</p>`).join('');
  // S70: an earlier grant made from this context is history, shown with the request.
  const grantHistoryNotice=d.grantHistory?.kind==='grant'?`<p class="notice">A standing grant was made from an earlier request of this agent on ${when(d.grantHistory.at)}.${d.grantHistory.usedAt!==undefined?` The change shown then ran under that grant on ${when(d.grantHistory.usedAt)}.`:''} It is shown as history; the decision below is on the current request.</p>`:'';
  const maxSeconds=offer?offer.max_expires-d.now:0,maxMinutes=maxSeconds/60,defaultMinutes=maxSeconds>=60?Math.min(60,Math.floor(maxMinutes)):maxMinutes,maxDuration=`${Math.floor(maxSeconds/60)} minutes${maxSeconds%60?' '+(maxSeconds%60)+' seconds':''}`;
  // S68(4): for a covered operation the form names the record the page displayed.
  const nameRecord=d.recordId?`<input type="hidden" name="record" value="${escape(d.recordId)}">`:'';
  const grant=offer?`<section><h2>Grant future changes</h2><p>A grant is a standing permission. It is not an approval of this one change.</p><div id="grant-terms">${terms(offer)}</div><form method="post">${hidden(csrf)}${nameRecord}<fieldset><legend>Which records may this grant cover?</legend>${offer.shapes.map((shape,i)=>`<div class="scope-choice"><input id="shape-${shape}" type="radio" name="shape" value="${shape}"${i===0?' checked':''}><label for="shape-${shape}">${shapeWords(shape)}</label><div class="scope-details">${shape==='these_records'?`<p>Fixed records for this choice:</p>${list(offer.records)}`:warning()}</div></div>`).join('')}</fieldset><label>Number of records <input type="number" name="max_records" min="1" max="${offer.max_records}" value="${offer.max_records}" required></label><p>Allowed maximum: ${escape(plural(offer.max_records))}, counted across all writes under this grant.</p><label>Number of minutes <input type="number" name="minutes" min="${1/60}" max="${maxMinutes}" step="any" value="${defaultMinutes}" required></label><p>Allowed maximum: ${escape(maxDuration)}. Fractional minutes are allowed to the nearest second.</p><p><strong>Latest possible expiry</strong>: the maximum expiry you may choose, if the grant is made now: ${when(offer.max_expires)}.</p><button name="decision" value="grant">Create standing grant</button></form></section>`:'';
  return `<h1>Review change</h1>${scope}${staleNotice}${siblingNotices}${grantHistoryNotice}<p>Review the saved change before deciding.</p><dl>${lineH('Operation',named(operationName(d.change.operation),d.change.operation))}${line('Account',d.change.account)}${line('Agent',d.change.principal)}${lineT(named('Object type','objectType'),a.objectType??'Not specified')}${lineT(named('Action','action'),action)}</dl><h2>Record changes</h2>${currentNote}${changes||'<p>No individual record fields are being set.</p>'}<form method="post">${hidden(csrf)}${nameRecord}<button name="decision" value="approve">Approve this change once</button><button name="decision" value="deny">Deny this change</button></form>${grant}<details><summary>Raw saved change</summary><pre>${escape(JSON.stringify(d.change,null,2))}</pre></details><p><a href="/grants">Your standing grants</a></p>`;
}
// S78: the page for a record whose identifier resolves to another record. It states the
// resolution to a person permitted to see it and offers no approval or grant.
export function resolutionPage(d) {
  // S78/S53: that an identifier now refers to another record, and which,
  // is content of that other record. It is shown only to a person permitted to read it;
  // any other person is told only that the change can no longer be decided here.
  const shown=(d.resolution??[]).filter(x=>x.shown);
  if(!shown.length)return `<h1>This change can no longer be decided</h1><p>This change can no longer be approved or granted here.</p><p><strong>What to do next:</strong> If the change is still needed, ask the assistant to request it again.</p>`;
  const items=shown.map(x=>`<li>${escape(x.id)} now refers to ${escape(x.to)}</li>`).join('');
  return `<h1>This change can no longer be decided</h1><p>The record this change names has been merged under another identifier in the system of record, so the change can no longer be approved or granted here.</p><ul>${items}</ul><p><strong>What to do next:</strong> If the change is still needed, ask the assistant to request it again.</p>`;
}
// S50/S58: the outcome page for a decided link describes the state when
// viewed. It never shows the change as open, old values, or a decision or grant form.
export const outcomeTitle=o=>o.kind==='approve'?'Change approved':o.kind==='deny'?'Change denied':o.kind==='cancelled'?'Request declined':o.kind==='superseded'?'Change already run':o.kind==='lapsed'?'Approval expired':'Grant created';
export function outcomePage(o,alreadyRecorded=false) {
  const lead=alreadyRecorded?'<p>A decision was already recorded for this change. The first decision stands.</p>':'';
  // S67/S50 (cold read, finding 8): an approval that expired unused inside its context.
  // The page describes the state when viewed and offers no decision; the next request
  // creates the context's new pending record.
  if (o.kind==='lapsed') return `<h1>Approval expired</h1><p>This change was approved on ${when(o.at)}. The approval was not used before it expired on ${when(o.until)}, so the change did not run under it.</p><p><strong>What to do next:</strong> If the change is still needed, ask the assistant to send the request again. This page will then show it for a new decision.</p>`;
  if (o.kind==='superseded') return `<h1>Change already run</h1>${lead}<p>This change already ran under another approval, so this link can no longer be decided.</p><p><strong>What to do next:</strong> Nothing more is needed here. The change has already run.</p>`;
  // S70: a context cancelled from the connection says so, in different words from a denial.
  if (o.kind==='cancelled') return `<h1>Request declined</h1>${lead}<p>The request was declined in the client, so the change did not run and its approval was cancelled.</p><p><strong>What to do next:</strong> Nothing more is needed here. The change will not run.</p>`;
  if (o.kind==='approve') return `<h1>Change approved</h1>${lead}<p>This change was approved on ${when(o.at)}. ${o.used?(o.usedAt!==undefined?`It has already been used, on ${when(o.usedAt)}, so it will not run again.`:'It has already been used, so it will not run again.'):`It can be used until ${when(o.until)}.`}</p><p><strong>What to do next:</strong> ${o.used?'Nothing more is needed here. The change has already run.':'Go back to the assistant and continue there.'}</p>`;
  if (o.kind==='deny') return `<h1>Change denied</h1>${lead}<p>This change was denied on ${when(o.at)}. It will not run.</p><p><strong>What to do next:</strong> Nothing else is needed here. The change will not run.</p>`;
  return `<h1>Grant created</h1>${lead}<p>A standing grant was made from this change on ${when(o.at)}. ${o.usedAt===undefined?'It has not been used yet.':`This change ran under that grant on ${when(o.usedAt)}.`}</p><p><strong>What to do next:</strong> You can list or revoke standing grants on <a href="/grants">the grants page</a>.</p>`;
}
export function grantConfirmation(g) {
  return `<h1>Granted future changes</h1><p>This grant is a standing permission, not an approval of this one change. This change is not yet approved; it will be matched and charged on retry.</p><dl>${line('Grant id',g.id)}${lineH('Shape',named(shapeWords(g.shape),g.shape))}${line('Record limit',plural(g.max_records))}${line('Records remaining',plural(g.max_records-g.charged))}${lineH('Made at',when(g.made_at))}${lineH('Expires at',when(g.expires))}</dl>${terms(g)}${g.shape==='these_records'?`<h2>These records only</h2>${list(g.records)}`:warning()}<details><summary>Grant record</summary><pre>${escape(JSON.stringify({...g,made_at:readableTime(g.made_at),expires:readableTime(g.expires),revoked:g.revoked===null?null:readableTime(g.revoked)},null,2))}</pre></details><p><a href="/grants">List or revoke grants</a></p>`;
}
export function grantsPage(grants,now,csrf) {
  return `<h1>Your standing grants</h1><p>Each grant is a standing permission, not an approval of one change.</p>${grants.length?`<div class="table-wrap"><table><caption>Grant allowances and current states</caption><thead><tr>${['Grant id / operation','Fields','Shape','State','Records used','Records remaining','Made at','Expires at','Action'].map(s=>`<th scope="col">${s}</th>`).join('')}</tr></thead><tbody>${grants.map(g=>{const state=grantState(g,now);return `<tr data-grant-id="${g.id}"><td>${escape(g.id)}<br>${named(operationName(g.operation),g.operation)}</td><td>${listH(g.fields.map(f=>named(fieldName(f),f)))}</td><td>${shapeWords(g.shape)}${g.shape==='these_records'?list(g.records):''}</td><td>${stateWords(state)}</td><td>${g.charged} of ${escape(plural(g.max_records))}</td><td>${state==='active'&&!mutated('inactive-grant-shows-remaining')?escape(plural(Math.max(0,g.max_records-g.charged))):'-'}</td><td>${when(g.made_at)}</td><td>${when(g.expires)}</td><td>${state==='active'||mutated('grants-list-revoke-on-inactive')?`<form method="post" action="/grants/${g.id}/revoke">${hidden(csrf)}<button>Revoke</button></form>`:'No action'}</td></tr>`;}).join('')}</tbody></table></div>`:'<p>You have no standing grants.</p>'}`;
}
