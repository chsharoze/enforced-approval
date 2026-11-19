export const formatTime=epoch=>new Date(epoch*1000).toISOString()+' UTC';
const MONTHS=['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'];
const pad=n=>String(n).padStart(2,'0');
export const readableTime=epoch=>{const d=new Date(epoch*1000);return `${d.getUTCDate()} ${MONTHS[d.getUTCMonth()]} ${d.getUTCFullYear()}, ${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())} UTC`;};
export const shapeWords=shape=>shape==='these_records'?'These records only':'Any record you may change';
export const anyWarning='This grant covers these fields on every record you may change, not only the records shown.';
export function grantState(g,now) {return g.revoked!==null?'revoked':now>=g.expires?'expired':g.charged>=g.max_records?'used_up':'active';}
export const durationWords=s=>{s=Math.max(0,Math.round(Number(s)||0));if(s<60)return s===1?'1 second':s+' seconds';const m=Math.round(s/60);if(m<60)return 'about '+(m===1?'1 minute':m+' minutes');const h=Math.round(m/60);return 'about '+(h===1?'1 hour':h+' hours');};
export const stateWords=state=>state==='used_up'?'used up':state;
// S59: message durations are for people only: plain words plus the
// absolute moment, never a raw second count. The numeric retry_after member stays in
// the refusal object; below one minute the wording is "under a minute".
export const plural=(n,word='record')=>`${n} ${Number(n)===1?word:word+'s'}`;
export const clock=epoch=>{const d=new Date(epoch*1000);return `${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())} UTC`;};
export const withDuration=(s,now)=>{s=Math.max(0,Math.round(Number(s)||0));const words=s<60?'under a minute':durationWords(s);return now===undefined?words:`${words} (until ${clock(now+s)})`;};
// People-readable names (S57). The technical identifier stays visible, secondary, in parentheses.
export const OPERATION_NAMES={'mcp:tools/call:manage_records':'Update records','mcp:tools/call:create_record':'Create record','mcp:tools/call:update_by_query':'Update records matching a filter','mcp:tools/call:delete_records':'Delete records'};
export const SELECTOR_NAMES={objectType:'Object type',action:'Action',filter:'Filter'};
export const FIELD_NAMES={owner:'Owner',lifecycle_stage:'Lifecycle stage',notes:'Notes',email:'Email',phone:'Phone',company:'Company'};
export const tidyName=s=>String(s).split(/[\s/_-]+/).filter(Boolean).map(w=>w[0].toUpperCase()+w.slice(1)).join(' ');
export const operationName=op=>OPERATION_NAMES[op]??tidyName(String(op).split(':').at(-1));
export const selectorName=key=>SELECTOR_NAMES[key]??tidyName(key);
export const fieldName=path=>{const decoded=String(path).replace(/^\//,'').split('/').map(p=>p.replaceAll('~1','/').replaceAll('~0','~')).join('/');return FIELD_NAMES[decoded]??tidyName(decoded);};
