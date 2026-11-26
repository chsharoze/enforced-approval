import { McpServer, inputRequired, inputResponse } from '@modelcontextprotocol/server';
import { pathToFileURL } from 'node:url';
import { serveStdio } from '@modelcontextprotocol/server/stdio';
import * as z from 'zod';
import { runtime } from './runtime.mjs';
import { mcpResult, mutated, OP } from './core.mjs';
import { authorize, resolveIdentifier } from './authorize.mjs';
import { leaves } from './fields.mjs';
let defaultRuntime;
// Section 7: "Its `message` names what was invalid." The schema's issue list is folded
// into one plain sentence naming each member and what it expected, so the refusal says
// what was wrong without echoing the SDK's error object.
function schemaMessage(error) {
  const issues=(error?.issues ?? []).map(i=>`${i.path?.length?i.path.join('.'):'the arguments'} ${i.message}`);
  return `The request's arguments are not valid for this tool: ${issues.length?issues.join('; '):'they do not match the tool schema'}.`;
}
export function build(r) {
  r ??= (defaultRuntime ??= runtime());
  const server=new McpServer({name:'enforced-approval-sandbox',version:'0.2.0'},{capabilities:{tools:{}},supportedProtocolVersions:['2026-07-28','2025-11-25']});
  // Input schemas describe the real arguments so a model can call the tools. The two
  // approval members mirror the pattern under test: an AI-set confirmation field (ignored
  // for authorization and stripped before hashing) and the optional receipt argument.
  const approval={confirmation:z.enum(['CONFIRMED','WAIVED']).optional().describe('Indicates whether the user has approved this action.'),approval_receipt:z.string().optional().describe('Approval receipt, if the caller holds one. Leave empty otherwise.')};
  const props=z.record(z.string(),z.any()).describe('Property names and their new values');
  const type=z.string().describe('Object type, for example contact');
  // S69(4): the distinguishing argument of the covered operations. Its only effect is
  // to tell one intended write from another; it never changes what the write does.
  const distinguishing={change_tag:z.string().optional().describe('Distinguishes one intended write from another identical one. Use a new value for a new write after an earlier attempt; it changes nothing the write does.')};
  // S4/S34 (CONFORMANCE test 58): a member the schema does not document is
  // never removed, at any level. Every object below is a passthrough object, and the guard
  // hands the core the arguments exactly as the client sent them, so an undocumented
  // member inside a record entry is hashed, shown to the approver and matches no grant.
  const entry=shape=>mutated('mcp-strips-entry-members')?z.object(shape):z.object(shape).passthrough();
  const tools={
    manage_records:{description:'Update synthetic CRM records by id. Before every update, show the proposed changes to the user and get explicit approval.',shape:{objectType:type,action:z.enum(['update']).optional(),records:z.array(entry({id:z.string(),properties:props})).describe('Records to change'),...distinguishing}},
    update_by_query:{description:'Update every synthetic CRM record of a type whose properties equal the filter. Before every update, show the proposed changes to the user and get explicit approval.',shape:{objectType:type,filter:props.describe('Property names and the values they must equal'),set:props,...distinguishing}},
    create_record:{description:'Create one synthetic CRM record. Before every create, show the proposed record to the user and get explicit approval.',shape:{objectType:type,id:z.string().describe('Identifier for the new record'),properties:props,...distinguishing}},
    delete_records:{description:'Delete synthetic CRM records by id. Before every delete, show the records to the user and get explicit approval.',shape:{objectType:type,records:z.array(entry({id:z.string()})),...distinguishing}},
  };
  if (r.core.settings().preconditions) tools.copy_record_owner={description:'Copy the current owner of one synthetic CRM record to another. The server copies the source owner into the approved arguments.',shape:{objectType:type,source:z.string().describe('Source record identifier'),target:z.string().describe('Target record identifier'),...distinguishing}};
  // Every registered tool's input schema is kept here so the guard below can validate
  // arguments the way the SDK would before it runs.
  const schemas=new Map();
  const registerTool=server.registerTool.bind(server);
  server.registerTool=(name,config,cb)=>{schemas.set(name,config?.inputSchema);return registerTool(name,config,cb);};
  // Guarded tools have no body of their own: the guard below IS the operation (it
  // refuses, or consumes the approval and writes). This callback is unreachable; if it
  // ever runs, the call went around the guard.
  const unguarded=()=>{throw Error('guarded tool reached its own callback: the tools/call guard did not run');};
  for (const [name,t] of Object.entries(tools)) server.registerTool(name,{description:t.description,inputSchema:z.object({...t.shape,confirmation:approval.confirmation,...(r.pending ? {} : {approval_receipt:approval.approval_receipt})}).passthrough()},unguarded);
  // S60: the unguarded read still checks the principal's read permission for that
  // record (the same can_read model the rest of the sandbox uses), before it reads
  // anything, so an existing and an absent record get the same ordinary refusal.
  // S78: the read checks the record the identifier resolves to as well as the
  // identifier, so a merged alias does not read a record the principal may not read.
  // Every permission answer of the read comes from authorize(), purpose `read`, for the
  // record named and then for the record its identifier resolves to; the one read of the
  // record goes through resolveIdentifier.
  const subject={id:r.principal};
  const reads=id=>authorize(r.sor,subject,{account:r.account,operation:OP,scope:{records:[id]}},'read');
  // S60/S76/S77: a read returns the fields the principal may read. A denied field is
  // omitted, at whatever depth it is denied, so a readable sibling of a denied field is
  // still returned. `withheld` is computed from the object type's definitions, never
  // from the record, so it says nothing about whether a value is held.
  const readableProperties=(properties,decision)=>{
    const paths=leaves(properties??{});
    if(!paths.length)return properties??{};
    const kept=paths.filter(path=>decision.mayReadField(path));
    if(kept.length===paths.length)return properties;
    const out={};
    for(const path of kept){
      const keys=path.slice(1).split('/').map(k=>k.replaceAll('~1','/').replaceAll('~0','~'));
      let src=properties,dst=out;
      for(let i=0;i<keys.length;i++){
        if(i===keys.length-1)dst[keys[i]]=src[keys[i]];
        else{dst[keys[i]]??={};dst=dst[keys[i]];src=src[keys[i]];}
      }
    }
    return out;
  };
  server.registerTool('read_record',{description:'Read one synthetic CRM record by id (not guarded).',inputSchema:z.object({id:z.string().describe('Record identifier, for example rec-EXAMPLE-42')})},async ({id})=>{
    // Section 2 (decided): a record the principal may not read is answered exactly as an
    // absent identifier (`null`), at record level and, below, at operation level, so the
    // read cannot be used as an oracle on which records exist. The field-level `withheld`
    // list is kept for a record the principal may read (S76, S60, S77). This release offers
    // only the absent answer: `read_tool_denied_answer` has that one value.
    const absent={content:[{type:'text',text:JSON.stringify(null)}]};
    const named=reads(id);
    // The principal may not read the record it names: the answer is the absent answer,
    // given before anything is read, so an existing and an absent record are alike.
    if(!mutated('read-record-ignores-permission')&&!named.allowed)return mutated('read-tool-denied-answer-permission-denied')?mcpResult({ok:false,approval:{error:'permission_denied'}}):absent;
    const found=resolveIdentifier(r.sor,r.account,id);
    if(!found.exists)return absent;
    if(!mutated('read-record-ignores-permission')&&found.redirected&&!mutated('read-record-alias-permission')&&!reads(found.resolved).allowed){
      // S78: an identifier that resolves to a record the principal may not read is
      // answered exactly as one that names no record. The identifier itself is readable;
      // only the record it resolves to is not.
      if(!mutated('read-alias-permission-denied'))return absent;
      return mcpResult({ok:false,approval:{error:'permission_denied'}});
    }
    const record=found.record;
    const withheld=mutated('read-record-withholds-nothing')?[]:named.deniedFields(record.type);
    const properties=mutated('read-record-withholds-nothing')?record.properties:readableProperties(record.properties,named);
    const answer={...record,properties,...(withheld.length?{withheld}:{})};
    // S76/S60: a withheld field must not be observable through another member. `version`
    // changes with every write, including a write to a withheld field, so it is withheld
    // too while any field is. No other member depends on the record's field values.
    if(withheld.length&&!mutated('read-record-withheld-keeps-version'))delete answer.version;
    return {content:[{type:'text',text:JSON.stringify(answer)}]};
  });
  // The guard around every tools/call. An operation is unguarded only if it is named in
  // UNGUARDED; any other registered tool is guarded by default, so a tool registered
  // without a guard call of its own cannot run unguarded. The SDK's own dispatch
  // (tool lookup and schema validation) is kept as the inner handler: unguarded tools
  // and calls whose arguments fail schema validation go to it unchanged, so their
  // answers are byte-identical to before. VA_MUTATE=guard-not-default removes the
  // default: only the operations named in GUARDED stay guarded, and a tool registered
  // without thought runs unguarded (killed by test/e2e-guard.mjs).
  const UNGUARDED=new Set(['read_record']);
  const GUARDED=new Set(Object.keys(tools));
  const dispatch=server.server._getRequestHandler('tools/call');
  server.server.setRequestHandler('tools/call',async (request,ctx)=>{
    const name=request.params?.name;
    const guarded=mutated('guard-not-default') ? GUARDED.has(name) : schemas.has(name) && !UNGUARDED.has(name);
    if (!guarded) return dispatch(request,ctx);
    // The arguments exactly as the client sent them. The schema is used to give the SDK's
    // own invalid-arguments answer for a documented member of the wrong type; what it
    // parsed is never used in place of what was received, so nothing can be stripped on
    // the way to the core (S1: "The server MUST compute the change hash itself, from the
    // request it received"; S4).
    let args=request.params.arguments ?? {};
    const schema=schemas.get(name);
    let schemaFault;
    if (schema!==undefined) {
      const parsed=await schema.safeParseAsync(args);
      // Section 7 with S17, S65: a guarded call the tool's schema refuses is
      // `invalid_input` whose `message` names what was invalid, given and recorded by the
      // core, not the SDK's own error, which bypasses the core and its audit record. Off:
      // schema-fault-as-sdk-error returns the SDK's answer instead.
      if (!parsed.success && mutated('schema-fault-as-sdk-error')) return dispatch(request,ctx);
      if (!parsed.success) schemaFault=schemaMessage(parsed.error);
      else if (mutated('mcp-strips-entry-members')) args=parsed.data;
    }
    const result=r.core.handle({account:r.account,principal:r.principal,operation:'mcp:tools/call:'+name,args,...(schemaFault?{schemaFault}:{}),meta:ctx.mcpReq._meta,inputResponses:ctx.mcpReq.inputResponses});
    const capabilities=ctx.mcpReq.envelope?.['io.modelcontextprotocol/clientCapabilities'] ?? server.server.getClientCapabilities();
    const answered=inputResponse(ctx.mcpReq.inputResponses,'approve').kind!=='missing';
    if (r.pending && result.approval?.error==='approval_required' && result.approval.approval_url && capabilities?.elicitation?.url && !answered) {
      // S56: a client that shows only this text must still show the reason a grant did not apply.
      // S59: the elicitation carries the link, so the message never does.
      const message=mutated('elicitation-drops-reason')?'Review and approve on the sandbox approval page.':result.approval.message;
      return inputRequired({inputRequests:{approve:inputRequired.elicitUrl({message,url:result.approval.approval_url})}});
    }
    // S59: without an elicitation the refusal message carries the link itself; where the
    // client already answered an elicitation for this request the link is not repeated.
    if (r.pending && result.approval?.error==='approval_required' && result.approval.approval_url && !answered)
      result.approval.message+=' Approval page: '+result.approval.approval_url;
    return mcpResult(result);
  });
  return server;
}
if (process.argv[1] && import.meta.url===pathToFileURL(process.argv[1]).href) {
  // The runtime is built at start, not on the first served request, so a restart the
  // stored setting forbids exits non-zero with its reason on stderr instead of answering
  // every call with "Internal server error".
  if (mutated('stdio-lazy-runtime')) serveStdio(()=>build());
  else try { const r=runtime(); serveStdio(()=>build(r)); }
  catch(e) { console.error(e.message); process.exit(1); }
}
