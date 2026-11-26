import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { Core, OP, QUERY, COPY } from '../src/core.mjs';
import { Sor } from '../src/sor.mjs';
import { Issuer } from '../src/issuer.mjs';
import { ServerIssued } from '../src/server-issued.mjs';
const vectors=JSON.parse(readFileSync(new URL('../spec/vectors/vectors.json',import.meta.url)));
// Milestone 1 (root-cause refactor): one test per corrected reading of a requirement, and
// one per new single function's key protection. Each names
// the requirement it checks and the Off hook (VA_MUTATE) it kills. Tests 171 to 189.
export function cases({helpers:{setup,req,ask,browser},fixture,call,A,P,admin,httpCall,sdk}) {
  const KEY=vectors.state_manifest_hmac_key, DEL='mcp:tools/call:delete_records', HTTPOP='http:PATCH:/records';
  const cov=(settings={})=>setup({preconditions:true,stateKey:KEY,...settings});
  const modes=[['default',()=>setup()],['covered',()=>cov()]];
  // A principal that may write but not read: a non-reader (S60).
  const nonReader=(f,operation=OP)=>f.sor.permission(A,P,operation,false,true);
  const who=(id='test-person')=>({id,authenticated:true});
  const tokenOf=r=>r.approval.approval_url.split('/').at(-1);
  const isCovered=f=>!!f.core.settings().preconditions;
  const update=(f,id,owner,tag)=>f.req({objectType:'contact',action:'update',records:[{id,properties:{owner}}],...(tag&&isCovered(f)?{change_tag:tag}:{})});
  const denied={ok:false,approval:{error:'permission_denied'}};
  // A decision or a grant made on the page's own interface, for the record it displayed.
  const decide=(f,token,yes=true,person=who(),session='session-i')=>{
    const d=f.pending.page(token,person,session);
    return d.recordId?f.pending.decideNamed(token,d.recordId,person,id=>f.pending.decide(id,person,yes,session)):f.pending.decide(token,person,yes,session);
  };
  const makeGrant=(f,token,{max=5,shape='any_record',person=who(),session='session-i'}={})=>{
    const d=f.pending.page(token,person,session),make=id=>f.pending.createGrant(id,person,max,f.now()+500,session,shape);
    return d.recordId?f.pending.decideNamed(token,d.recordId,person,make):make(token);
  };
  const count=(f,sql,...values)=>f.core.db.prepare(sql).get(...values).n;
  const tests=[
    // 171. S22, S46: a record write scope binds approvers and grant makers.
    // Off: approver-scope-off.
    function approverRecordWriteScope() {
      for (const [mode,make] of modes) {
        const f=make();
        f.sor.recordWriteScope(A,'test-person');f.sor.recordPermission(A,'test-person','rec-EXAMPLE-171-x',true,true);
        const r=update(f,'rec-EXAMPLE-42','scope-171','t171'),token=ask(f,r);
        assert.equal(f.pending.page(token,who(),'session-i').grantOffer,undefined,mode+': no grant is offered to a person who may not make the change');
        assert.throws(()=>decide(f,token),/permission_denied/,mode+': affirmed on another record only');
        assert.equal(call(f,r).approval?.error,'approval_required',mode);assert.equal(f.count(),0,mode);
        // Affirmed on the record the change names, the same person may approve it.
        f.sor.recordPermission(A,'test-person','rec-EXAMPLE-42',true,true);
        decide(f,token);assert(call(f,r).ok,mode);assert.equal(f.count(),1,mode);
        // S46: a grant whose maker is later scoped to another record writes nothing more.
        const g=make();makeGrant(g,ask(g,update(g,'rec-EXAMPLE-42','grant-171','g171')));
        g.sor.recordWriteScope(A,'test-person');g.sor.recordPermission(A,'test-person','rec-EXAMPLE-171-x',true,true);
        g.sor.seed(A,'rec-EXAMPLE-171-z',{owner:'z'});
        const out=call(g,update(g,'rec-EXAMPLE-171-z','under-grant-171','z171'));
        assert.equal(out.approval?.error,'approval_required',mode+': no grant matches and the normal approval request follows');
        assert.equal(g.count(),0,mode);assert.equal(count(g,'SELECT sum(charged) n FROM server_grants'),0,mode+': nothing is charged');
      }
    },
    // 172. Section 6 step 1, S60(c): the principal's own field-level write
    // denial is the ordinary step 1 refusal. Off: principal-field-write-unchecked.
    function principalFieldWriteAtStepOne() {
      for (const [mode,make] of modes) {
        const f=make();f.sor.fieldPermission(A,P,OP,'/owner',false,'write');
        const before=f.sor.reads();
        const present=call(f,update(f,'rec-EXAMPLE-42','x-172','t172')),absent=call(f,update(f,'rec-EXAMPLE-172-absent','x-172','t172'));
        assert.deepEqual(present,denied,mode);assert.deepEqual(absent,present,mode+': the same for a record that does not exist');
        assert.equal(f.sor.reads(),before,mode+': no record was read');
        assert.equal(count(f,'SELECT count(*) n FROM pending'),0,mode+': no approval record, so nothing can be approved');
        assert.equal(f.count(),0,mode);
        // A field the principal may write is still asked for approval.
        assert.equal(call(f,f.req({objectType:'contact',action:'update',records:[{id:'rec-EXAMPLE-42',properties:{lifecycle_stage:'customer'}}]})).approval.error,'approval_required',mode);
      }
    },
    // 173. S65, S60(a): a value copied from record state is validated
    // before approval only for a principal that may read it. Off: copy-validates-unread-source.
    function copyValidationNeedsAReader() {
      const values={plain:'plain',object:{private_key_name:1},array:['x'],float:1.5,unsafe:2**60};
      const copy=f=>f.req({objectType:'contact',source:'rec-EXAMPLE-173-src',target:'rec-EXAMPLE-42'},{operation:COPY});
      for (const [label,deny] of [['operation',f=>f.sor.permission(A,P,COPY,false,true)],['record',f=>f.sor.recordPermission(A,P,'rec-EXAMPLE-173-src',false,true)],['field',f=>f.sor.fieldPermission(A,P,COPY,'/owner',false,'read')]]) {
        const f=cov(),seen={};deny(f);
        for (const [name,owner] of Object.entries(values)) {f.sor.seed(A,'rec-EXAMPLE-173-src',{owner});seen[name]=JSON.stringify(call(f,copy(f)));}
        for (const name of Object.keys(values)) assert.equal(seen[name],seen.plain,`${label}/${name}: byte-identical to the answer for a plain value`);
        assert(seen.plain.includes('approval_required'),label);assert(!seen.object.includes('private_key_name'),label);
      }
      // After consumption the system of record's rejection is execution_failed, naming nothing.
      const g=cov();nonReader(g,COPY);g.sor.seed(A,'rec-EXAMPLE-173-src',{owner:{private_key_name:1}});
      const r=copy(g);decide(g,ask(g,r));
      const out=call(g,r);
      assert.equal(out.approval?.error,'execution_failed',JSON.stringify(out));assert(!JSON.stringify(out).includes('private_key_name'));assert.equal(g.count(),0);
      // A principal for which S60(a) holds is told before approval.
      const h=cov();h.sor.seed(A,'rec-EXAMPLE-173-src',{owner:{private_key_name:1}});
      const told=call(h,copy(h));
      assert.equal(told.approval.error,'invalid_input');assert.deepEqual(told.approval.invalid,['/owner/private_key_name']);
    },
    // 174. S53, S58, S70: a signed-in person not permitted to see a request
    // gets exactly the unknown-link page, GET and POST, in every token state.
    // Off: page-outcome-without-permission.
    async function pagesForAPersonNotPermitted() {
      for (const [mode,make] of modes) {
        const f=make();f.sor.recordPermission(A,'test-person-3','rec-EXAMPLE-42',false,false);
        const states={};
        states.pending=ask(f,update(f,'rec-EXAMPLE-42','p-174','p'));
        states.approved=ask(f,update(f,'rec-EXAMPLE-42','a-174','a'));decide(f,states.approved);
        const used=update(f,'rec-EXAMPLE-42','u-174','u');states.used=ask(f,used);decide(f,states.used);assert(call(f,used).ok);
        states.denied=ask(f,update(f,'rec-EXAMPLE-42','d-174','d'));decide(f,states.denied,false);
        const cancelled=update(f,'rec-EXAMPLE-42','c-174','c');states.cancelled=ask(f,cancelled);call(f,{...cancelled,inputResponses:{approve:{action:'decline'}}});
        const unknown='ab'.repeat(24);
        // A non-member, and a member denied read on the record.
        for (const person of ['test-person-4','test-person-3']) {
          const b=browser(f);await b.login(person);
          const unk=await b.send('GET','/approve/'+unknown);assert.equal(unk.status,403);
          for (const [state,token] of Object.entries(states)) {
            const got=await b.send('GET','/approve/'+token);
            assert.equal(got.status,unk.status,`${mode}/${person}/${state}`);assert.equal(got.body,unk.body,`${mode}/${person}/${state}: GET is the unknown-link page`);
          }
          if (person!=='test-person-3') continue;
          // The session's form token, from a request this person may see.
          f.sor.seed(A,'rec-EXAMPLE-174-readable',{owner:'r'});
          await b.show(ask(f,update(f,'rec-EXAMPLE-174-readable','r-174','r')));assert(b.token());
          for (const [state,token] of Object.entries(states)) for (const decision of ['approve','deny','grant']) {
            const form=()=>new URLSearchParams({csrf:b.token(),decision,...(decision==='grant'?{max_records:'5',minutes:'10',shape:'any_record'}:{})});
            const a=await b.send('POST','/approve/'+token,form()),u=await b.send('POST','/approve/'+unknown,form());
            assert.equal(a.status,u.status,`${mode}/${state}/${decision}`);assert.equal(a.body,u.body,`${mode}/${state}/${decision}: POST is the unknown-link page`);
          }
        }
        // Nothing was decided by those posts, and a permitted person still sees the outcome.
        assert.equal(call(f,update(f,'rec-EXAMPLE-42','d-174','d')).approval.error,'approval_denied',mode);
        const ok=browser(f);await ok.login();
        assert((await ok.send('GET','/approve/'+states.denied)).body.includes('Change denied'),mode);
      }
    },
    // 175. S4, S63, Section 6 steps 1 and 2, Section 7:
    // invalid_input comes before any hash and any record read, always with a message.
    // Off: effects-refused-after-hash.
    async function invalidInputBeforeAnyHash() {
      for (const [mode,make] of modes) {
        const f=make(),before=f.sor.reads();
        const r=call(f,{...update(f,'rec-EXAMPLE-42','x-175'),effects:{'x-write-mode':'force'}});
        assert.equal(r.approval.error,'invalid_input',mode);
        assert.deepEqual(Object.keys(r.approval).sort(),['error','message'],mode+': no change_hash, no change, no link');
        assert.equal(f.sor.reads(),before,mode+': refused before any record read');
        const viaHeader=JSON.parse((await httpCall(f,{headers:{'x-write-mode':'force'}})).body).approval;
        assert.equal(viaHeader.error,'invalid_input',mode);assert(!Object.hasOwn(viaHeader,'change_hash')&&!Object.hasOwn(viaHeader,'change'),mode);assert(viaHeader.message.length>0,mode);
        for (const raw of ['{"a":1,"a":2}','{"a":9007199254740993}','{"x":"\\ud800"}','[]','not json']) {
          const bad=JSON.parse((await httpCall(f,{body:raw})).body).approval;
          assert.equal(bad.error,'invalid_input',mode+': '+raw);
          assert(typeof bad.message==='string'&&bad.message.length>0,mode+': '+raw+' carries a message');
          assert(!Object.hasOwn(bad,'change_hash'),mode+': '+raw);
        }
        assert.equal(f.sor.reads(),before,mode+': none of these read a record');
        // Section 6: step 1 (the ordinary permission check) comes before step 2 (the input).
        f.sor.permission(A,P,HTTPOP,true,false);
        assert.deepEqual(JSON.parse((await httpCall(f,{body:'{"a":1,"a":2}'})).body).approval,{error:'permission_denied'},mode+': a principal that may not write is refused at step 1 whatever its input');
        assert.equal(f.count(),0,mode);
      }
    },
    // 176. S60(a), S60(c), S62: one reader decision
    // for step 1 and for the refusal; an empty set of written leaves never makes a reader.
    // Off: empty-leaves-make-a-reader.
    function oneReaderDecision() {
      for (const [mode,make] of modes) {
        // A delete under a record write scope, with a field-level read denial.
        const f=make(),del=id=>f.req({objectType:'contact',records:[{id}]},{operation:DEL});
        f.sor.recordWriteScope(A,P);f.sor.fieldPermission(A,P,DEL,'/notes',false,'read');
        f.sor.recordPermission(A,P,'rec-EXAMPLE-42',true,false); // outside the write scope
        const outside=call(f,del('rec-EXAMPLE-42')),absent=call(f,del('rec-EXAMPLE-176-absent'));
        assert.deepEqual(outside,denied,mode);assert.deepEqual(absent,outside,mode+': a missing record gets the same step 1 refusal');
      }
      // `properties: {}` with every field read denied: not a reader, so no change and no hash.
      const g=cov();
      for (const row of g.core.db.prepare("SELECT path FROM property_definitions WHERE object_type='contact'").all()) g.sor.fieldPermission(A,P,OP,row.path,false,'read');
      const empty=call(g,g.req({objectType:'contact',action:'update',records:[{id:'rec-EXAMPLE-42',properties:{}}]}));
      assert.equal(empty.approval.error,'approval_required');
      for (const member of ['change','change_hash']) assert(!Object.hasOwn(empty.approval,member),'properties: {} does not make a principal a reader: no '+member);
      assert(!JSON.stringify(empty).includes('state_hash'));
      // A copy under a record write scope whose source the principal may not read.
      const h=cov();h.sor.recordWriteScope(A,P);
      h.sor.seed(A,'rec-EXAMPLE-176-src',{owner:'secret-176'});h.sor.recordPermission(A,P,'rec-EXAMPLE-176-src',false,true);
      h.sor.recordPermission(A,P,'rec-EXAMPLE-42',true,false);
      const copy=target=>h.req({objectType:'contact',source:'rec-EXAMPLE-176-src',target},{operation:COPY});
      const present=call(h,copy('rec-EXAMPLE-42')),missing=call(h,copy('rec-EXAMPLE-176-absent'));
      assert.deepEqual(present,denied);assert.deepEqual(missing,present,'an unreadable source does not make the principal a reader of a missing target');
    },
    // 177. S67 ("The audit record carries it."): every audit entry of a
    // covered request carries the request key. Off: audit-omits-request-key.
    function auditCarriesTheRequestKey() {
      const f=cov();nonReader(f);
      const r=update(f,'rec-EXAMPLE-42','rk-177','a'),first=call(f,r),keys=[first.approval.request_key];assert(keys[0]);
      decide(f,tokenOf(first));assert(call(f,r).ok);
      const r2=update(f,'rec-EXAMPLE-42','rk-177-denied','b'),second=call(f,r2);keys.push(second.approval.request_key);
      decide(f,tokenOf(second),false);assert.equal(call(f,r2).approval.error,'approval_denied');
      const r3=update(f,'rec-EXAMPLE-42','rk-177-cancelled','c'),third=call(f,r3);keys.push(third.approval.request_key);
      assert.equal(call(f,{...r3,inputResponses:{approve:{action:'cancel'}}}).approval.error,'approval_cancelled');
      const r4=update(f,'rec-EXAMPLE-42','rk-177-granted','d'),fourth=call(f,r4);keys.push(fourth.approval.request_key);
      makeGrant(f,tokenOf(fourth));
      assert.equal(new Set(keys).size,4);
      const rows=f.core.records();
      for (const phase of ['refusal','decision','consumption','outcome']) {
        const of=rows.filter(x=>x.record_phase===phase);assert(of.length>0,phase);
        for (const x of of) assert(keys.includes(x.action_detail.request_key),`${phase} (${x.outcome}): ${JSON.stringify(x.action_detail).slice(0,200)}`);
      }
      assert.deepEqual([...new Set(rows.filter(x=>x.record_phase==='decision').map(x=>x.outcome))].sort(),['approved','cancelled','denied','granted']);
    },
    // 178. S69(4), S65, S67: the sibling notice and
    // the page of a copy use the request's own arguments, never the copied value.
    // Off: sibling-compares-copied-value, page-rebuilds-from-copied-value.
    async function copySiblingNoticeAndUnencodableSource() {
      const f=cov();nonReader(f,COPY);
      f.sor.seed(A,'rec-EXAMPLE-178-src',{owner:'owner-v1'});
      const copy=tag=>f.req({objectType:'contact',source:'rec-EXAMPLE-178-src',target:'rec-EXAMPLE-42',change_tag:tag},{operation:COPY});
      decide(f,ask(f,copy('first')),false);
      f.sor.seed(A,'rec-EXAMPLE-178-src',{owner:'owner-v2'});
      const second=f.pending.page(ask(f,copy('second')),who(),'session-178');
      assert(second.siblings.some(s=>s.status==='denied'),'the earlier denial is told after the source changed: '+JSON.stringify(second.siblings));
      // A source value with no RFC 8785 form: the page still renders, with the notice.
      f.sor.seed(A,'rec-EXAMPLE-178-src',{owner:2**60});
      const token=ask(f,copy('third'));
      const third=f.pending.page(token,who(),'session-178');
      assert(third.recordId,'the page renders');assert(third.siblings.some(s=>s.status==='denied'));
      const b=browser(f);await b.login();const page=await b.show(token);
      assert.equal(page.status,200,page.body.slice(0,300));assert(page.body.includes('was denied'),'the notice is on the page');
    },
    // 179. S70: a value the page shows that the open record is not
    // bound to is marked as such. Off: query-page-claims-values-bound.
    async function queryPageMarksUnboundValues() {
      const f=cov();
      f.sor.seed(A,'rec-EXAMPLE-179',{group:'selected-179',owner:'before-179'});
      const r=f.req({objectType:'contact',filter:{group:'selected-179'},set:{owner:'new-179'}},{operation:QUERY});
      const token=ask(f,r),b=browser(f);await b.login();const page=await b.show(token);
      assert.equal(page.status,200,page.body.slice(0,300));
      assert(page.body.includes('before-179'),'the page shows the current value');
      assert(!page.body.includes('They are part of what this approval is bound to.'),'the old values of a query are not presented as bound');
      assert(page.body.includes('not part of what this approval is bound to'),'they are marked as not bound');
      assert(page.body.includes('bound to the selection shown'),'the page says what the approval is bound to');
      // The value changes after the approval and the write still runs: the selection is bound.
      assert.equal((await b.decide(token,'approve')).status,200);
      f.sor.seed(A,'rec-EXAMPLE-179',{group:'selected-179',owner:'after-179'});
      const out=call(f,r);assert(out.ok,JSON.stringify(out));assert.equal(f.sor.get(A,'rec-EXAMPLE-179').properties.owner,'new-179');
      // An update by identifier is bound to the values shown, and its page still says so.
      assert((await b.show(ask(f,update(f,'rec-EXAMPLE-42','bound-179','t179')))).body.includes('They are part of what this approval is bound to.'));
    },
    // 180. S67 (last sentence), S68(3): a read of record state that began
    // before a record was rendered does not replace it. Off: late-read-replaces-record.
    function lateReadDoesNotReplaceANewerRecord() {
      const f=cov(),r=update(f,'rec-EXAMPLE-42','late-180','t180'),token=ask(f,r);
      const sor2=new Sor(f.db),core2=new Core(sor2,{adminCredential:admin,now:f.now}),pending2=new ServerIssued(core2);
      const get=f.sor.get.bind(f.sor);
      try {
        let fired=false,newer;
        // While this instance's read is in flight, the record changes and another instance
        // renders the context's page for a person, which creates and displays a newer record.
        f.sor.get=(account,id)=>{const old=get(account,id);if(!fired&&id==='rec-EXAMPLE-42'){fired=true;sor2.seed(A,'rec-EXAMPLE-42',{lifecycle_stage:'lead',owner:'newer-180'});newer=pending2.page(token,who(),'other-instance').recordId;}return old;};
        const out=call(f,r);
        f.sor.get=get;
        assert.equal(out.approval.error,'approval_required');assert(newer,'the other instance rendered a newer record');
        assert.equal(f.pending.get(newer).status,'pending','the record a person is viewing is not replaced on the strength of an older read');
        const open=f.core.db.prepare("SELECT id,json FROM pending WHERE context=? AND status='pending'").all(token);
        assert.equal(open.length,1);assert.equal(open[0].id,newer);
        assert.equal(JSON.parse(open[0].json).current['rec-EXAMPLE-42'].owner,'newer-180','the open record holds the newer state');
      } finally { f.sor.get=get;sor2.close(); }
    },
    // 181. S1, S4, S34 (CONFORMANCE test 58): over MCP an undocumented member
    // is never stripped, at any level, so nothing runs under a grant without it.
    // Off: mcp-strips-entry-members. (The connector uses the same guard; test/matrix.mjs
    // drives it over HTTP as well.)
    async function mcpNeverStripsAMember() {
      for (const [mode,make,env] of [['default',()=>setup(),{VA_PRECONDITIONS:''}],['covered',()=>cov(),{VA_PRECONDITIONS:'1'}]]) {
        const f=make();makeGrant(f,ask(f,update(f,'rec-EXAMPLE-42','grant-seed-181','g181')));
        const tag=mode==='covered'?{change_tag:'u181'}:{};
        const nested={objectType:'contact',action:'update',records:[{id:'rec-EXAMPLE-42',properties:{owner:'unapproved-181'},undocumented:'x'}],...tag};
        const top={objectType:'contact',action:'update',records:[{id:'rec-EXAMPLE-42',properties:{owner:'unapproved-181-top'}}],undocumented:'x',...tag};
        const core={nested:call(f,f.req(structuredClone(nested))),top:call(f,f.req(structuredClone(top)))};
        for (const k of ['nested','top']) assert.equal(core[k].approval?.error,'approval_required',`${mode}/${k}: the core gives the normal approval request (S34)`);
        await sdk(f,'server',async c=>{
          for (const [k,a] of [['nested',nested],['top',top]]) {
            const r=await c.callTool({name:'manage_records',arguments:a});
            assert.equal(r.isError,true,`${mode}/${k}: ${JSON.stringify(r).slice(0,300)}`);
            const body=JSON.parse(r.content[0].text);
            assert.equal(body.error,core[k].approval.error,`${mode}/${k}: the same answer as the core`);
            if (core[k].approval.change_hash) assert.equal(body.change_hash,core[k].approval.change_hash,`${mode}/${k}: the member was hashed, not removed`);
          }
        },{},env);
        assert.equal(f.count(),0,mode+': nothing ran under the grant');
        assert.equal(f.sor.get(A,'rec-EXAMPLE-42').properties.owner,'user-EXAMPLE-3',mode);
      }
    },
    // 182. Section 3, S48, S65: grant_status does not tell an unestablished
    // principal which definitions exist. Off: grant-status-reveals-definitions.
    function grantStatusDoesNotRevealDefinitions() {
      for (const [mode,make] of modes) {
        const f=make();nonReader(f);
        f.sor.defineProperty('contact','/restricted_prop_182',{restricted:true});
        makeGrant(f,ask(f,update(f,'rec-EXAMPLE-42','seed-182','s182')),{max:1});
        const probe=(prop,tag)=>call(f,f.req({objectType:'contact',action:'update',records:[{id:'rec-EXAMPLE-182-a',properties:{[prop]:'x'}},{id:'rec-EXAMPLE-182-b',properties:{[prop]:'x'}}],...(mode==='covered'?{change_tag:tag}:{})})).approval;
        const restricted=probe('restricted_prop_182','r'),unknown=probe('undefined_prop_182','u');
        assert.equal(restricted.error,'approval_required',mode);assert.equal(unknown.error,'approval_required',mode);
        assert(restricted.grant_status,mode+': a grant that did not apply is still reported');
        assert.equal(restricted.grant_status,unknown.grant_status,mode+': the same grant_status for a restricted and an undefined property');
        assert(!/restricted_prop_182|undefined_prop_182/.test(String(restricted.message)+String(unknown.message)),mode);
      }
    },
    // 183. S66 ("without reading record state"): with no server-issued
    // profile for a covered operation the refusal comes before the record-scope read.
    function s66BeforeAnyRecordRead() {
      for (const operation of [OP,DEL]) {
        const answers=[];
        for (const present of [true,false]) {
          const f=fixture({preconditions:true,stateKey:KEY}); // no server-issued profile
          f.sor.permission(A,P,operation,false,true);f.sor.recordWriteScope(A,P);f.sor.recordPermission(A,P,'rec-EXAMPLE-183',false,true);
          if (present) f.sor.seed(A,'rec-EXAMPLE-183',{owner:'secret-183'});
          const before=f.sor.reads();
          const r=call(f,f.req(operation===OP?{objectType:'contact',action:'update',records:[{id:'rec-EXAMPLE-183',properties:{owner:'x'}}]}:{objectType:'contact',records:[{id:'rec-EXAMPLE-183'}]},{operation}));
          assert.equal(f.sor.reads(),before,'no record state is read');
          assert.deepEqual(r,{ok:false,approval:{error:'approver_not_authorized'}});
          answers.push(JSON.stringify(r));
        }
        assert.equal(answers[0],answers[1]);
      }
    },
    // 184. S69, S80, S68(2), S68(5): the recorded outcome of an identical
    // request comes before the record-scope check. Off: replay-after-state-read.
    function recordedOutcomeBeforeTheRecordScope() {
      for (const [mode,make] of modes) {
        const f=make();nonReader(f,DEL);f.sor.recordWriteScope(A,P);
        f.sor.seed(A,'rec-EXAMPLE-184',{owner:'o'});f.sor.recordPermission(A,P,'rec-EXAMPLE-184',false,true);
        const del=f.req({objectType:'contact',records:[{id:'rec-EXAMPLE-184'}]},{operation:DEL});
        decide(f,ask(f,del));
        const ran=call(f,del);assert(ran.ok,mode+': '+JSON.stringify(ran));assert.equal(f.sor.get(A,'rec-EXAMPLE-184'),undefined,mode);
        const writes=f.count(),again=call(f,del);
        assert.equal(again.result?.recorded_outcome?.outcome,'success',mode+': the repeat of a consumed delete is its recorded outcome, not a step 1 refusal: '+JSON.stringify(again));
        assert.equal(again.result.recorded_outcome.sent_now,false,mode);assert.equal(f.count(),writes,mode);
        // An update whose record was merged away after it ran.
        const g=make();nonReader(g);g.sor.recordWriteScope(A,P);
        g.sor.seed(A,'rec-EXAMPLE-184u',{owner:'o'});g.sor.recordPermission(A,P,'rec-EXAMPLE-184u',false,true);
        const up=update(g,'rec-EXAMPLE-184u','after-184','t184');decide(g,ask(g,up));assert(call(g,up).ok,mode);
        g.sor.seed(A,'rec-EXAMPLE-184-other',{owner:'y'});g.sor.merge(A,'rec-EXAMPLE-184u','rec-EXAMPLE-184-other');
        assert.equal(call(g,up).result?.recorded_outcome?.outcome,'success',mode+': after the merge');
        // A request that was never consumed still gets the step 1 refusal.
        assert.deepEqual(call(g,update(g,'rec-EXAMPLE-184u','never-approved-184','n184')),denied,mode);
      }
      // S68(5): "After a denial or a cancellation, an identical request is answered
      // `approval_denied` or `approval_cancelled` until the context expires, whether or not
      // record state changed." Off: context-answers-after-state-read.
      const h=cov();nonReader(h);h.sor.recordWriteScope(A,P);
      h.sor.seed(A,'rec-EXAMPLE-184d',{owner:'o'});h.sor.recordPermission(A,P,'rec-EXAMPLE-184d',false,true);
      const dr=update(h,'rec-EXAMPLE-184d','denied-184','d184');decide(h,ask(h,dr),false);
      const before=call(h,dr);assert.equal(before.approval.error,'approval_denied');
      h.sor.db.prepare('DELETE FROM records WHERE account=? AND id=?').run(A,'rec-EXAMPLE-184d');
      const after=call(h,dr);
      assert.equal(after.approval.error,'approval_denied','a denial stays the answer after the record is gone');
      assert.deepEqual(Object.keys(after.approval).sort(),Object.keys(before.approval).sort());
    },
    // 185. S27, S34, S35, S70: grant matching comes before the pending cap.
    // Off: cap-before-grant-match.
    function grantMatchesAtThePendingCap() {
      for (const [mode,make] of modes) {
        const f=make();f.core.admin(admin,'settings',{pendingCap:1});nonReader(f);
        makeGrant(f,ask(f,update(f,'rec-EXAMPLE-42','cap-1','c1')));
        const second=call(f,update(f,'rec-EXAMPLE-42','cap-2','c2'));
        assert(second.ok,mode+': a request a grant covers runs at the cap: '+JSON.stringify(second.approval));assert(second.grant,mode);
        assert.equal(f.count(),1,mode);
        // A request no grant covers is still refused at the cap, and opens nothing. Panel
        // item 2 (S50): in the default mode the grant closed its pending record when it
        // was recorded, so it no longer counts toward the cap; the request is then an
        // ordinary one and gets the normal approval request rather than the cap refusal.
        // A covered context counts from its creation until it is consumed (S70), so the
        // cap refusal still stands there.
        const records=count(f,'SELECT count(*) n FROM pending');
        const third=call(f,f.req({objectType:'contact',action:'update',records:[{id:'rec-EXAMPLE-42',properties:{lifecycle_stage:'customer'}}],...(mode==='covered'?{change_tag:'c3'}:{})}));
        if(mode==='covered') {
          assert.equal(third.approval?.error,'approval_limit_reached',mode);
          assert.equal(count(f,'SELECT count(*) n FROM pending'),records,mode+': no record was created at the cap');
        } else {
          assert.equal(third.approval?.error,'approval_required',mode+': the grant closed its record, releasing the cap slot (S50)');
        }
      }
    },
    // 186. S13, S14, S25, S69(1)-(3), S80: the outcome is recorded as unknown
    // in the consumption transaction and is only ever moved on by a compare-and-set.
    // Off: consume-without-placeholder, outcome-overwrites-terminal.
    function unknownOutcomeIsRecordedAtConsumption() {
      for (const [mode,make] of modes) for (const withGrant of [false,true]) {
        const f=make(),t0=f.now(),label=`${mode}${withGrant?' under a grant':''}`;nonReader(f);
        const r=update(f,'rec-EXAMPLE-42','crash-186','t186');
        if (withGrant) makeGrant(f,ask(f,update(f,'rec-EXAMPLE-42','seed-186','s186'))); else decide(f,ask(f,r));
        // The process stops between consumption and the outcome: nothing after the
        // consumption transaction is recorded.
        const store=f.core.storeOutcome;f.core.storeOutcome=()=>{throw Error('the process stopped');};
        f.sor.inject('after-consume',()=>{throw Error('the process stopped');});
        try { f.core.handle(r); } catch {}
        f.core.storeOutcome=store;f.core.inFlight.clear();
        assert.equal(f.count(),0,label);assert.equal(count(f,'SELECT count(*) n FROM used'),1,label+': the approval is consumed');
        for (const later of [20,311,601,5000]) {
          f.time(t0+later);
          const rep=call(f,r);
          assert.equal(rep.result?.recorded_outcome?.outcome,'unknown',`${label} +${later}s: ${JSON.stringify(rep).slice(0,300)}`);
          assert.equal(rep.result.recorded_outcome.sent_now,false,label);assert.equal(f.count(),0,label+': nothing is sent again');
        }
        assert.equal(count(f,'SELECT count(*) n FROM used'),1,label+': and nothing else was consumed');
        if (withGrant) assert.equal(count(f,'SELECT sum(charged) n FROM server_grants'),1,label+': the grant is charged once');
      }
      // An outcome record that cannot be written never turns a write that ran into a failure.
      const h=setup(),hr=req(h,'audit-186');decide(h,ask(h,hr));
      const audit=h.core.audit.bind(h.core);let failed=false;
      h.core.audit=(phase,...rest)=>{if(phase==='outcome'&&!failed){failed=true;throw Error('the audit store is unavailable');}return audit(phase,...rest);};
      const out=h.core.handle(hr);h.core.audit=audit;
      assert(failed);assert.equal(h.count(),1,'the write ran');
      assert(out.ok,'the request is told what happened: '+JSON.stringify(out));
      const rep=call(h,hr);
      assert.notEqual(rep.approval?.error,'execution_failed','a write that ran is never recorded as failed');
      assert.equal(rep.result?.recorded_outcome?.outcome,'unknown','the outcome that could not be recorded stays unknown');
      assert.equal(h.count(),1,'and nothing is sent again');
    },
    // 187. S53, S78: page access depends on permissions only; a merge
    // resolution is shown only to a person who may read the surviving record.
    // Off: page-resolution-shown-to-all.
    async function pageAccessFromPermissionsOnly() {
      const views=[];
      for (const secret of [undefined,'hidden-187']) {
        const f=setup();f.sor.fieldPermission(A,'test-person-3',OP,'/profile/secret',false,'read');
        f.sor.seed(A,'rec-EXAMPLE-187',{profile:{name:'public-187',...(secret?{secret}:{})}});
        const token=ask(f,f.req({objectType:'contact',action:'update',records:[{id:'rec-EXAMPLE-187',properties:{profile:{name:'new-187'}}}]}));
        const b=browser(f);await b.login('test-person-3');const page=await b.show(token);
        assert.equal(page.status,200,'access does not depend on whether a sibling leaf the viewer may not read holds a value');
        assert(page.body.includes('public-187'),'the value at the leaf the request sets is shown');
        assert(!page.body.includes('hidden-187'),'the sibling value is not shown');
        assert(!f.core.db.prepare('SELECT json FROM pending').all().some(x=>x.json.includes('hidden-187')),'nor stored with the request');
        views.push(page.body.replace(/[a-f0-9]{48}/g,'T'));
      }
      assert.equal(views[0],views[1],'the page is the same whatever the sibling leaf holds');
      for (const [mode,make] of modes) {
        const f=make();
        f.sor.seed(A,'rec-EXAMPLE-187-from',{owner:'a'});f.sor.seed(A,'rec-EXAMPLE-187-to',{owner:'secret-to-187'});
        f.sor.recordPermission(A,'test-person-3','rec-EXAMPLE-187-to',false,false);
        const token=ask(f,update(f,'rec-EXAMPLE-187-from','b-187','m187'));
        f.sor.merge(A,'rec-EXAMPLE-187-from','rec-EXAMPLE-187-to');
        const other=browser(f);await other.login('test-person-3');const page=await other.show(token);
        assert.equal(page.status,200,mode);assert(!page.body.includes('name="decision"'),mode+': no approval or grant is offered');
        assert(page.body.includes('can no longer be decided'),mode);
        assert(!page.body.includes('refers to'),mode+': the resolution is not told to a person who may not read the surviving record');
        assert(!page.body.includes('rec-EXAMPLE-187-to')&&!page.body.includes('secret-to-187'),mode);
        const reader=browser(f);await reader.login();
        assert((await reader.show(token)).body.includes('rec-EXAMPLE-187-from now refers to rec-EXAMPLE-187-to'),mode+': a person who may read it is told');
      }
    },
    // 188. WP3 (S50, S67, S70): a grant closes its record in the step that records it, and
    // no pending or approved record outlives its context.
    // Off: grant-decision-leaves-record-open, context-expiry-lazy.
    function recordsCloseWithTheirDecisionAndTheirContext() {
      const f=cov(),token=ask(f,update(f,'rec-EXAMPLE-42','close-188','t188'));
      const d=f.pending.page(token,who(),'session-188');
      f.pending.decideNamed(token,d.recordId,who(),id=>f.pending.createGrant(id,who(),5,f.now()+500,'session-188','these_records'));
      // No later request has been made.
      assert.equal(f.core.db.prepare('SELECT status FROM pending WHERE id=?').get(d.recordId).status,'granted','the record is closed in the step that records the grant');
      assert.equal(count(f,"SELECT count(*) n FROM pending WHERE context=? AND status='pending'",token),0);
      const g=cov(),gtoken=ask(g,update(g,'rec-EXAMPLE-42','expire-188','e188'));
      const shown=g.pending.page(gtoken,who(),'session-188');
      g.pending.decideNamed(gtoken,shown.recordId,who(),id=>g.pending.decide(id,who(),true,'session-188'));
      assert.equal(g.pending.get(shown.recordId).status,'approved');
      g.time(g.now()+g.core.settings().pendingLifetime+1);
      // No request, page or decision has been made since the context expired.
      assert.equal(g.pending.get(shown.recordId).status,'expired','no approved record outlives its context');
      assert.equal(g.pending.contextOf(gtoken).status,'expired');
    },
    // 189. Root-cause map 1.2 (S22, S46, S53): the organization issuer and the signed-receipt
    // grant branch decide through the same authorize().
    // Off: signed-grant-skips-authority, issuer-operation-permission-only.
    function organizationApproversAreAuthorized() {
      const f=fixture(),issuer=new Issuer(f.core),change=f.core.prepare(f.req()).change;
      const terms={id:'grant-EXAMPLE-189',principal:P,audience:change.audience,account:A,operations:[OP],fields:['lifecycle_stage','owner'],max_records:5,not_before:f.now()-1,expires:f.now()+600};
      issuer.createGrant(issuer.displayGrant(terms),who(),true);
      const receipt=issuer.underGrant('grant-EXAMPLE-189',change);
      // The maker's write permission is then scoped to another record.
      f.sor.recordWriteScope(A,'test-person');f.sor.recordPermission(A,'test-person','rec-EXAMPLE-189-x',true,true);
      const out=call(f,{...f.req(),receipt});
      assert.equal(out.approval?.error,'grant_exceeded',JSON.stringify(out));assert.equal(f.count(),0);
      assert.equal(count(f,'SELECT count(*) n FROM used'),0,'nothing is recorded as used');
      assert.throws(()=>issuer.underGrant('grant-EXAMPLE-189',change),/grant terms/,'the issuer issues nothing more under that grant either');
      // Affirmed on the record again, the same receipt runs.
      f.sor.recordPermission(A,'test-person','rec-EXAMPLE-42',true,true);
      assert(call(f,{...f.req(),receipt}).ok);assert.equal(f.count(),1);
      for (const [label,deny] of [['not a member',s=>s.member(A,'outsider-189',false)],['record write denied',s=>s.recordPermission(A,'outsider-189','rec-EXAMPLE-42',true,false)],['field write denied',s=>s.fieldPermission(A,'outsider-189',OP,'/owner',false,'write')],['record read denied',s=>s.recordPermission(A,'outsider-189','rec-EXAMPLE-42',false,true)],['write scope without the record',s=>{s.recordWriteScope(A,'outsider-189');s.recordPermission(A,'outsider-189','rec-EXAMPLE-189-x',true,true);}]]) {
        const g=fixture();g.sor.permission(A,'outsider-189',OP,true,true);deny(g.sor);
        const i=new Issuer(g.core),p=g.core.prepare(g.req());
        assert.throws(()=>i.decide(i.display(p.change,{current:p.current}),who('outsider-189'),true),/permission_denied/,label);
        assert.equal(count(g,'SELECT count(*) n FROM decisions'),0,label+': no decision is recorded');
      }
      const ok=fixture(),io=new Issuer(ok.core);
      assert.equal(typeof io.decide(io.display(ok.core.prepare(ok.req()).change),who(),true),'string','a person who holds every permission is approved');
    },
  ];
  const names=['Record write scope for approvers and grant makers','Field write denial of the principal at step 1','Copy validation needs a reader','Unknown-link page for a person not permitted','Invalid input before any hash','One reader decision','Request key in every audit record','Sibling notice and page of a copy','Query page marks unbound values','Late read does not replace a newer record','MCP never strips a member','Grant status does not reveal definitions','S66 before any record read','Recorded outcome before the record scope','Grant matching before the pending cap','Unknown outcome recorded at consumption','Page access from permissions only','Records close with their decision and context','Organization approvers are authorized'];
  return {tests,names};
}
