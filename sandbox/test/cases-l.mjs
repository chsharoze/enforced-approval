import assert from 'node:assert/strict';
import { readFileSync, mkdtempSync, rmSync } from 'node:fs';
import path from 'node:path';
import { OP, hash, Core } from '../src/core.mjs';
import { Sor } from '../src/sor.mjs';
import { runtime } from '../src/runtime.mjs';
import { REGISTRY } from '../src/settings.mjs';
const vectors=JSON.parse(readFileSync(new URL('../spec/vectors/vectors.json',import.meta.url)));
// Start the runtime with exactly these environment values, restoring the process's own
// afterwards. A throw from runtime() is the start refusal the test asserts on.
function runtimeWith(env) {
  const saved=Object.fromEntries(Object.keys(env).map(k=>[k,process.env[k]]));
  Object.assign(process.env,env);
  try { return runtime(); } finally { for (const [k,v] of Object.entries(saved)) { if (v===undefined) delete process.env[k]; else process.env[k]=v; } }
}
// Release-fix tests (CONFORMANCE.md numbering ends at 199; these are the sandbox's own,
// from 209). One test per release-fix item that changes behaviour. Each names the
// requirement it checks and the Off hook (VA_MUTATE) it kills.
export function cases({helpers:{setup,req,ask,browser},fixture,call,A,P,admin,sdk}) {
  const used=f=>f.core.db.prepare('SELECT count(*) n FROM used').get().n;
  const tests=[
    // 209. S85 binding of who may approve. Every setting that changes who may approve is
    // in the effect record: the approver model, the named-approver list and the
    // administrators list, as well as the operation's approver types. An approval made
    // before a change to one of them no longer matches and the normal approval request
    // follows; a grant made under a different effect record no longer matches either (E2,
    // E2c, E4). Off: approver-rule-change-unbound.
    async function approverRuleChangeVoids() {
      // The administrators list alone voids an approval (default and covered modes).
      for (const covered of [false,true]) {
        const f=setup(covered?{preconditions:true}:{});
        f.core.admin(admin,'settings',{approver_model:'administrators',pageAdministrators:{[A]:['test-admin','test-person']}});
        const r=req(f,'admins-209-'+covered),id=ask(f,r),b=browser(f);await b.login();await b.show(id);
        assert.equal((await b.decide(id,'approve')).status,200,'covered='+covered);
        const before=f.core.effectHash();
        f.core.admin(admin,'settings',{pageAdministrators:{[A]:['test-admin']}});
        assert.notEqual(f.core.effectHash(),before,'covered='+covered+': removing an administrator changes the effect record');
        const out=call(f,r);
        assert.equal(out.approval?.error,'approval_required','covered='+covered+': the approval no longer matches');
        assert.equal(f.count(),0,'covered='+covered+': no write');
        assert.equal(used(f),0,'covered='+covered+': no consumption');
        assert(out.approval.approval_url,'covered='+covered+': the normal approval request follows');
      }
      // The named-approver list alone voids an approval (S85; S22 narrowing).
      const g=setup();
      g.core.admin(admin,'settings',{approver_model:'named',approvers:{[A]:['test-person','test-person-3']}});
      const gr=req(g,'named-209'),gid=ask(g,gr),gb=browser(g);await gb.login();await gb.show(gid);
      assert.equal((await gb.decide(gid,'approve')).status,200);
      g.core.admin(admin,'settings',{approvers:{[A]:['test-person-3']}});
      assert.equal(call(g,gr).approval?.error,'approval_required','the named-approver list change voids the match');
      assert.equal(g.count(),0);assert.equal(used(g),0);
      // A grant made under a different effect record no longer matches (E4).
      const k=setup(),kr=req(k,'grant-209'),kid=ask(k,kr),kb=browser(k);await kb.login();await kb.show(kid);
      assert.equal((await kb.decide(kid,'grant',{max_records:5,expires:k.now()+500})).status,200);
      k.core.admin(admin,'settings',{approver_model:'administrators',pageAdministrators:{[A]:['test-admin']}});
      const after=call(k,req(k,'grant-209-next'));
      assert.equal(after.approval?.error,'approval_required','a grant made under another effect record no longer matches');
      assert.equal(k.count(),0,'the grant writes nothing after the change');
      assert.equal(k.core.db.prepare('SELECT sum(charged) n FROM server_grants').get().n,0,'the grant is not charged');
    },
    // 210. S84 with S67: tightening the pending lifetime applies to a covered context too.
    // A context expires no later than its creation plus the lifetime now in force, so a
    // person cannot approve into a context the new limit has already closed, and the write
    // does not run (E5, E5c). Loosening the setting extends no context and revives none.
    // Off: covered-context-outlives-tightening.
    async function tighteningAppliesToContexts() {
      const f=setup({preconditions:true}),r=req(f,'context-tighten-210'),t0=f.now();
      const first=call(f,r),a=first.approval;
      assert.equal(a?.error,'approval_required');
      const token=a.approval_url.split('/').at(-1);
      assert.equal(a.pending_expires-t0,3600,'before the change the context expires a full pending lifetime after creation');
      f.core.admin(admin,'settings',{pending_lifetime_seconds:60});
      assert.equal(f.pending.contextOf(token).expires,t0+60,'S84/S67: the existing context expires at the new limit, measured from its creation');
      const again=call(f,r).approval;
      assert.equal(again.pending_expires,t0+60,'S90: the refusal reports the context\'s tightened expiry');
      // At the new limit the context is closed, the page offers no decision, and the
      // request is answered as a new context — nothing runs under the old approval.
      f.time(t0+120);
      const b=browser(f);await b.login();
      assert(!(await b.show(token)).body.includes('name="decision"'),'the expired context\'s page offers no decision');
      const next=call(f,r);
      assert.equal(next.approval?.error,'approval_required','the request is answered as a new context after the tightening');
      assert.equal(f.count(),0,'nothing ran');
      assert.equal(f.pending.contextOf(token).status,'expired','the old context is closed');
      // E5c: approval posted to the old link after the new limit records nothing and does
      // not run the write.
      const g=setup({preconditions:true}),gr=req(g,'context-late-210'),g0=g.now();
      const gid=call(g,gr).approval.approval_url.split('/').at(-1);
      g.core.admin(admin,'settings',{pending_lifetime_seconds:60});
      g.time(g0+600);
      const gb=browser(g);await gb.login();await gb.show(gid);
      assert.equal((await gb.decide(gid,'approve')).status,403,'a decision after the new limit is refused');
      assert.equal(call(g,gr).approval?.error,'approval_required','the request is a new approval request');
      assert.equal(g.count(),0,'the write does not run');
      // Loosening extends no context and revives none.
      const k=setup({preconditions:true}),kr=req(k,'context-loosen-210'),k0=k.now();
      const kid=call(k,kr).approval.approval_url.split('/').at(-1);
      k.core.admin(admin,'settings',{pending_lifetime_seconds:7200,approver_notification:true});
      assert.equal(k.pending.contextOf(kid).expires,k0+3600,'loosening extends no existing context');
      k.time(k0+3601);
      assert.equal(call(k,kr).approval?.error,'approval_required','a loosening revives no expired context');
    },
    // 211. Registry completeness (S23, S81, S82, S90). The registry also carries the maximum
    // approval lifetime, the skew, the grant-record and grant-second limits, the key-cache
    // period and an upper bound on the retention floor, each with a default and a hard
    // limit; no value is unlimited or out of range, at the admin call or at start (E1, E1c,
    // E1d, E10). The lifetime is at least 2 seconds, so S90's poll_interval is always
    // shorter than it. Tightening the grant limits applies to existing grants and loosening
    // never widens one (E11). Raising the skew never revives an approval that expired under
    // the old value (S84). Off: registry-unbounded-value.
    async function registryCompleteness() {
      // Each added setting is in the registry with a default and a hard limit.
      for (const name of ['max_lifetime_seconds','skew_seconds','grant_charge_limit','grant_seconds_limit','key_cache_seconds']) {
        const e=REGISTRY.find(x=>x.name===name);
        assert(e,name+' is a registry setting');
        assert.notEqual(e.default,undefined,name+' has a default');
        assert(Number.isSafeInteger(e.ceiling),name+' has a finite hard limit');
      }
      // A value past each hard limit, and an "unlimited" value, are refused at the admin
      // call, the value in force is unchanged, and the refusal is recorded (S81).
      const f=setup(),probes={max_lifetime_seconds:[86401,1,0,2**60],skew_seconds:[61,-1,2**60],grant_charge_limit:[1001,0,2**60],grant_seconds_limit:[31536001,0,2**60],key_cache_seconds:[86401,0,2**60],retention_floor_seconds:[31536001,2**60]};
      for (const [name,values] of Object.entries(probes)) {
        const key=REGISTRY.find(e=>e.name===name).key,before=f.core.settings()[key];
        for (const value of values) {
          assert.throws(()=>f.core.admin(admin,'settings',{[name]:value}),Error,`${name} ${value} is refused`);
          assert.equal(f.core.settings()[key],before,`${name} in force is unchanged`);
          assert.equal(f.core.records().at(-1).outcome,'refused',`${name} ${value} refusal is recorded`);
        }
      }
      // The maximum lifetime may be as small as 2 seconds, and S90's poll_interval is
      // always shorter than it (E1: maxLifetime 1 made them equal).
      const g=setup();
      g.core.admin(admin,'settings',{max_lifetime_seconds:2});
      const a=call(g,req(g,'poll-211')).approval;
      assert.equal(a.max_lifetime,2);
      assert(a.poll_interval<a.max_lifetime,`poll_interval ${a.poll_interval} is shorter than max_lifetime ${a.max_lifetime}`);
      // Raising the lifetime beyond the stored retention floor requires raising the floor
      // with it (S13): the floor is never below the S13 period, and a stored floor below
      // the new computed one is a lowering, refused rather than silently raised.
      assert.throws(()=>g.core.admin(admin,'settings',{max_lifetime_seconds:3600}),/retention_floor_seconds/,'raising the lifetime alone would lower the floor');
      g.core.admin(admin,'settings',{max_lifetime_seconds:3600,retention_floor_seconds:3600});
      assert.equal(g.core.settings().maxLifetime,3600);
      assert(g.core.settings().retentionFloor>=3600+g.core.settings().skew,'the retention floor is at least the maximum lifetime');
      // Tightening a grant limit applies to existing grants; loosening never widens one.
      const k=setup(),kr=req(k,'grant-limit-211'),kid=ask(k,kr),kb=browser(k);await kb.login();await kb.show(kid);
      assert.equal((await kb.decide(kid,'grant',{max_records:8,expires:k.now()+900})).status,200);
      const id=k.core.db.prepare('SELECT id FROM server_grants').get().id;
      assert.equal(k.pending.grants.get(id).max_records,8);
      k.core.admin(admin,'settings',{grant_charge_limit:1});
      let ran=0;for(let i=0;i<3;i++) if(call(k,req(k,'grant-limit-211-'+i)).ok) ran++;
      assert.equal(ran,1,'S84: the tightened record limit applies to the existing grant');
      // S84: the tightened limit is recorded on the grant itself, so a later loosening of
      // the ceiling finds the tightened grant and restores no authority.
      assert.equal(k.pending.grants.get(id).max_records,1,'the tightened record limit is stored on the grant');
      k.core.admin(admin,'settings',{grant_charge_limit:1000});
      assert.equal(k.pending.grants.get(id).max_records,1,'loosening the ceiling does not restore the grant\'s earlier limit');
      for(let i=0;i<3;i++) assert.equal(call(k,req(k,'grant-loosened-211-'+i)).ok,false,'the grant writes nothing after a loosening');
      assert.equal(k.count(),1,'no further write under the loosened ceiling');
      const grantRow=k.pending.grants.get(id);
      k.core.admin(admin,'settings',{grant_seconds_limit:60});
      const tightened=k.pending.grants.get(id);
      assert(tightened.expires<grantRow.expires,'the tightened second limit is stored on the grant');
      assert.equal(tightened.expires,grantRow.made_at+60,'the grant expires at its own made_at plus the tightened ceiling');
      k.time(tightened.expires);
      assert.equal(call(k,req(k,'grant-limit-211-late')).approval?.error,'approval_required','the tightened second limit stops the existing grant');
      k.core.admin(admin,'settings',{grant_seconds_limit:31536000});
      assert.equal(call(k,req(k,'grant-limit-211-late-2')).approval?.error,'approval_required','loosening the second ceiling revives no expired grant');
      assert.equal(k.count(),1,'no further write under the loosened limits');
      // A loosening of the grant limits widens no existing grant.
      const w=setup(),wr=req(w,'grant-loosen-211'),wid=ask(w,wr),wb=browser(w);await wb.login();await wb.show(wid);
      assert.equal((await wb.decide(wid,'grant',{max_records:2,expires:w.now()+100})).status,200);
      const wid2=w.core.db.prepare('SELECT id FROM server_grants').get().id;
      w.core.admin(admin,'settings',{grant_charge_limit:1000,grant_seconds_limit:31536000});
      assert.equal(w.pending.grants.get(wid2).max_records,2,'a loosening does not widen the existing grant');
      assert.equal(w.pending.grants.get(wid2).expires,w.now()+100,'nor extend its expiry');
      // Raising the skew never revives an approval that expired under the old value (S84).
      const s=setup(),sr=req(s,'skew-revive-211'),sid=ask(s,sr),sb=browser(s);await sb.login();await sb.show(sid);
      assert.equal((await sb.decide(sid,'approve')).status,200);
      s.time(s.now()+301); // the approval expired with skew 0
      // Raising the skew raises the computed S13 floor, so the floor is raised with it; the
      // expired approval is still not revived.
      s.core.admin(admin,'settings',{skew_seconds:60,retention_floor_seconds:400});
      const late=call(s,sr);
      assert.equal(late.ok,false,'S84: raising the skew revives no expired approval');
      assert(['approval_expired','approval_required'].includes(late.approval?.error),'the expired approval is refused, not accepted');
      assert.equal(s.count(),0,'nothing from the expired approval runs');
      assert.equal(f.core.settings().keyCacheSeconds,3600,'the key cache is a registry setting in force');
    },
    // 212. S87: `config_hash` and the deployment record cover every setting in force. Each
    // registry setting has a member in the record, and a change to the maximum lifetime or
    // the skew changes `config_hash` (E15, E15b). Off: deployment-record-omits-setting.
    async function configHashCoversEverySetting() {
      const f=setup(),rec=f.core.deploymentRecord();
      for (const e of REGISTRY) assert.equal(rec[e.name],f.core.settings()[e.key],e.name+' is in the record and equals the value in force');
      for (const name of ['max_lifetime_seconds','skew_seconds']) assert(name in rec,name+' is in the record');
      const h0=f.core.configHash();
      f.core.admin(admin,'settings',{skew_seconds:60,retention_floor_seconds:400});
      assert.notEqual(f.core.configHash(),h0,'a change of the skew changes config_hash');
      const h1=f.core.configHash();
      f.core.admin(admin,'settings',{max_lifetime_seconds:1200,retention_floor_seconds:1260});
      assert.notEqual(f.core.configHash(),h1,'a change of the maximum lifetime changes config_hash');
      // The record is the one the audit chain records, and the hash is over the record
      // without its own hash member.
      const {config_hash,...object}=f.core.deploymentRecord();
      assert.equal(hash(object),config_hash);
      const deployment=f.core.records().at(-1);
      assert.equal(deployment.record_phase,'deployment','the new record is in the chain');
      assert.equal(deployment.action_detail.deployment_record.config_hash,config_hash);
      // A consumption record carries the value in force.
      const r=req(f,'config-hash-212'),id=ask(f,r),b=browser(f);await b.login();await b.show(id);
      assert.equal((await b.decide(id,'approve')).status,200);
      assert(call(f,r).ok);
      assert.equal(f.core.records().filter(x=>x.record_phase==='consumption').at(-1).action_detail.config_hash,config_hash);
    },
    // 213. `read_tool_denied_answer` has one value in this release, `absent`: the read tool
    // answers a record the principal may not read exactly as an absent identifier. The
    // other value the earlier draft named, `not_permitted`, is refused, so code, registry
    // and documentation agree. Off: read-tool-denied-answer-permission-denied.
    async function readToolDeniedAnswerIsAbsentOnly() {
      const e=REGISTRY.find(x=>x.name==='read_tool_denied_answer');
      assert.deepEqual(e.values,['absent'],'the registry offers only the absent answer');
      assert.equal(e.default,'absent');
      const f=setup();
      for (const bad of ['not_permitted','refuse','',null]) assert.throws(()=>f.core.admin(admin,'settings',{read_tool_denied_answer:bad}),Error,`${JSON.stringify(bad)} is refused`);
      assert.equal(f.core.settings().readToolDeniedAnswer,'absent','the value in force is unchanged');
      // The tool answers an unreadable record exactly as an absent one, at record and
      // operation level, in both modes, whatever the setting.
      for (const settings of [{},{preconditions:true}]) {
        const g=setup(settings);
        g.sor.seed(A,'rec-ABSENT-213',{owner:'secret-213'});
        g.sor.recordPermission(A,P,'rec-ABSENT-213',false,true);
        await sdk(g,'server',async c=>{
          const read=async id=>JSON.stringify(await c.callTool({name:'read_record',arguments:{id}}));
          assert.equal(await read('rec-ABSENT-213'),await read('rec-NEVER-213'),'an unreadable record answers exactly as an absent one');
          g.sor.permission(A,P,OP,false,true);
          assert.equal(await read('rec-ABSENT-213'),await read('rec-NEVER-213'),'the operation-level denial answers the same');
        },undefined,settings.preconditions?{VA_PRECONDITIONS:'1'}:{});
      }
    },
    // 214. The `named` approver model narrows S22: a person may approve only if they are on
    // the named list for the account AND pass S22. A person who passes S22 but is not named
    // cannot approve; a person who is named but fails S22 cannot approve. The default model
    // is `permission`, and code, README, AMBIGUITIES and core agree (E3). Off:
    // named-model-ignores-list.
    async function namedModelNarrows() {
      // A person who passes S22 but is not on the list may not approve.
      const f=setup();
      f.core.admin(admin,'settings',{approver_model:'named',approvers:{[A]:['test-person-3']}});
      const r=req(f,'named-214'),id=ask(f,r),b=browser(f);await b.login('test-person');await b.show(id);
      assert.equal((await b.decide(id,'approve')).status,403,'a person who passes S22 but is not named may not approve');
      assert.equal(f.count(),0,'nothing ran');
      // A named person who passes S22 may approve.
      const n=browser(f);await n.login('test-person-3');await n.show(id);
      assert.equal((await n.decide(id,'approve')).status,200,'a named person who passes S22 may approve');
      assert(call(f,r).ok);assert.equal(f.count(),1);
      // A person named on the list but failing S22 may not approve.
      const g=setup();
      g.core.admin(admin,'settings',{approver_model:'named',approvers:{[A]:['test-person']}});
      g.sor.permission(A,'test-person',OP,true,false); // may read, may not write
      const gr=req(g,'named-214-deny'),gid=ask(g,gr),gb=browser(g);await gb.login('test-person');await gb.show(gid);
      assert.equal((await gb.decide(gid,'approve')).status,403,'a named person who fails S22 may not approve');
      assert.equal(g.count(),0);
      // The default model is `permission`, and the documentation says so.
      assert.equal(setup().core.settings().approverModel,'permission','the default approver model is permission');
      for (const doc of ['../README.md','../AMBIGUITIES.md','../../core.md']) {
        const text=readFileSync(new URL(doc,import.meta.url),'utf8');
        assert(!/`named`.*\badefault\b|named.*\(the default/i.test(text),doc+': does not call named the default');
      }
    },
    // 215. S78 with S77: the applied-to identifier is returned only where S77 permits it.
    // S77 permits "the identifier of a record, where the server can establish that this write
    // created it", requires it to conform to the documented format, and permits it only where
    // the principal may read that record. A misdirected update took effect on a merged-into
    // record that it did not create, so the identifier is withheld even from a principal
    // established to read that record; only the client-sent identifier is returned. A
    // misdirected create did create the record, so a conforming identifier is returned.
    // Off: leak-applied-identifier, return-unchecked-identifier.
    async function appliedIdentifierOnlyWherePermitted() {
      // A full reader: it may read the surviving record, yet the applied-to identifier is
      // withheld because this write did not create that record.
      const f=setup();f.sor.conditional=false;
      f.sor.seed(A,'rec-APPLIED-215-from',{owner:'from-215'});f.sor.seed(A,'rec-APPLIED-215-target',{owner:'target-215'});
      const r=f.req({objectType:'contact',action:'update',records:[{id:'rec-APPLIED-215-from',properties:{owner:'new-215'}}]});
      const id=ask(f,r),b=browser(f);await b.login();await b.show(id);await b.decide(id,'approve');
      f.sor.inject('before-write',()=>{f.sor.merge(A,'rec-APPLIED-215-from','rec-APPLIED-215-target');});
      const out=call(f,r);
      assert(out.ok,JSON.stringify(out.approval));
      const entry=out.result.entries?.[0];
      assert(entry,'a per-record result');
      assert.equal(entry.outcome,'misdirected');
      assert.equal(entry.id,'rec-APPLIED-215-from','the client-sent identifier is returned');
      assert(!Object.hasOwn(entry,'applied_identifier'),'the applied-to identifier is not returned to a reader: the write did not create that record');
      assert(entry.identifier_withheld===true,'the result says it was withheld');
      const replay=call(f,r);
      assert(replay.ok);
      assert.equal(replay.result.entries[0].identifier_withheld,true);
      assert(!Object.hasOwn(replay.result.entries[0],'applied_identifier'));
      // The audit record still holds the identifier the write was applied to (S78).
      assert(JSON.stringify(f.core.records().find(x=>x.record_phase==='outcome')).includes('rec-APPLIED-215-target'));
      // A create that succeeds returns the count changed; the identifier it created is the
      // one the client sent, which S77 permits by construction.
      const g=setup();
      const cr={account:A,principal:P,operation:'mcp:tools/call:create_record',args:{objectType:'contact',id:'rec-APPLIED-215-made',properties:{owner:'made-215'}}};
      const tid=ask(g,cr),tb=browser(g);await tb.login();await tb.show(tid);await tb.decide(tid,'approve');
      const made=call(g,cr);
      assert(made.ok,JSON.stringify(made.approval));
      assert.equal(made.result.changed,1,'the create ran');
      assert.equal(g.sor.get(A,'rec-APPLIED-215-made').properties.owner,'made-215');
    },
    // 216. Section 7: a recorded `conflict` or `execution_failed` is a refusal whose
    // `recorded_outcome` object carries the `message` member the text requires. The
    // enclosing refusal had a message, but the object did not, in either mode
    // (replayAnswer and coveredReplay). Off: recorded-outcome-omits-message.
    async function recordedOutcomeCarriesMessage() {
      for (const [covered,label] of [[false,'default'],[true,'covered']]) {
        for (const [error,inject] of [['conflict',()=>{throw Object.assign(Error('conflict'),{sorText:'rejected'});}],['execution_failed',()=>{throw Error('write rejected');}]]) {
          const base=covered?{preconditions:true}:{};
          const f=setup(base),r=req(f,`recorded-216-${label}-${error}`);
          const id=ask(f,r),b=browser(f);await b.login();await b.show(id);assert.equal((await b.decide(id,'approve')).status,200);
          f.sor.inject('before-write',inject);
          assert.equal(call(f,r).approval?.error,error,label);
          const replay=call(f,r),marker=replay.approval.recorded_outcome;
          assert(marker,label+'/'+error+': the replay is marked');
          assert.equal(marker.outcome,error);
          assert.equal(typeof marker.message,'string',label+'/'+error+': recorded_outcome carries a message');
          assert(marker.message.length>0,label+'/'+error+': the message is not empty');
          assert(marker.message.includes('Nothing was sent now'),label+'/'+error+': the message says nothing was sent now');
          assert.equal(replay.approval.message,marker.message,label+'/'+error+': the refusal message and the object message agree');
        }
      }
    },
    // 217. S61: the key `state_hash` and `manifest_hash` use MUST have at least 256 bits from
    // a cryptographic random source. The server generates one when it is missing; a
    // configured key shorter than 256 bits is refused at start. Off:
    // short-state-key-accepted.
    async function shortStateKeyRefused() {
      const KEY=vectors.state_manifest_hmac_key; // 64 hex characters, 256 bits
      const dir=mkdtempSync(path.resolve('.va-key-'));
      try {
        // A key shorter than 256 bits is refused at start, when the database is created.
        for (const short of ['ab','ab'.repeat(15),'0'.repeat(63)]) {
          const db=path.join(dir,`key-${short.length}-${Math.random().toString(16).slice(2)}.sqlite`);
          let refused='';
          try { const core=new Core(new Sor(db),{adminCredential:'admin-key',settings:{stateKey:short,preconditions:true}}); core.sor.close(); } catch (e) { refused=e.message; }
          assert(refused,`a ${short.length*4}-bit key is refused at start`);
          assert(/256|state.?key/i.test(refused),'the refusal names the key requirement: '+refused);
        }
        // S61: the key is 256 bits written as hexadecimal digits. A string that is not
        // hexadecimal is refused at start even when its byte count would pass, because it
        // decodes to an empty key under Buffer.from(key,'hex').
        for (const notHex of ['z'.repeat(32),'not-a-hexadecimal-key-but-long-enough-to-count-as-32-bytes','0'.repeat(63)+'x','g'.repeat(64)]) {
          const db=path.join(dir,`key-hex-${Math.random().toString(16).slice(2)}.sqlite`);
          let refused='';
          try { const core=new Core(new Sor(db),{adminCredential:'admin-key',settings:{stateKey:notHex,preconditions:true}}); core.sor.close(); } catch (e) { refused=e.message; }
          assert(refused,'a key that is not hexadecimal is refused at start: '+JSON.stringify(notHex.slice(0,12)));
          assert(/hexadecimal|256|state.?key/i.test(refused),'the refusal says the key must be hexadecimal: '+refused);
        }
        // The administrative surface applies the same rule (S81, S61).
        const a=setup();
        for (const notHex of ['zz','z'.repeat(64)]) {
          assert.throws(()=>a.core.admin(admin,'settings',{stateKey:notHex}),/hexadecimal|256|state.?key/i,'the admin call refuses a key that is not 256 hexadecimal digits');
          assert.equal(a.core.settings().stateKey,undefined,'no invalid key is stored');
        }
        // A 256-bit configured key is accepted.
        const db=path.join(dir,'key-ok.sqlite');
        const core=new Core(new Sor(db),{adminCredential:'admin-key',settings:{stateKey:KEY,preconditions:true}});
        assert.equal(core.settings().stateKey,KEY,'a 256-bit configured key is accepted');
        core.sor.close();
      } finally { rmSync(dir,{recursive:true,force:true}); }
    },
    // 218. Settings given at start on an existing database that differ from the stored
    // values: the server refuses to start with a clear message, never silently ignoring the
    // start values (E14). The administrative surface refuses changing `preconditions` on a
    // live database, because that builds a change object and needs a state key the running
    // deployment does not have (E9). Off: start-settings-ignored, admin-flips-preconditions.
    async function startSettingsAndLivePreconditions() {
      // E14: a start value that disagrees with the store is refused, for a registry setting
      // given under its documented name or its storage key.
      for (const [key,env,requested,stored] of [['pending_cap','VA_PENDING_CAP',5,20],['selection_limit','VA_SELECTION_LIMIT',50,100]]) {
        const dir=mkdtempSync(path.resolve('.va-start10-'));
        try {
          const file=path.join(dir,'s.sqlite');
          const first=runtimeWith({VA_DB:file,VA_ADMIN:'adm',VA_MODE:'organization',VA_TEST_ISSUER:'1'});
          first.core.admin('adm','settings',{[key]:stored});
          first.sor.close();
          let refused='';
          try { const again=runtimeWith({VA_DB:file,VA_ADMIN:'adm',VA_MODE:'organization',VA_TEST_ISSUER:'1',[env]:String(requested)}); again.sor.close(); }
          catch (e) { refused=e.message; }
          assert(refused,`${key}=${requested} on a database storing ${stored} is refused at start`);
          assert(/database|stored|refus/i.test(refused),'the refusal is clear: '+refused);
        } finally { rmSync(dir,{recursive:true,force:true}); }
      }
      // E14 in the Core constructor itself: a start value that disagrees with the store is
      // refused rather than silently ignored, whether given by the registry name or the key.
      for (const settings of [{pending_cap:5},{pendingCap:5}]) {
        const dir=mkdtempSync(path.resolve('.va-core10-'));
        try {
          const db=path.join(dir,'c.sqlite');
          const core=new Core(new Sor(db),{adminCredential:'adm'});
          core.admin('adm','settings',{pending_cap:20});
          let refused='';
          try { new Core(new Sor(db),{adminCredential:'adm',settings}).sor.close(); } catch (e) { refused=e.message; }
          assert(refused,'a start value disagreeing with the stored value is refused: '+JSON.stringify(settings));
        } finally { rmSync(dir,{recursive:true,force:true}); }
      }
      // A start value that matches the store starts fine.
      const dir=mkdtempSync(path.resolve('.va-start10-ok-'));
      try {
        const file=path.join(dir,'s.sqlite');
        const first=runtimeWith({VA_DB:file,VA_ADMIN:'adm',VA_MODE:'organization',VA_TEST_ISSUER:'1'});
        first.core.admin('adm','settings',{pending_cap:20}); first.sor.close();
        const again=runtimeWith({VA_DB:file,VA_ADMIN:'adm',VA_MODE:'organization',VA_TEST_ISSUER:'1',VA_PENDING_CAP:'20'});
        assert.equal(again.core.settings().pendingCap,20,'a matching start value starts');
        again.sor.close();
      } finally { rmSync(dir,{recursive:true,force:true}); }
      // E9: the admin surface refuses to change `preconditions` on a live database.
      const f=setup();
      assert.throws(()=>f.core.admin(admin,'settings',{preconditions:true}),/preconditions/,'changing preconditions on a live database is refused');
      assert.equal(f.core.settings().preconditions,false,'the value in force is unchanged');
      assert.equal(f.core.records().at(-1).outcome,'refused','the refusal is recorded');
    },
    // 219. Section 7 with S17, S65: a guarded MCP call whose arguments the tool's schema
    // refuses is answered `invalid_input` through the core's mapping, with a `message`
    // that names what was invalid, and it is recorded like every other refusal. The SDK's
    // own invalid-arguments error never reaches the client, because it bypasses the core
    // and its audit record. Off: schema-fault-as-sdk-error.
    async function mcpSchemaFaultReachesTheCore() {
      const f=setup();
      const before=f.sor.reads(),records=f.core.records().length;
      await sdk(f,'server',async c=>{
        for (const args of [{objectType:'contact',records:'not-an-array'},{objectType:123,records:[]}]) {
          const r=await c.callTool({name:'manage_records',arguments:args});
          assert.equal(r.isError,true,'a schema fault is an error result: '+JSON.stringify(r).slice(0,300));
          const body=JSON.parse(r.content[0].text);
          assert.equal(body.error,'invalid_input','the core answers invalid_input');
          assert.equal(typeof body.message,'string');assert(body.message.length>0,'its message names what was invalid');
          assert(/records|objectType/.test(body.message),'the message names the member: '+body.message);
          assert(!Object.hasOwn(body,'change_hash'),'S63: invalid_input carries no change hash');
          assert(!Object.hasOwn(body,'approval_url'),'no approval link');
        }
      });
      assert.equal(f.sor.reads(),before,'nothing was read from the system of record');
      assert.equal(f.count(),0,'nothing ran');
      const refusals=f.core.records().slice(records);
      assert.equal(refusals.length,2,'each schema fault is recorded as a refusal (S17)');
      assert(refusals.every(x=>x.record_phase==='refusal'&&x.action_detail.error==='invalid_input'),JSON.stringify(refusals));
    },
  ];
  const names=['Approver-rule change voids a match','Tightening the pending lifetime reaches a covered context','Registry completeness and bounded values','config_hash covers every setting in force','The read tool answers a denied record as absent only','The named approver model narrows S22','The applied-to identifier is returned only where S77 permits','A recorded refusal carries a message in recorded_outcome','A short configured state key is refused at start','A start value that disagrees with the store is refused; preconditions cannot be changed live','An MCP schema fault reaches the core as invalid_input'];
  return {tests,names};
}
