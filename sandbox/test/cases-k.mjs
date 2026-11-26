import assert from 'node:assert/strict';
import { OP, hash } from '../src/core.mjs';
import { REGISTRY, PRINCIPAL_MODELS, resolve } from '../src/settings.mjs';
// Conformance tests 190 to 199, exactly as CONFORMANCE.md words them. A test whose
// meaning was already covered by a milestone 2 test keeps one implementation under the
// CONFORMANCE number (190 defaults, 191 hard limits, 194 tightening, 195 binding,
// 197 deployment record); the milestone 2 tests that cover other decided behaviour are
// the sandbox's own tests 200 to 208.
export function cases({helpers:{setup,req,ask,browser},fixture,call,A,P,admin,sdk}) {
  const used=f=>f.core.db.prepare('SELECT count(*) n FROM used').get().n;
  const storageKey=name=>REGISTRY.find(e=>e.name===name).key;
  const tests=[
    // 190. Defaults. On a deployment where no setting was made, every setting of the
    // registry is at its default, and the deployment record says so. Make one setting
    // unreadable: the server applies its default. Off: a setting starts at a looser value,
    // or an unreadable setting is treated as loose. (S81, S87)
    async function defaults() {
      const f=setup(),rec=f.core.deploymentRecord(),def=resolve({}).values;
      for (const e of REGISTRY) assert.equal(rec[e.name],def[e.name],e.name+' is at its default');
      assert.deepEqual(rec.deviations,{},'the deployment record says no setting differs from its default');
      assert.equal(typeof rec.config_hash,'string');
      assert(PRINCIPAL_MODELS.includes(rec.principal_model),'the record states the principal model in force');
      // A stored value outside its range is not used: the default applies.
      const g=setup();
      const stored=JSON.parse(g.core.db.prepare('SELECT json FROM settings WHERE id=1').get().json);
      g.core.db.prepare('UPDATE settings SET json=? WHERE id=1').run(JSON.stringify({...stored,pendingLifetime:100000}));
      assert.equal(g.core.settings().pendingLifetime,3600,'an out-of-range stored setting means the default');
      // A setting that cannot be read at all means the default too.
      g.core.db.prepare('UPDATE settings SET json=? WHERE id=1').run('{not json');
      assert.equal(g.core.settings().pendingLifetime,3600,'an unreadable setting means the default');
      assert.equal(g.core.settings().approverModel,'permission','an unreadable setting is never treated as loose');
    },
    // 191. Hard limits. On the administrative surface, set each setting one step past its
    // hard limit, then empty, then unlimited: each is refused, the value in force is
    // unchanged and the refusal is recorded. Set a pending lifetime over 1 hour with no
    // approver notification: refused. Off: a value past the limit is accepted. (S81, S27)
    async function hardLimits() {
      const f=setup();
      const probes={
        pending_lifetime_seconds:[86401,'',-1],
        approver_notification:['yes','',null],
        pending_cap:[101,'',-1],
        selection_limit:[1001,'',-1],
        retention_floor_seconds:[0,'',-1],
        read_tool_denied_answer:['refuse','','unlimited'],
        approver_model:['anyone','','unlimited'],
      };
      for (const [name,values] of Object.entries(probes)) {
        for (const value of values) {
          const before=f.core.settings()[storageKey(name)];
          assert.throws(()=>f.core.admin(admin,'settings',{[name]:value}),Error,`${name} ${JSON.stringify(value)} is refused`);
          assert.equal(f.core.settings()[storageKey(name)],before,`${name} in force is unchanged`);
          const last=f.core.records().at(-1);
          assert.equal(last.record_phase,'settings','the refusal is recorded');
          assert.equal(last.outcome,'refused');
          assert.equal(last.action_detail.attempted[name],value,'the recorded refusal names the value');
        }
      }
      // A pending lifetime over one hour with no approver notification is refused.
      assert.throws(()=>f.core.admin(admin,'settings',{pending_lifetime_seconds:7200}),/approver_notification/);
      assert.equal(f.core.records().at(-1).outcome,'refused');
      assert.equal(f.core.settings().pendingLifetime,3600);
    },
    // 192. Invariants at the limits. Run the server's S82 invariant set at the default of
    // every setting, then with each setting at its hard limit in turn. Each run gives the
    // same results. Off: a test that passes at the default fails at a limit. (S82, S88)
    // The whole conformance suite is run the same way by `npm run test:matrix`.
    async function invariantsAtLimits() {
      const configs=[
        ['default',{}],
        ['pending_lifetime_seconds',{pending_lifetime_seconds:86400,approver_notification:true}],
        ['approver_notification',{approver_notification:true,pending_lifetime_seconds:7200}],
        ['pending_cap',{pending_cap:100}],
        ['selection_limit',{selection_limit:1000}],
        ['retention_floor_seconds',{retention_floor_seconds:300}],
        ['read_tool_denied_answer',{read_tool_denied_answer:'absent'}],
        ['max_lifetime_seconds',{max_lifetime_seconds:86400,retention_floor_seconds:86400}],
        ['skew_seconds',{skew_seconds:60,retention_floor_seconds:360}],
        ['grant_charge_limit',{grant_charge_limit:1000}],
        ['grant_seconds_limit',{grant_seconds_limit:31536000}],
        ['key_cache_seconds',{key_cache_seconds:86400}],
        // Adding the named model is the loosening direction of the approver model, and the
        // list is non-empty so that it narrows S22 to the named people.
        ['approver_model',{approver_model:'named',approvers:{[A]:['test-person']}}],
      ];
      const probe=async settings=>{
        const f=setup(settings);
        // S6/S16: no approval, no write.
        const noApproval=call(f,req(f,'invariant-no-approval'));
        const refuses=noApproval.approval?.error==='approval_required'&&f.count()===0;
        // S1/S4/S13/S80: an approval runs exactly once, and the repeat is the recorded outcome.
        const r=req(f,'invariant-run'),id=ask(f,r),b=browser(f);await b.login();await b.show(id);
        const approved=(await b.decide(id,'approve')).status===200;
        const ran=call(f,r),once=ran.ok&&f.count()===1&&used(f)===1;
        const replay=call(f,r),recorded=replay.ok&&replay.result.recorded_outcome?.sent_now===false&&f.count()===1&&used(f)===1;
        // P7/S21: nothing received on the connection is an approval.
        const connection=call(f,{...req(f,'invariant-connection'),inputResponses:{approve:{action:'accept'}}});
        const noConnection=connection.approval?.error==='approval_required'&&f.count()===1;
        // S23: the agent cannot change a setting.
        let agentRefused=false;try{f.core.admin(admin,'settings',{pending_cap:5},{agent:true});}catch{agentRefused=true;}
        // S15/S60: a step 1 refusal for a credential without the write permission.
        const g=setup(settings);g.sor.permission(A,P,OP,true,false);
        const stepOne=call(g,req(g,'invariant-step1'));
        const stepOneRefused=stepOne.approval?.error==='permission_denied'&&g.count()===0;
        // S17: the refusal is recorded (call asserts the audit row for every refusal).
        assert.equal(f.core.chainCheck().ok,true);
        return {refuses,approved,once,recorded,noConnection,agentRefused,stepOneRefused};
      };
      const base=await probe({});
      for (const [label,settings] of configs) assert.deepEqual(await probe(settings),base,label+' keeps every invariant');
    },
    // 193. Scope. The administrative surface offers no setting scoped by record content, for
    // example a pending lifetime or an approver model that applies only to records holding
    // some value. Off: such a scope exists. (S83)
    async function scope() {
      const f=setup();
      for (const e of REGISTRY) assert.doesNotMatch(e.name,/record|content|value/i,'no setting is named for record content');
      for (const bad of [
        {pending_lifetime_by_record:{'rec-EXAMPLE-42':60}},
        {approver_model_by_record:{'rec-EXAMPLE-42':'permission'}},
        {pending_cap_for_records:5},
      ]) assert.throws(()=>f.core.admin(admin,'settings',bad),/unknown setting/,'a record-scoped setting is refused');
      // The scopes that do exist are account, operation and principal; the account-scoped
      // lists are keyed by account, never by a record or its content.
      f.core.admin(admin,'settings',{approvers:{[A]:['test-person']},pageAdministrators:{[A]:['test-admin']}});
      const rec=f.core.deploymentRecord();
      assert.deepEqual(rec.approvers,{[A]:['test-person']});
      assert.deepEqual(rec.page_administrators,{[A]:['test-admin']});
      f.sor.seed(A,'rec-EXAMPLE-setting-text',{owner:'pending_lifetime_seconds'});
      assert.equal(f.core.settings().pendingLifetime,3600,'record content changes no setting');
    },
    // 194. Tightening and loosening. Lower the pending lifetime: an existing pending record
    // expires at the new limit. Then raise it: a record that expired, was denied or was
    // cancelled stays so, and an existing grant's terms are unchanged. Off: a lowered limit
    // waits for new records, or a raised one revives a record or widens a grant. (S84)
    async function tighteningAndLoosening() {
      // Lower it: the record already open expires at the new limit.
      const f=setup(),r=req(f,'tighten'),id=ask(f,r),created=f.now();
      f.core.admin(admin,'settings',{pending_lifetime_seconds:60});
      assert.equal(f.pending.get(id).expires,created+60,'the existing pending record expires at the new limit');
      f.time(f.now()+61);
      assert.equal(call(f,r).approval?.error,'approval_required','the lowered limit takes effect for the existing record');
      // Raise it: an expired record is not revived.
      const e=setup(),er=req(e,'raise-expired');ask(e,er);e.time(e.now()+3601);
      e.core.admin(admin,'settings',{pending_lifetime_seconds:7200,approver_notification:true});
      assert.equal(call(e,er).approval?.error,'approval_required','a raised limit revives no expired record');
      // A denied record stays denied, and a cancelled one stays cancelled.
      for (const [how,code] of [['deny','approval_denied'],['decline','approval_cancelled']]) {
        const g=setup(),gr=req(g,'raise-'+how);
        if (how==='deny') {const gid=ask(g,gr),gb=browser(g);await gb.login();await gb.show(gid);assert.equal((await gb.decide(gid,'deny')).status,200);}
        else {ask(g,gr);assert.equal(call(g,{...gr,inputResponses:{approve:{action:'decline'}}}).approval?.error,'approval_cancelled');}
        assert.equal(call(g,gr).approval?.error,code);
        g.core.admin(admin,'settings',{pending_lifetime_seconds:7200,approver_notification:true});
        assert.equal(call(g,gr).approval?.error,code,'a raised limit revives nothing');
      }
      // An existing grant's terms are unchanged.
      const k=setup(),kr=req(k,'raise-grant'),kid=ask(k,kr),kb=browser(k);await kb.login();await kb.show(kid);
      assert.equal((await kb.decide(kid,'grant',{max_records:2,expires:k.now()+100})).status,200);
      const g0=k.pending.grants.get(k.core.db.prepare('SELECT id FROM server_grants').get().id);
      k.core.admin(admin,'settings',{pending_lifetime_seconds:7200,approver_notification:true});
      const g1=k.pending.grants.get(g0.id);
      assert.equal(g1.max_records,g0.max_records,'a loosening does not widen a grant');
      assert.equal(g1.expires,g0.expires,'nor extend its expiry');
    },
    // 195. Configuration change voids a match. Obtain an approval; change a value fixed by
    // configuration for the operation (S4), and separately change the approver model so that
    // the approver is no longer permitted; send the approved request each time: no write, no
    // consumption and the normal approval request. Off: the approved request runs. (S85)
    async function configurationVoidsAMatch() {
      // A value fixed by configuration for the operation: the approver types it allows.
      const f=setup(),r=req(f,'config-change'),id=ask(f,r),b=browser(f);await b.login();await b.show(id);
      assert.equal((await b.decide(id,'approve')).status,200);
      f.core.admin(admin,'settings',{operationTypes:{[OP]:['person']}});
      const out=call(f,r);
      assert.equal(out.approval?.error,'approval_required','the approval no longer matches');
      assert.equal(f.count(),0,'no write');assert.equal(used(f),0,'no consumption');
      // The approver model changes so that the approver is no longer permitted.
      const g=setup(),gr=req(g,'model-change'),gid=ask(g,gr),gb=browser(g);await gb.login();await gb.show(gid);
      assert.equal((await gb.decide(gid,'approve')).status,200);
      g.core.admin(admin,'settings',{approver_model:'administrators',pageAdministrators:{[A]:['test-admin']}});
      const refused=call(g,gr);
      assert.equal(refused.approval?.error,'approval_required','the approver model change voids the match');
      assert.equal(g.count(),0);assert.equal(used(g),0);
      assert(refused.approval.approval_url,'the normal approval request follows');
    },
    // 196. Setting changes are audited. Each change of a setting is in the audit chain with
    // who made it, when, and the old and new values, and the chain check reports no broken
    // link. Off: a change is missing from the chain. (S86)
    async function settingChangesAudited() {
      const f=setup();
      const mark=f.core.records().length;
      f.core.admin(admin,'settings',{pending_cap:20});
      f.core.admin(admin,'settings',{selection_limit:250});
      const changes=f.core.records().slice(mark).filter(r=>r.record_phase==='settings'&&r.outcome==='changed');
      assert.equal(changes.length,2,'each change is one audit record');
      const cap=changes.find(r=>r.action_detail.changed.pending_cap);
      assert(cap,'the pending cap change is recorded');
      assert.equal(cap.action_detail.changed.pending_cap.old,10);
      assert.equal(cap.action_detail.changed.pending_cap.new,20);
      assert.equal(cap.principal,'administrator');
      assert.equal(typeof cap.timestamp,'number','the time is recorded');
      const sel=changes.find(r=>r.action_detail.changed.selection_limit);
      assert.equal(sel.action_detail.changed.selection_limit.old,100);
      assert.equal(sel.action_detail.changed.selection_limit.new,250);
      assert.equal(f.core.chainCheck().ok,true,'the chain has no broken link');
    },
    // 197. Deployment record and `config_hash`. Compute `config_hash` from the deployment
    // record: it equals the value in every consumption audit record made since the last
    // change of a setting. Change a setting: the deployment record is recorded in the chain
    // and later consumption records carry the new value. Off: a consumption record lacks
    // `config_hash`, or carries a value that does not match the record in force. (S87)
    async function deploymentRecordAndConfigHash() {
      const f=setup(),rec=f.core.deploymentRecord();
      const {config_hash,...object}=rec;
      assert.equal(hash(object),config_hash,'config_hash is the RFC 8785 SHA-256 of the record');
      const consume=async owner=>{
        const r=req(f,owner),id=ask(f,r),b=browser(f);await b.login();await b.show(id);
        assert.equal((await b.decide(id,'approve')).status,200);
        assert(call(f,r).ok);return f.core.records().filter(x=>x.record_phase==='consumption').at(-1);
      };
      assert.equal((await consume('config-hash-1')).action_detail.config_hash,config_hash,'the first consumption carries the record in force');
      const mark=f.core.records().length;
      f.core.admin(admin,'settings',{selection_limit:50});
      const next=f.core.deploymentRecord();
      assert.notEqual(next.config_hash,config_hash,'a change of a setting changes config_hash');
      const deployment=f.core.records().slice(mark).find(x=>x.record_phase==='deployment');
      assert(deployment,'the new deployment record is recorded in the chain');
      assert.equal(deployment.action_detail.deployment_record.config_hash,next.config_hash);
      assert.equal((await consume('config-hash-2')).action_detail.config_hash,next.config_hash,'later consumption records carry the new value');
      assert(f.core.chainCheck().ok);
    },
    // 198. Notification for a longer pending lifetime. With a pending lifetime over 1 hour
    // and a notification channel set, each new pending record produces one logged
    // notification to the approver, on a channel the agent's credential cannot read. Off: a
    // pending record over 1 hour has no logged notification. (S27, S81)
    async function notificationForLongLifetime() {
      const f=setup({pending_lifetime_seconds:7200,approver_notification:true});
      f.core.admin(admin,'settings',{approvers:{[A]:['test-person']},pageAdministrators:{}});
      const r=req(f,'notified'),id=ask(f,r);
      const rows=f.core.db.prepare('SELECT * FROM notifications WHERE record=?').all(id);
      assert.equal(rows.length,1,'one logged notification for the new pending record');
      assert.equal(rows[0].person,'test-person');
      assert.match(rows[0].message,/open until/);
      // A repeat does not notify again.
      call(f,r);
      assert.equal(f.core.db.prepare('SELECT count(*) n FROM notifications WHERE record=?').get(id).n,1);
      // The agent's credential cannot read the channel: no tool offers it and no refusal
      // carries it.
      await sdk(f,'server',async c=>{
        const tools=await c.listTools();
        assert(!tools.tools.some(t=>/notification/i.test(t.name)),'no tool reads the notification channel');
      });
      const refusal=call(f,r);
      assert(!/notification/i.test(JSON.stringify(refusal)),'no refusal exposes the channel');
    },
    // 199. Poll and expiry members. The `approval_required` refusal carries
    // `pending_expires`, equal to the pending record's expiry (for a covered operation the
    // context's), and `poll_interval`, shorter than `max_lifetime`. Sending the identical
    // request every `poll_interval` seconds after a person approves runs the write once.
    // Off: either member is missing, or the interval is not shorter than `max_lifetime`.
    // (S90)
    async function pollAndExpiryMembers() {
      for (const covered of [false,true]) {
        const f=setup(covered?{preconditions:true}:{}),r=req(f,'poll-'+covered);
        const first=call(f,r),a=first.approval;
        assert.equal(a?.error,'approval_required');
        assert.equal(typeof a.pending_expires,'number',`covered=${covered}: pending_expires is present`);
        assert.equal(typeof a.poll_interval,'number',`covered=${covered}: poll_interval is present`);
        assert(a.poll_interval<a.max_lifetime,`covered=${covered}: poll_interval ${a.poll_interval} is shorter than max_lifetime ${a.max_lifetime}`);
        const token=a.approval_url.split('/').at(-1);
        const expected=covered?f.pending.contextOf(token).expires:f.pending.get(token).expires;
        assert.equal(a.pending_expires,expected,`covered=${covered}: the expiry is the record's or the context's`);
        const b=browser(f);await b.login();await b.show(token);
        assert.equal((await b.decide(token,'approve')).status,200);
        // Poll at the advertised interval: the identical request runs the write once.
        f.time(f.now()+a.poll_interval);
        assert(call(f,r).ok,`covered=${covered}: the polled request runs`);
        assert.equal(f.count(),1,`covered=${covered}: exactly one write`);
        assert.equal(call(f,r).ok,true,`covered=${covered}: the repeat is a result`);
        assert.equal(f.count(),1,`covered=${covered}: no second write`);
      }
    },
  ];
  const names=['Defaults','Hard limits','Invariants at the limits','Scope','Tightening and loosening','Configuration change voids a match','Setting changes are audited','Deployment record and `config_hash`','Notification for a longer pending lifetime','Poll and expiry members'];
  return {tests,names};
}
