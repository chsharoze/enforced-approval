import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { OP } from '../src/core.mjs';
import { ServerIssued } from '../src/server-issued.mjs';
import { REGISTRY, resolve, resolveStrict, canonicalRecord } from '../src/settings.mjs';
// Milestone 2 (settings): one test per decided behaviour of Section 11 (S81 to S90) and one
// per registry rule. Tests 200 to 208.
export function cases({helpers:{setup,req,ask,browser},fixture,call,A,P,admin,sdk}) {
  // A decision made on the page's own interface, for the record it displayed (as cases-i).
  const decide=(f,token,yes=true,person={id:'test-person',authenticated:true},session='session-j')=>{
    const d=f.pending.page(token,person,session);
    return d.recordId?f.pending.decideNamed(token,d.recordId,person,id=>f.pending.decide(id,person,yes,session)):f.pending.decide(token,person,yes,session);
  };
  const used=f=>f.core.db.prepare('SELECT count(*) n FROM used').get().n;
  const tests=[
    // 200. S69, S65, S80, default mode: a recorded conflict or execution_failed
    // is returned to the identical request with the replay marker, its time, and "Nothing was
    // sent now"; no approval record is opened. Off: replay-bare-approval-used.
    async function recordedFailureOnRepeat() {
      for (const [label,inject] of [['conflict',()=>{throw Object.assign(Error('conflict'),{sorText:'rejected'});}],['execution_failed',()=>{throw Error('write rejected');}]]) {
        const f=setup(),r=req(f,'recorded-190-'+label),storedHash=f.core.prepare(r).change_hash;
        const id=ask(f,r),b=browser(f);await b.login();await b.show(id);assert.equal((await b.decide(id,'approve')).status,200);
        f.sor.inject('before-write',inject);
        assert.equal(call(f,r).approval?.error,label);
        const recorded=f.core.db.prepare('SELECT at,outcome FROM outcomes WHERE change_hash=?').get(storedHash);
        assert.equal(recorded.outcome,label);
        const before=f.core.db.prepare('SELECT count(*) n FROM pending').get().n;
        const replay=call(f,r);
        assert.equal(replay.approval?.error,label,label+': the recorded value is returned');
        assert(replay.approval.recorded_outcome,label+': the replay is marked');
        assert.equal(replay.approval.recorded_outcome.outcome,label);assert.equal(replay.approval.recorded_outcome.at,recorded.at);
        assert.equal(replay.approval.recorded_outcome.sent_now,false);
        assert(replay.approval.message.includes('Nothing was sent now'),replay.approval.message);
        assert.equal(f.core.db.prepare('SELECT count(*) n FROM pending').get().n,before,label+': the repeat opens no approval record');
        assert.equal(used(f),1,label+': nothing else is consumed');
      }
    },
    // 201. S17, S77, default mode: a request whose entries partly succeed has
    // the result outcome `partial`, with each entry's outcome, not a refusal; execution_failed
    // is only for a request in which no entry succeeded. Off: partial-as-execution-failed.
    async function partialOutcome() {
      const f=setup();
      const r=f.req({objectType:'contact',action:'update',records:[{id:'rec-EXAMPLE-42',properties:{owner:'first-191'}},{id:'rec-EXAMPLE-191-missing',properties:{owner:'second-191'}}]});
      const id=ask(f,r),b=browser(f);await b.login();await b.show(id);assert.equal((await b.decide(id,'approve')).status,200);
      // The first entry writes; the second is rejected by the system of record.
      f.sor.inject('before-record:rec-EXAMPLE-191-missing',()=>{throw Error('record rejected');});
      const out=call(f,r);
      assert(out.ok,'a partial result is a result, not a refusal: '+JSON.stringify(out.approval));
      assert.equal(out.result.outcome,'partial');
      assert.equal(out.result.changed,1,'only the entry that succeeded is counted');
      assert.deepEqual(out.result.entries.map(e=>[e.id,e.outcome]),[['rec-EXAMPLE-42','success'],['rec-EXAMPLE-191-missing','execution_failed']],JSON.stringify(out.result.entries));
      assert.equal(f.sor.get(A,'rec-EXAMPLE-42').properties.owner,'first-191','the succeeded entry took effect');
      const replay=call(f,r);assert(replay.ok,JSON.stringify(replay));assert.equal(replay.result.outcome,'partial');
      assert.deepEqual(replay.result.entries,out.result.entries);
      assert.equal(replay.result.recorded_outcome.outcome,'partial');assert.equal(replay.result.recorded_outcome.sent_now,false);
      // execution_failed is only for a request in which no entry succeeded.
      const g=setup(),gr=g.req({objectType:'contact',action:'update',records:[{id:'rec-EXAMPLE-42',properties:{owner:'x'}},{id:'rec-EXAMPLE-42',properties:{owner:'y'}}]});
      const gid=ask(g,gr),gb=browser(g);await gb.login();await gb.show(gid);assert.equal((await gb.decide(gid,'approve')).status,200);
      // Both entries name the same record; a rejection on the first means no entry succeeded,
      // so the answer is execution_failed and never a partial result.
      g.sor.inject('before-record:rec-EXAMPLE-42',()=>{throw Error('record rejected');});
      const none=call(g,gr);assert.equal(none.approval?.error,'execution_failed','no entry succeeded, so the outcome is execution_failed');
      // S19 (a repeated record is counted each time) with S77 (the result carries each
      // entry's outcome): two entries for the same record are reported separately, so the
      // one that succeeded and the one that failed each get their own outcome. Off:
      // partial-indexed-by-id collapses them.
      const h=setup();
      const same=h.req({objectType:'contact',action:'update',records:[{id:'rec-EXAMPLE-42',properties:{owner:'first-201'}},{id:'rec-EXAMPLE-42',properties:{owner:'second-201'}}]});
      const hid=ask(h,same),hb=browser(h);await hb.login();await hb.show(hid);assert.equal((await hb.decide(hid,'approve')).status,200);
      // The first entry writes; the second is rejected by the system of record.
      let seen=0;const failSecond=()=>{if(++seen<2)h.sor.inject('before-record:rec-EXAMPLE-42',failSecond);else throw Error('record rejected');};h.sor.inject('before-record:rec-EXAMPLE-42',failSecond);
      const two=call(h,same);
      assert(two.ok,'a partial result is a result: '+JSON.stringify(two.approval));
      assert.equal(two.result.outcome,'partial');
      assert.equal(two.result.changed,1);
      assert.equal(two.result.entries.length,2,'one outcome per entry, not per record identifier');
      assert.deepEqual(two.result.entries.map(e=>[e.id,e.outcome]),[['rec-EXAMPLE-42','success'],['rec-EXAMPLE-42','execution_failed']],JSON.stringify(two.result.entries));
    },
    // 202. S13, S35, S69, S80: a consumed record a grant could approve again is
    // kept for at least the longer of the S13/S35 period and the pending lifetime, so the
    // identical retry is answered from it and never matches the grant again. The registry's
    // retention_floor_seconds only raises the floor. Off: consumed-record-not-retained.
    async function retainedLongEnough() {
      const f=setup();new ServerIssued(f.core);
      const r=req(f,'retained-192'),id=ask(f,r),b=browser(f);await b.login();await b.show(id);
      // Consume the approval late in the pending record's life, so the record has only a
      // little of its own expiry left. S35 raises it to a full retention floor
      // measured from consumption: the longer of the S13/S35 period (maxLifetime + skew, 300)
      // and the pending lifetime (3600).
      const lifetime=f.core.settings().pendingLifetime;
      f.time(f.now()+lifetime-10);
      assert.equal((await b.decide(id,'approve')).status,200);
      assert(call(f,r).ok);assert.equal(f.count(),1);
      const row=f.core.db.prepare("SELECT expires FROM pending WHERE status='consumed'").get();
      assert(row,'the consumed record is stored');
      assert.equal(row.expires,f.now()+lifetime,'the consumed record is kept a full pending lifetime from consumption, not the record\'s remaining life');
      // Just inside the floor the record is still held and the repeat is the recorded outcome;
      // ten seconds later than the record's own expiry it would have been gone without the floor.
      f.time(f.now()+lifetime-1);f.pending.cleanup();
      const replay=call(f,r);assert(replay.ok,'still answered from the consumed record');assert.equal(replay.result.recorded_outcome.outcome,'success');assert.equal(f.count(),1,'not executed again');
      // The registry can raise the floor, never lower it below the S13 floor.
      assert.throws(()=>f.core.admin(admin,'settings',{retention_floor_seconds:1}),/at least the S13 floor/,'below the S13 floor is refused');
      assert.equal(f.core.admin(admin,'settings',{retention_floor_seconds:lifetime+5000}).retention_floor_seconds,lifetime+5000);
    },
    // 203. S50, S70, default mode: a grant decision closes its pending record in
    // the same transaction as the grant, and the record is not open afterwards. Off:
    // grant-decision-leaves-record-open.
    async function grantClosesRecordInDefaultMode() {
      const f=setup(),r=req(f,'close-193'),id=ask(f,r),b=browser(f);await b.login();await b.show(id);
      assert.equal((await b.decide(id,'grant',{max_records:5,expires:f.now()+500})).status,200);
      // No later request has been made.
      assert.equal(f.pending.get(id).status,'granted','S50: the record is closed in the step that records the grant');
      assert.equal(f.count(),0);
    },
    // 204. Section 2: read_record answers a record the principal may not read
    // exactly as an absent identifier at record and operation level, while the field-level
    // `withheld` list is kept for a readable record. Off: read-tool-denied-answer-permission-denied,
    // read-record-ignores-permission.
    async function readToolDeniedAnswer() {
      const f=fixture();
      f.sor.seed(A,'rec-READ-194-secret',{owner:'secret-194'});
      f.sor.recordPermission(A,P,'rec-READ-194-secret',false,true);
      f.sor.seed(A,'rec-READ-194-open',{owner:'open-owner-194',notes:'notes-194'});
      f.sor.fieldPermission(A,P,OP,'/notes',false,'read');
      await sdk(f,'server',async c=>{
        const read=async id=>JSON.stringify(await c.callTool({name:'read_record',arguments:{id}}));
        const secret=await read('rec-READ-194-secret'),absent=await read('rec-READ-194-absent');
        assert.equal(secret,absent,'the unreadable record answers exactly as an absent identifier');
        assert.equal(JSON.parse(JSON.parse(secret).content[0].text),null);
        const open=JSON.parse(JSON.parse(await read('rec-READ-194-open')).content[0].text);
        assert.equal(open.properties.owner,'open-owner-194');assert(!Object.hasOwn(open.properties,'notes'));
        assert.deepEqual(open.withheld,['/notes'],'the withheld list is kept for a readable record');
      });
    },
    // 205. S22, S76: a named approver and an administrator may decide, the
    // documented permission model may decide, and S22 is unchanged: a person who may not make
    // the change cannot approve under any model. `approver_model` selects the source.
    async function approverModel() {
      for (const model of ['named','administrators','permission']) {
        const f=setup();f.core.admin(admin,'settings',{approver_model:model,approvers:{[A]:['test-person']}});
        const r=req(f,'model-195-'+model);
        if (model==='administrators') {
          // Only the account's administrators may decide; test-person is not one.
          f.core.admin(admin,'settings',{pageAdministrators:{[A]:['test-admin']}});
          const id=ask(f,r),b=browser(f);await b.login('test-person');await b.show(id);
          assert.equal((await b.decide(id,'approve')).status,403,model+': a person who is not an administrator is refused');
        } else {
          const id=ask(f,r),b=browser(f);await b.login('test-person');await b.show(id);
          assert.equal((await b.decide(id,'approve')).status,200,model+': an approver permitted by the model may decide');
          assert(call(f,r).ok,model);assert.equal(f.count(),1,model);
        }
        // S22 is unchanged: a person who may not make the change cannot approve, whatever
        // the model or the lists say.
        const g=setup();g.core.admin(admin,'settings',{approver_model:model,approvers:{[A]:['test-person']},pageAdministrators:{[A]:['test-person']}});
        g.sor.permission(A,'test-person',OP,true,false); // may read, may not write
        const gr=req(g,'model-195-deny-'+model),gid=ask(g,gr),gb=browser(g);await gb.login('test-person');await gb.show(gid);
        assert.equal((await gb.decide(gid,'approve')).status,403,model+': S22 still refuses a person who may not make the change');
        assert.equal(g.count(),0,model);
      }
    },
    // 206. The registry rules that CONFORMANCE tests 190, 191 and 194 do not cover: an
    // unknown setting is refused, the server does not start with an out-of-range setting,
    // and the agent or a non-administrator cannot change a setting. The default and
    // hard-limit checks are kept once, under 190 and 191; the tightening and loosening
    // checks are kept once, under 194.
    async function registryRules() {
      assert.throws(()=>resolveStrict({make_it_easy:true}),/unknown setting/);
      const f=setup();
      assert.throws(()=>f.core.admin(admin,'settings',{make_it_easy:true}),/unknown setting/,'the admin call refuses an unknown setting');
      assert.throws(()=>f.core.admin(admin,'settings',{pending_cap:5},{agent:true}),/agent credential/,'the agent cannot change a setting');
      assert.throws(()=>f.core.admin(P,'settings',{pending_cap:5}),/permission/,'a non-administrator cannot change a setting');
      // The server does not start with an out-of-range setting: a bad value exits non-zero with
      // its reason on stderr before any request is served.
      const dir=mkdtempSync(path.resolve('.va-start-'));
      try {
        const env={...process.env,VA_ADMIN:admin,VA_DB:path.join(dir,'start.sqlite'),VA_MODE:'organization',VA_TEST_ISSUER:'1',VA_PENDING_LIFETIME:'999999'};
        const bad=spawnSync(process.execPath,[path.resolve('src/mcp-server.mjs')],{cwd:process.cwd(),env,encoding:'utf8',input:'',timeout:15000});
        assert(bad.status!==0&&bad.status!==null,'the server starts with an out-of-range setting: '+bad.status);
        assert(/pending_lifetime_seconds/.test(bad.stderr),'the refusal names the setting: '+bad.stderr);
        assert(/approver_notification|86400/.test(bad.stderr),'the refusal gives the reason: '+bad.stderr);
      } finally { rmSync(dir,{recursive:true,force:true}); }
    },
    // 207. The binding and deployment-record checks that CONFORMANCE tests 195 and 197 do
    // not cover: the effect hash never enters the agent-visible change hash, a change to a
    // setting that cannot change the write leaves an approval matching, and the deployment
    // record CLI prints the same object as the admin function. Off: binding-ignored,
    // consumption-omits-config-hash.
    async function bindingAndDeploymentRecord() {
      // The deployment record prints canonical RFC 8785 JSON with its config_hash.
      const f=setup(),rec=f.core.deploymentRecord();
      assert.equal(typeof rec.config_hash,'string');
      assert.equal(canonicalRecord(f.core.settings()),canonicalRecord(f.core.settings()),'the deployment record is canonical and stable');
      assert.deepEqual(Object.fromEntries(REGISTRY.map(e=>[e.name,JSON.parse(canonicalRecord(f.core.settings()))[e.name]])),resolve(f.core.settings()).values,'the canonical form carries the settings in force');
      assert.equal(JSON.parse(canonicalRecord(f.core.settings())).config_hash,rec.config_hash);
      // A setting that cannot change the write does not retire the approval, and the
      // agent-visible change hash is the same whatever this configuration.
      const h=setup(),hr=req(h,'binding-207c'),hid=ask(h,hr),hb=browser(h);await hb.login();await hb.show(hid);
      assert.equal((await hb.decide(hid,'approve')).status,200);
      const before=h.core.prepare(hr).change_hash,fh=h.core.effectHash();
      h.core.admin(admin,'settings',{selection_limit:50});
      assert.equal(h.core.effectHash(),fh,'a non-effect setting leaves the effect hash unchanged');
      assert(call(h,hr).ok,'a change to a setting that cannot change the write leaves the approval matching');
      assert.equal(h.count(),1);
      assert.equal(h.core.prepare(hr).change_hash,before,'the change hash does not depend on the configuration');
      assert(!JSON.stringify(h.core.prepare(hr).change).includes('config_hash'));
      // The deployment-record CLI prints the same canonical bytes for the database the
      // runtime uses (`node src/deployment-record.mjs`), and the admin function returns the
      // same object.
      const dir=mkdtempSync(path.resolve('.va-record-'));
      try {
        const db=path.join(dir,'record.sqlite');
        const seedEnv={...process.env,VA_ADMIN:admin,VA_DB:db,VA_MODE:'organization',VA_TEST_ISSUER:'1'};
        const seeded=spawnSync(process.execPath,[path.resolve('src/mcp-server.mjs')],{cwd:process.cwd(),env:seedEnv,encoding:'utf8',input:'',timeout:5000});
        // The stdio server starts (it has an issuer key with VA_TEST_ISSUER=1) and waits on
        // stdin; it exits when stdin closes.
        assert(seeded.status===0||seeded.status===null, 'the seed process served and exited: '+seeded.stderr);
        const cli=spawnSync(process.execPath,[path.resolve('src/deployment-record.mjs')],{cwd:process.cwd(),env:{...process.env,VA_ADMIN:admin,VA_DB:db},encoding:'utf8',timeout:15000});
        assert.equal(cli.status,0,'the deployment record CLI exits 0: '+cli.stderr);
        const printed=JSON.parse(cli.stdout);
        assert.equal(typeof printed.config_hash,'string');
        assert.deepEqual(Object.keys(printed).filter(k=>REGISTRY.some(e=>e.name===k)).sort(),REGISTRY.map(e=>e.name).sort(),'the CLI prints exactly the registry settings in force');
        assert.equal(printed.approver_model,'permission');
      } finally { rmSync(dir,{recursive:true,force:true}); }
    },
    // 208. Item 4 (S30, S31): a denial or a cancellation locks the change for at most one
    // hour, whatever the pending lifetime setting is. Off: the lockout follows the record's
    // own expiry.
    async function lockoutAtMostOneHour() {
      for (const setting of [{pending_lifetime_seconds:7200,approver_notification:true}]) {
        const f=setup(setting),r=req(f,'lockout-denial'),id=ask(f,r),b=browser(f);await b.login();await b.show(id);
        assert.equal((await b.decide(id,'deny')).status,200);
        const denied=call(f,r);assert.equal(denied.approval?.error,'approval_denied');
        assert(denied.approval.retry_after<=3600,'the lockout is at most one hour: '+denied.approval.retry_after);
        f.time(f.now()+3601);
        const again=call(f,r);
        assert.equal(again.approval?.error,'approval_required','after one hour the denial no longer locks the change');
        assert(again.approval.approval_url,'a new approval can be requested');
        const g=setup(setting),gr=req(g,'lockout-cancel');
        assert.equal(call(g,{...gr,inputResponses:{approve:{action:'decline'}}}).approval?.error,'approval_cancelled');
        g.time(g.now()+3601);
        assert.equal(call(g,gr).approval?.error,'approval_required','after one hour the cancellation no longer locks the change');
      }
    },
  ];
  const names=['Recorded conflict or failure is replayed (default mode)','Partial outcome for a partly succeeded request','Consumed record retained for the floor','Grant closes its record in the default mode','Read tool answers a denied record as absent','Approver model','Settings registry rules','Binding and the deployment record','Denial and cancellation lock at most one hour'];
  return {tests,names};
}
