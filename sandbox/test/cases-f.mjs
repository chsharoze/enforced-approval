import assert from 'node:assert/strict';
import { readableTime } from '../src/presentation.mjs';
// Test 96 of spec/CONFORMANCE.md.
export function cases({helpers:{setup,req,ask,browser,grant},call,A}) {
  const tests=[
    // 96. Outcome pages stay true (S50): the page describes the state when viewed.
    async function outcomePagesStayTrue() {
      // A grant made from a change: before any use, and after the change ran under it.
      const f=setup(),{id:gId,b}=await grant(f,req(f,'grant-outcome'));
      const before=await b.show(gId);
      assert(before.body.includes('A standing grant was made from this change on'),'the grant outcome sentence');
      assert(before.body.includes('It has not been used yet.'),'before any use it says so');
      assert(!before.body.includes('This change ran under that grant'),'the change has not run yet');
      assert(!before.body.includes('The grant did not approve this change'),'the old sentence is gone');
      f.time(f.now()+60); // the change runs a minute after the grant was made
      assert(call(f,req(f,'grant-outcome')).ok);
      const after=await b.show(gId);
      assert(after.body.includes('This change ran under that grant on'),'after use it says the change ran under the grant');
      assert(after.body.includes(readableTime(f.now())),'and when, in the single page time form');
      assert(!after.body.includes('It has not been used yet.'),'no stale unused sentence after use');
      assert(!after.body.includes('The grant did not approve this change'));
      // An approval: the use window while unused, the moment of use afterwards.
      const a=setup(),aId=ask(a,req(a,'approval-outcome')),ab=browser(a);
      await ab.login();await ab.show(aId);
      assert.equal((await ab.decide(aId,'approve')).status,200);
      const unused=await ab.show(aId);
      assert(unused.body.includes('It can be used until'),'the use window while unused');
      assert(!unused.body.includes('already been used'),'not yet used');
      a.time(a.now()+60);
      assert(call(a,req(a,'approval-outcome')).ok);
      const used=await ab.show(aId);
      assert(used.body.includes('already been used'),'says the approval was used');
      assert(used.body.includes(readableTime(a.now())),'and when it was used');
      assert(!used.body.includes('It can be used until'),'no stale window after use');
    },
  ];
  return {tests,names:['Outcome pages stay true']};
}
