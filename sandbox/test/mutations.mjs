import { spawnSync } from 'node:child_process';
import { writeFileSync } from 'node:fs';
const mutations=['skip-hash-compare','skip-audience','skip-expiry','skip-signature','accept-alg-none','skip-single-use','skip-issuer-scope','skip-approver-type','skip-grant-limit','approval-field-authorizes','principal-not-in-hash','accept-connection-accept','skip-precondition-refill','requery-at-execution','ignore-decline','decline-erases-denial','veto-creates-pending','cap-counts-pending-only','cancel-not-sticky','cap-refuses-as-required','grant-ignores-field-cover','grant-ignores-selector','grant-ignores-limit','grant-ignores-revocation','grant-ignores-expiry','grant-from-connection','grant-skips-permission','page-no-csrf','page-decision-without-display','page-session-from-url','grant-ignores-record-set','grant-any-record-without-config','grant-skips-authority-at-use','grant-double-execution','decision-replay-creates-second','page-renders-markup','page-view-without-permission','signin-keeps-session','signin-open-return','any-record-no-warning','grant-on-undefined-property','no-grant-reason','grants-list-revoke-on-inactive','page-error-bare-response','invalid-input-no-reason','inactive-grant-shows-remaining','elicitation-drops-reason','decided-link-shows-form','error-page-hides-decision','unknown-link-says-expired','message-names-member','grant-outcome-stale'];
function run(mutation='') {
  const r=spawnSync(process.execPath,['test/run.mjs'],{env:{...process.env,VA_MUTATE:mutation,VA_REPORT:'0',VA_DEBUG:''},encoding:'utf8',maxBuffer:8*1024*1024,timeout:60000});
  const failures=[...r.stdout.matchAll(/^\| (\d+) \|[^\n]*\| FAIL \|/gm)].map(m=>Number(m[1]));
  if (r.error || r.signal || !r.stdout.includes('SUMMARY:')) throw Error(`Suite did not complete (${mutation}): ${r.error ?? r.signal ?? r.stderr}`);
  const nonpasses=[...r.stdout.matchAll(/^\| (\d+) \|[^\n]*\| (?:FAIL|NOT AUTOMATED) \|/gm)].map(m=>Number(m[1]));
  return {failures,nonpasses,summary:r.stdout.match(/SUMMARY:.*/)[0],exit:r.status};
}
const baseline=run();console.log('BASELINE '+baseline.summary);
const rows=[];
for(const name of mutations) {
  const r=run(name),newFailures=r.failures.filter(n=>!baseline.nonpasses.includes(n));
  rows.push({name,...r,newFailures});console.log(`${name}: ${newFailures.length ? 'KILLED' : 'SURVIVED (HOLE)'}; failed tests: ${r.failures.join(', ') || 'none'}`);
}
const survivors=rows.filter(r=>!r.newFailures.length).map(r=>r.name);
const summary=`MUTATIONS SUMMARY: total=${rows.length} killed=${rows.length-survivors.length} surviving=${survivors.length}`;
const text=[`Surviving mutations (holes): ${survivors.join(', ') || 'none'}`,'',`Baseline: ${baseline.summary}`,'','| Mutation | Result | Failed tests | Credited tests |','|---|---|---|---|',...rows.map(r=>`| ${r.name} | ${r.newFailures.length?'KILLED':'SURVIVED'} | ${r.failures.join(', ') || 'none'} | ${r.newFailures.join(', ') || 'none'} |`),'',summary,'','Only baseline PASS tests can receive mutation kill credit. NOT AUTOMATED cases never count as kills.',''].join('\n');
writeFileSync('MUTATIONS.md',text);console.log(summary);console.log('SURVIVING MUTATIONS: '+(survivors.join(', ')||'none'));
if(survivors.length || baseline.failures.length)process.exitCode=1;
