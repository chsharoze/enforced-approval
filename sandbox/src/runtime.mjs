import { existsSync } from 'node:fs';
import path from 'node:path';
import { Sor } from './sor.mjs';
import { Core, OP, QUERY, CREATE, COPY, ISSUER, mutated } from './core.mjs';
import { jwk } from './receipt.mjs';
import { ServerIssued } from './server-issued.mjs';
import { resolveStrict } from './settings.mjs';
// The registry settings an operator sets at start. A value here is validated with the
// registry at start, so a bad value exits non-zero with its reason (S23).
function envSettingOverrides() {
  const out = {};
  const int = (name, key) => { const v = process.env[key]; if (v === undefined || v === '') return; const n = Number(v); out[name] = Number.isSafeInteger(n) ? n : v; };
  int('pending_lifetime_seconds', 'VA_PENDING_LIFETIME');
  int('pending_cap', 'VA_PENDING_CAP');
  int('selection_limit', 'VA_SELECTION_LIMIT');
  int('retention_floor_seconds', 'VA_RETENTION_FLOOR');
  int('max_lifetime_seconds', 'VA_MAX_LIFETIME');
  int('skew_seconds', 'VA_SKEW');
  int('grant_charge_limit', 'VA_GRANT_CHARGE_LIMIT');
  int('grant_seconds_limit', 'VA_GRANT_SECONDS_LIMIT');
  int('key_cache_seconds', 'VA_KEY_CACHE');
  if (process.env.VA_APPROVER_NOTIFICATION !== undefined) out.approver_notification = process.env.VA_APPROVER_NOTIFICATION === '1';
  if (process.env.VA_APPROVER_MODEL !== undefined) out.approver_model = process.env.VA_APPROVER_MODEL;
  if (process.env.VA_PRINCIPAL_MODEL !== undefined) out.principal_model = process.env.VA_PRINCIPAL_MODEL;
  return out;
}
// The organization's issuer public key, in the same JWK form the registry stores. The
// built-in test key is not an operator key and is accepted only with VA_TEST_ISSUER=1.
function operatorIssuerKey() {
  const raw=process.env.VA_ISSUER_PUBLIC_KEY;
  if(raw===undefined||raw==='')return undefined;
  let key; try { key=JSON.parse(raw); } catch { throw Error('VA_ISSUER_PUBLIC_KEY must be a JSON key (JWK)'); }
  if(!key||typeof key!=='object'||Array.isArray(key)||typeof key.kty!=='string'||typeof key.kid!=='string'||!['EdDSA','ES256'].includes(key.alg))
    throw Error('VA_ISSUER_PUBLIC_KEY must be a JWK with kty, kid and alg (EdDSA or ES256)');
  return key;
}
export function runtime() {
  const root=process.cwd(), file=path.resolve(process.env.VA_DB ?? 'sandbox.sqlite');
  if (!file.startsWith(root+path.sep)) throw Error('database must be inside this directory');
  const adminCredential=process.env.VA_ADMIN; if (!adminCredential) throw Error('set VA_ADMIN to a test administrator credential');
  // S23/the registry (src/settings.mjs): the server does not start with an out-of-range or
  // unknown setting. The environment's values are resolved through the registry here, so a
  // bad value exits non-zero with its reason on stderr before any request is served.
  const envSettings=envSettingOverrides();
  try { resolveStrict(envSettings); }
  catch (e) { throw Error(`refusing to start: ${e.message}`); }
  // Signed receipts (organization mode) verify against the operator's issuer key. The
  // built-in test key is a test fixture, so it is accepted only when VA_TEST_ISSUER=1.
  const operatorKey=operatorIssuerKey();
  const acceptTestIssuer=mutated('organization-mode-accepts-test-key')||process.env.VA_TEST_ISSUER==='1';
  if(process.env.VA_MODE!=='server'&&!operatorKey&&!acceptTestIssuer)
    throw Error("organization mode requires the operator's issuer public key in VA_ISSUER_PUBLIC_KEY; set VA_TEST_ISSUER=1 only to use the built-in test issuer key");
  const fresh=!existsSync(file);
  // R2: the preconditions setting is stored in the database when it is created. The
  // operator's setting is authoritative, so a start whose request disagrees with the
  // stored value fails closed rather than silently adopting or overwriting it. The
  // check runs whatever the mode.
  const preconditions=process.env.VA_PRECONDITIONS==='1'||(mutated('default-preconditions-on')&&process.env.VA_MODE==='server');
  const sor=new Sor(file), core=new Core(sor,{adminCredential,now:process.env.VA_NOW ? ()=>Number(process.env.VA_NOW) : undefined,settings:{preconditions,...envSettings}});
  const stored=core.settings().preconditions;
  if (!mutated('stored-preconditions-adopted') && stored!==preconditions) {
    // The first remedy is a new database file. The variable is offered only to someone
    // who intends the experimental covered mode, which is named as such.
    const remedy=mutated('restart-advice-names-variable-first')
      ? `Use a new database file, or set VA_PRECONDITIONS=${stored?'1':'unset'} to match what the database stores.`
      : `Use a new database file. Only someone who intends the experimental covered mode should instead set VA_PRECONDITIONS=${stored?'1':'unset'} to match what the database stores.`;
    throw Error(`the database "${file}" stores preconditions ${stored}, but this start requested preconditions ${preconditions}. ${remedy}`);
  }
  // The sign-in secret belongs on the console of an entry point that serves the approval
  // pages (mcp-http.mjs, http.mjs). The stdio server never prints it: its stderr is read
  // by the MCP client, which would hand the secret to the agent.
  if(mutated('signin-secret-always-printed'))console.error(`Sandbox sign-in secret: ${core.signinSecret}`);
  const account=process.env.VA_ACCOUNT ?? 'acct-EXAMPLE-0001', principal=process.env.VA_PRINCIPAL ?? 'agent-EXAMPLE-sync';
  if(fresh)core.admin(adminCredential,'settings',{grantConfig:{[account]:{[OP]:{maxRecords:100,maxSeconds:3600,anyRecord:true},[CREATE]:{maxRecords:100,maxSeconds:3600,anyRecord:false}}},pageAdministrators:{[account]:['test-admin']}},{initial:true});
  sor.member(account,'test-admin');
  // The default permissions belong to a new database only. Granting them on every start
  // would undo the operator's read, field, record and write-scope settings; an existing
  // database keeps what it stores.
  const operations=[OP,QUERY,CREATE,'mcp:tools/call:delete_records','http:PATCH:/records'];
  if(preconditions)operations.push(COPY);
  if (fresh||mutated('defaults-regranted-on-restart'))
    for (const operation of operations) { sor.permission(account,principal,operation); sor.permission(account,'test-person',operation);sor.permission(account,'test-person-3',operation); }
  if (!sor.get(account,'rec-EXAMPLE-43'))sor.seed(account,'rec-EXAMPLE-43',{owner:'other-owner'});
  if (!sor.get(account,'rec-EXAMPLE-42')) sor.seed(account,'rec-EXAMPLE-42',{lifecycle_stage:'lead',owner:'user-EXAMPLE-3'});
  // The environment decides which issuer keys this start accepts: the operator's key,
  // and the built-in test key only with VA_TEST_ISSUER=1. Writing the row on every start
  // means a test key left by an earlier start cannot outlive the flag.
  const issuerKeys=[...(operatorKey?[operatorKey]:[]),...(acceptTestIssuer?[jwk]:[])];
  if (issuerKeys.length) core.admin(adminCredential,'issuer',{account,issuer:ISSUER,keys:issuerKeys,operations,types:['person','grant','policy']});
  if (process.env.VA_TEST_FAULT==='crash-after-consume') sor.inject('after-consume',()=>process.exit(77));
  const pending=process.env.VA_MODE==='server' ? new ServerIssued(core,process.env.VA_BASE_URL ?? 'http://127.0.0.1:8787') : undefined;
  return {sor,core,pending,account,principal};
}
