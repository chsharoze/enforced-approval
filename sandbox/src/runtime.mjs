import { existsSync } from 'node:fs';
import path from 'node:path';
import { Sor } from './sor.mjs';
import { Core, OP, QUERY, CREATE, ISSUER } from './core.mjs';
import { jwk } from './receipt.mjs';
import { ServerIssued } from './server-issued.mjs';
export function runtime() {
  const root=process.cwd(), file=path.resolve(process.env.VA_DB ?? 'sandbox.sqlite');
  if (!file.startsWith(root+path.sep)) throw Error('database must be inside this directory');
  const adminCredential=process.env.VA_ADMIN; if (!adminCredential) throw Error('set VA_ADMIN to a test administrator credential');
  const fresh=!existsSync(file);
  const sor=new Sor(file), core=new Core(sor,{adminCredential,now:process.env.VA_NOW ? ()=>Number(process.env.VA_NOW) : undefined,settings:{preconditions:process.env.VA_MODE==='server'}});
  const account=process.env.VA_ACCOUNT ?? 'acct-EXAMPLE-0001', principal=process.env.VA_PRINCIPAL ?? 'agent-EXAMPLE-sync';
  if(fresh)core.admin(adminCredential,'settings',{grantConfig:{[account]:{[OP]:{maxRecords:100,maxSeconds:3600,anyRecord:true},[CREATE]:{maxRecords:100,maxSeconds:3600,anyRecord:false}}},pageAdministrators:{[account]:['test-admin']}});
  sor.member(account,'test-admin');
  const operations=[OP,QUERY,CREATE,'mcp:tools/call:delete_records','http:PATCH:/records'];
  for (const operation of operations) { sor.permission(account,principal,operation); sor.permission(account,'test-person',operation);sor.permission(account,'test-person-3',operation); }
  if (!sor.get(account,'rec-EXAMPLE-43'))sor.seed(account,'rec-EXAMPLE-43',{owner:'other-owner'});
  if (!sor.get(account,'rec-EXAMPLE-42')) sor.seed(account,'rec-EXAMPLE-42',{lifecycle_stage:'lead',owner:'user-EXAMPLE-3'});
  if (!core.db.prepare('SELECT 1 FROM issuers WHERE account=? AND issuer=?').get(account,ISSUER)) core.admin(adminCredential,'issuer',{account,issuer:ISSUER,keys:[jwk],operations,types:['person','grant','policy']});
  if (process.env.VA_TEST_FAULT==='crash-after-consume') sor.inject('after-consume',()=>process.exit(77));
  const pending=process.env.VA_MODE==='server' ? new ServerIssued(core,process.env.VA_BASE_URL ?? 'http://127.0.0.1:8787') : undefined;
  return {sor,core,pending,account,principal};
}
