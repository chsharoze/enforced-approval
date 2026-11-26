// The deployment record: the settings in force and the deployment's configuration, as the
// canonical RFC 8785 JSON that the audit chain hashes, with its SHA-256 `config_hash`
// (S87: "values, guarded list, ... deviations from default ... It is
// hashed into the audit chain").
//
// Run it as `node src/deployment-record.mjs`. It reads the deployment's database, so it
// prints the values a running server uses, not this file's defaults. The output is one
// JSON object on stdout, canonical, so two deployments with the same configuration print
// the same bytes. The hash is the `config_hash` every consumption audit record carries.
import { pathToFileURL } from 'node:url';
import { resolve } from 'node:path';
import { existsSync } from 'node:fs';
import { Sor } from './sor.mjs';
import { Core } from './core.mjs';
import { canonicalRecord, deploymentRecord } from './settings.mjs';

// The record for the database the runtime would use. Reading the store is the only way to
// see the values in force; the registry's defaults are what a missing value means.
export function printRecord({ db = process.env.VA_DB ?? 'sandbox.sqlite', admin = process.env.VA_ADMIN } = {}) {
  const file = resolve(db);
  if (!existsSync(file)) throw Error(`no database at ${file}; start the server first, or set VA_DB`);
  const sor = new Sor(file);
  try {
    const core = new Core(sor, { adminCredential: admin ?? 'deployment-record' });
    const settings = core.settings();
    return { canonical: canonicalRecord(settings), record: deploymentRecord(settings) };
  } finally { sor.close(); }
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try { process.stdout.write(printRecord().canonical + '\n'); }
  catch (e) { console.error(e.message); process.exit(1); }
}
