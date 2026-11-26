import { formatTime, plural, readableTime, shapeWords, withDuration } from './presentation.mjs';
import { finite } from './server-grants.mjs';
import crypto from 'node:crypto';
import { changeObject, hash, hashTotal, jcs, jcsTotal } from './json.mjs';
import { parseReceipt } from './receipt.mjs';
import { currentAt } from './fields.mjs';
import { authorize, modelKnows, resolveIdentifier } from './authorize.mjs';
import { APPROVAL_FIELDS, INPUT_KINDS, UNSERIALIZABLE, shapeRequest } from './shape.mjs';
import { configHash, deploymentRecord, resolveStrict, settingsView, storedValues, assertKnown, effectHash, toStoredKeys, resolve, REGISTRY, SettingsRefusal, retentionFloorFor } from './settings.mjs';
export { changeObject, hash } from './json.mjs';
export { authorize, resolveIdentifier } from './authorize.mjs';
export { shapeRequest } from './shape.mjs';
export { settingsView, deploymentRecord, canonicalRecord, effectRecord, effectHash, configHash } from './settings.mjs';
export const OP = 'mcp:tools/call:manage_records';
export const QUERY = 'mcp:tools/call:update_by_query';
// Plain-word guidance in server-issued refusals (spec 6.2, S59). Nothing is carried by the
// client and no message names a protocol member. Durations are for people only:
// plain words plus the absolute moment, never a raw second count.
const MESSAGES = {
  approval_required: () => mutated('message-names-member')
    ? 'This change needs approval. A person approves or denies it on the approval page at approval_url. Nothing needs to be copied or pasted back. After the decision, send the same request again.'
    : "This change needs a person's approval. Open the approval page, review the change, and approve or deny it there. Nothing needs to be copied or pasted back. Then continue here.",
  approval_denied: (d,now) => `A person denied this change on the approval page. It will not run. It cannot be asked for again for ${withDuration(d.retry_after ?? 0,now)}, and no approval prompt will appear before then. Do not ask again unless the person asks.`,
  approval_cancelled: (d,now) => `The request was declined in the client, so the change did not run and its approval was cancelled. ${d.retry_after ? `No approval prompt will appear for this change for ${withDuration(d.retry_after,now)}.` : 'It can be asked for again.'}`,
  approval_limit_reached: (d,now) => `No approval can be requested now: ${d.open} of ${plural(d.limit,'approval request')} are open or were recently declined or denied, and those count until they expire. Nothing is pending for this change. Try again in ${withDuration(d.retry_after,now)}.`,
  // S64/S65: after consumption the approval stays used. Neither message names a
  // record-state reason, so it is safe for a principal that may not read (S77).
  conflict: () => 'The approved change was not made because it no longer fits the records now. The approval has been used and will not run again. If the change is still wanted, ask for it again as a new change, which needs a new approval.',
  execution_failed: () => 'The approved change could not be carried out. The approval has been used and will not run again. If the change is still wanted, ask for it again as a new change, which needs a new approval.',
};
// S80: every replayed answer identifies itself as the recorded outcome of an earlier
// attempt, with the time recorded for it, and says that nothing was sent now.
export const recordedSentence = at => `This is the recorded outcome of an earlier attempt, made at ${readableTime(at)}. Nothing was sent now.`;
// S77: an identifier the system of record returns is checked against this documented
// format before it is returned or placed in a message; a non-conforming identifier is
// withheld and the result says so. The format is the one the system of record's own
// identifiers satisfy (its identifier rules: 64 characters or fewer from the URL-safe set).
export const ID_FORMAT = /^[A-Za-z0-9_-]{1,64}$/;
export const CREATE = 'mcp:tools/call:create_record';
export const COPY = 'mcp:tools/call:copy_record_owner';
// S60(c)/S65: the kind of write is derived from the operation in one place, used by
// step 1, prepare, presentation and execution. The tools that name a kind of write
// declare it in their operation; the generic HTTP mapping, which has no tool schema,
// takes the action its body declares; anything else is an update.
export function actionFor(operation, args = {}) {
  if (operation === CREATE || /:create_record$/.test(operation ?? '')) return 'create';
  if (args.action === 'create') return 'create';
  if (/delete_records$/.test(operation ?? '')) return 'delete';
  if (args.action === 'delete') return 'delete';
  return 'update';
}
export const ISSUER = 'https://approvals.org.example';
// The values the registry defaults to where the sandbox needs a starting store. The
// registry (src/settings.mjs) is the source of truth for the settings it lists; these are
// the rest of the sandbox's configuration and are not in its first release.
export const DEFAULT = { audience: 'https://mcp.crm.example/mcp', maxLifetime: 300, skew: 0, selectionLimit: 100, preconditions: false, approverTypes: ['person','grant','policy'], pendingLifetime: 3600, pendingCap: 10, keyCacheSeconds: 3600, removalSeconds: 3600, grantConfig: {}, pageAdministrators: {}, approvers: {}, approverModel: 'permission', approverNotification: false, retentionFloor: null, readToolDeniedAnswer: 'absent', principal_model: 'dedicated' };
export const mutated = name => process.env.VA_MUTATE === name;
// S61: the configured state key is 256 bits, written as at least 64 hexadecimal digits.
// The key is used as Buffer.from(key,'hex'), so a string that is not hexadecimal decodes
// to an empty key however many bytes it holds; it is refused here, at start and at the
// administrative surface, rather than accepted by counting its bytes.
export function stateKeyProblem(key) {
  if (typeof key !== 'string' || !/^[0-9a-fA-F]+$/.test(key))
    return 'the configured state key must be hexadecimal digits; S61 requires at least 256 bits from a cryptographic random source';
  const bits = key.length * 4;
  if (bits < 256) return `the configured state key has ${bits} bits; S61 requires at least 256 bits from a cryptographic random source`;
  return undefined;
}
class Refusal extends Error { constructor(code) { super(code); this.code = code; } }
const refuse = code => { throw new Refusal(code); };
const invalidInput = details => Object.assign(new Refusal('invalid_input'), { details });
// Milestone 1, WP3. Every guarded request goes through Core.handle in this order, and
// no other order exists in the sandbox:
//   shape      shapeRequest: one parse, no state, no hash (S3, S4, S65)
//   authorize  step 1 of Section 6 from the permission model alone (operation,
//              membership, field write, a query under a record scope)
//   identity   the request's arguments before any record state: the request key (S67),
//              which for an operation that is not covered is the change hash itself;
//              `covered` comes from S67's definition
//   replay     the recorded outcome of a consumed approval (S69, S80), before any read
//              of record state, the record-scope check and any grant match
//   scope      the one step 1 check S60(c) lets read record state
//   prepare    the reads of record state, preconditions, the query, the copied value
//   approval   the approved record or a matching grant (grants before the pending cap),
//              or the receipt
//   consume    one transaction, which also writes the outcome as unknown
//   execute    the write, at most once
//   outcome    recordOutcome: compare-and-set from unknown, with its audit record
export class Core {
  constructor(sor, { adminCredential, now = () => Math.floor(Date.now()/1000), settings = {} } = {}) {
    if (!adminCredential) throw Error('admin credential required');
    // S23/the registry: an out-of-range or unknown setting is refused at start, so the
    // process does not serve with a configuration it could not validate. A missing value
    // means the registry's default.
    resolveStrict({ ...DEFAULT, ...settings });
    this.sor = sor; this.db = sor.db; this.adminCredential = adminCredential; this.now = now; this.unavailable = {}; this.preconditionCache = new Map();
    // The sandbox's fake sign-in is not an identity provider, so it takes a secret. The
    // server generates one at random unless the operator sets VA_SIGNIN_SECRET; the
    // runtime prints it once on the operator's console and no answer ever carries it.
    this.signinSecret = process.env.VA_SIGNIN_SECRET ?? crypto.randomBytes(16).toString('hex');
    // S80/S69(5): the executions this instance knows to be running. The marker is set
    // inside the consumption transaction, before it commits, so no identical request can
    // see a consumed approval of this instance without it. It is lost with the process;
    // after a restart the durable unknown outcome answers (S69(3)).
    this.inFlight = new Set();
    this.db.exec(`CREATE TABLE IF NOT EXISTS settings(id INTEGER PRIMARY KEY, json TEXT);
      CREATE TABLE IF NOT EXISTS issuers(account TEXT, issuer TEXT, json TEXT, refreshed INTEGER DEFAULT -10000000000, refreshes INTEGER DEFAULT 0, PRIMARY KEY(account,issuer));
      CREATE TABLE IF NOT EXISTS used(issuer TEXT, jti TEXT, expires INTEGER, PRIMARY KEY(issuer,jti));
      CREATE TABLE IF NOT EXISTS grants(account TEXT, issuer TEXT, id TEXT, max_records INTEGER, expires INTEGER, charged INTEGER, PRIMARY KEY(account,issuer,id));
      CREATE TABLE IF NOT EXISTS outcomes(issuer TEXT, jti TEXT, change_hash TEXT, outcome TEXT, at INTEGER, json TEXT, PRIMARY KEY(issuer,jti));
      CREATE INDEX IF NOT EXISTS outcomes_hash ON outcomes(change_hash);
      CREATE TABLE IF NOT EXISTS audit(seq INTEGER PRIMARY KEY AUTOINCREMENT, json TEXT, hash TEXT);`);
    const outCols = this.db.prepare('PRAGMA table_info(outcomes)').all().map(r => r.name);
    if (!outCols.includes('request_key')) this.db.prepare('ALTER TABLE outcomes ADD COLUMN request_key TEXT').run();
    this.db.exec('CREATE INDEX IF NOT EXISTS outcomes_rk ON outcomes(request_key)');
    // Item 10 (E14): a setting given at start on an existing database must agree with the
    // value the database stores. A differing start value is refused with a clear message,
    // never silently ignored (a start cannot quietly adopt a different configuration). A
    // fresh database creates the row from these values, so there is nothing to disagree
    // with. `preconditions` is checked by the runtime with its own message; the constructor
    // leaves it to the runtime.
    const existed = !!this.db.prepare('SELECT 1 FROM settings WHERE id=1').get();
    this.db.prepare('INSERT OR IGNORE INTO settings VALUES(1,?)').run(JSON.stringify({ ...DEFAULT, ...settings }));
    if (existed && !mutated('start-settings-ignored')) this.#refuseStartMismatch(settings);
    // S61: the HMAC key for state_hash and manifest_hash is held only by the server,
    // is never derived from account data, and is shared by every instance through the
    // database. A deployment without one gets a fresh 256-bit random key. A key the
    // deployment configures MUST have at least 256 bits, written as hexadecimal digits
    // (the form Buffer.from(key,'hex') decodes; anything else decodes to an empty key);
    // a shorter or non-hexadecimal key is refused at start, so the server never runs with
    // a weak or empty key (item 1).
    const s0 = this.settings();
    if (s0.stateKey !== undefined && s0.stateKey !== null && !mutated('short-state-key-accepted')) {
      const problem = stateKeyProblem(s0.stateKey);
      if (problem) throw Error(problem);
    }
    if (s0.preconditions && !s0.stateKey) {
      s0.stateKey = crypto.randomBytes(32).toString('hex');
      this.db.prepare('UPDATE settings SET json=? WHERE id=1').run(JSON.stringify(s0));
    }
  }
  // Item 10 (E14): a setting given at start on an existing database must equal the value it
  // stores. The comparison is on resolved values, so the documented name and the storage
  // key are alike. A registry setting that was never stored resolves to its default; a
  // start value equal to that default matches. A differing value stops the server.
  // `preconditions` and `stateKey` are not registry rows and are the runtime's checks.
  #refuseStartMismatch(settings) {
    const stored = this.#storedSettings();
    const before = resolve(stored).values;
    const start = resolve({ ...stored, ...settings }).values;
    for (const e of REGISTRY)
      if (JSON.stringify(before[e.name]) !== JSON.stringify(start[e.name]))
        throw Error(`the database stores ${e.name} = ${JSON.stringify(before[e.name])}, but this start requests ${JSON.stringify(start[e.name])}. Use a new database file, or start with the value the database stores.`);
  }
  // S84: raising the skew never revives an approval that expired under the old value. An
  // approval the server issued records the skew in force when it was made (`skew_at`); it
  // is judged against that value where it was smaller, and against the value now in force
  // where it was larger (a tightening applies at once). A receipt from an organization's
  // issuer carries no such value and is judged against the value in force.
  expirySkew(c) {
    const now=this.settings().skew;
    if (mutated('skew-raise-revives')) return now;
    return Number.isSafeInteger(c?.skew_at) ? Math.min(c.skew_at, now) : now;
  }
  // S61: state_hash and manifest_hash are HMAC-SHA-256 under the server key, over the
  // RFC 8785 form of the objects the text gives, encoded base64url without padding.
  // S65: the state holds values read from the system of record, which need not have an
  // RFC 8785 form; jcsTotal hashes those in its total tagged form rather than letting a
  // record value become invalid_input before approval.
  stateHash(s, change, record, state) {
    const input = { purpose:'enforced-approval/state_hash/2', audience:change.audience, account:change.account, operation:change.operation, record, state };
    if (mutated('state-hash-binds-no-record')) delete input.record;
    if (mutated('record-value-refused')) {
      if (mutated('state-hash-unkeyed')) return hash(input);
      return crypto.createHmac('sha256', Buffer.from(s.stateKey, 'hex')).update(jcs(input)).digest('base64url');
    }
    if (mutated('state-hash-unkeyed')) return hashTotal(input);
    return crypto.createHmac('sha256', Buffer.from(s.stateKey, 'hex')).update(jcsTotal(input)).digest('base64url');
  }
  manifestHash(s, change, records) {
    const input = { purpose:'enforced-approval/manifest_hash/2', audience:change.audience, account:change.account, operation:change.operation, arguments:change.arguments, records:[...records].sort() };
    if (mutated('manifest-hash-binds-no-arguments')) delete input.arguments;
    if (mutated('state-hash-unkeyed')) return hash(input);
    return crypto.createHmac('sha256', Buffer.from(s.stateKey, 'hex')).update(jcs(input)).digest('base64url');
  }
  // The configuration in force. The registry's values are resolved on every read: a
  // missing value is the default and a stored value outside its range is never used, so a
  // change to the store cannot loosen a setting past its ceiling (S23; settings.mjs).
  settings() { return settingsView(this.#storedSettings()); }
  #storedSettings() { try { return JSON.parse(this.db.prepare('SELECT json FROM settings WHERE id=1').get().json); } catch { return { ...DEFAULT }; } }
  // The deployment record's hash and the effect-changing part of the configuration
  // (Section 11.4, S85, S87). Every consumption audit record carries the former;
  // each approval record stores the latter.
  configHash() { return configHash(this.settings()); }
  effectHash() { return effectHash(this.settings()); }
  deploymentRecord() { return deploymentRecord(this.settings()); }
  // S76: whether a person may approve a change. S22 is unchanged in every model — "the
  // approving person MUST hold, in the account, the permission to make the change
  // themselves" — so every branch ends in that same check, asked of the documented
  // permission model (S76). S76 makes "who may approve" and "what a person may change"
  // separate answers, and S22 is the second of them. `approver_model` chooses the source:
  //   permission (default) the documented permission model (S76) alone, which is the system
  //                    of record's answer. It names every approver when it can answer.
  //   named            the account's named approvers, and only them; where the account
  //                    names none the model decides, as before. The list narrows S22: a
  //                    person must be on the list AND pass S22.
  //   administrators  the account's administrators only, where it configures any.
  // No model lets a person who fails S22 approve, and no model can turn the check off
  // (configure who, never whether).
  mayApprove(person, request) {
    if (!person?.authenticated) return false;
    const s = this.settings(), account = request?.account ?? request?.change?.account;
    const operationName = request?.operation ?? request?.change?.operation;
    const admins = Array.isArray(s.pageAdministrators?.[account]) ? s.pageAdministrators[account] : [];
    const named = Array.isArray(s.approvers?.[account]) ? s.approvers[account] : [];
    // S22, from the permission model (S76). It is not a setting, and every branch uses it.
    const s22 = () => authorize(this.sor, person, { account, operation:operationName, change:request?.change, records:request?.records }, 'approve').allowed;
    if (s.approverModel === 'administrators') return (admins.length ? admins.includes(person.id) : true) && s22();
    // S22 with the named list (S76): where the account names approvers, a person must be on
    // the list (whichever model names every approver when the list is empty). Off:
    // named-model-ignores-list.
    if (s.approverModel === 'named' && named.length && !mutated('named-model-ignores-list')) return named.includes(person.id) && s22();
    return s22();
  }
  // S67: the request key of a covered operation, independent of record state: the
  // change object's identity members with arguments as Section 5 defines them before
  // any value derived from record state is copied in.
  requestKey(change) { return hash({ v:change.v, audience:change.audience, account:change.account, principal:change.principal, operation:change.operation, arguments:change.arguments }); }
  // S67: "An operation is covered if it uses `preconditions` or `resolved`, or copies a
  // value derived from record state into `arguments` under S4". Which operations do is
  // configuration: with the preconditions setting every operation that names its records
  // uses `preconditions` and the copy operation copies its source's owner; a query uses
  // `resolved` whatever the setting.
  coveredBy(s, operation) {
    const resolved = operation === QUERY, copied = !!s.preconditions && operation === COPY, preconditions = !!s.preconditions && !resolved;
    return { preconditions, resolved, copied, any: preconditions || resolved || copied };
  }
  // S60(a): whether the principal is established, from the permission model (S76), to
  // read every field and record the answer depends on. Established for each answer, by
  // the same authorize() call that step 1 uses (S60(a)).
  coveredReader(req, p) {
    return authorize(this.sor, { id:req.principal }, { account:req.account, operation:req.operation, change:p.change, records:p.records, copies:p.copies ?? [] }, 'read').allowed;
  }
  admin(credential, action, data, { agent = false, initial = false } = {}) {
    // S23: every setting is changeable only through an administrative surface with
    // administrator authentication, never through a guarded tool or the credential an
    // agent uses. The agent's credential is refused explicitly, with a clear message.
    if (agent) throw Error('permission_denied: settings are changed only with an administrator credential, never an agent credential');
    if (credential !== this.adminCredential) throw Error('permission_denied');
    if (action === 'settings') {
      try {
        // An unknown or out-of-range setting, an empty value or an unlimited value is
        // refused at the admin call with a clear message, and the refusal is recorded
        // (S81). A missing value means the default; a tightening applies at once and a
        // loosening never revives a denied, cancelled or expired request or widens a
        // grant (S84).
        assertKnown(data);
        // Item 10 (E9): `preconditions` decides at database creation whether a change object
        // is built and a state key exists. Changing it on a live database would build cover-
        // ed changes with no key, or stop building them under stored approvals, so it is
        // refused here and changed only with a new database (S23, S61).
        if (!mutated('admin-flips-preconditions') && 'preconditions' in data && !!data.preconditions !== this.#storedSettings().preconditions)
          throw new SettingsRefusal('preconditions: this setting is fixed when the database is created and cannot be changed on a live database; use a new database file');
        // S61: a replacement state key must be 256 bits written as hexadecimal digits, the
        // same rule the constructor applies at start (item 1).
        if ('stateKey' in data && !mutated('short-state-key-accepted')) {
          const problem = stateKeyProblem(data.stateKey);
          if (problem) throw new SettingsRefusal(`stateKey: ${problem}`);
        }
        for (const e of REGISTRY) {
          const value = data[e.name] !== undefined ? data[e.name] : data[e.key];
          if (value === '' || value === null) throw new SettingsRefusal(`${e.name}: an empty value is refused`);
        }
        // The registry's documented names (pending_cap) and the sandbox's storage keys
        // (pendingCap) are both accepted; a value given by its documented name replaces the
        // stored copy of the same setting (toStoredKeys).
        const byKey = toStoredKeys(data);
        const before = this.#storedSettings();
        const oldLifetime = resolve({ ...DEFAULT, ...before }).values.pending_lifetime_seconds;
        const s = { ...before, ...byKey };
        // Loosening the retention floor below the verified floor is refused; raising it is
        // allowed. Raising the maximum lifetime or the skew raises the computed S13 floor:
        // a stored floor below the new computed floor is a lowering and is refused here,
        // never silently raised (S13, S35, S84).
        if (Number.isSafeInteger(s.retentionFloor) && s.retentionFloor < retentionFloorFor(s))
          throw new SettingsRefusal(`retention_floor_seconds: must be at least the S13 floor: ${retentionFloorFor(s)} seconds`);
        if (s.skew < 0 || s.skew > 60 || s.maxLifetime <= 0 || s.keyCacheSeconds > 86400 || s.removalSeconds > 3600) throw new SettingsRefusal('invalid settings');
        for(const ops of Object.values(s.grantConfig??{}))for(const cfg of Object.values(ops))if(!finite(cfg))throw new SettingsRefusal('invalid grant settings');
        const resolved = resolveStrict(s); // the registry's range, type and dependency checks
        const storedJson = { ...s, ...storedValues({ ...DEFAULT, ...s }) };
        // Loosening the retention floor below the verified floor is refused; raising it is
        // always allowed. (The registry check above already enforces the floor.)
        this.db.prepare('UPDATE settings SET json=? WHERE id=1').run(JSON.stringify(storedJson));
        // S84: a tightened pending lifetime takes effect at once. An existing pending record
        // expires at the new limit; a raised one revives nothing and widens no grant.
        const newLifetime = resolved.pending_lifetime_seconds;
        if (newLifetime < oldLifetime && this.pending) this.pending.tightenLifetime(newLifetime);
        // S84: a tightened grant-record or grant-second ceiling is written down on every
        // existing grant in the same step as the setting change, so loosening the ceiling
        // later restores no authority the tightening took away (item 2).
        if (this.pending?.grants) this.pending.grants.tighten(settingsView(before), this.settings());
        // S86: every change an administrator makes goes in the chain with who, when and the
        // old and new values. S87: the new deployment record is recorded in the chain too.
        // A deployment's own initial configuration is set at start by the runtime before any
        // request; it is disclosed by the deployment record, not recorded as a change.
        const changed = Object.keys(byKey).filter(k => JSON.stringify(before[k]) !== JSON.stringify(s[k]));
        const CHANGED_NAMES = {pendingLifetime:'pending_lifetime_seconds',approverNotification:'approver_notification',pendingCap:'pending_cap',selectionLimit:'selection_limit',retentionFloor:'retention_floor_seconds',readToolDeniedAnswer:'read_tool_denied_answer',approverModel:'approver_model'};
        if (changed.length && !initial) {
          if (!mutated('audit-omits-setting-change')) this.audit('settings', { principal: 'administrator', operation: 'admin:settings' },
            { changed: Object.fromEntries(changed.map(k => [CHANGED_NAMES[k] ?? k, { old: before[k] ?? null, new: s[k] ?? null }])), config_hash: this.configHash() }, 'changed');
          if (!mutated('deployment-record-not-audited')) this.audit('deployment', { principal: 'administrator', operation: 'admin:settings' },
            { deployment_record: this.deploymentRecord() }, 'recorded');
        }
        return resolved;
      } catch (e) {
        // S81: the administrative surface records its refusal as well as returning it.
        if (!initial && !mutated('setting-refusal-not-recorded')) { try { this.audit('settings', { principal: 'administrator', operation: 'admin:settings' }, { attempted: data, error: String(e.message) }, 'refused'); } catch {} }
        throw e;
      }
    }
    // The admin function that prints the deployment record (S87), the
    // same object `node src/deployment-record.mjs` writes to stdout.
    if (action === 'deploymentRecord') return this.deploymentRecord();
    if (action === 'removeIssuer') { this.db.prepare('DELETE FROM issuers WHERE account=? AND issuer=?').run(data.account, data.issuer); return; }
    if (action !== 'issuer') throw Error('unknown admin action');
    for (const row of this.db.prepare('SELECT issuer,json FROM issuers WHERE account=? AND issuer<>?').all(data.account,data.issuer)) {
      const existing = JSON.parse(row.json).keys;
      if (data.keys.some(k => existing.some(e => hash({kty:e.kty, ...(e.kty === 'OKP' ? {crv:e.crv,x:e.x} : {crv:e.crv,x:e.x,y:e.y})}) === hash({kty:k.kty, ...(k.kty === 'OKP' ? {crv:k.crv,x:k.x} : {crv:k.crv,x:k.x,y:k.y})})))) throw Error('key already registered');
    }
    this.db.prepare('INSERT INTO issuers(account,issuer,json) VALUES(?,?,?) ON CONFLICT(account,issuer) DO UPDATE SET json=excluded.json').run(data.account,data.issuer,JSON.stringify(data));
  }
  audit(phase, req, detail, outcome) {
    const ownTransaction=!this.db.isTransaction;
    if(ownTransaction)this.db.exec('BEGIN IMMEDIATE');
    try {
      const prev = this.db.prepare('SELECT hash FROM audit ORDER BY seq DESC LIMIT 1').get()?.hash ?? null;
      const record = { record_id: crypto.randomUUID(), timestamp: this.now(), agent_id: req.principal ?? 'unknown', principal: req.principal ?? 'unknown', action_type: req.operation ?? 'unknown', action_detail: detail, outcome, prev_hash: prev, record_phase: phase };
      this.db.prepare('INSERT INTO audit(json,hash) VALUES(?,?)').run(jcs(record), hash(record));
      if(ownTransaction)this.db.exec('COMMIT');return record.record_id;
    }catch(e){if(ownTransaction)this.db.exec('ROLLBACK');throw e;}
  }

  chainCheck() {
    let prev = null;
    for (const row of this.db.prepare('SELECT * FROM audit ORDER BY seq').all()) {
      try { const r = JSON.parse(row.json); if (r.prev_hash !== prev || hash(r) !== row.hash) return { ok:false, seq:row.seq }; prev = row.hash; } catch { return {ok:false,seq:row.seq}; }
    }
    return { ok:true, head:prev };
  }
  records() { return this.db.prepare('SELECT json FROM audit ORDER BY seq').all().map(r => JSON.parse(r.json)); }
  // Builds the change object. With `state:false` it reads no record state: that form
  // exists only for an operation that is not covered, whose change object holds nothing
  // derived from record state, so its change hash is known before any read (identity).
  // prepare never decides a permission; where an answer depends on one it asks authorize().
  prepare(req, { state = true } = {}) {
    const s = this.settings();
    const shaped = shapeRequest(req);
    if (!shaped.ok) throw Object.assign(Error('invalid_input'), { inputMessage:shaped.message });
    const subject = { id:req.principal };
    // S67: "The server MUST NOT replace or close a record on the strength
    // of a read of record state that began before the latest of: the creation of that
    // record, its last rendering for a decision (S68(3)), and the recording of its
    // decision; it reads again." The moment this read began is kept with what it read.
    const readEpoch = state && this.pending ? this.pending.epoch() : 0;
    const change = changeObject({ account:req.account, principal:req.principal, operation:req.operation, args:shaped.args, audience:s.audience, approvalFields:APPROVAL_FIELDS });
    if (mutated('principal-not-in-hash')) change.principal = 'agent-EXAMPLE-sync';
    const a = change.arguments; let entries = a.records ?? []; let copies = []; let referenceResolved = false;
    const action = mutated('write-action-from-arguments') ? (req.operation === CREATE ? 'create' : a.action ?? 'update') : actionFor(req.operation, a);
    const cov = this.coveredBy(s, req.operation);
    if (cov.any && !state) return undefined;
    if (cov.copied) {
      // S67/S4: this operation copies one literal source field, not an arbitrary
      // computed value. Handle has already computed the request key before this read.
      const source = resolveIdentifier(this.sor, req.account, a.source);
      // S78 (cold read, finding 1): "MUST compare, on every read of record state ...
      // the identifier returned with the identifier named". A source whose identifier
      // resolves to another record gives no value of that other record: the change is
      // built as for a source that names no record, so the answer before consumption
      // is the answer for a missing source, and the write is not sent (see handle).
      referenceResolved = source.redirected && !mutated('copy-follows-merged-source');
      const copied_owner = referenceResolved ? null : source.record?.properties.owner ?? null;
      copies = [{ record:a.source, fields:['/owner'] }];
      if (!mutated('copied-record-value-omitted')) a.copied_owner = copied_owner;
      entries = [{ id:a.target, properties:{ owner:copied_owner } }];
    }
    if (action === 'create') entries = a.records ?? [{ id:a.id, properties:a.properties ?? {} }];
    // S48/S65: whether a property is defined is schema for a principal established to see
    // every definition of the object type, and record state for any other principal, whose
    // validation runs after consumption and is answered execution_failed naming nothing.
    const reads = authorize(this.sor, subject, { account:req.account, operation:req.operation, change, records:cov.copied ? [a.target] : undefined, copies }, 'read');
    if (reads.definitions || mutated('restricted-definitions-validated-early')) {
      // S65: "A validation of the request's input whose outcome depends on
      // record state runs before approval only where S60(a) holds; otherwise it runs
      // after consumption." The value a copy takes from its source is record state, so
      // it is validated here only for a principal that may read the source; for any
      // other principal the system of record validates it at the write.
      if (!cov.copied || reads.allowed || mutated('copy-validates-unread-source')) for(const e of entries)this.sor.validateProperties(a.objectType,e.properties??{});
      if(a.set!==undefined)this.sor.validateProperties(a.objectType,a.set);
      if(a.properties!==undefined)this.sor.validateProperties(a.objectType,a.properties);
    }
    let records = cov.copied ? [a.target] : undefined;
    if (req.operation === QUERY) {
      records = this.sor.query(req.account,a.objectType,a.filter);
      if (records.length > s.selectionLimit) refuse('selection_limit');
      // S61: in the covered mode the manifest hash is keyed; the default mode keeps the
      // Draft 0.1 form it had before covered operations were implemented.
      change.resolved = { count:records.length, manifest_hash:s.preconditions ? this.manifestHash(s,change,records) : hash(records) };
      entries = records.map(id => ({id, properties:a.set}));
    }
    const versions = {}; const current = {};
    if (cov.preconditions) {
      // S28/S61/S62/S64: one entry per record the change touches, exactly the members
      // record and state_hash, filled from the record's actual state each time the
      // change object is built. A create whose record exists and an update whose
      // record is gone are not refused here: the absent or actual state is hashed in
      // (S64), and the write itself is made conditional on the version the state was
      // read at, so a change after approval gives a different hash or a failed write.
      change.preconditions = entries.map(e => {
        const found = resolveIdentifier(this.sor, req.account, e.id), old = found.record;
        // S78: an identifier that resolves to another record uses the absent kind, so an
        // approval given before the resolution is stale.
        const gone = !found.present;
        if (!gone) versions[e.id] = old.version;
        let state;
        if (gone) state = {kind:'absent'};
        // S62: "the server MAY use the `version` kind only where the system of record
        // changes the token on every write to that record; otherwise, and where the
        // server cannot establish this, it MUST use the `fields` kind. A token qualifies
        // only if every write to the record changes it to a value it has not had before
        // for that record, by any path". The sandbox's version counter starts again at 1
        // when a record is replaced or created again, so it does not qualify. A delete
        // sets no field, so its `fields` state holds the fields the server documents for
        // it (S61): every field of the record, each with its current value. S60(a) then
        // holds only for a principal that may read the whole record (authorize, `whole`).
        else if (action === 'delete') state = mutated('delete-uses-version-token') ? {kind:'version', value:String(old.version)} : {kind:'fields', value:old.properties};
        // S61/S60(a) (cold read, finding 2): the fields kind holds "the fields the
        // request sets on that record", at leaf level, the level at which the reader
        // decision is made. A sibling leaf under the same top-level property is not
        // hashed, so the hash cannot tell a principal that such a leaf changed.
        else state = {kind:'fields', value:mutated('state-hash-covers-siblings')
          ? Object.fromEntries(Object.keys(e.properties ?? {}).map(k => [k, old.properties[k] ?? null]))
          : currentAt(old.properties, e.properties)};
        current[e.id] = state.kind === 'fields' && action !== 'delete' ? state.value : {};
        const entry = {record:e.id, state_hash:this.stateHash(s,change,e.id,state)};
        if (mutated('precondition-version-member') && !gone) entry.version = old.version;
        return entry;
      });
      if (mutated('skip-precondition-refill')) {
        const key = hash({account:req.account,args:a});
        if (this.preconditionCache.has(key)) change.preconditions = this.preconditionCache.get(key);
        else this.preconditionCache.set(key, change.preconditions);
      }
    }
    // The values the approval page shows beside the change (S71): the record's current
    // value at each leaf the request sets and at nothing else, so a sibling leaf the
    // viewer may not read is never stored or shown (S53); none of another
    // record where the identifier resolves to one (S78).
    if (state) for(const e of entries)if(!current[e.id]){const found=resolveIdentifier(this.sor,req.account,e.id);current[e.id]=currentAt(found.present?found.record.properties:undefined,e.properties??{});}
    // S65: a covered copy copies a value read from the system of record into the change,
    // and that value need not have an RFC 8785 form; the hash is still total (hashTotal).
    return {change, change_hash:mutated('record-value-refused') ? hash(change) : hashTotal(change), entries, action, versions, current, records, copies, referenceResolved, readEpoch};
  }
  refusal(req, error, prepared, claims, details) {
    const s = this.settings(); const approval = {error};
    if (prepared) Object.assign(approval, {change_hash:prepared.change_hash, audience:s.audience, operation:req.operation, approver_types:s.approverTypes, max_lifetime:s.maxLifetime});
    // S63: only an approval_required refusal carries the change object; for an operation
    // that is not covered it is always included.
    if (prepared && (error==='approval_required' || mutated('change-on-every-refusal'))) approval.change = prepared.change;
    if (prepared?.covered) {
      // S67: a covered refusal carries request_key wherever the server computed one.
      approval.request_key = prepared.request_key;
      // S63/S68(1): a principal for which S60(a) does not hold gets no change and no
      // change_hash, before or after consumption; the hash is still recorded below.
      const reader=this.coveredReader(req,prepared);
      if (mutated('covered-reader-omits-change') || (!mutated('covered-refusal-carries-change') && !reader)) { delete approval.change; delete approval.change_hash; }
    }
    if (this.pending && prepared && error==='approval_required') {
      // S68(2): the approval link is taken from the context, not from the record.
      const url = prepared.contextToken && !mutated('context-link-from-record') ? `${this.pending.baseURL}/approve/${prepared.contextToken}` : this.pending.url(prepared.change_hash);
      if (url) approval.approval_url=url;
      // S90: every approval_required refusal carries the pending record's expiry and the
      // interval at which a client sends the identical request again. For a covered
      // operation both come from the context, and the expiry is the context's.
      if (!mutated('approval-required-omits-poll-expiry')) {
        const expiry = prepared.contextToken ? this.pending.contextExpiry(prepared.contextToken) : this.pending.pendingExpiry(prepared.change_hash);
        if (expiry !== undefined) {
          approval.pending_expires = expiry;
          approval.poll_interval = Math.min(30, Math.max(1, s.maxLifetime - 1));
        }
      }
    }
    // S77: text the system of record returned never reaches the answer; sorText stays
    // out of the members, and reaches the message only under its mutation.
    const { sorText, __hash, ...rest } = details ?? {};
    if (details) Object.assign(approval, rest);
    if (this.pending && MESSAGES[error] && !Object.hasOwn(approval,'message')) approval.message = MESSAGES[error](approval, this.now());
    if (mutated('leak-sor-error-text') && sorText) approval.message = (approval.message ?? '') + ' ' + sorText;
    if(this.pending&&prepared&&error==='approval_required'&&!mutated('no-grant-reason')) {
      // S48/S56 (S65): the `grant_status` given to a principal not established to
      // see the definitions of the object type does not depend on which definitions exist.
      const definitions=authorize(this.sor,{id:req.principal},{account:req.account,operation:req.operation,change:prepared.change},'read').definitions;
      const reason=this.pending.grants.explain(prepared.change,prepared.records,{definitions});
      if(reason){approval.grant_status=reason.status;approval.message+=' '+reason.message;}
    }
    if (error === 'approval_required' && !this.pending) approval.issuers = this.db.prepare('SELECT issuer FROM issuers WHERE account=?').all(req.account).map(r => r.issuer);
    // The current and records refusal members are withdrawn (S66); the default mode
    // keeps them as it was before covered operations were implemented.
    if (prepared && !prepared.covered && (prepared.change.preconditions?.some(p => p.state_hash) || prepared.records) && this.coveredReader(req,prepared)) {
      if (prepared.change.preconditions?.some(p => p.state_hash)) approval.current = prepared.current;
      if (prepared.records) approval.records = prepared.records;
    }
    // S67: "The audit record carries it." Every audit entry of a covered request records
    // the request key (S67).
    const key = prepared?.covered ? prepared.request_key : rest.request_key;
    this.audit('refusal',req,{error,...(prepared ? {change_hash:prepared.change_hash} : __hash ? {change_hash:__hash} : {}),...(key !== undefined && !mutated('audit-omits-request-key') ? {request_key:key} : {}),...(claims && prepared ? this.details(prepared,claims) : {})},'refused');
    return {ok:false,approval};
  }
  verify(token, req, p, onVerified=()=>{}) {
    let parsed; try { parsed = parseReceipt(token,mutated('accept-alg-none')); } catch { refuse('approval_invalid'); }
    const {claims:c,header:h} = parsed;
    if (this.unavailable.registry) refuse('approval_unavailable');
    let row = this.db.prepare('SELECT * FROM issuers WHERE account=? AND issuer=?').get(req.account,c.iss);
    if (!row) refuse('approval_invalid'); let issuer = JSON.parse(row.json);
    let key = issuer.keys.find(k => k.kid === h.kid);
    const ttl=Math.min(this.settings().keyCacheSeconds,this.settings().removalSeconds || this.settings().keyCacheSeconds);
    const expired=issuer.cachedAt !== undefined && this.now()-issuer.cachedAt>=ttl;
    if (!key || expired) {
      if (this.unavailable.keys) refuse('approval_unavailable');
      const updated = this.db.prepare('UPDATE issuers SET refreshed=?,refreshes=refreshes+1 WHERE account=? AND issuer=? AND refreshed<=?').run(this.now(),req.account,c.iss,this.now()-60);
      if (updated.changes && this.keyRefresh) {
        issuer.keys = this.keyRefresh(req.account,c.iss); if (!Array.isArray(issuer.keys)) refuse('approval_unavailable'); issuer.cachedAt = this.now();
        this.db.prepare('UPDATE issuers SET json=? WHERE account=? AND issuer=?').run(JSON.stringify(issuer),req.account,c.iss);
      }
      else if (expired) refuse('approval_unavailable');
      key = issuer.keys.find(k => k.kid === h.kid);
    }
    if (!key) refuse('approval_invalid');
    if (!(mutated('accept-alg-none') && h.alg === 'none')) {
      if (key.alg !== h.alg) refuse('approval_invalid');
      if (!mutated('skip-signature')) {
        try { if (!crypto.verify(h.alg === 'ES256' ? 'sha256' : null, Buffer.from(parsed.input), {key:crypto.createPublicKey({key,format:'jwk'}),dsaEncoding:'ieee-p1363'},parsed.signature)) refuse('approval_invalid'); } catch { refuse('approval_invalid'); }
      }
    }
    onVerified(c);
    if (!mutated('skip-issuer-scope') && (!issuer.operations.includes(req.operation) || !issuer.types.includes(c.approver.type))) refuse('approver_not_authorized');
    if (!mutated('skip-audience') && c.aud !== this.settings().audience) refuse('approval_invalid');
    return c;
  }
  // What an outcome row keeps beside the outcome. For a covered operation the stored
  // approved change and its record set are kept, so a repeat can be answered (and a
  // reader shown the stored change's hash) without rebuilding state (S69).
  #outcomeExtra(p, extra) {
    return p.covered ? { ...extra, change:p.change, records:p.records ?? null, entries:p.entries, action:p.action, versions:p.versions ?? null, copies:p.copies ?? [] } : extra;
  }
  // S80/S77/S25: the outcome of a consumed approval, held for as long as the consumed
  // record is held (the sandbox keeps it indefinitely) and replayed to a repeat.
  // S13/S25/S69(3): the row is written as `unknown` inside the consumption
  // transaction (see consume), so it exists from the moment the approval is consumed.
  // This is the compare-and-set that follows: it moves the outcome from unknown to what
  // is now known and never replaces a terminal outcome. It returns whether it applied.
  storeOutcome(p, c, outcome, extra = {}) {
    const json = JSON.stringify(this.#outcomeExtra(p, extra));
    if (mutated('outcome-overwrites-terminal')) { this.db.prepare('INSERT OR REPLACE INTO outcomes VALUES(?,?,?,?,?,?,?)').run(c.iss, c.jti, p.change_hash, outcome, this.now(), json, p.request_key ?? null); return true; }
    const set = this.db.prepare("UPDATE outcomes SET change_hash=?, outcome=?, at=?, json=?, request_key=? WHERE issuer=? AND jti=? AND outcome='unknown'").run(p.change_hash, outcome, this.now(), json, p.request_key ?? null, c.iss, c.jti).changes;
    if (set) return true;
    // No row at all (a store written before the placeholder existed): record it once.
    return !!this.db.prepare('INSERT OR IGNORE INTO outcomes VALUES(?,?,?,?,?,?,?)').run(c.iss, c.jti, p.change_hash, outcome, this.now(), json, p.request_key ?? null).changes;
  }
  // The terminal outcome and its audit record in one transaction. If the audit record
  // cannot be written, the transaction rolls back and the outcome stays as it was
  // (unknown); a failure to record never turns a write that ran into one that did not.
  recordOutcome(req, p, c, outcome, extra, auditDetail, auditOutcome) {
    const own = !this.db.isTransaction;
    if (own) this.db.exec('BEGIN IMMEDIATE');
    try {
      const applied = this.storeOutcome(p, c, outcome, extra);
      if (applied) this.audit('outcome', req, auditDetail, auditOutcome);
      if (own) this.db.exec('COMMIT');
      return applied;
    } catch (e) { if (own) this.db.exec('ROLLBACK'); throw e; }
  }
  // S25: the write is about to be sent. Recorded before the send, so that after a crash
  // the unknown outcome says that the write may have been sent.
  #markSent(p, c) {
    const row = this.db.prepare("SELECT json FROM outcomes WHERE issuer=? AND jti=? AND outcome='unknown'").get(c.iss, c.jti);
    if (!row) return;
    let held = {}; try { held = JSON.parse(row.json ?? '{}'); } catch {}
    this.db.prepare("UPDATE outcomes SET json=? WHERE issuer=? AND jti=? AND outcome='unknown'").run(JSON.stringify({ ...held, sent:true, placeholder:true }), c.iss, c.jti);
  }
  #outcomeRow(where, ...args) { const r = this.db.prepare(`SELECT * FROM outcomes WHERE ${where}`).get(...args); if (!r) return undefined; try { return { outcome:r.outcome, at:r.at, iss:r.issuer, jti:r.jti, change_hash:r.change_hash, ...JSON.parse(r.json ?? '{}') }; } catch { return { outcome:r.outcome, at:r.at, iss:r.issuer, jti:r.jti, change_hash:r.change_hash }; } }
  outcomeByJti(iss, jti) { return this.#outcomeRow('issuer=? AND jti=?', iss, jti); }
  outcomeByHash(change_hash) { return this.#outcomeRow('change_hash=?', change_hash); }
  outcomeByRequestKey(request_key) { return this.#outcomeRow('request_key=?', request_key); }
  // Test hook: the system of record reports the outcome of an execution whose response
  // was lost (Setup, "a lost outcome"). A compare-and-set from unknown, like every other
  // change of an outcome (S69(3): "An unknown-outcome answer becomes the recorded outcome
  // when the server learns the outcome of that execution").
  learnOutcome(change_hash, patch) {
    const row = this.db.prepare("SELECT issuer,jti,json FROM outcomes WHERE change_hash=? AND outcome='unknown'").get(change_hash);
    if (row) { const held = JSON.parse(row.json ?? '{}'); delete held.placeholder; this.db.prepare("UPDATE outcomes SET outcome=?, json=? WHERE issuer=? AND jti=? AND outcome='unknown'").run(patch.outcome, JSON.stringify({ ...held, ...patch }), row.issuer, row.jti); }
  }
  // S77 with S78: the applied-to identifier of a misdirected write is returned only where
  // all three of S77's conditions hold. (1) S77 permits "the identifier of a record, where
  // the server can establish that this write created it": a create the store applied to a
  // new identifier created that record, while a write that took effect on a record that
  // already existed (a merge-into target, or a create replacing one) did not. (2) The
  // identifier MUST conform to the documented format (`ID_FORMAT`), a pattern the system of
  // record's own identifiers satisfy; one that does not is withheld. (3) It is data read
  // from the system of record, so S60 establishes the principal's read permission for that
  // record before it is returned. Otherwise the identifier is withheld and the entry says
  // so. Off: leak-applied-identifier, return-unchecked-identifier.
  entryIdentifier(req, id, applied) {
    if (mutated('leak-applied-identifier')) return { applied_identifier:id };
    if (!applied?.created || !ID_FORMAT.test(id) || mutated('return-unchecked-identifier')) return { identifier_withheld:true };
    const may = authorize(this.sor, { id:req.principal }, { account:req.account, operation:req.operation, scope:{ names:[], records:[id] } }, 'read').allowed;
    return may ? { applied_identifier:id } : { identifier_withheld:true };
  }
  #appliedEntries(req, applied, entries) {
    return (applied ?? []).map(a => a.to === a.id ? { id:a.id, outcome:'success' } : { id:a.id, outcome:'misdirected', ...this.entryIdentifier(req, a.to, a) });
  }
  writeOptions(c) { return this.sor.idempotent && !mutated('idempotency-key-ignored') ? { key:c.iss + ':' + c.jti } : {}; }
  // S69/S80: the answer to an identical request whose approval was consumed, from the
  // durable outcome row alone. It runs before any read of record state, before the
  // record-scope check of step 1 (S60(c), S69(1)) and before any grant is matched or any
  // approval record opened (S69(1)). `identity` is what the request is before any state.
  replayIfConsumed(req, identity) {
    if (mutated('replay-after-state-read')) return undefined;
    if (identity.covered) {
      // S69(1): a repeat of a consumed request key never executes, matches a grant or
      // opens an approval record; the answer comes before any rebuild of state.
      const prior = this.outcomeByRequestKey(identity.request_key);
      const running = this.inFlight.has('rk:'+identity.request_key) && !mutated('ignore-in-progress');
      if (!prior && !running) return undefined;
      if (mutated('covered-replay-executes')) return undefined; // the repeat falls through and runs again
      if (!running && prior.placeholder && mutated('unknown-outcome-as-approval-used')) refuse('approval_used');
      return this.coveredReplay(req, identity.request_key, running ? { outcome:'in_progress', at:this.now() } : prior);
    }
    // An operation that is not covered, in the server-issued profile: the approval is
    // found by the change hash (step 3), which is the request's identity. A receipt of
    // the signed-receipts profile is its own identity and is answered at step 10, after
    // it has been verified (Section 6; see AMBIGUITIES.md).
    const p = identity.p;
    if (!this.pending || !p) return undefined;
    if (mutated('replay-bare-approval-used') || mutated('grant-double-execution')) return undefined;
    // S30: a decline or cancel response is handled where the record is looked up.
    const act = req.inputResponses?.approve?.action;
    if (act === 'decline' || act === 'cancel') return undefined;
    const prior = this.outcomeByHash(p.change_hash);
    if (!prior) return undefined;
    const running = this.inFlight.has(prior.iss + ':' + prior.jti) && !mutated('ignore-in-progress');
    if (!running && prior.placeholder && mutated('unknown-outcome-as-approval-used')) refuse('approval_used');
    return this.replayAnswer(req, p, undefined, running ? { outcome:'in_progress', at:this.now(), grantId:prior.grantId } : prior);
  }
  // S80: the answer to a request forbidden because its approval was consumed.
  replayAnswer(req, p, c, row) {
    const grantId = c?.grant?.id ?? row.grantId;
    const grantMember = this.pending && grantId ? { grant:this.pending.grants.get(grantId) } : {};
    const mark = (message, extra = {}) => ({ outcome:row.outcome, at:row.at, sent_now:false, message, ...extra });
    if (row.outcome === 'in_progress') return { ok:true, result:{ recorded_outcome:mark('The earlier request is still being carried out. Nothing was sent now. Ask again in a moment to learn the outcome.') }, ...grantMember };
    if (row.outcome === 'unknown') {
      if (row.sent && this.sor.idempotent) {
        // S25: the system of record treats the keyed repeat as the same write, so the
        // server sends it again and reports the recovered outcome.
        const again = this.sor.write(req.account, p.entries, p.action, p.change.arguments.objectType, p.versions, this.writeOptions(row));
        this.storeOutcome(p, row, 'success', { sent:true, changed:again.changed, grantId });
        return { ok:true, result:{ changed:again.changed, recorded_outcome:{ outcome:'success', at:row.at, sent_now:false, sent_again:true, message:`The write was sent again and the system of record reported the outcome of the original write. ${recordedSentence(row.at)}` } }, ...grantMember };
      }
      return { ok:true, result:{ recorded_outcome:mark('The outcome of the earlier approved write is not known. Nothing was sent now. If the write is still wanted, ask for it again as a new change, which needs a new approval.') }, ...grantMember };
    }
    if (row.outcome === 'success' || row.outcome === 'misdirected') {
      const entries = row.outcome === 'misdirected' ? { entries:this.#appliedEntries(req, row.applied, p?.entries) } : {};
      return { ok:true, result:{ changed:row.changed, ...entries, recorded_outcome:mark(recordedSentence(row.at)) }, ...grantMember };
    }
    // S17: a recorded `partial` is a result, so the replay of it is a result too
    // (S17), and it carries the same outcome and per-entry outcomes it was recorded with.
    if (row.outcome === 'partial') return { ok:true, result:{ outcome:'partial', changed:row.changed, entries:row.entries, recorded_outcome:mark(recordedSentence(row.at)) }, ...grantMember };
    // A recorded conflict or execution_failed remains a refusal (S65, S80). Section 7: its
    // `recorded_outcome` object carries the same `message` the refusal does.
    const base = this.pending && MESSAGES[row.outcome] ? MESSAGES[row.outcome](row) + ' ' : '';
    const message = base + recordedSentence(row.at);
    const readOutcome = mutated('recorded-outcome-omits-message') ? { outcome:row.outcome, at:row.at, sent_now:false } : { outcome:row.outcome, at:row.at, sent_now:false, message };
    const answer = this.refusal(req, row.outcome, p, c, { recorded_outcome:readOutcome, message });
    return { ...answer, ...grantMember };
  }
  // S69/S80 for a covered operation: the answer to an identical request after
  // consumption, given before the server rebuilds record state or applies the
  // selection limit (S67). It carries request_key (S67); a non-reader gets no change
  // and no change_hash (S68(1)); a reader gets the stored change's hash. The message
  // says that nothing was sent now and that a new write needs a new value of the
  // distinguishing argument (S69(2)).
  coveredReplay(req, request_key, row) {
    const grantMember = this.pending && row.grantId ? { grant:this.pending.grants.get(row.grantId) } : {};
    const reader = row.change ? this.coveredReader(req, { change:row.change, records:row.records, copies:row.copies ?? [] }) : false;
    const base = { request_key, ...(reader ? { change_hash:row.change_hash } : {}) };
    const tail = ' A new write needs a new value of the change_tag argument.';
    const mark = message => ({ outcome:row.outcome, at:row.at, sent_now:false, message });
    if (row.outcome === 'in_progress') return { ok:true, result:{ ...base, recorded_outcome:mark('The earlier request is still being carried out. Nothing was sent now. Ask again in a moment to learn the outcome.') }, ...grantMember };
    if (row.outcome === 'unknown') {
      if (row.sent && this.sor.idempotent && !mutated('covered-unknown-repeat-without-idempotency')) {
        // S69(3) applies S25 unchanged: where the record treats the keyed repeat as the
        // same write, send that stored write again and report the recovered outcome.
        const p = { covered:true, request_key, change:row.change, change_hash:row.change_hash, records:row.records ?? null, entries:row.entries, action:row.action, versions:structuredClone(row.versions ?? {}), copies:row.copies ?? [] };
        const again = this.sor.write(req.account, p.entries, p.action, p.change.arguments.objectType, p.versions, this.writeOptions(row));
        this.storeOutcome(p, row, 'success', { sent:true, changed:again.changed, applied:again.applied, grantId:row.grantId });
        const message = `The write was sent again as the same write and the system of record reported the recovered outcome of the earlier attempt, recorded at ${readableTime(row.at)}. No additional write was made. A new intended write needs a new value of the change_tag argument.`;
        return { ok:true, result:{ ...base, changed:again.changed, recorded_outcome:{ outcome:'success', at:row.at, sent_now:false, sent_again:true, message } }, ...grantMember };
      }
      return { ok:true, result:{ ...base, recorded_outcome:mark('The outcome of the earlier approved write is not known. Nothing was sent now. If the write is still wanted, ask for it again as a new change with a new value of the change_tag argument, which needs a new approval.') }, ...grantMember };
    }
    if (row.outcome === 'success' || row.outcome === 'misdirected') {
      const entries = row.outcome === 'misdirected' ? { entries:this.#appliedEntries(req, row.applied, row.entries) } : {};
      return { ok:true, result:{ ...base, changed:row.changed, ...entries, recorded_outcome:mark(recordedSentence(row.at) + tail) }, ...grantMember };
    }
    // S17: a recorded `partial` is a result, so the covered replay is a
    // result too, with the per-entry outcomes it was recorded with.
    if (row.outcome === 'partial') return { ok:true, result:{ ...base, changed:row.changed, entries:row.entries, recorded_outcome:mark(recordedSentence(row.at) + tail) }, ...grantMember };
    // A recorded conflict or execution_failed remains a refusal (S65, S80). Section 7: its
    // `recorded_outcome` object carries the same `message` the refusal does.
    const message = (this.pending && MESSAGES[row.outcome] ? MESSAGES[row.outcome]({}) + ' ' : '') + recordedSentence(row.at) + tail;
    const readOutcome = mutated('recorded-outcome-omits-message') ? { outcome:row.outcome, at:row.at, sent_now:false } : { outcome:row.outcome, at:row.at, sent_now:false, message };
    const approval = { error:row.outcome, ...base, recorded_outcome:readOutcome, message };
    this.audit('refusal', req, { error:row.outcome, change_hash:row.change_hash, request_key }, 'refused');
    return { ok:false, approval, ...grantMember };
  }
  // The key under which this instance marks the execution of a consumed approval.
  #writeKey(p, c) { return p.covered ? 'rk:' + p.request_key : c.iss + ':' + c.jti; }
  // S13: "Consumption MUST be one atomic, durable transaction ... covering the receipt
  // identifier, the grant counter and the consumption record, and MUST complete before
  // execution starts." The same transaction writes the outcome as unknown, so a crash at
  // any later point leaves a recorded (unknown) outcome for the identical request (S25,
  // S69(3), S80), and marks the execution as running on this instance.
  consume(req, p, c) {
    if (this.unavailable.store) refuse('approval_unavailable');
    this.sor.hit('before-consume',{req,p,c});
    const writeKey = this.#writeKey(p, c); let marked = false;
    this.db.exec('BEGIN IMMEDIATE');
    try {
      if (!mutated('skip-single-use') && this.db.prepare('SELECT 1 FROM used WHERE issuer=? AND jti=?').get(c.iss,c.jti)) {
        // S80: while the outcome is held the repeat gets the recorded outcome; a bare
        // approval_used is given only where the server no longer holds it.
        if (mutated('replay-bare-approval-used')) refuse('approval_used');
        const key = c.iss + ':' + c.jti;
        if (!mutated('ignore-in-progress') && this.inFlight.has(key)) throw Object.assign(Error('recorded'),{ recorded:{ outcome:'in_progress', at:this.now() } });
        const row = this.outcomeByJti(c.iss, c.jti);
        if ((!row || row.placeholder) && mutated('unknown-outcome-as-approval-used')) refuse('approval_used');
        throw Object.assign(Error('recorded'),{ recorded:row ?? { outcome:'unknown', at:this.now() } });
      }
      if(c.iss==='server'&&this.pending) {
        const record=this.pending.get(c.jti);
        if(record&&['denied','cancelled'].includes(record.status))throw Object.assign(Error(record.status),{code:'approval_'+record.status,details:{retry_after:Math.max(0,record.expires-this.now())}});
      }
      this.sor.hit('before-grant-charge',{req,p,c});
      if (c.iss==='server'&&c.grant) this.pending.grants.charge(req,p,c);
      else if (c.grant) {
        const g = c.grant; const count = p.change.resolved?.count ?? (Array.isArray(p.change.arguments.records) ? p.change.arguments.records.length : (req.operation === CREATE ? 1 : undefined));
        if (count === undefined) refuse('grant_exceeded');
        // S46: "Each write under a grant MUST also be one that the person who made the
        // grant is permitted to make at that moment, on those records (S22 applied at
        // use)." Step 10 of Section 6: "If a grant check fails, refuse with
        // `grant_exceeded` ... and record nothing as used." In the signed-receipts
        // profile the grantor is the receipt's approver; the server's own model answers
        // for a person it knows (see authorize.mjs, modelKnows, and AMBIGUITIES.md).
        if (!mutated('signed-grant-skips-authority') && modelKnows(this.sor, req.account, c.approver.id)
          && !authorize(this.sor, { id:c.approver.id, authenticated:true }, { account:req.account, operation:req.operation, change:p.change, records:p.records }, 'grant').allowed) refuse('grant_exceeded');
        const old = this.db.prepare('SELECT * FROM grants WHERE account=? AND issuer=? AND id=?').get(req.account,c.iss,g.id);
        if (this.now() >= g.expires || (old && (old.max_records !== g.max_records || old.expires !== g.expires))) refuse('grant_exceeded');
        if (!mutated('skip-grant-limit') && (old?.charged ?? 0) + count > g.max_records) refuse('grant_exceeded');
        this.db.prepare('INSERT INTO grants VALUES(?,?,?,?,?,?) ON CONFLICT(account,issuer,id) DO UPDATE SET charged=charged+excluded.charged').run(req.account,c.iss,g.id,g.max_records,g.expires,count);
      }
      this.db.prepare('INSERT OR IGNORE INTO used VALUES(?,?,?)').run(c.iss,c.jti,c.exp+this.settings().skew);
      if(c.iss==='server') {
        // S13, S35: a consumed record a grant could approve again is kept
        // for at least the longer of the S13/S35 period and the pending lifetime, so the
        // identical retry is still answered from it (S69, S80) and never matches the grant
        // again while the grant could still apply. The record's stored expiry is raised to
        // that floor; cleanup then discards it no earlier. Off: consumed-record-not-retained.
        const floor = this.pending && !mutated('consumed-record-not-retained') ? this.pending.retentionSeconds() : 0;
        this.db.prepare("UPDATE pending SET status='consumed', expires=max(expires,?) WHERE id=?").run(this.now()+floor,c.jti);
      }
      // S35/S50/S68(6): when an approval is consumed, every other pending or approved
      // record for the same change hash — for a covered operation, for the same request
      // key, including the context's open record — is closed as superseded in the same
      // atomic step, and its page says that the change already ran under another
      // approval. The context stops counting toward the limit (S70).
      if (p.contextToken) {
        this.db.prepare("UPDATE pending SET status='superseded', hash=hash||'#'||id WHERE context=? AND id<>? AND status IN ('pending','approved')").run(p.contextToken,c.jti);
        this.db.prepare("UPDATE contexts SET status='consumed' WHERE token=?").run(p.contextToken);
      }
      else if(c.iss==='server') this.db.prepare("UPDATE pending SET status='superseded', hash=hash||'#'||id WHERE hash=? AND id<>? AND status IN ('pending','approved')").run(p.change_hash,c.jti);
      // The outcome of this consumption, unknown until recordOutcome says otherwise.
      if (!mutated('consume-without-placeholder'))
        this.db.prepare('INSERT OR REPLACE INTO outcomes VALUES(?,?,?,?,?,?,?)').run(c.iss, c.jti, p.change_hash, 'unknown', this.now(), JSON.stringify(this.#outcomeExtra(p, { sent:false, placeholder:true, grantId:c.grant?.id })), p.request_key ?? null);
      const id = this.audit('consumption',req,this.details(p,c),'consumed');
      this.inFlight.add(writeKey); marked = true;
      this.db.exec('COMMIT'); return id;
    } catch (e) { if (marked) this.inFlight.delete(writeKey); this.db.exec('ROLLBACK'); throw e; }
  }
  // S67: "The audit record carries it": the request key of a covered operation is part
  // of the consumption and outcome records. Every consumption and outcome record also
  // carries the deployment record's `config_hash` in force (S87).
  details(p,c) { return { change_hash:p.change_hash, ...(p.covered && !mutated('audit-omits-request-key') ? {request_key:p.request_key} : {}), receipt_id:c.jti, issuer:c.iss, approver_type:c.approver.type, approver_id:c.approver.id, ...(c.grant ? {grant_id:c.grant.id,...(c.grant.shape?{grant_shape:c.grant.shape}:{})} : {}), ...(c.policy ? {policy:c.policy} : {}), ...(mutated('consumption-omits-config-hash') ? {} : {config_hash:this.configHash()}) }; }
  handle(req) {
    let p,c,request_key;
    try {
      const s = this.settings();
      // ---- shape. One parse of what the transport received; no state, no hash.
      const shaped = shapeRequest(req);
      const subject = { id:req.principal };
      // ---- authorize, step 1 of Section 6: "Authenticate the credential and apply its
      // ordinary permission checks. A request the credential may not make is refused as
      // usual and consumes nothing." Step 2 checks the input, so a principal that may not
      // use the operation at all is refused here whatever its input is (S65).
      if (!authorize(this.sor, subject, { account:req.account, operation:req.operation }, 'write').allowed) refuse('permission_denied');
      // S66: "Where the server does not offer the server-issued profile for a covered
      // operation, or the account allows no approver type for it in that profile, the
      // server MUST refuse every request for it with `approver_not_authorized`, without
      // reading record state and with no `change_hash`." A query is a covered operation
      // (S67), and the default mode (preconditions off) offers no server-issued profile
      // for it, so it is refused here before preparing a change: no SOR read, no count,
      // no manifest hash, no approval link, and the same answer on every call. S60(c)'s
      // ordinary step 1 permission_denied above still comes first for a principal that
      // may not write at all.
      const cov = this.coveredBy(s, req.operation);
      if (cov.any && !s.preconditions && !mutated('query-allowed-in-default'))
        refuse(mutated('query-default-refusal-permission-denied')?'permission_denied':'approver_not_authorized');
      // Step 2, S3/S4/S65: what shapeRequest refused. S63: `invalid_input` "arises before
      // a hash is computed and carries none"; Section 7: "Its `message` names what was
      // invalid."
      if (!shaped.ok) {
        if (mutated('invalid-input-no-reason')) refuse('invalid_input');
        throw invalidInput({ message:shaped.message });
      }
      req = shaped;
      // Step 1 with the request's arguments, still from the permission model alone: the
      // principal's field-level write (S60(c)) and, for a query, its record scope.
      // S60(c)/S72 (cold read, finding 10), covered mode only: the scope also governs
      // the two covered operations that do not name their record in `records` or `id`.
      const writeRequest = { account:req.account, operation:req.operation, arguments:req.args, coveredScope:!!s.preconditions && !mutated('record-scope-skips-query-and-copy') };
      const mayWrite = authorize(this.sor, subject, writeRequest, 'write');
      if (!mayWrite.allowed && !mayWrite.needsState) refuse('permission_denied');
      // ---- identity. The request before any record state.
      // Covered operations (S67): the request key is computed first, and every answer that
      // must not rebuild record state — S66's approver_not_authorized, S69's recorded
      // outcome and the context answers of S30 and S68(5) — is given from it before
      // prepare reads any state.
      const covered = cov.any && !!s.preconditions;
      if (covered) {
        const keyChange = changeObject({ account:req.account, principal:req.principal, operation:req.operation, args:req.args, audience:s.audience, approvalFields:APPROVAL_FIELDS });
        // S66 (item 6): where the server does not offer the server-issued profile for a
        // covered operation, S66's `approver_not_authorized` is the answer for every
        // request and, for a query, "takes precedence over S72": it comes before the
        // read-domain check, for a principal that holds the operation's write permission
        // (that ordinary step 1 refusal is above). It reads no record state. Off:
        // query-domain-before-s66 runs the S72 check first.
        if (!mutated('covered-lists-issuers') && !this.pending && !mutated('query-domain-before-s66')) refuse('approver_not_authorized');
        // S72: this ordinary step 1 refusal precedes the request key, every context
        // answer and, above all, evaluation of the query or of its selection limit.
        if (req.operation === QUERY && !mutated('query-runs-before-domain-check') && !authorize(this.sor, subject, { account:req.account, operation:req.operation, change:keyChange }, 'read').allowed) refuse('permission_denied');
        // S66: a covered operation cannot be approved through an organization's issuer.
        // S67 (cold read, finding 12): the request key and "a refusal carries
        // `request_key` wherever the server computed one" are requirements of the
        // server-issued profile. A server that does not offer that profile for the
        // operation computes no request key, so this refusal comes before the key and
        // carries none; every refusal after the key is computed carries it (see the
        // catch at the end of handle). It also comes before the record-scope check, the
        // only step 1 check that reads record state (S60(c), S66).
        if (!mutated('covered-lists-issuers') && !this.pending) refuse('approver_not_authorized');
        request_key = this.requestKey(keyChange);
        if (!mutated('covered-lists-issuers')) {
          if (!(s.operationTypes?.[req.operation] ?? s.approverTypes).length) refuse('approver_not_authorized');
          if (req.receiptFault) refuse('approval_invalid');
          if (req.token !== undefined) refuse('approver_not_authorized');
        }
      } else {
        // An operation that is not covered holds nothing derived from record state, so
        // its change object and change hash are complete here (step 2), before any read.
        p = this.#prepared(req, { state:false });
        // S5: more than one receipt is refused before any record state is read.
        if (req.receiptFault) refuse('approval_invalid');
      }
      // ---- replay (S69, S80), before any read of record state.
      const replayed = this.replayIfConsumed(req, { covered, request_key, p });
      if (replayed) return replayed;
      // S30/S68(5)/S70: a veto, a denial and a cancellation are answered from the context,
      // "whether or not record state changed" (S68(5)), so they too come before the one
      // step 1 check that reads record state (S68(5), S72).
      if (covered && !mutated('context-answers-after-state-read')) this.pending.coveredPrelude(req, request_key);
      // ---- scope. S60(c): where the write permission is scoped by record, an update, a
      // delete or an association on a missing record gets the same step 1 refusal as a
      // record outside the scope, unless the principal may read it, in which case S64
      // applies. A create is never refused here. This is the one permission decision
      // that reads record state, through the single resolveIdentifier.
      // It is still the ordinary step 1 refusal: it carries nothing the later steps
      // computed (no change hash, no request key).
      if (mayWrite.needsState && !authorize(this.sor, subject, writeRequest, 'write', { resolve:id => resolveIdentifier(this.sor, req.account, id) }).allowed)
        throw Object.assign(new Refusal('permission_denied'), { stepOne:true });
      if (covered && mutated('context-answers-after-state-read')) this.pending.coveredPrelude(req, request_key);
      // ---- prepare and approval. A read that began before the record it would replace
      // was created, rendered or decided is made again (S67).
      for (let attempt = 0; ; attempt++) {
        p = this.#prepared(req, { state:true }, () => { p = undefined; });
        p.covered = covered; if (covered) p.request_key = request_key;
        if (req.effects && Object.keys(req.effects).length) throw invalidInput({ message:'The request carries inputs outside the change object, which cannot be approved, so the change was refused.' });
        if (req.receiptFault) refuse('approval_invalid');
        try {
          if (this.pending) c = covered ? this.pending.coveredLookup(req,p) : this.pending.lookup(req,p);
          else if (req.token === undefined) {
            if (mutated('approval-field-authorizes') && req.args?.confirmation) c = {iss:ISSUER,jti:crypto.randomUUID(),iat:this.now(),exp:this.now()+300,change_hash:p.change_hash,approver:{type:'person',id:'agent'}};
            else refuse('approval_required');
          } else c = this.verify(req.token,req,p,claims=>{c=claims;});
          break;
        } catch (e) {
          if (!e.reread) throw e;
          if (attempt >= 2) refuse('approval_unavailable');
        }
      }
      if (!mutated('skip-expiry') && (c.iat > this.now()+this.expirySkew(c) || this.now() >= c.exp+this.expirySkew(c) || c.exp-c.iat > s.maxLifetime)) refuse('approval_expired');
      if (!mutated('skip-hash-compare') && c.change_hash !== p.change_hash) refuse('approval_mismatch');
      if (!mutated('skip-approver-type') && !(s.operationTypes?.[req.operation] ?? s.approverTypes).includes(c.approver.type)) refuse('approver_not_authorized');
      // ---- consume.
      let authorization;
      try {authorization=this.consume(req,p,c);}catch(e){
        if(e.recorded) return this.replayAnswer(req,p,c,e.recorded);
        if(e.code==='server_grant_unavailable') { this.pending.releaseExempt?.(c); return this.pending.grantFallback(req,p,c); }
        throw e;
      }
      const grantMember=c.iss==='server'&&c.grant?{grant:this.pending.grants.get(c.grant.id)}:{};
      // S69(5): for a covered operation an identical request is tracked by request key.
      const writeKey=this.#writeKey(p,c);
      const audited=detail=>({...this.details(p,c),authorization_record_id:authorization,...detail});
      try {
        // ---- execute.
        let written;
        try {
          this.sor.hit('after-consume',{req,p,c});
          // S78 (cold read, finding 1): "Where a read the server makes shows that the
          // identifier of a record the request only refers to resolves to another record,
          // the server MUST NOT send the write; after consumption it answers
          // `execution_failed` as S65 provides". The read is the one prepare made at
          // step 8 for this request. The approval stays consumed and the reason is
          // recorded; the answer names no record-state reason.
          if (p.referenceResolved && !mutated('copy-writes-through-merged-source')) {
            this.recordOutcome(req,p,c,'execution_failed',{sent:false,grantId:c.grant?.id},audited({reason:'reference_resolved'}),'failed_or_unknown');
            return {...this.refusal(req,'execution_failed',p,c),...grantMember};
          }
          if (mutated('requery-at-execution') && p.records) {
            this.sor.hit('before-write',{account:req.account,entries:p.entries});
            p.entries = this.sor.query(req.account,p.change.arguments.objectType,p.change.arguments.filter).map(id => ({id,properties:p.change.arguments.set}));
          }
          // S64/S78: where the system of record offers neither a conditional write nor a
          // refusal, the server reads each named record immediately before the write and
          // sends nothing where the check finds a conflict or another identifier. The
          // check is not atomic with the write.
          if (!this.sor.conditional && !mutated('skip-prewrite-check')) {
            const entryBlocked=e=>{
              const found=resolveIdentifier(this.sor,req.account,e.id);
              if (!found.exists) return p.action!=='create';
              return found.redirected || p.action==='create';
            };
            if (p.entries.some(entryBlocked)) {
              // S77: the entry whose own check failed is conflict; every other entry's
              // write was not sent because of that entry, so it is not_sent.
              const entries=p.entries.map(e=>({id:e.id,outcome:(mutated('notsent-as-conflict')||entryBlocked(e))?'conflict':'not_sent'}));
              this.recordOutcome(req,p,c,'conflict',{sent:false,grantId:c.grant?.id},audited({reason:'pre_write_check',entries}),'conflict');
              return {...this.refusal(req,'conflict',p,c),...grantMember};
            }
          }
          this.#markSent(p,c);
          written = this.sor.write(req.account,p.entries,p.action,p.change.arguments.objectType,p.versions,this.writeOptions(c));
        } catch (e) {
          // The approval stays consumed whatever the outcome (S64, S65). S17
          // (S77, S17): a request whose entries partly succeeded has the result outcome
          // `partial`, not `execution_failed`; `execution_failed` is only for a request in
          // which no entry succeeded. A partial result is a result (S17: a refusal carries
          // no part of the write's result), so it is answered as one.
          const unknown=!!e.lost;
          if (e.partial && !mutated('partial-as-execution-failed')) {
            // An entry that wrote is success or misdirected; the entry that failed is
            // execution_failed; every entry after it was never sent (S77: not_sent).
            // S19 permits the same record to appear more than once, and S77 requires each
            // entry's outcome, so outcomes are indexed by entry position: the store writes
            // entries in order and `applied` holds the leading ones that wrote, so
            // applied[i] is entry i's outcome. Two entries for one record are each
            // reported. Off: partial-indexed-by-id collapses them by record identifier.
            const notSent=new Set(e.partial.notSent), byPosition=!mutated('partial-indexed-by-id');
            const appliedByPosition=e.partial.applied, appliedById=new Map(e.partial.applied.map(a=>[a.id,a]));
            const entries=p.entries.map((x,index)=>{
              const done=byPosition ? appliedByPosition[index] : appliedById.get(x.id);
              if (done) return done.to===x.id ? {id:x.id,outcome:'success'} : {id:x.id,outcome:'misdirected',...this.entryIdentifier(req,done.to,done)};
              return {id:x.id,outcome:notSent.has(x.id)?'not_sent':'execution_failed'};
            });
            const result={ outcome:'partial', changed:e.partial.applied.length, entries };
            this.recordOutcome(req,p,c,'partial',{sent:true,changed:e.partial.applied.length,applied:e.partial.applied,entries,grantId:c.grant?.id},audited({partial:true,entries}),'partial');
            return {ok:true,result,...grantMember};
          }
          // S25, S64, S77: the write was sent and its response was lost, so the outcome
          // is unknown. It is recorded as unknown and answered as unknown, never as
          // `execution_failed`, which says that no write was made. An unknown outcome is
          // one of S77's outcomes, so the answer is a result; the replay says the same and
          // adds the recorded_outcome marker (S80). Off: unknown-as-execution-failed.
          const outcome=e.message==='conflict'?'conflict':unknown&&!mutated('unknown-as-execution-failed')?'unknown':'execution_failed';
          this.recordOutcome(req,p,c,outcome,{sent:true,grantId:c.grant?.id},audited(e.sorText?{reason:e.message==='conflict'?'conflict':'rejected_by_system_of_record'}:{}),e.message==='conflict'?'conflict':unknown?'unknown':'failed_or_unknown');
          if (outcome==='unknown') {
            // S25: where the system of record offers no way to treat a repeat as the same
            // write, the answer says the outcome is unknown and that a new write needs a
            // new approval.
            const message='The approved change was sent, but the system of record did not report whether it was made. It is not sent again; if the change is still wanted, ask for it again as a new change, which needs a new approval.';
            return {ok:true,result:{outcome:'unknown',message},...grantMember};
          }
          const answer=this.refusal(req,outcome,p,c,e.sorText?{sorText:e.sorText}:undefined);
          return {...answer,...grantMember};
        }
        // ---- outcome. The write ran; what follows only records it.
        const misdirected=(written.applied??[]).some(a=>a.to!==a.id);
        // S77: the result carries only what the requirement permits, never the record
        // content or text the system of record returned.
        const result = mutated('leak-sor-result') ? written
          : { changed:written.changed, ...(misdirected?{entries:this.#appliedEntries(req,written.applied,p.entries)}:{}) };
        try {
          this.recordOutcome(req,p,c,misdirected?'misdirected':'success',{sent:true,changed:written.changed,applied:written.applied,grantId:c.grant?.id},audited(misdirected?{misdirected:written.applied.filter(a=>a.to!==a.id)}:{}),misdirected?'misdirected':'success');
        } catch (e) {
          // The outcome could not be recorded. The write ran, so it is not turned into a
          // failure: the durable outcome stays unknown and this request is told the truth.
          if (mutated('outcome-overwrites-terminal')) {
            this.storeOutcome(p,c,'execution_failed',{sent:true,grantId:c.grant?.id});
            return {...this.refusal(req,'execution_failed',p,c),...grantMember};
          }
        }
        return {ok:true,result,...grantMember};
      } finally { this.inFlight.delete(writeKey); }
    } catch (e) {
      if (e.recorded) return p?.covered ? this.coveredReplay(req,p.request_key,e.recorded) : this.replayAnswer(req,p,undefined,e.recorded);
      if (e.stepOne) return this.refusal(req,e.code);
      const code = e instanceof Refusal || (this.pending && ['approval_required','approval_denied','approval_cancelled','approval_limit_reached','approval_used'].includes(e.code)) ? e.code : 'approval_unavailable';
      // S63: `invalid_input` "arises before a hash is computed and carries none".
      if (code === 'invalid_input' && !mutated('effects-refused-after-hash')) p = undefined;
      // S67 (cold read, finding 12): "For a covered operation a refusal carries
      // `request_key` wherever the server computed one". A refusal raised after the key
      // was computed and before the change object was built (S66's
      // approver_not_authorized, and the refusals raised while the change is prepared)
      // has no prepared change to take it from, so it is added here. It does not depend
      // on record state.
      const details = request_key !== undefined && !p?.covered && !mutated('covered-early-refusal-omits-request-key') ? { ...e.details, request_key } : e.details;
      return this.refusal(req,code,p,c,details);
    }
  }
  // prepare, with what it throws mapped to refusals. `onFailure` runs before a failure
  // is rethrown, so a refusal raised while state is read carries no earlier change.
  #prepared(req, options, onFailure = () => {}) {
    try { return this.prepare(req, options); } catch (e) {
      onFailure();
      // S60(i): a read of record state that did not complete is approval_unavailable,
      // never invalid_input, and nothing is consumed.
      if (e.code && !(mutated('read-failure-plain-error') && e.code==='approval_unavailable')) throw e;
      if (mutated('invalid-input-no-reason')) refuse('invalid_input');
      if (e.invalid?.length) throw invalidInput({invalid:e.invalid,message:`The system of record does not define ${e.invalid.length===1?'this property':'these properties'}: ${e.invalid.join(', ')}. The change was refused.`});
      throw invalidInput({message:e.inputMessage ?? INPUT_KINDS[e.message] ?? UNSERIALIZABLE});
    }
  }
}
export function mcpResult(result) {
  const grantText=result.grant?[{type:'text',text:`Ran under grant ${result.grant.id}; a standing permission, not an approval of this one change. Shape: ${shapeWords(result.grant.shape)} (${result.grant.shape}); records remaining: ${plural(result.grant.max_records-result.grant.charged)}; expires: ${formatTime(result.grant.expires)}.`}]:[];
  if (result.ok) return {content:[{type:'text',text:JSON.stringify(result.result)},...grantText]};
  return {isError:true,content:[{type:'text',text:JSON.stringify(result.approval)},...grantText],_meta:{'org.enforcedapproval/refusal':result.approval}};
}
