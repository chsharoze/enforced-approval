// The settings registry: the one place that says which values a deployment may configure,
// what each one defaults to, how far it may go, which way is looser, and the requirement it
// parameterises (S23; Section 11.1 to 11.5 of the core).
//
// The line the registry holds (S82): a setting configures the
// parameters of the guarantee — who, how long, how many, which operations — never its
// logic. Nothing here can turn off a check: there is no setting for "no approval", for the
// server computing the hash, for single use or for failing closed.
//
// Rules every entry follows (S81, S83 to S87):
//   * default      a safe starting value; a missing value means the default.
//   * range        a hard ceiling (or a closed set of values); out-of-range is refused.
//   * scope        by account, never by record content (the approver list and the page
//                  administrators are keyed by account for that reason).
//   * direction    tightening applies at once; loosening never revives a denied or expired
//                  request and never widens an existing grant (Core.admin and the matching
//                  code enforce the second half).
//   * binding      a setting marked `effect` changes what the write does or who may
//                  approve. Its value is bound into every approval record as `effect_hash`,
//                  and an approval whose effect hash no longer matches is no approval.
//   * audit        Core.admin records who changed what, with the old and new values.
//   * visibility   the deployment record prints the values in force; the agent sees only
//                  what the wire already carries.
import { hash, jcs } from './json.mjs';

// The sandbox's default maximum receipt lifetime and skew. The S13/S35 retention floor is
// built from them, so a resolver called without a configuration still gets the documented
// default (300 seconds) rather than zero.
export const DEFAULT_MAX_LIFETIME = 300;
export const DEFAULT_SKEW = 0;
// One year, in seconds: the hard limit for the retention floor and for a grant's life.
export const ONE_YEAR = 31536000;
const s13Floor = all => (Number.isSafeInteger(all.max_lifetime_seconds) ? all.max_lifetime_seconds : Number.isSafeInteger(all.maxLifetime) ? all.maxLifetime : DEFAULT_MAX_LIFETIME) + (Number.isSafeInteger(all.skew_seconds) ? all.skew_seconds : Number.isSafeInteger(all.skew) ? all.skew : DEFAULT_SKEW);
// The computed S13 floor for the settings in a raw configuration, so a write that raises
// the maximum lifetime or the skew can raise a stored floor with them (Core.admin).
export const retentionFloorFor = s13Floor;

// The settings this release exposes. Exactly these; adding one is a decision, not a value.
// `key` is the member the sandbox already stores and reads (`pendingLifetime`); `name` is
// the documented name in the /settings family. Both are accepted where a value is written.
export const REGISTRY = [
  {
    name: 'pending_lifetime_seconds', key: 'pendingLifetime',
    requirement: "S27: a pending record expires within the server's documented limit (at most 1 hour); at most 24 hours, only with a notification the agent cannot read (S27)",
    kind: 'integer', default: 3600, ceiling: 86400, looser: 'higher',
    check: (v, all) => !Number.isSafeInteger(v) || v < 1 || v > 86400
      ? 'must be a whole number of seconds from 1 to 86400'
      : v > 3600 && all.approver_notification !== true
        ? 'a lifetime above 3600 seconds is allowed only when approver_notification is on'
        : true,
  },
  {
    name: 'approver_notification', key: 'approverNotification',
    requirement: 'S27: the approver is told, through a channel the agent cannot read, that a request is open; each notification is logged',
    kind: 'boolean', default: false, looser: 'adding a channel',
    check: v => typeof v === 'boolean' || 'must be true or false',
  },
  {
    name: 'pending_cap', key: 'pendingCap',
    requirement: 'S27: how many unexpired pending, denied and cancelled records one principal may hold',
    kind: 'integer', default: 10, ceiling: 100, looser: 'higher',
    check: v => Number.isSafeInteger(v) && v >= 1 && v <= 100 || 'must be a whole number from 1 to 100',
  },
  {
    name: 'selection_limit', key: 'selectionLimit',
    requirement: 'S29: the largest selection an update by query may address',
    kind: 'integer', default: 100, ceiling: 1000, looser: 'higher',
    check: v => Number.isSafeInteger(v) && v >= 1 && v <= 1000 || 'must be a whole number from 1 to 1000',
  },
  {
    name: 'retention_floor_seconds', key: 'retentionFloor',
    requirement: 'S13 and S35: used identifiers are kept until their expiry plus the allowed skew; at least the longer of that period and the pending lifetime (S35)',
    kind: 'integer', default: null, looser: 'a shorter floor, down to the S13 period',
    floor: s13Floor, ceiling: ONE_YEAR,
    check: (v, all) => !Number.isSafeInteger(v) || v < s13Floor(all)
      ? `must be at least the S13 floor: ${s13Floor(all)} seconds`
      : v > ONE_YEAR
        ? `must not exceed the one-year hard limit of ${ONE_YEAR} seconds`
        : true,
  },
  {
    name: 'max_lifetime_seconds', key: 'maxLifetime',
    requirement: 'S10, S27, S35, S60, S90: the longest an approval may be usable; S90 requires poll_interval shorter than it, so it is at least 2 seconds',
    kind: 'integer', default: DEFAULT_MAX_LIFETIME, ceiling: 86400, looser: 'higher',
    check: v => Number.isSafeInteger(v) && v >= 2 && v <= 86400 || 'must be a whole number of seconds from 2 to 86400',
  },
  {
    name: 'skew_seconds', key: 'skew',
    requirement: 'S10, S84: the allowed clock skew; raising it never revives an approval that expired under the old value',
    kind: 'integer', default: DEFAULT_SKEW, ceiling: 60, looser: 'higher',
    check: v => Number.isSafeInteger(v) && v >= 0 && v <= 60 || 'must be a whole number of seconds from 0 to 60',
  },
  {
    name: 'grant_charge_limit', key: 'grantChargeLimit',
    requirement: 'S18, S35: the ceiling on the record limit a standing grant may be made with; tightening it applies to existing grants',
    kind: 'integer', default: 100, ceiling: 1000, looser: 'higher',
    check: v => Number.isSafeInteger(v) && v >= 1 && v <= 1000 || 'must be a whole number from 1 to 1000',
  },
  {
    name: 'grant_seconds_limit', key: 'grantSecondsLimit',
    requirement: 'S18, S35: the ceiling on how long a standing grant may last; tightening it applies to existing grants',
    kind: 'integer', default: 3600, ceiling: ONE_YEAR, looser: 'higher',
    check: v => Number.isSafeInteger(v) && v >= 1 && v <= ONE_YEAR || `must be a whole number of seconds from 1 to ${ONE_YEAR}`,
  },
  {
    name: 'key_cache_seconds', key: 'keyCacheSeconds',
    requirement: 'S15, S26: how long a fetched issuer key may be reused before it is refreshed',
    kind: 'integer', default: 3600, ceiling: 86400, looser: 'higher',
    check: v => Number.isSafeInteger(v) && v >= 1 && v <= 86400 || 'must be a whole number of seconds from 1 to 86400',
  },
  {
    name: 'read_tool_denied_answer', key: 'readToolDeniedAnswer',
    requirement: 'Section 2: what the read tool answers for a record the principal may not read; this release answers as for an absent record',
    kind: 'enum', values: ['absent'], default: 'absent', looser: 'none in this release',
    check: v => v === 'absent' || 'must be absent in this release',
  },
  {
    name: 'approver_model', key: 'approverModel',
    requirement: 'S22 with S76: who may approve a change; the default is the permission source alone, and adding a documented model only narrows S22',
    kind: 'enum', values: ['permission', 'named', 'administrators'], default: 'permission', looser: 'adding a model',
    effect: true,
    check: v => ['permission', 'named', 'administrators'].includes(v) || 'must be permission, named or administrators',
  },
];
// A further setting the server documents (S87): the deployment record states the principal
// model in force. It is not one of the seven settings of the core's table.
export const PRINCIPAL_MODELS = ['delegated', 'dedicated', 'service_account'];
export const principalModel = raw => raw.principal_model ?? raw.principalModel ?? 'dedicated';
// The settings the sandbox already had that are not part of this registry's first release.
// They are known, so they are not refused as unknown, but they have no registry row yet.
export const OTHER = ['audience', 'maxLifetime', 'skew', 'preconditions', 'stateKey', 'operationTypes', 'approverTypes', 'keyCacheSeconds', 'removalSeconds', 'grantConfig', 'pageAdministrators', 'approvers', 'guardedOperations', 'principal_model', 'principalModel'];
const ALIAS = new Map(REGISTRY.flatMap(e => [[e.name, e.key], [e.key, e.key]]));
const NAMES = new Set([...REGISTRY.map(e => e.name), ...REGISTRY.map(e => e.key), ...OTHER]);

export class SettingsRefusal extends Error { constructor(message) { super(message); this.code = 'invalid_settings'; } }
const list = names => names.length === 1 ? names[0] : names.slice(0, -1).join(', ') + ' and ' + names.at(-1);

// An unknown setting is refused wherever settings are written: a name nobody documents
// cannot be silently stored (S23: every setting is administratively changeable and, by the
// same token, only a setting that is defined can be changed).
export function assertKnown(raw) {
  const unknown = Object.keys(raw ?? {}).filter(k => !NAMES.has(k));
  if (unknown.length) throw new SettingsRefusal(`unknown setting${unknown.length === 1 ? '' : 's'}: ${list(unknown)}`);
}
// The value written under either name. A canonical name (`pending_lifetime_seconds`) wins
// over the storage key (`pendingLifetime`) when both are present, so an admin write in the
// documented vocabulary is never shadowed by the stored copy. A computed value (the
// retention floor) may be stored as null, which means "not set".
export const stored = (raw, e) => raw[e.name] !== undefined ? raw[e.name] : raw[e.key];
const givenValue = (raw, e) => { const v = stored(raw, e); return v === null && e.floor ? undefined : v; };
// Translate a write in the documented vocabulary into the sandbox's storage keys, so a value
// given by its canonical name replaces the stored copy of the same setting.
export function toStoredKeys(data = {}) {
  const out = { ...data };
  for (const e of REGISTRY) if (e.name in data) { out[e.key] = data[e.name]; delete out[e.name]; }
  return out;
}
// The values in force and the reason each refused value was refused. A missing value is
// the default; a computed default (the retention floor) is derived from the values it
// hangs on, never set separately.
// Off hook for item 3: the added registry rows (maximum lifetime, skew, grant limits, key
// cache and the retention-floor ceiling) accept an out-of-range or unlimited value, so no
// hard limit holds for them (killed by test 211).
const BOUNDED = new Set(['max_lifetime_seconds','skew_seconds','grant_charge_limit','grant_seconds_limit','key_cache_seconds','retention_floor_seconds']);
export const registryBounded = name => !(process.env.VA_MUTATE === 'registry-unbounded-value' && BOUNDED.has(name));
export function resolve(raw = {}) {
  const values = {};
  for (const e of REGISTRY) { const given = givenValue(raw, e); values[e.name] = given === undefined ? (e.floor ? e.floor(raw) : e.default) : given; }
  // The settings a computed bound hangs on (maxLifetime, skew) are not registry rows, so the
  // checks see the raw configuration as well as the resolved registry values.
  const all = { ...raw, ...values };
  const errors = {};
  for (const e of REGISTRY) { const ok = registryBounded(e.name) ? e.check(values[e.name], all, raw) : true; if (ok !== true) errors[e.name] = ok; }
  return { values, errors };
}
export const explain = errors => Object.entries(errors).map(([name, reason]) => `${name}: ${reason}`).join('; ');
// Used at start (the server does not start) and at the admin call (the change is refused),
// with one clear message either way.
export function resolveStrict(raw = {}) {
  assertKnown(raw);
  const { values, errors } = resolve(raw);
  if (Object.keys(errors).length) throw new SettingsRefusal(explain(errors));
  const pm = principalModel(raw);
  if (!PRINCIPAL_MODELS.includes(pm)) throw new SettingsRefusal(`principal_model: must be ${PRINCIPAL_MODELS.slice(0, -1).join(', ')} or ${PRINCIPAL_MODELS.at(-1)}`);
  return values;
}
export const isSetting = name => NAMES.has(name);
export const canonicalName = name => ALIAS.get(name) ?? name;
// The registry values under the members the rest of the sandbox reads. A stored value that
// is out of range is not used: the default applies, so a corrupted store cannot loosen a
// setting. Nothing here reads record content.
export function settingsView(raw = {}) {
  const { values, errors } = resolve(raw);
  const out = { ...raw };
  for (const e of REGISTRY) out[e.key] = errors[e.name] ? (e.floor ? e.floor(raw) : e.default) : values[e.name];
  return out;
}
// The members to store for a proposed change, in the sandbox's own names.
export function storedValues(raw = {}) {
  const { values } = resolve(raw);
  return Object.fromEntries(REGISTRY.map(e => [e.key, values[e.name]]));
}

// The deployment record (S87): the settings in force as one JSON object, with a member for
// each setting of the core's table and for each further setting the server documents, and
// the principal model in force. It also states where each setting differs from its default
// (S89). Its `config_hash` is the base64url SHA-256 of the RFC 8785 serialization of that
// object; the hash member itself is not part of the object hashed.
export function deploymentRecord(raw = {}) {
  const { values } = resolve(raw);
  // Off: `config_hash` and the record omit two settings in force (the maximum lifetime and
  // the skew), so a change to either leaves the hash the same (killed by test 212).
  const omit = process.env.VA_MUTATE === 'deployment-record-omits-setting';
  const record = {
    v: 1,
    ...Object.fromEntries(Object.entries(values).filter(([name]) => !(omit && ['max_lifetime_seconds','skew_seconds'].includes(name)))), // one member per setting of the core's table
    ...(process.env.VA_MUTATE === 'principal-model-omitted' ? {} : { principal_model: principalModel(raw) }),
    audience: raw.audience ?? null,
    preconditions: !!raw.preconditions,
    approver_types: raw.operationTypes ?? raw.approverTypes ?? [],
    approvers: raw.approvers ?? {},
    page_administrators: raw.pageAdministrators ?? {},
    grant_limits: raw.grantConfig ?? {},
    retention_floor_applied_seconds: Math.max(values.retention_floor_seconds ?? 0, values.pending_lifetime_seconds),
    deviations: Object.fromEntries(REGISTRY.filter(e => values[e.name] !== (e.floor ? e.floor(raw) : e.default)).map(e => [e.name, values[e.name]])),
  };
  return { ...record, config_hash: hash(record) };
}
// S85: the effect-changing part of the configuration, "what a write does (a value fixed by
// configuration under S4) or who may approve (S22, S76)". It holds every registry entry
// marked `effect`, the operation's approver types, `preconditions`, and the two account
// lists that name who may approve (the named approvers and the page administrators). Each
// approval record stores this hash and every grant stores it too; only this one is
// compared, so a change to a setting that cannot change a write does not retire an
// approval. The lists are sorted so that a reordering of the same people is not a change.
// It never includes the agent's change, so it stays out of the change hash.
const namedLists = raw => {
  // Off: a change to a named-approver or administrators list leaves the effect record as
  // it was, so an approval made before the change still matches (killed by test 209).
  if (process.env.VA_MUTATE === 'approver-rule-change-unbound') return { approvers: null, page_administrators: null };
  const each = obj => Object.fromEntries(Object.entries(obj ?? {}).sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0).map(([account, people]) => [account, Array.isArray(people) ? [...people].sort() : people]));
  return { approvers: each(raw.approvers), page_administrators: each(raw.pageAdministrators) };
};
export function effectRecord(raw = {}) {
  const { values } = resolve(raw);
  return {
    v: 1,
    settings: Object.fromEntries(REGISTRY.filter(e => e.effect).map(e => [e.name, values[e.name]])),
    ...namedLists(raw),
    operation_types: raw.operationTypes ?? raw.approverTypes ?? null,
    preconditions: !!raw.preconditions,
  };
}
export const effectHash = raw => hash(effectRecord(raw));
export const configHash = raw => deploymentRecord(raw).config_hash;
// The canonical form the deployment record prints (RFC 8785, RFC 8785 = JCS).
export const canonicalRecord = raw => jcs(deploymentRecord(raw));
