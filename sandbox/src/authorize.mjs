// Milestone 1, WP1: the one permission decision of the sandbox and the one read that
// resolves an identifier. No other module reads a permission table (permissions,
// field_permissions, read_fields, members, record_permissions, write_scopes,
// definition_readers): core.mjs, server-issued.mjs, server-grants.mjs, mcp-server.mjs
// and issuer.mjs call authorize() and act on its decision. The Sor methods it calls
// (can, canFields, belongs, recordRow, mayReadRecord, mayWriteRecord, writeScoped,
// hasReadDenials, mayReadDomain, deniedFields, established, knows) are the low-level
// source and have no other caller in src/.
//
// S76: "The model MUST state separately what a person may change (S22, S33, S46), what a
// person may see (S53), what a principal may read (S60(a), S72, S77), which definitions of
// an object type a principal may see (S48, S65), and what a principal may write (step 1
// of Section 6 of the core); an answer to one is not an answer to another." Each purpose
// below is one of those answers. S76 also: "a principal or person the model has not
// affirmed MUST be treated as not permitted", so every dimension fails closed.
import { copySource, fields, identifiers, leaves } from './fields.mjs';
import { actionFor } from './core.mjs';
const mutated = name => process.env.VA_MUTATE === name;
const unique = values => [...new Set(values)];
const isQuery = operation => /:update_by_query$/.test(operation ?? '');

// S78: "MUST compare, on every read of record state ... the identifier returned with the
// identifier named, both in a canonical form it documents that does not depend on record
// state." The canonical form of an identifier is its exact string. This is the single
// merge-resolution read: every read of a record the server makes for a request, a page or
// read_record goes through it, so no caller can use a record without having compared the
// two identifiers. `record` is what the system of record returned; where `redirected` is
// true it is another record, which the caller may use only for a subject that
// authorize() says may read `resolved`.
export function resolveIdentifier(sor, account, id) {
  const record = sor.get(account, id);
  const redirected = !!record && record.id !== id;
  return { named: id, resolved: record ? record.id : id, exists: !!record, redirected, present: !!record && !redirected, record };
}

// What a request reads: the fields and records its answer depends on (S60(a)).
function readScope(change, request) {
  const args = change.arguments, copy = copySource(change);
  const copied = request.copies ?? (copy ? [{ record: copy.record, fields: copy.fields }] : []);
  const names = unique([...fields(change), ...leaves(args.filter ?? {}), ...copied.flatMap(c => c.fields)]);
  const records = unique([...identifiers(change, request.records), ...copied.map(c => c.record)]);
  const entries = Array.isArray(args.records) ? args.records : [{ properties: args.set ?? args.properties ?? (copy ? { owner: null } : {}) }];
  // S62: "Where the `version` kind is used, the answer depends on every field of the
  // record, so S60(a) holds only for a principal that may read the whole record." The
  // same holds wherever a request sets no field on a record (a delete, `properties: {}`):
  // the answer then depends on the record itself, and an empty set of written leaves
  // never makes a principal a reader (S60(a), S62).
  const whole = !mutated('empty-leaves-make-a-reader') && (actionFor(change.operation, args) === 'delete' || entries.some(e => !leaves(e?.properties ?? {}).length));
  return { names, records, whole, domain: isQuery(change.operation) };
}
function mayRead(sor, account, id, operation, { names = [], records = [], whole = false, domain = false }) {
  if (!sor.belongs(account, id)) return 'membership';
  if (!sor.can(account, id, operation, 'read')) return 'operation';
  if (!sor.canFields(account, id, operation, names, 'read')) return 'fieldRead';
  if (!records.every(r => typeof r === 'string' && sor.mayReadRecord(account, id, r))) return 'recordRead';
  if (whole && sor.hasReadDenials(account, id, operation)) return 'wholeRecord';
  // S72: the model must affirm the whole domain a query addresses.
  if (domain && !sor.mayReadDomain(account, id, operation, names)) return 'domain';
  return undefined;
}

// authorize(sor, subject, request, purpose, stateAccess) -> decision
//   subject      { id, authenticated? }: a principal (purposes write, read) or a person.
//   request      { account, operation, change | arguments, records?, copies?, coveredScope?,
//                  scope? } — `change` is a change object (only its account, operation and
//                  arguments are used); `records` the identifiers a query resolved;
//                  `scope` an explicit read scope { names, records, whole } for a read of
//                  one record (read_record, an applied identifier, a merge resolution).
//   purpose      write   what a principal may write (step 1 of Section 6, S60(c))
//                read    what a principal may read (S60(a), S62, S72, S77, S78)
//                approve what a person may change (S22)
//                grant   the same for the maker of a grant, at offer and at use (S46)
//                view    what a person may see (S53)
//                issuer  approve and view together (the organization issuer's page)
//   stateAccess  { resolve(id) }: the only record state a permission decision may use, and
//                only for the step 1 record-scope facts S60(c) and S78 permit.
// The decision is { allowed, purpose, denied?, needsState?, reader?, definitions?,
// mayReadField(), deniedFields() }. `allowed` is true only when every dimension the
// purpose needs was affirmed; `denied` names the first one that was not.
export function authorize(sor, subject, request, purpose, stateAccess) {
  const account = request?.account ?? request?.change?.account, operation = request?.operation ?? request?.change?.operation;
  const id = subject?.id, args = request?.change?.arguments ?? request?.arguments ?? {};
  const change = { account, operation, arguments: args };
  const hasInput = request?.change !== undefined || request?.arguments !== undefined;
  const d = { purpose, allowed: false };
  const deny = dimension => { d.allowed = false; d.denied = dimension; return d; };
  const allow = () => { d.allowed = true; return d; };
  if (typeof id !== 'string' || !id || typeof account !== 'string' || !account) return deny('subject');
  d.mayReadField = path => typeof operation === 'string' && sor.canFields(account, id, operation, [path], 'read');
  d.deniedFields = type => sor.deniedFields(account, id, operation, type);
  const personPurpose = ['approve', 'grant', 'view', 'issuer'].includes(purpose);
  if (personPurpose && subject.authenticated !== true) return deny('authentication');

  if (purpose === 'write') {
    // Step 1 of Section 6: "Authenticate the credential and apply its ordinary permission
    // checks. A request the credential may not make is refused as usual and consumes
    // nothing."
    if (typeof operation !== 'string' || !sor.can(account, id, operation, 'write')) return deny('operation');
    if (!sor.belongs(account, id)) return deny('membership');
    if (!hasInput) return allow(); // the operation-level answer, before the input is checked (step 2)
    // S60(c), S65: the principal's own field-level write denial is an ordinary step 1
    // refusal, decided before any record read, so it cannot depend on record state.
    const copy = copySource(change);
    if (!mutated('principal-field-write-unchecked') && !sor.canFields(account, id, operation, unique([...fields(change), ...(copy ? copy.fields : [])]), 'write')) return deny('fieldWrite');
    if (mutated('record-scope-off') || !sor.writeScoped(account, id)) return allow();
    d.scoped = true;
    // S60(c)/S72: a write permission scoped by record does not affirm the whole domain a
    // query addresses, so the query is refused at step 1 without evaluating anything.
    if (isQuery(operation)) return request.coveredScope ? deny('recordScope') : allow();
    const action = actionFor(operation, args);
    const kinds = mutated('record-scope-refuses-create') ? ['create', 'update', 'delete'] : ['update', 'delete'];
    if (!kinds.includes(action)) return allow();
    const named = (args.records ?? (args.id ? [{ id: args.id }] : request.coveredScope && copy ? [{ id: copy.target, properties: { owner: null } }] : [])).filter(e => typeof e?.id === 'string');
    if (!named.length) return allow();
    // S60(c): "Where the write permission is scoped by record and the operation needs the
    // named record to exist (an update, a delete, an association), a missing record MUST
    // get the same step 1 refusal ... as a record the principal may not write, unless
    // S60(a) holds, in which case S64 applies." This is the one place a permission
    // decision reads record state, through stateAccess; without it the decision stays
    // closed and says that it needs the state.
    if (!stateAccess) { d.needsState = true; return deny('recordScope'); }
    for (const e of named) {
      const found = stateAccess.resolve(e.id);
      // Whether S60(a) holds for this entry is the full read model: the record named, the
      // record its identifier resolves to (S78), every field the request sets on it, the
      // record a copy reads from, and the whole record where no field is set (S62).
      const set = leaves(e.properties ?? {});
      const reader = mutated('step1-reader-operation-level')
        ? sor.can(account, id, operation, 'read')
        : !mayRead(sor, account, id, operation, {
          names: unique([...set, ...(copy ? copy.fields : [])]),
          records: unique([e.id, ...(found.redirected ? [found.resolved] : []), ...(copy ? [copy.record] : [])]),
          whole: !mutated('empty-leaves-make-a-reader') && (action === 'delete' || !set.length),
        });
      // S78: "the server MUST establish at step 1 whether the named identifier resolves to
      // another record and treat one that does as a missing record under S60(c)."
      const present = found.exists && !(found.redirected && !mutated('scope-resolved-record-writable'));
      if (present ? !sor.mayWriteRecord(account, id, e.id) : !reader) return deny('recordScope');
    }
    return allow();
  }

  if (purpose === 'read') {
    if (typeof operation !== 'string') return deny('operation');
    // S48/S65: which definitions of the object type this principal may see.
    d.definitions = sor.established(account, id, args.objectType);
    const scope = request.scope ?? (hasInput ? readScope(change, request) : {});
    const failed = mayRead(sor, account, id, operation, scope);
    d.reader = !failed;
    return failed ? deny(failed) : allow();
  }

  if (personPurpose) {
    // S53: "the signed-in person belongs to the account". S22 says "in the account".
    if (!sor.belongs(account, id)) return deny('membership');
    if (!hasInput) return allow(); // the person's own pages (listing and revoking grants)
    if (typeof operation !== 'string') return deny('operation');
    // S53/S22: a covered copy sets the owner of its target from the owner of its source.
    // A person who views it must be able to read that field and the source record; a
    // person who decides it must hold the permission to make the change, which is the
    // write on the field and the target and the read of the source it copies from.
    const copy = mutated('copy-approver-unchecked') ? null : copySource(change);
    const target = copy && typeof copy.target === 'string' ? [copy.target] : [];
    const ids = unique([...identifiers(change, request.records), ...target]);
    const mayChange = () => {
      if (!sor.canFields(account, id, operation, unique([...fields(change), ...(copy ? copy.fields : [])]), 'write')) return 'fieldWrite';
      // S22/S46 with a record-scoped write permission (S22, S46): a record with no
      // row is not affirmed, exactly as step 1 treats the principal. Without a scope the
      // model grants by object type, and only an explicit denial refuses.
      const scoped = !mutated('approver-scope-off') && sor.writeScoped(account, id);
      if (!ids.every(r => { const row = sor.recordRow(account, id, r); return scoped ? row?.can_write === 1 : row?.can_write !== 0; })) return 'recordWrite';
      if (copy && !(sor.canFields(account, id, operation, copy.fields, 'read') && sor.recordRow(account, id, copy.record)?.can_read !== 0)) return 'copySource';
      return undefined;
    };
    // S53: what a person may see is decided from permissions alone, never from
    // the record's current values; the page then shows values at the set leaves only.
    const maySee = () => {
      if (!sor.canFields(account, id, operation, unique([...fields(change), ...(copy ? copy.fields : []), ...leaves(args.filter ?? {})]), 'read')) return 'fieldRead';
      if (!unique([...ids, ...(copy ? [copy.record] : [])]).every(r => sor.recordRow(account, id, r)?.can_read !== 0)) return 'recordRead';
      return undefined;
    };
    const failed = purpose === 'view' ? maySee() : purpose === 'issuer' ? (mayChange() ?? maySee()) : mayChange();
    return failed ? deny(failed) : allow();
  }
  return deny('purpose');
}
// S46 for a grant receipt of the signed-receipts profile. That profile leaves the
// person's permission to the issuer; the server's own model answers only for a person it
// holds a membership answer about, and for such a person S46 applies at use.
export function modelKnows(sor, account, subjectId) { return typeof subjectId === 'string' && sor.knows(account, subjectId); }
