// Milestone 1, WP2: the one place a transport envelope becomes a request. MCP (stdio and
// the connector), the HTTP mapping and the in-process core all pass what they received
// to shapeRequest(); nothing else parses arguments, collects receipts or looks at inputs
// outside the change object. It reads no state and computes no hash, so every answer it
// gives is the same whatever any record holds (S65: "the server returns `invalid_input`
// only for reasons that follow from the request, the operation's schema and the server's
// configuration").
//
// It never removes a member. S4: "The server MUST execute exactly the arguments it
// hashed." S34: "An input the server cannot classify as a selector, a field or a
// documented record identifier MUST mean no match." A member the operation does not
// document therefore stays in `arguments`, is hashed, is shown to the approver and makes
// every grant not match (CONFORMANCE tests 32 and 58 expect the normal approval request
// for it); the only members ever taken out are the operation's approval fields (S2), and
// those are taken out in one place, changeObject().
import { jcs, object, parseJSON } from './json.mjs';
import { actionFor } from './core.mjs';
const mutated = name => process.env.VA_MUTATE === name;
// S3/S48: an invalid_input refusal says what kind of input was refused.
export const INPUT_KINDS = {
  'arguments must be object': 'The arguments are not a JSON object, so the change was refused.',
  surrogate: 'A string in the arguments contains a lone surrogate character, which cannot be serialized, so the change was refused.',
  number: 'A number in the arguments cannot be serialized exactly as JSON, so the change was refused.',
  duplicate: 'The arguments contain a duplicate member name, so the change was refused.',
  'unsafe integer': 'The arguments contain an integer beyond the safe range for exact JSON numbers, so the change was refused.',
  key: 'A member name in the arguments is not valid JSON, so the change was refused.',
  'not JSON': 'The arguments contain a value that is not JSON, so the change was refused.',
  trailing: 'The arguments have extra content after the JSON value, so the change was refused.',
  value: 'The arguments are not valid JSON, so the change was refused.',
  string: 'A string in the arguments is not valid JSON, so the change was refused.',
  colon: 'The arguments are not valid JSON, so the change was refused.',
  comma: 'The arguments are not valid JSON, so the change was refused.',
};
export const UNSERIALIZABLE = 'The arguments cannot be hashed and serialized, so the change was refused.';
// S2: the approval fields of every guarded operation of this sandbox, as JSON Pointers.
export const APPROVAL_FIELDS = ['/confirmation', '/approval_receipt'];
const BAD_IDENTIFIER = 'A record identifier in the request is missing or is not a string, so the change was refused.';
// The per-operation schema: the types of the members each operation documents. A member
// outside it is kept (see above); a documented member of the wrong type is refused.
const isCopy = operation => /:copy_record_owner$/.test(operation ?? '');
function schemaFault(operation, args) {
  // S65: whether a record identifier in the request is a string follows from the
  // request, not from record state.
  if (!mutated('nonstring-identifier-accepted')) {
    const entries = args.records !== undefined ? args.records : (args.id !== undefined ? [{ id: args.id }] : undefined);
    if (entries !== undefined && (!Array.isArray(entries) || entries.some(e => !e || typeof e !== 'object' || typeof e.id !== 'string'))) return BAD_IDENTIFIER;
    if (isCopy(operation) && (typeof args.source !== 'string' || typeof args.target !== 'string')) return BAD_IDENTIFIER;
  }
  // S65: an entry's properties, when the entry has them, must be an object.
  if (!mutated('null-properties-accepted')) {
    const entries = args.records !== undefined ? args.records : undefined;
    if (Array.isArray(entries) && entries.some(e => e && typeof e === 'object' && Object.hasOwn(e, 'properties') && !object(e.properties)))
      return 'A record entry has properties that are not an object, so the change was refused.';
  }
  return undefined;
}
// shapeRequest(envelope) -> shaped request | invalid input
//   envelope  { account, principal, operation, args | rawArguments, meta, receipt, effects,
//               inputResponses, excludeGrants } exactly as the transport holds them.
//               `rawArguments` is the JSON text where the transport still has it (the HTTP
//               mapping); the MCP SDK has parsed the arguments before the server sees
//               them, so over MCP duplicate member names and integers beyond 2^53-1
//               cannot be detected (AMBIGUITIES.md).
//   result    { ok:true, shaped:true, account, principal, operation, args, action, token,
//               receiptFault, meta, inputResponses, excludeGrants }
//             or { ok:false, error:'invalid_input', message, kind }.
// The members account, principal and operation come from the authenticated credential
// and the request target, never from the arguments (S1).
const SHAPED = new WeakSet(); // the objects this function returned; a flag on an envelope proves nothing
export function shapeRequest(envelope) {
  if (envelope && typeof envelope === 'object' && SHAPED.has(envelope)) return envelope;
  const { account, principal, operation } = envelope ?? {};
  const invalid = (message, kind) => ({ ok: false, error: 'invalid_input', message, kind, account, principal, operation });
  // Section 7 with S17: a request the tool's own schema refuses is `invalid_input`, whose
  // `message` names what was invalid, given through this one mapping and recorded like
  // every other refusal. The MCP guard hands the schema's answer here rather than
  // returning the SDK's own error, so a guarded call never bypasses the core.
  if (envelope && typeof envelope.schemaFault === 'string' && !mutated('schema-fault-as-sdk-error'))
    return invalid(envelope.schemaFault, 'schema');
  let args;
  try {
    args = envelope.rawArguments !== undefined ? parseJSON(envelope.rawArguments) : (envelope.args ?? {});
    if (!object(args)) throw Error('arguments must be object');
    jcs(args);
  } catch (e) { return invalid(INPUT_KINDS[e.message] ?? UNSERIALIZABLE, e.message); }
  // S4: "An input outside the change object that changes what the write does (an HTTP
  // header, a session setting) MUST be refused on guarded operations or copied into
  // `arguments` under a documented name before hashing." S63: `invalid_input` "arises
  // before a hash is computed and carries none". So it is refused here, before any state
  // is read and before anything is hashed.
  if (!mutated('effects-refused-after-hash') && envelope.effects && Object.keys(envelope.effects).length)
    return invalid('The request carries inputs outside the change object, which cannot be approved, so the change was refused.', 'effects');
  const fault = schemaFault(operation, args);
  if (fault) return invalid(fault, 'schema');
  // Every receipt the request carries, wherever it carries it (S5): `_meta`, the
  // receipt argument, the HTTP header. More than one, or one that is not a single
  // string, is a fault the core answers `approval_invalid` at step 4.
  const tokens = [];
  for (const [k, v] of Object.entries(envelope.meta ?? {})) if (k.endsWith('/receipt')) tokens.push(v);
  if (Object.hasOwn(args, 'approval_receipt')) tokens.push(args.approval_receipt);
  if (envelope.receipt !== undefined) tokens.push(envelope.receipt);
  const receiptFault = tokens.length > 1 || tokens.some(t => typeof t !== 'string' || t.includes(','));
  const shaped = {
    ok: true, shaped: true, account, principal, operation, args, action: actionFor(operation, args),
    token: receiptFault ? undefined : tokens[0], receiptFault, receipt: envelope.receipt,
    meta: envelope.meta, inputResponses: envelope.inputResponses, excludeGrants: envelope.excludeGrants,
    ...(mutated('effects-refused-after-hash') && envelope.effects ? { effects: envelope.effects } : {}),
  };
  SHAPED.add(shaped);
  return shaped;
}
