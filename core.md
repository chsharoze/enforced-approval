# Enforced Approval

Server-side approval of exact agent actions.

Draft 0.2, 2026-11-26. Core document. Author: Sharoze Iftikhar.

## 1. What this is

This specification states the rules a server follows to refuse an agent's write unless an approval
exists for that exact change. It is written for the implementer of a server that holds the credential
to a system of record, for example an MCP server in front of a customer records system. It is not a
framework, a policy language or a receipt format.

This core defines the change hash, the properties of an approval, the verification steps, refusals,
consumption and the audit record. Two profiles define how the approval is obtained:

- **Server-issued approval** (`profile-server-issued.md`). The server obtains the approval itself, on
  its own approval page. The client carries nothing.
- **Signed receipts (experimental)** (`profile-signed-receipts.md`). An issuer that the organization
  registers with the server signs a receipt, and the client carries it on the request.

A server claims conformance to this core plus at least one profile. A server that accepts receipts
claims conformance separately for each receipt encoding it accepts. A product claim and a deployment
claim mean different things (Section 11.5).

Sections 3 to 11 are normative, as are the conformance statements of this section. Section 2 is informative; where it restates a requirement, the requirement governs. The key words MUST, MUST NOT, SHOULD, SHOULD NOT and MAY are used as in
RFC 2119 and RFC 8174 when they appear in capitals. Each requirement has an identifier: S for servers,
I for issuers. Identifiers never change and are never reused. Some live in a profile, so the numbers
in this document have gaps. The conformance tests cite them.

## 2. Problem and threat model

Many write tools ask for approval in two ways only. They tell the model to show the change and ask,
and they have an argument the model fills in to say that approval happened. The server cannot tell an
approved call from an unapproved one, because the party that proposes the change also reports the
approval. A study of a sample of the official MCP registry found that about 90% of destructive tools
have no server-side confirmation [STUDY]. The MCP specification leaves the check to the host
[MCP-TOOLS] and says that MCP "cannot enforce these security principles at the protocol level" [MCP].

A prompt in the client is useful, and this specification does not replace it. It covers what a client
prompt cannot:

- T1. The client does not prompt: a headless agent, an automatic permission mode, or a client the
  organization does not control.
- T2. A person approved once, and the approval was reused for later, different changes.
- T3. The model sets the approval argument itself, by mistake or after prompt injection.
- T4. The change that runs differs from the change that was shown.
- T5. Afterwards, nobody can show who approved which change.

Out of scope: an approver who approves without reading; a grant or policy that is too wide; a
compromised server or issuer; reads, and data leaving through reads; write paths that do not pass the
guarded server; side effects that the system of record adds to an approved write; a permission model (S76) set wider than the system of record's own scopes. A policy that reads free-text values of the change object can be steered by the agent that wrote them (I4). Read tools are out of scope, but whether a record exists is record state (Section 3): a read tool on the same server should answer a record the principal may not read as it answers an absent one, or it tells the agent what S60 withholds.

Residual disclosures. For every guarded operation, a principal can still learn (c), (d), (g) and (i). For a covered operation a non-reader can also learn (f), and any principal (h). Items (c), (d), (f) and (i) are the exceptions (c), (d), (f) and (i) of S60 (Section 7), restated here and accepted; (a) is the reader case, and (b) and (e) are unused:

- (c) Whether the principal may make the write at all. A refusal for lack of permission at step 1 of Section 6 is answered as usual, including where the permission is record-scoped. What the write permission is scoped by. Where it is scoped by record, `approval_required` tells the principal that the named record exists and that it may write it. For an upsert, a step 1 refusal can tell the principal that the named record exists and that it may not write it. These answers cost no approval.
- (d) Whether a grant matches, and the `grant_status` of a grant that did not apply (S34, S35, S46, S55, S56). A match can depend on the permission of the person who made the grant on the named record (S46), and a request that matches no grant is not charged.
- (f) After a person approved a change, a covered request whose record changed is answered as not yet approved. An agent that knows an approval was given, from the profile's own signal to look again or from the person, learns that the record changed, at the cost of one approval per observation: that approval is closed as stale and is not consumed (S68(3)). With the `version` kind a change to any field of the record makes an approval stale.
- (g) The outcome of a write after consumption. Success, `conflict` and `execution_failed` each tell the principal something about the record, and the result of a write under a grant states the records remaining (S36). Under a person's approval each observation costs one approval. Under a grant no person decides each write, so a principal holding a grant observes these outcomes within the grant's record limit, charged as S19 states. An outcome also tells the principal about a record the request only refers to. In a batch each record entry has an outcome, so one approval gives one observation per entry. A created identifier tells whether an upsert created its record and, where identifiers are sequential, how many records were created between two writes.
- (h) Whether S60(a) holds for a named record, which the presence of `change` shows.
- Response time. Reading and replacing a record takes time, and S60 only asks that it not differ observably.
- (i) A read of one record that fails where others succeed (S67). For a covered operation, during such a failure a non-reader's repeat is answered from the context until the open record is displayed and `approval_unavailable` afterwards, which tells it that the page was opened.
- For a person's approval, S22 is checked when the person decides and not again at use, so an approval authorises its write until it expires, also where that person has since lost the permission. A write under a grant is checked again at use against the permission of the person who made the grant (S46). Where S74 applies, a decision or a grant use can commit up to its bound, plus any delay in the source's own answer, after the permission was withdrawn, the write of a grant use is sent after that commit, and a page sent within the bound stays in front of the person.
- A principal whose read permission is withdrawn is answered as a reader, before consumption, until the documented period of S60 ends.
- Where the join identifier can be reassigned, a person who is given another person's address carries that person's standing until the proxy and the system of record are both updated (S75).
- An agent that operates the person's own signed-in browser acts with that person's interactive session. No check on an identity assertion or a session can tell the two apart, and S38 and S75 do not address it. It is narrowed by short sessions and by a second factor that needs a physical action for each decision on the approval pages.
- Where S78 applies and the system of record offers neither a write conditional on the identifier nor a refusal, an identifier that comes to resolve to another record between the server's check and the write changes that other record; the outcome is then `misdirected` where the answer to the write shows it. Where a read does not reveal the resolution, the check cannot find it.
- Whether an object type has a definition whose visibility is restricted. Under S48 a property that is not defined is answered `invalid_input` to a principal established to see every definition of the type and as any other change otherwise, so the answer changes when the type gains or loses a restricted definition.

Item (g) concerns outcomes after consumption, which S60 does not govern. Item (h) follows from S60(a).

Delegated credentials. The most common deployment is a connector that acts with the signed-in user's own delegated permissions, so the agent can read and write whatever that user can. Where the principal may read everything the person may, the rules on what an agent may learn (S60 to S80) have little to protect. Every approval rule still applies in full: the approval is for the exact change, it is used once, the server enforces it, the audit record names the approver, and a form mode elicitation answer is not an approval (P7, S21).

## 3. Terms

- **Server**: the component that holds the credential to the system of record and executes the write.
- **Account**: the tenant in the system of record that the request acts on.
- **Organization**: the party that owns the account and decides who may approve what.
- **Agent**: the AI system and client that send the request.
- **Principal**: the identity the server derives from the agent's authenticated credential. Agents
  that share one credential are one principal. The principal is the credential the connection
  presents, also where that credential is delegated from a person, as when a connector acts with the
  signed-in user's own permissions. That person is a different party when they act on the server's
  approval page after signing in there, so the same human may approve a change their own agent
  requested: on the page, under S22 and S38, and never through the connection (S21, P7). Where this
  specification bars the agent from approving, it bars the principal and the connection, not the
  person from whom a credential was delegated.
- **Guarded operation**: a tool or endpoint for which the account requires approval.
- **Change**: one request to a guarded operation, identified by its change hash (Section 5).
- **Approval fields**: arguments whose only purpose is to state that approval happened (S2).
- **Approver**: a person, a grant or a policy (Section 9).
- **Record**: a data object of the account held in the system of record, as distinct from the account's schema.
- **Schema**: object types, field definitions, option lists and pipeline and stage definitions that the server documents as schema and that every member of the account may see. A definition whose visibility the system of record restricts to some members is record state for a principal not established to see it. Where the server cannot tell whether a definition's visibility is restricted, it treats the definition as restricted.
- **Record state**: the existence and contents of any record, including one a request only refers to, such as an owner or an associated record. Schema is not record state. A record a request only refers to is not a record the change touches: it has no `preconditions` entry and is not counted under S19. Whether a record identifier resolves to a record with another identifier, as after a merge, is record state, and the identifier it resolves to is content read from the system of record.
- **Approval record**: an entry in the server's own store for one change and its approval, as distinct from a record of the account. Pending, open, approved, denied, cancelled, granted, consumed, superseded and stale records are approval records, as is the record in which the server keeps a consumed approval and its outcome (S13, S35, S69, S80). Consumption and outcome records are audit records (Section 10).
- **Covered operation**: a guarded operation that uses `preconditions` or `resolved`, or copies a value
  derived from record state into `arguments` (S67).
- **Request key**: the identity of a request to a covered operation, independent of record state (S67).
- **Approval context**: the group of approval records for one request key (S67).
- **Reader**, of a request: a principal for which S60(a) holds. **Non-reader**: one for which it does not.
- **Distinguishing argument**: an optional argument whose only effect is to tell one intended write
  from another (S69(4)).
- **Grant**: a person's approval of a bounded set of future changes.
- **Issuer**: the party that records the approver's decision. In the server-issued profile it is the
  server. In the signed-receipts profile it is an issuer the organization registers.
- **Receipt**: the statement, with the properties of Section 4, that one approver approved one change.
  In the server-issued profile it is an approved record in the server's own store. In the
  signed-receipts profile it is a signed object the client carries.

## 4. Receipt properties

These properties are what is normative about a receipt. Each profile, and each receipt encoding a
server accepts, documents how it meets them. The default encoding is in the signed-receipts profile.

- P1. **Exact change.** The receipt carries or is found by the change hash of the change it approves.
- P2. **One server, one account, one principal.** The receipt is for one server, and the change hash
  covers the server, the account and the principal. A receipt cannot be spent by another principal.
- P3. **Single use.** The receipt has a unique identifier and authorizes at most one execution.
- P4. **Expiry.** The receipt has an issue time and an expiry time.
- P5. **Approver.** The receipt states the approver type and an identifier for the approver.
- P6. **Authentic.** The receipt is protected against change by an issuer the server trusts for that
  account.
- P7. **Not self-made.** The agent cannot produce a receipt with the credentials and channels it holds.
  Under every profile, nothing received on the agent's connection is an approval, including a form mode
  elicitation answer.

## 5. Change object and change hash

The change object is a JSON object with these members and no others, except the optional members of
Section 5.1:

| Member | Value |
|---|---|
| `v` | The integer 2. |
| `audience` | The server's own identifier. For MCP with OAuth, its canonical resource URI [MCP-AUTHZ]. Otherwise an identifier the server documents. |
| `account` | The server's identifier for the account, taken from the authenticated credential. |
| `principal` | The server's identifier for the principal, taken from the authenticated credential. |
| `operation` | `mcp:tools/call:<tool name>`, or `http:<METHOD>:<request target>` with the request target (path and query) exactly as received. |
| `arguments` | The `arguments` object of the `tools/call` request (the empty object if absent), or the JSON object in the HTTP request body. The approval fields are removed, and any inputs copied in under S4 are added. For a covered operation, a value derived from record state and copied in under S4 is added after the request key is computed (S67); other inputs copied in under S4 are part of the request key. |

The change hash is the base64url encoding, without padding, of the SHA-256 digest of the change object
serialized with the JSON Canonicalization Scheme (RFC 8785).

- S1. The server MUST compute the change hash itself, from the request it received, the credential it
  authenticated and its own configuration. It MUST NOT use a hash, audience, account or principal
  supplied by the request.
- S2. For each guarded operation the server MUST define its approval fields, each identified by a JSON
  Pointer. These are removed before hashing and MUST NOT affect whether the request is authorized or
  what the write does.
- S3. The server MUST refuse a guarded request whose arguments are not a JSON object or cannot be
  serialized under RFC 8785. Where its request layer exposes them, it MUST also refuse duplicate member
  names and integers beyond 2^53-1, which parsers alter silently. Identifiers and exact decimals belong
  in strings.
- S4. The server MUST execute exactly the arguments it hashed. An input outside the change object that
  changes what the write does (an HTTP header, a session setting) MUST be refused on guarded operations
  or copied into `arguments` under a documented name before hashing. Values fixed by configuration for
  the account and the operation are allowed and SHOULD be shown to the approver. Any value that depends
  on the request or on record state MUST be in the change object or covered by `preconditions`. For a copied value in a covered operation, see S67. For the distinguishing argument of a covered operation, see S69(4).

### 5.1 Optional members

An operation MAY use these members. The server documents which, per operation. Covered operations are experimental in this draft (Section 12). A server need not offer covered operations (S67). A server whose operations use neither member and copy no value derived from record state has no approval contexts and no check that a record is unchanged between approval and write; S60, S63 to S65 and S77 still apply to it, and S71 says what its approval pages tell the approver.

An operation that upserts, updates relative to the current value, finds its record by a key other than its identifier, or selects records by a query depends on record state. The server MUST treat it as covered and give it `preconditions` or `resolved` as fits, and S72 applies where it evaluates record contents to find its target. An operation that resolves a related record by a key, such as a company by its domain name, copies a value derived from record state and is covered, and S72 applies to that lookup. A delete or an association by identifier is covered only if it uses `preconditions`. A create that carries a uniqueness key and is refused as a duplicate when repeated is not an upsert: it either creates or is refused, and is not covered for that reason. Refusing a duplicate does not by itself make a repeat the same write under S25: that depends on the system of record keeping the identity of the original write across retries, keyed as S25 requires, whatever the kind of operation.

| Member | Value |
|---|---|
| `preconditions` | An array with one entry per record the change touches: `record` (its identifier) and `state_hash` (S61). The `version` and `absent` members are withdrawn in Draft 0.2 (S62). |
| `resolved` | For an operation that selects records by a query: an object with `count` and `manifest_hash` (S61), for the records the query selects now. |

- S28. Where an operation uses `preconditions`, the server MUST fill them from the record's actual
  state each time it builds the change object, so a record that changed after approval gives a
  different hash and the receipt no longer matches. (The Draft 0.1 clause that refused a create whose record exists and an update whose record is gone as an ordinary conflict is withdrawn; see S64.) It MUST make the write conditional
  on the preconditions where the system of record supports conditional writes, and otherwise MUST
  document that the check is not atomic. For a repeat of a consumed request key of a covered
  operation, see S67 and S69.
- S29. Where an operation uses `resolved`, the server MUST run the query each time it builds the change
  object, so a selection that changed after approval gives a different hash. It MUST then write to
  exactly the identifiers it hashed, without running the query again, and MUST refuse a selection
  larger than its documented limit with `selection_limit`. This is the one case where the write is defined by the change
  object and not by the arguments alone. For a repeat of a consumed request key of a covered
  operation, see S67 and S69.

- S61. `state_hash` and `manifest_hash` MUST be computed as HMAC-SHA-256 under a secret key held only by the server, over the RFC 8785 serialization of the values below, encoded as base64url without padding.
  `state_hash`: `{"purpose":"enforced-approval/state_hash/2","audience":A,"account":C,"operation":O,"record":R,"state":S}`, where S is `{"kind":"absent"}`, `{"kind":"version","value":<token as a string>}` or `{"kind":"fields","value":{...}}`, the last holding the fields the request sets on that record, or, for an operation that sets no field on the record such as a delete or an association, the fields the server documents for that operation, which MUST include every field the approval page shows, each with the record's current value (`null` if unset). Such an operation MAY use the `version` kind where the token qualifies.
  `manifest_hash`: `{"purpose":"enforced-approval/manifest_hash/2","audience":A,"account":C,"operation":O,"arguments":G,"records":[...]}`, where G is the `arguments` member of the change object and `records` is the selected record identifiers as strings, sorted by UTF-16 code units.
  A, C and O are the `audience`, `account` and `operation` members of the change object. The key MUST have at least 256 bits from a cryptographic random source, MUST NOT be derived from account data, and MUST NOT be disclosed to agents, clients or issuers. All instances of a server share it. When the key is replaced, approvals of operations that use these members stop matching once the previous key is retired; a server MAY accept a match under the previous key for no longer than its documented maximum approval lifetime. While two keys are accepted, the server builds the complete change object under each accepted key and compares each as a whole; it MUST NOT mix keys within one change object. A match under either is a match, for an open record as for an approved one. The key published with the test vectors is for the vectors only and MUST NOT be used by a deployed server.

- S62. An entry of `preconditions` has exactly two members, `record` and `state_hash`. The members `version` and `absent` of Draft 0.1 are withdrawn; their cases are the `version` and `absent` kinds of S61. For a record that does not exist, the server MUST use the `absent` kind. For an existing record, the server MAY use the `version` kind only where the system of record changes the token on every write to that record; otherwise, and where the server cannot establish this, it MUST use the `fields` kind. A token qualifies only if every write to the record changes it to a value it has not had before for that record, by any path and to any field, including writes made by automation; a last-modified time that two writes can share does not qualify. Where the `version` kind is used, the answer depends on every field of the record, so S60(a) holds only for a principal that may read the whole record.

- S64. The clause of S28 that a create whose record exists and an update whose record is gone are refused as an ordinary conflict is withdrawn and restated here. Before an approval is consumed, the server MUST NOT refuse for either reason unless S60(a) holds, in which case it MAY, and except where S60(c) requires a step 1 refusal; otherwise it builds the change object, with the `absent` or actual state where the operation uses `preconditions`, and answers as for any other change. After consumption, where the record a create names exists or the record an update names is gone, the write MUST NOT take effect where the system of record offers a conditional write or itself refuses such a write. Where it offers neither, the server MUST check immediately before the write, MUST NOT send the write where that check finds the conflict, and MUST document that the check is not atomic with the write, as S28 allows. The read of record state at step 2 serves as this check only where the server makes no other call to the system of record between it and the write, and documents that consumption falls inside that window; otherwise it checks again after consumption. The server MUST answer `conflict` where it can establish that reason, from the system of record's answer or from its own check; otherwise it answers `execution_failed`, or reports the outcome as unknown (S69(3)) where it cannot tell whether the write took effect. It documents which of these it gives. A record that a create names exists where the system of record would refuse the create as a duplicate, by its identifier or by a uniqueness key the operation documents. Where the operation uses `preconditions`, in the server-issued profile the approval page MUST tell the approver that the record is missing or already exists, subject to S53. This requirement applies to every guarded operation, whether or not it uses `preconditions`, and does not make an operation covered (S67).

- S72. An operation that selects its target records by evaluating a predicate or a query, including
  one on the record identifier alone, or that finds its target record by a key other than the record
  identifier, reads what it evaluates. An operation that only names its records by identifier in its
  arguments is not such an operation. For such an
  operation the server MUST establish, from the system of record or from a permission model, neither
  of which consults record contents or the result of the evaluation, that the principal may read every
  field the evaluation uses, every field
  the request sets, and the identifier and existence of a record, on every record in the domain the
  evaluation addresses. That domain is fixed by the request and by configuration and MUST NOT be derived
  from the result: for an evaluation on the record identifier alone it is the records the request names;
  for any other evaluation it is what configuration fixes, for example an object type in an account.
  Where the model cannot affirm this for the whole domain, the server MUST treat the principal as not
  permitted and refuse the request at step 1 of Section 6 without evaluating anything, and its answer
  MUST NOT depend on which records the evaluation would select or on what any record holds. The step 1
  refusal is the `permission_denied` refusal of Section 7, which carries no member that depends on
  record state, and is recorded as Section 10 requires. For such an
  operation S60(a) is established this way and never from the result. A principal whose permission to
  read is scoped to particular records therefore cannot use such an operation unless the model affirms
  the whole domain. A filter fixed by configuration is evaluated under the same rule. A create's check
  for a duplicate, by identifier or by a uniqueness key, is a constraint at the time of the write under
  S64 and is not an evaluation under this requirement. For example: an update whose filter is a predicate the server evaluates over the identifier field is a query on the identifier; an update that takes a list of identifiers as its target names its records; an update of record R names its record; an upsert by identifier names its record and is covered through `preconditions`, not through this requirement.

- S78. Where the system of record resolves the identifier a request names to a record with another identifier, the write MUST NOT change that other record, to the extent S64 grades: it MUST NOT take effect where the system of record offers a write conditional on the identifier or itself refuses; otherwise the server MUST read the named record immediately before the write, for every guarded operation that names a record identifier, covered or not, under a person's approval or a grant, MUST NOT send the write where the identifier returned differs from the identifier named, and MUST document that the check is not atomic with the write. The read of record state at step 2 serves as this check only as S64 provides. A server whose system of record resolves identifiers this way MUST document it and MUST compare, on every read of record state and on the read this requirement adds before a write, the identifier returned with the identifier named, both in a canonical form it documents that does not depend on record state. After consumption, where the write was not sent or was refused, a create or an upsert is answered as S64 provides for a create whose record exists, and an update, a delete or an association as for an update whose record is gone. Before consumption the answer to a principal that may not read for an identifier that resolves to another record MUST be the answer for an identifier that names no record (S60(c), S64). In the server-issued profile, where the page shows record values to a person permitted to see them (S53) and the identifier resolves to another record, the page MUST say so and MUST NOT offer that person approval or a grant; any other person is shown nothing from the record. For a covered operation the server MUST use the `absent` kind (S61, S62) for an identifier that resolves to another record, so an approval given before the resolution is stale (S68(3)). The result does not carry the identifier it resolves to unless S77 permits it. Where a read the server makes shows that the identifier of a record the request only refers to resolves to another record, the server MUST NOT send the write; after consumption it answers `execution_failed` as S65 provides, and before consumption a non-reader is answered as for any other change. Where the system of record does not reveal the resolution on a read and offers no write conditional on the identifier, the comparison cannot find it; the server MUST document that a write through such an identifier can change the other record (Section 2). Where the write permission is scoped by record, the server MUST establish at step 1 whether the named identifier resolves to another record and treat one that does as a missing record under S60(c). Where the check is not atomic and the answer to the write shows that it took effect on another record, the server MUST record in the audit record that the write was applied and to which identifier, and MUST report that entry's outcome as `misdirected`: the write took effect, on a record other than the one named. It tells the principal that the record named should be checked and MUST NOT return the other identifier unless S77 permits it. Where the server shows outcomes to the approver, it shows this one.

## 6. Verification

For every guarded request, the server performs these steps in order and stops at the first failure.
Every failure is a refusal: the write does not run. A profile may meet a step by construction.

1. Authenticate the credential and apply its ordinary permission checks. A request the credential may
   not make is refused with `permission_denied` (Section 7) and consumes nothing.
2. Determine the account and the principal, check the input (S3) and compute the change hash.
3. Find the approval: the receipt on the request (signed receipts), or an approved record for
   this change hash or a matching grant (server-issued; for a covered operation, see S67). If there is none, refuse with
   `approval_required` or follow the profile's approval flow.
4. Check that the approval is well formed and comes from an issuer registered for this account.
   Otherwise refuse with `approval_invalid`.
5. Check that the issuer may approve this operation with this approver type. Otherwise refuse with
   `approver_not_authorized`.
6. Check that the approval is for this server. Otherwise refuse with `approval_invalid`.
7. Check the times: not issued in the future, not expired, and a lifetime within the server's
   maximum, each within the allowed skew. Otherwise refuse with `approval_expired`.
8. Check that the approved change hash equals the computed one. Otherwise refuse with
   `approval_mismatch`. For a covered operation in the server-issued profile, see S68(3).
9. Check that the account allows this approver type for this operation. Otherwise refuse with
   `approver_not_authorized`.
10. Consume the approval (Section 8). If it was already used, refuse with `approval_used`. If a grant
    check fails, refuse with `grant_exceeded`, or in the server-issued profile continue as for a
    request with no approval, and record nothing as used.
11. Execute the write once, then write the audit record of the outcome (Section 10).

- S6. The server MUST refuse a guarded request for which no receipt is presented and, in the
  server-issued profile, no approved record exists.
- S16. No content of the request, including approval fields, tool arguments and `_meta`, may turn the
  check off or widen it. A receipt is an extra condition, never a permission.

- S79. A server reached over a network MUST accept guarded requests, and serve its pages and decision requests, only where the client's connection used TLS. Where a proxy or edge terminates TLS, the server MUST accept requests only on a channel from that edge, which it authenticates, and MUST establish the scheme of the client's connection from a source the client cannot set, such as a marker the edge adds after removing any the client sent, or the server's own configuration, never from the request's own URL or from a header a client can send. The scheme of the hop between the edge and the server is not the client's scheme. An indication that the client's connection was plain HTTP is used only to refuse, never to accept. A request refused for this reason is not executed, matched or consumed and is answered with no page content; a redirect to the same location over TLS is permitted. The edge SHOULD refuse or redirect plain HTTP before it reaches the server. This applies to the agent's endpoint as well as to the pages. A credential sent over plain HTTP is exposed whatever the server answers: the server MUST treat a credential it knows it received over a plain HTTP client connection as disclosed. It MUST NOT act on that request, MUST record the event and MUST report it to an administrator; whether the credential is revoked is the account's policy.

## 7. Refusals

A refusal carries an `approval` object. `error` is always present. `change_hash` is present whenever the server computed one, except as S63 provides, so not after a refusal under S3. For `approval_required` the object also has `audience`, `operation`, `approver_types`, `max_lifetime` (seconds) and, where S63 permits, `change`: the change object as the server built it. For a covered operation, `request_key` is present where S67 provides. Each profile adds its own members.

```json
{ "error": "approval_required", "change_hash": "9UVEfyojuhKYMbk1pgjL1_U-H2oYAxLEg7uJ4SnfNjc",
  "audience": "https://mcp.crm.example/mcp", "operation": "mcp:tools/call:manage_records",
  "approver_types": ["person", "grant"], "max_lifetime": 300 }
```

The `change` member is left out of this example.

| `error` | Meaning | Used in |
|---|---|---|
| `approval_required` | No approval for this change. | Both |
| `approval_invalid` | Malformed, unregistered issuer or key, or another server. | Both |
| `approval_expired` | Not yet valid, expired, or too long a lifetime. | Both |
| `approval_mismatch` | Approval for a different change. | Signed receipts |
| `approval_used` | Already consumed. | Both |
| `approver_not_authorized` | Approver type or issuer not allowed here. | Both |
| `grant_exceeded` | Grant expired or record limit exceeded. | Signed receipts |
| `approval_unavailable` | Cannot verify or consume now (S15). | Both |
| `approval_denied` | A person denied this change. | Server-issued |
| `approval_cancelled` | The client declined or cancelled. | Server-issued |
| `approval_limit_reached` | Too many open approval requests. | Server-issued |
| `permission_denied` | The credential may not make this request: a refusal at step 1 of Section 6, including under S60(c) and S72. No change hash, no `change`, no approval link, and nothing that depends on record state the principal may not read. | Both |
| `invalid_input` | The request cannot be hashed (S3), or is invalid for a reason that does not depend on record state the principal may not read (S65). Its `message` names what was invalid. Where properties the request sets are invalid, its `invalid` member lists them as JSON Pointers. No change hash, no approval link. | Both |
| `conflict` | The record a create names exists, or the record an update names is gone. Before approval only where S60(a) holds, otherwise only after consumption (S64). Carries `change_hash` except as S68(1) provides. | Both |
| `execution_failed` | The write was refused or failed after the approval was consumed (S65). Carries `change_hash` except as S68(1) provides. Its `message` names a record-state reason only where S60(a) holds. | Both |
| `selection_limit` | The selection is larger than the documented limit (S29); reached only by a principal for which S72 holds. | Both |

In the server-issued profile a request whose hash matches no approval is answered `approval_required`,
so `approval_mismatch` (step 8 of Section 6) arises only where a receipt is presented.

**Recorded outcomes.** An answer under S69(2), S69(3), S69(5) or S80 carries the member
`recorded_outcome`, an object with these members: `outcome`, one of the outcomes of S77; `at`, the time
recorded for it, in seconds since the epoch; `sent_now`, always `false`, because no new write is sent;
`sent_again`, present and `true` only where the server sent the same write again under S25; and
`message`, which says the same in plain words. In a result, `recorded_outcome` is a member of the result.
Where the recorded outcome is `conflict` or `execution_failed`, the answer is a refusal whose `error` is
that value, and `recorded_outcome` is a member of its `approval` object (S80).

**Results that are not success.** The outcomes `in_progress` (S69(5), S80), `partial` (S77) and
`misdirected` (S78) are answered as results, never as refusals: on MCP an ordinary tool result without
`isError`, on HTTP status 200.

- MCP: a tool result with `isError: true`, with the `approval` object as JSON in a text content block
  (some clients pass only text to the model) and in the result's `_meta` under
  `org.enforcedapproval/refusal`. Not in `structuredContent`, which follows the tool's output schema.
- HTTP: status 403, also for `permission_denied` (503 for `approval_unavailable`, 429 with a `Retry-After` header for
  `approval_limit_reached`, 409 for `conflict` and 500 for `execution_failed`), with an `application/problem+json` body (RFC 9457) whose `type` is
  `https://enforcedapproval.org/problems/refusal`, one type for every refusal, with the `error` member
  inside the `approval` object telling them apart, and which has the `approval` object as an
  extension member. A principal that may not read receives `conflict` and `execution_failed` only after consumption (S64, S65), so these statuses give it no answer that differs with record state before consumption.
- S17. A refusal MUST NOT include any part of the write's result, and MUST be recorded (Section 10).
  The server MUST NOT echo a receipt in a refusal or write receipts to its logs. This means the receipt
  itself; its identifier is recorded as Section 10 requires.

- S60. Until an approval for the change has been consumed (S13), the server's answer to a guarded request MUST NOT depend on the state or existence of a record, or on the result of a query, except:
  (a) where the server has established that the principal may read every field and record the answer depends on;
  (c) a refusal at step 1 of Section 6 because the principal lacks permission for the write, or under S72 for the read. Where the write permission is scoped by record and the operation needs the named record to exist (an update, a delete, an association), a missing record MUST get the same step 1 refusal, identical in body, status and headers apart from values taken from the request and clock values, as a record the principal may not write, unless S60(a) holds, in which case S64 applies. This does not apply to a create or an upsert.
  (d) the outcome of grant matching (S34, S35, S46, S55) and `grant_status` (S56);
  (f) after a person approved a change, a covered request (S67) whose record changed is answered as not yet approved;
  (i) `approval_unavailable` where a read of record state the server needs did not complete; the rule S67 gives for such a read applies to every guarded operation.
  Item (b) is unused.
  Item (e) is unused. The selection limit of S29 is met only by a principal for which S72 holds.
  "Established" means an affirmative answer for that principal from the system of record, or from a permission model the server documents. What the server's own credential can read is not evidence. Where the server cannot tell, it MUST treat the principal as not permitted. The server establishes this for each answer. Before consumption it MAY reuse an affirmative answer for the same principal, fields and records for a finite period it documents, no longer than its maximum approval lifetime; it MUST establish it anew for every answer after consumption, including each recorded outcome returned under S14 or S69(2). The server SHOULD NOT let response time differ observably between cases this rule makes equal. This requirement applies to every guarded operation, covered or not.

- S63. A refusal carries `change_hash` where the server computed one, except as S66 and S68(1) provide; `invalid_input` arises before a hash is computed and carries none. Only an `approval_required` refusal carries `change`. Where the operation is covered (S67), the refusal includes `change` only where S60(a) holds for every field and record involved; otherwise it MUST omit `change` entirely and MUST NOT return a change object with members removed. For an operation that is not covered, `change` is always included. The sentence of Draft 0.1 Section 7 that `approval_required` carries the full change object is withdrawn.

- S65. Before an approval is consumed, the server returns `invalid_input` only for reasons that follow from the request, the operation's schema and the server's configuration. A validation of the request's input whose outcome depends on record state runs before approval only where S60(a) holds; otherwise it runs after consumption. This does not defer permission checks, approval verification, grant checks (S35, S46) or the selection limit (S29). A write that is refused or fails after consumption, for a reason other than S64, is answered `execution_failed`, except that a request in which at least one entry succeeded is answered `partial` (S77); the approval stays consumed and the audit record shows the failure and its reason. `conflict` and `execution_failed` after consumption are outcomes of the consumed approval, recorded as such (S14, S25), and include no part of a write's result (S17). `conflict` and `execution_failed` are refusals in the sense of S17 and are also recorded as the outcome of the consumed approval. Whether a record a request refers to exists is record state; whether a schema definition it refers to exists is not.

## 8. Consumption and execution

- S13. Consumption MUST be one atomic, durable transaction across all instances of the server, covering
  the receipt identifier, the grant counter and the consumption record, and MUST complete before
  execution starts. It MUST survive a restart. A receipt stays consumed if execution fails; a retry
  needs a new receipt. Used identifiers MUST be kept at least until the expiry plus the allowed skew.
- S14. A second request with a consumed receipt MUST NOT execute. When its change hash is the same, the
  server MAY answer with the recorded outcome of the first execution; that answer is a result, not a
  refusal. For what that answer states, see S80. For a covered operation, see S69, which applies in its place.
- S15. If the consumption store or the issuer registry is unavailable, or no source of keys for the
  issuer can be reached and no valid cached key exists, the server MUST refuse with
  `approval_unavailable` (fail closed). A key identifier that is still unknown after the one permitted
  refresh is not this case; it is `approval_invalid`.
- S25. The server MUST execute a consumed receipt's write at most once. If the outcome of the write is
  unknown (a lost response, a crash), the server MUST NOT send it again unless the system of record
  treats the repeat as the same write, keyed by the receipt identifier. A write lost before it was sent
  needs a new approval. After a batch that partly failed, the failed items are a new change with a
  new hash. Where the outcome is unknown and the system of record offers no way to treat a repeat as the same write, the server MUST NOT send the write again and answers that the outcome is unknown.

- S69. Identical requests after consumption. For a covered operation and every principal of it, once an approval has been consumed for a request key, whether the write then succeeded, was answered under S64 or S65, was `misdirected` (S78), or has an unknown outcome, the following hold for as long as the server keeps the consumed record under S13 or S35, a period the server MUST document and which is at least the period S13 or S35 requires:
  (1) An identical request MUST NOT execute, MUST NOT match a grant, and MUST NOT open an approval record, except that (3) governs an unknown outcome.
  (2) Where the outcome is recorded, the answer is that recorded outcome, whether or not record state changed since. The answer MUST identify itself, in a client-visible member named `recorded_outcome` and in its `message`, as the recorded outcome of an earlier attempt and give the time recorded for it: the time of the execution, or the time of consumption where the write was never sent. It MUST NOT imply that a new write occurred or that current record state was checked, and it MUST say that nothing was sent now and that a new write needs a new value of the distinguishing argument of item (4). It SHOULD give the time until which an identical request is answered this way.
  (3) Where the outcome is unknown, S25 applies unchanged: the server does not send the write again unless the system of record treats the repeat as the same write, in which case it MAY send it as S25 provides, and its answer then says that the write was sent again and gives the outcome. Otherwise the answer says that the outcome is unknown and that a write still wanted is sent as a new intended write. An unknown-outcome answer becomes the recorded outcome when the server learns the outcome of that execution; record state read afterwards MUST NOT decide that change. Where the system of record offers no way to learn the outcome, the answer stays unknown for as long as the consumed record is kept. This is expected. A consumed record whose outcome is unknown MUST be kept for at least a period the server documents, which MUST NOT be shorter than the bound the system of record states for completing a write, or, where it states none, a period the server documents as its assumption, and never shorter than the period it documents under S13 or S35. While the server holds that record, the approval page for a request that differs only in the distinguishing argument MUST say that an earlier write's outcome is not known.
  (4) A covered operation MUST accept, and MUST NOT require, an argument named in its documentation whose only effect is to distinguish one intended write from another. Its name SHOULD be `change_tag`; a server that uses another name MUST document it for each operation. It is part of `arguments` and is hashed, so a different value, or its absence, gives a different change hash and request key: a request without it and a request with it are different requests. It is not an approval field. The clause of S4 that the server executes exactly the arguments it hashed does not extend to this argument: the server MAY leave it out of the call to the system of record, and it MUST NOT change what the write does. For grants it is not a selector, a field or a record identifier: the server MUST leave it out when it derives a grant's terms and when it matches a grant (S32, S34, S47, S48), and its presence MUST NOT cause "no match". The approval page MUST tell the approver when a request from the same principal in the same account that differs only in this argument was denied, cancelled or consumed and the server still holds that record.
  (5) While the server knows that the execution for a consumed approval is still in progress, an identical request MUST NOT execute and is answered that the earlier request is in progress, that this request sent nothing, and that the client should ask again. That answer is a result, not a refusal, and its recorded outcome is `in_progress` (Section 7). Where the server can no longer tell whether that execution is running, item (3) applies.
  For a covered operation, this requirement applies in place of the clause of S14 on a same change hash, and in place of grant matching under S34 and S35 for a request that repeats a consumed request key. An answer under this requirement identifies the stored approved change; it MUST NOT describe current record state. The rules on which members a refusal or result may carry (S63, S68(1)) are unchanged, so any `change` or `change_hash` such an answer may carry is that of the stored change, and this requirement adds no member that those rules forbid.

- S77. The result of a write, and a recorded outcome returned under S14 or S69(2), MUST NOT carry content read from the system of record unless the server has established, as S60 defines, that the principal may read it. Text that the system of record returns in an error, such as a message or a description of a conflict, is content read from the system of record. A result MAY carry the outcome, which is one of success, `conflict`, `execution_failed`, unknown, `not_sent`, `misdirected` (S78), `in_progress` (S69(5), S80) or `partial`, for the request and for each record entry the client sent, the identifiers and values as the client sent them (not a value the server derived from record state), the identifier of a record, where the server can establish that this write created it, and what the server holds itself: the grant text of S36, `request_key`, and the members S69 requires. This applies to every guarded operation, under a person's approval or a grant. `not_sent` means the server did not send that entry's write, for a reason other than that entry's own condition under S64 or S65. `partial` is an outcome of the request as a whole, never of an entry: at least one entry succeeded and at least one did not. A request with that outcome is answered with a result, not a refusal, which carries each entry's outcome. The request's outcome is `execution_failed` only where no entry succeeded. Where the server sends nothing for a request because another entry failed its check, the other entries are `not_sent`. An outcome MAY carry a reason from a closed list the server documents. A reason MUST be derived only from the transport, from the server's own handling, from the bare fact that the system of record rejected the entry, which gives one and the same reason whatever the status, category or text of the answer, or from a status of the system of record that is independent of any record, such as a rate limit or an outage, and that the server documents as such; a status that tells whether a record exists, is a duplicate, conflicts or failed validation is not independent of any record, whatever the documentation says; it MUST NOT be derived from record contents or from text the system of record returned. A record that is not found has no reason of its own: a named record is answered as S64 provides and a record the request only refers to as S65 provides. An identifier returned by the system of record MUST be checked against a format the server derives from that system's own identifier rules, a pattern its real identifiers satisfy, and documents with that derivation, with a bounded length and character set, before it is returned or placed in a `message`. An identifier that does not conform MUST NOT be returned or placed in any text; the result says that the identifier was withheld, and where the server cannot otherwise tell that the write took effect, the outcome for that record is reported as unknown (S69(3)). A conforming identifier is still data from the system of record, not an instruction.

A server that cannot provide a shared, atomic store on the write path cannot claim this specification.

- S80. For every guarded operation, for as long as the server keeps the consumed record under S13 or S35, a period it MUST document, the answer to a request that S14 or S35 forbids to execute because its approval was consumed MUST state the recorded outcome, subject to S77, MUST identify itself as the recorded outcome of an earlier attempt with the time recorded for it, and MUST say that nothing was sent now. Where the outcome is unknown, S25 applies in place of that sentence: the answer says that the outcome is unknown, or, where S25 permits a repeat and the server sends it, that the write was sent again and its outcome. While the server knows the execution is still in progress, the answer says so and that this request sent nothing; it is a result, not a refusal, and its recorded outcome is `in_progress`. A bare `approval_used`, at step 10 of Section 6, is given only where the server no longer holds the outcome. The clauses of S14 and S35 that the server MAY answer with the recorded outcome are restated this way. The sentence of S14 that the answer is a result, not a refusal, applies only where the recorded outcome was a success; a recorded `conflict` or `execution_failed` remains a refusal (S65), whose `error` is the recorded value, `conflict` or `execution_failed`, never `approval_used`, and which carries the `recorded_outcome` member of Section 7. A recorded `misdirected` is a result. An answer under this requirement is a recorded outcome returned under S14 for S60 and S77. For a covered operation S69 applies as well.

## 9. Approver types

The account sets, per guarded operation, which approver types are acceptable. This specification gives
no method and no default for choosing an approver type, or for how wide a grant should be, and it
defines no policy language.

- **Person.** A person saw the change and approved it.
- **Grant.** A person approved a bounded set of future changes: one principal, one account, one
  operation, a set of fields, a record limit and an expiry. Each profile says where the grant is kept.
- **Policy.** A rule of the organization approved the change with no person involved. The approval
  carries the policy's identifier and a hash of its version, so the audit record shows which rule
  decided. The rule is opaque to the server.

- S18. The server keeps the authoritative counter per issuer and grant `id`. It MUST store
  `max_records` and `expires` from the first receipt of a grant and refuse a later receipt that states
  different values. It MUST refuse when the grant has expired or when the records already charged plus
  the records in this change exceed `max_records`. It MUST keep the counter until the grant expires.
  In the server-issued profile the terms are the ones stored when the grant was made.
- S19. The server MUST define, for each guarded operation, how many records a request changes: the
  number of record entries in the request, counted before execution, with a repeated record counted
  each time. A failed execution stays charged. For an update by query the count is `resolved.count`
  (S29). Where the count cannot be computed before execution, the server MUST refuse grant receipts
  for that operation.
- S20. The approver type in the audit record MUST be the type in the receipt. A grant or policy approval
  MUST NOT be reported as a person's approval.

Records changed indirectly (cascades, automation in the system of record) are not counted.

## 10. Audit record

The server writes a record for each refusal, each consumption and each outcome. Records reuse the
fields and the hash chain of [AUDIT-TRAIL]: `record_id`, `timestamp`, `agent_id`, `principal`,
`action_type`, `action_detail`, `outcome`, `prev_hash`, `record_phase`. This specification adds, inside
`action_detail`: `change_hash`, `receipt_id`, `issuer`, `approver_type`, `approver_id`, `grant_id` or
`policy` where present, the refusal `error`, `config_hash` on the consumption record (S87), and `authorization_record_id` on the outcome record,
pointing at the consumption record.

- S24. The consumption record MUST be durable before execution starts (S13), so that a write never
  exists without it. Each record MUST be linked to the previous one by hash, and the server MUST
  provide a check that walks the chain and reports the first broken link. The chain head SHOULD be
  anchored outside the server's control (for example an RFC 3161 timestamp). Without an anchor, a chain
  cannot detect rewriting by its own writer or the removal of its newest records.

The hash of a predictable change can be guessed, so audit records are as sensitive as the changes.

## 11. Configuration

- S23. Issuer registration, the list of guarded operations and every other setting of this
  specification (approver types per operation, which operations offer grants, grant limits, lifetimes,
  limits) MUST be changeable only through an administrative surface with administrator authentication.
  They MUST NOT be changeable through a guarded tool, an MCP request or the credential an agent uses.

### 11.1 Settings registry

A setting is a value of this specification that an administrator may choose. A setting configures who
may approve, how long, how many and which operations; it never configures whether a check runs. The
table below gives, for each setting, the requirement it parameterises, the default a server applies
where the administrator sets nothing, the hard limit it may not pass in either direction, and which
direction is the looser one. The defaults are safe starting values, not each setting's most
restrictive value; the hard limit is what bounds a setting, and S81 refuses a value beyond it. The
direction each setting loosens in is stated in the last column, and S84 says what a tightening and a
loosening each do.

| Setting | Requirement | Default | Hard limit | Loosened by |
|---|---|---|---|---|
| Pending lifetime | S27 | 1 hour | 24 hours, only with approver notification | a longer lifetime |
| Approver notification | S27 | none, so the pending lifetime is at most 1 hour | a channel the agent cannot read, each notification logged | adding a channel |
| Pending cap | S27 | a finite value the server documents | finite and documented | a higher cap |
| Selection limit | S29 | a finite value the server documents | finite and documented | a higher limit |
| Maximum approval lifetime | S10, S27, S35, S60, S90 | a finite value the server documents, short enough for S90 | finite and documented, at least 2 seconds so `poll_interval` < `max_lifetime` always holds | a longer lifetime |
| Skew | S10, S84 | the smallest value the server allows, documents as 0 | finite and documented | a larger skew; raising it never revives an approval already expired under the old value |
| Grant record limit | S18, S35 | a finite value the server documents | finite and documented; a tightening applies to existing grants | a higher limit |
| Grant lifetime | S18, S35 | a finite value the server documents | finite and documented; a tightening applies to existing grants | a longer lifetime |
| Key cache period | S15, S26 | a finite value the server documents | finite and documented | a longer period |
| Retention floor | S13, S35, S69, S80 | the period those requirements set: the maximum approval lifetime plus the skew | no shorter than the default and no longer than a documented upper bound | a shorter floor, down to the S13 period; a longer floor is a tightening and is allowed up to the documented upper bound |
| Read tool answer for a denied record | Section 2 | answered as for an absent record | answered as for an absent record; this draft offers no other answer | none in this draft |
| Approver model | S22, S76 | the system of record's answer alone | a documented model under S76 that only narrows S22 | adding a model |

- S81. The server MUST apply each setting of the table within its hard limit. Where a setting is
  missing or cannot be read, the server MUST apply its default. The administrative surface MUST refuse
  a value beyond the hard limit, an empty value and an unlimited value, and MUST record the refusal.

### 11.2 Invariants

- S82. No setting, and no combination of settings, may change the following, and a server MUST NOT
  offer a setting that does: no write without an approval (S6, S16); the server executes exactly what it
  hashed (S1, S4); an approval is used once and consumed before execution (P3, S13, S25); the server
  fails closed (S15, S60, S76); the connection cannot approve (P7, S21); refusals are recorded and a
  grant or policy is never reported as a person (S17, S20, S24); and no setting has an unlimited value
  (S49).

### 11.3 Rules for every setting

S23 applies to every setting: the agent can never change one.

- S83. A setting MUST be scoped by account, by operation or by principal, never by record content.
- S84. Tightening a setting MUST take effect for the next request. Loosening a setting MUST NOT revive
  a denied, cancelled or expired record and MUST NOT widen an existing approval or grant.
- S85. A configuration change that alters what a write does (a value fixed by configuration under S4)
  or who may approve (S22, S76) MUST make an existing approval not match. The server records with each
  approval record the configuration in force when it was made, and treats an approval made under other
  configuration as no approval. This configuration is not part of the change hash.
- S86. Every change of a setting MUST be recorded in the audit chain of Section 10, with who made it,
  when, and the old and new values.

### 11.4 Deployment record

- S87. The server MUST keep a deployment record: the settings in force, as one JSON object with a
  member for each setting of the table and for each further setting the server documents. The record
  MUST state the principal model in force: a credential delegated from a person, a dedicated agent
  credential with its own scope, or a service account. Its
  `config_hash` is the base64url encoding, without padding, of the SHA-256 digest of the RFC 8785
  serialization of that object. The server MUST carry the `config_hash` in force in every consumption
  audit record and MUST record each new deployment record in the audit chain.

### 11.5 Conformance claims

- S88. A product conforms only if no value of any setting that an administrator can reach breaks an
  invariant of S82. The conformance tests are run at the default of every setting and again with each
  setting at its hard limit.
- S89. A deployment does not conform by the values it chooses; it discloses them. A deployment that
  claims this specification MUST make its deployment record (S87) available to the organization,
  stating where each setting differs from its default.

## 12. Status (informative)

| Part | Status on 2026-11-26 |
|---|---|
| Change hash (`v` 2) | One public implementation, the sandbox's, generates and checks 14 vectors. The independent second implementation recorded for Draft 0.1 has not been repeated for `v` 2. |
| Server-issued flow | One sandbox implementation, run in its default mode and with covered operations turned on. Of conformance tests 1 to 146, 143 pass and 3 cannot be automated on one machine (2 need several server instances, 1 a real browser); none fails and none is reported as not implemented. Conformance tests 190 to 199 all pass. All tests ran against a single server instance. Not exercised live in a client under Draft 0.2; the Draft 0.1 sandbox was, in two clients of one client family. |
| Grants and approval pages in the server-issued profile | Specified and implemented in one sandbox. Not exercised live under Draft 0.2. |
| HTTP mapping | By conformance tests 10, 20 and 31, over the in-process mapping and over loopback on one machine, never from an independent client. |
| Signed-receipts flow | By conformance tests 8 to 39, on one machine, never from an independent client. |
| Consumption across several instances | Not tested. The requirement for atomic consumption across instances (S13) has not been tested. |
| Human security review | None yet. |
| Independent server implementation | None yet. |
| Operations that are not covered, in the core and the server-issued profile | The part of Draft 0.2 meant to be implemented first. Specified, and implemented and tested by the sandbox. |
| Covered operations: the optional members of Section 5.1 and S28, S29, S61, S62, S66 to S70, S72 and S73, with the parts of other requirements that speak of a covered operation | Experimental in Draft 0.2, as the signed-receipts profile is. Specified, implemented and tested by the sandbox, and likely to change in a later draft. |
| Draft 0.2 additions (S60 to S80, I5, `v` 2, and the changed and new tests) | Implemented and tested by the sandbox, for operations that are not covered and for covered operations, except S74 and S75: the sandbox's permission source is inside the server, so S74 does not arise, and it signs people in itself rather than through a proxy, so S75 is not implemented. |
| Settings and deployment record (Section 11.1 to 11.5, S81 to S89) and S90 | Specified, implemented and tested by the sandbox: conformance tests 190 to 199. The `partial` outcome of S77 is covered by conformance test 47. |

The rows above describe the Draft 0.2 sandbox and tests.

The specification, the sandbox and the tests were written by one author working with AI coding and
review models. Several AI models from different vendors reviewed the drafts. No human other than the
author has reviewed it. Every number in this table can be reproduced with the commands in the sandbox
README.

## 13. Open questions

1. The permanent name of the HTTP header, and whether the MCP form belongs in an MCP extension. The
   `_meta` keys and the problem type URI are settled (Section 7).
2. How the MCP refusal should align with the open MCP proposals for asynchronous approval and for
   structured authorization denials.
3. Whether `preconditions` should be required for updates to existing records.
4. Partial failure in a batch: the receipt is consumed and the grant charged for the whole request. Is
   that the right rule?
5. Requests that are not JSON objects (multipart, form-encoded, arrays), and normalization of the HTTP
   request target. A request target that differs in any byte, including the order of query parameters, is another operation and so another request key. Until this is settled, a server that offers HTTP writes documents for each operation that it hashes the request target exactly as received and applies no normalization, so a client sends the identical request target, byte for byte, when it asks again.
6. More than one approver for one change.
7. Server defaults and side effects: should the server prepare the change first and hash the prepared
   result? It costs a second round trip.
8. A way for an organization's issuer to deposit a receipt at the server directly, for hosted
   connectors.
9. An agent can fill a principal's cap on open approval requests, so a person cannot get a new
   approval until records expire. Should the approval page let a person clear them? Until this is
   settled, a server documents its cap, how long a pending, denied or cancelled record counts toward it
   (S27, S30, S31), and whether anyone can end that wait sooner; any such clearing is an administrative
   action under S23 and is recorded in the audit chain.

## References

- [MCP] Model Context Protocol specification, revision 2026-07-28. https://modelcontextprotocol.io/specification/2026-07-28
- [MCP-TOOLS] same, Tools. https://modelcontextprotocol.io/specification/2026-07-28/server/tools
- [MCP-AUTHZ] same, Authorization. https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization
- [STUDY] J. Yao, Z. Yang, Z. Wang, Y. Zhou, W. Ye, "When Neither Side Confirms: Destructive Tool Approval Across MCP Servers and Hosts", arXiv:2611.02527, 2026.
- [AUDIT-TRAIL] draft-sharif-agent-audit-trail-10, 2026-11-17 (individual Internet-Draft, not by this author).
- RFC 2119, RFC 8174 (key words), RFC 2104 (HMAC), RFC 8785 (JCS), RFC 9457 (Problem Details), RFC 3161 (timestamps).

## Changes from Draft 0.1

**Security changes.** Draft 0.1 let a refusal disclose record state to the agent. An `approval_required` refusal carried the full change object, including `state_hash`, an unkeyed hash of current field values, so an agent could name a field it may not read and recover a low-entropy value by guessing. `change_hash`, `resolved.count`, a conflict refused before approval and a repeated request also disclosed state, and the signed-receipts profile's `current` and `records` gave values in clear. The author found the first of these while reviewing an implementation of the core and the server-issued profile, working with AI review models; the others were found in the review that followed. Draft 0.2 specifies the fix (S60 to S80) and lists what remains in Section 2; Section 12 records which of these additions the sandbox implements and tests. An implementation of Draft 0.1 can be affected where the server's credential can read more than the agent's principal should. Until it moves to Draft 0.2, it should omit `change`, `current` and `records` from what it returns to such a principal and keep the full change in its pending record and on its approval page. That advice does not stop guessing through `change_hash` itself; the fix specified in Draft 0.2 addresses that channel.

Draft 0.2 adds requirements S60 to S80 and I5. The `v` member of the change object is now the integer 2 instead of 1, so every change hash differs from Draft 0.1, and the test vectors are recomputed for it. `state_hash` and `manifest_hash` are now keyed with a secret that only the server holds (S61), and an entry of `preconditions` has only `record` and `state_hash` (S62). The refusals `conflict` and `execution_failed` are added, and `invalid_input` is narrowed (S63 to S65). For covered operations, the server-issued profile adds approval contexts and their rules (S67 to S70), and the signed-receipts profile offers no issuer for them (S66).

Draft 0.2 withdraws the `version` and `absent` members of `preconditions`, the sentence that `approval_required` carries the full change object, the refusal members `current` and `records`, the last sentence of I1, the clause of S28 on a conflict before approval, and the clause of conformance test 40 on `current` and `records`. The clauses of S4, S14, S27, S28, S29, S30, S31, S32, S34, S35, S43, S47, S48, S50 and S58, and the `retry_after` sentence of Section 4 of the server-issued profile, are superseded or narrowed for covered operations as S67 to S70 state, and each affected clause carries a pointer. The HTTP mapping gained the statuses 409 for `conflict` and 500 for `execution_failed`. Conformance tests 1, 45 and 46 changed, and tests 97 to 146 are new. Section 12 records which of the Draft 0.2 additions are implemented and tested.

Draft 0.2 also adds S72 and S73. A principal whose read permission is scoped to particular records cannot use a query operation unless the permission model answers for the whole domain. S69 now applies to every principal of a covered operation, not only to a principal that cannot read the record, so a second identical write needs a new value of the distinguishing argument. Exception (e) of S60 is unused. A denied or consumed write can be asked again with a new value of the distinguishing argument; each new approval request counts toward the limit of S27, and a write under a grant is charged as S18 and S19 state. A client whose principal may not read correlates its requests by `request_key`, which a refusal carries for a covered operation where the server computed one, because it can no longer check the change it sent against a change hash.

Draft 0.2 also adds S74 to S77. S77 limits what the result of a write and a recorded outcome may carry, because a result could carry record content, including error text of the system of record, to a principal not established to read it. Section 3 now defines record, schema and record state. Recording a decision or a grant is one atomic step, and applies only if the record is still pending at that step (S50). When an approval is consumed, every other pending or approved record for the same change is closed in the same atomic step (S35, S68(6)). S74 lets a server whose permission source is outside it obtain the permission facts immediately before a step, for that step alone and within a bound it documents of at most 5 seconds; Section 2 states what that window leaves open. S75 covers sign-in performed by a proxy. S76 covers a server that applies its own permission model where the system of record cannot answer. The `_meta` keys are `org.enforcedapproval/refusal` and `org.enforcedapproval/receipt`. The HTTP problem type is `https://enforcedapproval.org/problems/refusal`, one type for every refusal, with the `error` member inside the `approval` object telling them apart. The refusal `selection_limit` is added for a selection larger than the documented limit (S29). Conformance tests 43 and 61 also changed, and the conformance document now says what each test needs to run against a deployed server and lists the requirements not yet covered by a test.

Draft 0.2 has two parts of different maturity (Section 12): the rules for operations that are not covered, which are meant to be implemented first, and covered operations, which are experimental in this draft.

Draft 0.2 also adds S79 and S80. S79 requires TLS on the client's connection for the agent's endpoint as well as the pages, and says how a server behind a proxy or edge establishes that. S80 requires the answer to an identical request after consumption to state the recorded outcome, for every guarded operation. A sixth outcome, `misdirected`, reports a write that took effect on a record other than the one named (S78).

Draft 0.2 also adds S78. Where the system of record resolves the identifier a request names to a record with another identifier, as after a merge, the write does not change that other record, and Section 3 says that such a resolution is record state. S77 now names the outcomes a result may carry and adds `not_sent` for an entry whose write the server did not send. An outcome may carry a reason only from a closed list the server documents, and a reason is never derived from record contents or from text the system of record returned. An identifier returned by the system of record is checked against a documented format before it is returned or placed in a `message`, and is withheld where it does not conform. S75 is stricter about the audience of the proxy's assertion: it is a value an administrator registered for that proxy, which the proxy issues for the server's pages alone and only after interactive sign-in. S75 also says how the person named is mapped to a member of the account: by a documented join identifier, anew for each request, with the proxy's subject identifier and the member identifier both recorded. Under S76 the answer of the system of record governs where it can answer, and a permission model states separately what a person may change, what a person may see, what a principal may read, which definitions of an object type a principal may see, and what a principal may write. S60 lets a server reuse an affirmative read-permission answer before consumption only for a finite period it documents, no longer than its maximum approval lifetime, and exception (i) of S60 now applies to every guarded operation. S48 answers a property that is not schema alike whether it is undefined or restricted, and S74 says from when its bound is measured. Section 2 adds residuals: a principal whose read permission is withdrawn is answered as a reader until that period ends, a join identifier that is reassigned carries the earlier person's standing, and an agent that operates the person's own signed-in browser cannot be told apart from that person. It also says more about what a step 1 refusal of an upsert and the outcomes of a batch tell a principal, and restates what S74 leaves open. Conformance tests 77 and 91 also changed.

Draft 0.2 also names the client-visible member that marks a recorded outcome, `recorded_outcome` (S69(2)), and the `invalid` member of `invalid_input` (Section 7). Section 1 now says that Sections 3 to 11 are normative and that Section 2 is informative, and Section 3 defines an approval record. S64 and S78 now say that the read of record state at step 2 of Section 6, not step 8, is the read that can serve as the check before the write; profile S68(3) says the same.

Draft 0.2 also settles these points. Core P7 says that under every profile nothing received on the agent's connection, a form mode elicitation answer included, is an approval. Section 2 says how a read tool should answer a record the principal may not read. S69(4) names the distinguishing argument `change_tag` by default. S69(5) and S80 make the answer for an execution still in progress a result with the outcome `in_progress`. S80 says that a recorded `conflict` or `execution_failed` is answered with that value as `error` and with the `recorded_outcome` member, which closes the former open question 11. S77 adds the outcomes `in_progress` and `partial`, and S65 answers `execution_failed` for a request only where no entry succeeded, which closes the former open question 10. In the server-issued profile, Section 2 says that the host or orchestrator sends the identical request again and that a loop can poll by doing so, with an informative note on holding a request as an MCP task; S27 lets an administrator set a pending limit of up to 24 hours, only with a logged notification to the approver; S35 adds a retention floor where a grant could approve a repeat, which closes the former open question 12; and S76 says that a principal's membership means that its credential is affirmatively bound to the account, and that an approver list of the permission model only narrows S22. Conformance test 37 changed.

Draft 0.2 also adds Section 11.1 to 11.5: a registry of the settings of this specification with their defaults, hard limits and the requirements they parameterise (S81), the invariants no setting may change (S82), the rules for every setting (S83 to S86), the deployment record and its `config_hash`, which every consumption audit record carries (S87, Section 10), and the product and deployment conformance claims (S88, S89). Conformance tests 190 to 198 are new. The registry table also carries the maximum approval lifetime (at least 2 seconds, so S90's `poll_interval` is always shorter), the skew (raising it never revives an approval already expired), the grant record and lifetime limits (a tightening applies to existing grants), the key cache period and an upper bound on the retention floor, so no setting accepts an unlimited value (S82, S49).

Draft 0.2 also names what clients parse. The step 1 refusal is `permission_denied` with status 403 (Section 6, S72, Section 7), where S72 formerly said that it carries no `approval` object. Section 7 defines the members of `recorded_outcome` and says that `in_progress`, `partial` and `misdirected` are results, with status 200 on HTTP. In the server-issued profile, S90 adds `pending_expires` and `poll_interval` to `approval_required`. Open questions 5 and 9 now say what a server documents until they are settled. Conformance tests 31, 124 and 130 changed, and test 199 is new.

Section 12 now records that the sandbox implements and tests covered operations, and gives the counts of its latest recorded run.

Section 3 now says that the principal is the credential the connection presents, also where it is delegated from a person, and that the same person may approve their own agent's change on the approval page, never through the connection. Section 2 says what a delegated credential leaves to protect, and S87 requires the deployment record to state the principal model in force.

In the server-issued profile, the lockout of S30 and S31 after a cancellation or a denial now lasts at most one hour, whatever the pending limit of S27 is. For a covered operation the same rule holds (S68(5), S70): a denial or a cancellation stops locking the change one hour after the decision, even where the context has not expired, and the change can be asked for again.

In the server-issued profile, S67 now says that an approval context expires no later than its creation plus the pending lifetime in force, so that tightening that setting shortens an existing context at once (S84) instead of only applying to the next context. The sentence that fixed a context's expiry when its first record was created is withdrawn; the creation time is still fixed then.

Under S81 and S84, a setting given when the server starts on an existing database must agree with the value the database stores; a differing value stops the start with a clear message rather than being ignored. A setting that decides how a change object is built, such as `preconditions`, is fixed when the database is created and is not changed on a live database through the administrative surface.

In the signed-receipts profile, S66 now says how it and S72 meet for a covered query: where the server offers no server-issued profile for the operation, S66's `approver_not_authorized` is the answer for every request and comes before S72's read-domain check; where it offers the profile, S66 does not apply and S72's `permission_denied` is the only step 1 refusal.

S61 now states the form of the key: the secret is 256 bits from a cryptographic random source, written as hexadecimal digits, and a configured key that is not is refused at start rather than read as an empty key. S25 with S77 states that a write whose response was lost is answered as the outcome `unknown`, a result, and never as `execution_failed`, which says that the write did not run. S77 states that a result reports the outcome of each record entry the client sent, so two entries for one record are each reported, and that an identifier from the system of record is checked against the documented format before it is returned. In the signed-receipts profile, Section 4 states that a policy receipt's `inputs` is an array of objects with `ref` and `hash`, and S7 refuses any other shape. S84 states that a tightened grant limit is recorded on the grant itself, so a later loosening of the ceiling restores no earlier authority. S30 and S31 state, with S68(5) and S70, that a denial or a cancellation locks the change for at most one hour, whatever the pending lifetime is, for a covered operation as for one that is not covered.
