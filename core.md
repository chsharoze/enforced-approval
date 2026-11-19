# Enforced Approval

Server-side approval of exact agent actions.

Draft 0.1, 2026-11-20. Core document. Author: Sharoze Iftikhar.

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
claims conformance separately for each receipt encoding it accepts.

Sections 4 to 11 are normative. The key words MUST, MUST NOT, SHOULD, SHOULD NOT and MAY are used as in
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
guarded server; side effects that the system of record adds to an approved write.

## 3. Terms

- **Server**: the component that holds the credential to the system of record and executes the write.
- **Account**: the tenant in the system of record that the request acts on.
- **Organization**: the party that owns the account and decides who may approve what.
- **Agent**: the AI system and client that send the request.
- **Principal**: the identity the server derives from the agent's authenticated credential. Agents
  that share one credential are one principal.
- **Guarded operation**: a tool or endpoint for which the account requires approval.
- **Change**: one request to a guarded operation, identified by its change hash (Section 5).
- **Approval fields**: arguments whose only purpose is to state that approval happened (S2).
- **Approver**: a person, a grant or a policy (Section 9).
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

## 5. Change object and change hash

The change object is a JSON object with these members and no others, except the optional members of
Section 5.1:

| Member | Value |
|---|---|
| `v` | The integer 1. |
| `audience` | The server's own identifier. For MCP with OAuth, its canonical resource URI [MCP-AUTHZ]. Otherwise an identifier the server documents. |
| `account` | The server's identifier for the account, taken from the authenticated credential. |
| `principal` | The server's identifier for the principal, taken from the authenticated credential. |
| `operation` | `mcp:tools/call:<tool name>`, or `http:<METHOD>:<request target>` with the request target (path and query) exactly as received. |
| `arguments` | The `arguments` object of the `tools/call` request (the empty object if absent), or the JSON object in the HTTP request body. The approval fields are removed, and any inputs copied in under S4 are added. |

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
  on the request or on record state MUST be in the change object or covered by `preconditions`.

### 5.1 Optional members

An operation MAY use these members. The server documents which, per operation.

| Member | Value |
|---|---|
| `preconditions` | An array with one entry per record the change touches: `record` (its identifier) and one of `version` (the system of record's version token), `state_hash` (below) or `absent: true` (the record does not exist; for creates). |
| `resolved` | For an operation that selects records by a query: an object with `count` and `manifest_hash` (below), for the records the query selects now. |

`state_hash` and `manifest_hash` are computed like the change hash, over a different value. For
`state_hash`: the JSON object whose members are exactly the fields the request sets on that record,
each with the record's current value (`null` if unset). For `manifest_hash`: the JSON array of the
selected record identifiers as strings, sorted by UTF-16 code units.

- S28. Where an operation uses `preconditions`, the server MUST fill them from the record's actual
  state each time it builds the change object, so a record that changed after approval gives a
  different hash and the receipt no longer matches. It MUST refuse, as an ordinary conflict, a create
  whose record already exists and an update whose record is gone. It MUST make the write conditional
  on the preconditions where the system of record supports conditional writes, and otherwise MUST
  document that the check is not atomic.
- S29. Where an operation uses `resolved`, the server MUST run the query each time it builds the change
  object, so a selection that changed after approval gives a different hash. It MUST then write to
  exactly the identifiers it hashed, without running the query again, and MUST refuse a selection
  larger than its documented limit. This is the one case where the write is defined by the change
  object and not by the arguments alone.

## 6. Verification

For every guarded request, the server performs these steps in order and stops at the first failure.
Every failure is a refusal: the write does not run. A profile may meet a step by construction.

1. Authenticate the credential and apply its ordinary permission checks. A request the credential may
   not make is refused as usual and consumes nothing.
2. Determine the account and the principal, check the input (S3) and compute the change hash.
3. Find the approval: the receipt on the request (signed receipts), or an approved record for
   this change hash or a matching grant (server-issued). If there is none, refuse with
   `approval_required` or follow the profile's approval flow.
4. Check that the approval is well formed and comes from an issuer registered for this account.
   Otherwise refuse with `approval_invalid`.
5. Check that the issuer may approve this operation with this approver type. Otherwise refuse with
   `approver_not_authorized`.
6. Check that the approval is for this server. Otherwise refuse with `approval_invalid`.
7. Check the times: not issued in the future, not expired, and a lifetime within the server's
   maximum, each within the allowed skew. Otherwise refuse with `approval_expired`.
8. Check that the approved change hash equals the computed one. Otherwise refuse with
   `approval_mismatch`.
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

## 7. Refusals

A refusal carries an `approval` object. `error` is always present. `change_hash` is present whenever
the server computed one, so not after a refusal under S3. For `approval_required` the object also has
`audience`, `operation`, `approver_types`, `max_lifetime` (seconds) and `change`: the full change object
as the server built it. Each profile adds its own members.

```json
{ "error": "approval_required", "change_hash": "gdTr35hU7NHRlWWwpztLe-mPxr0Lhh37XPYGnimiFIU",
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
| `invalid_input` | The request cannot be hashed (S3) or the system of record rejects it before approval. Its `message` names what was invalid. No change hash, no approval link. | Both |

In the server-issued profile a request whose hash matches no approval is answered `approval_required`,
so `approval_mismatch` (step 8 of Section 6) arises only where a receipt is presented.

- MCP: a tool result with `isError: true`, with the `approval` object as JSON in a text content block
  (some clients pass only text to the model) and in the result's `_meta` under
  `com.example.approval/refusal`. Not in `structuredContent`, which follows the tool's output schema.
- HTTP: status 403 (503 for `approval_unavailable`, 429 with a `Retry-After` header for
  `approval_limit_reached`), with an `application/problem+json` body (RFC 9457) whose `type` is the
  problem type URI of this specification (to be assigned) and which has the `approval` object as an
  extension member.
- S17. A refusal MUST NOT include any part of the write's result, and MUST be recorded (Section 10).
  The server MUST NOT echo a receipt in a refusal or write receipts to its logs. This means the receipt
  itself; its identifier is recorded as Section 10 requires.

## 8. Consumption and execution

- S13. Consumption MUST be one atomic, durable transaction across all instances of the server, covering
  the receipt identifier, the grant counter and the consumption record, and MUST complete before
  execution starts. It MUST survive a restart. A receipt stays consumed if execution fails; a retry
  needs a new receipt. Used identifiers MUST be kept at least until the expiry plus the allowed skew.
- S14. A second request with a consumed receipt MUST NOT execute. When its change hash is the same, the
  server MAY answer with the recorded outcome of the first execution; that answer is a result, not a
  refusal.
- S15. If the consumption store or the issuer registry is unavailable, or no source of keys for the
  issuer can be reached and no valid cached key exists, the server MUST refuse with
  `approval_unavailable` (fail closed). A key identifier that is still unknown after the one permitted
  refresh is not this case; it is `approval_invalid`.
- S25. The server MUST execute a consumed receipt's write at most once. If the outcome of the write is
  unknown (a lost response, a crash), the server MUST NOT send it again unless the system of record
  treats the repeat as the same write, keyed by the receipt identifier. A write lost before it was sent
  needs a new approval. After a batch that partly failed, the failed items are a new change with a
  new hash.

A server that cannot provide a shared, atomic store on the write path cannot claim this specification.

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
`policy` where present, the refusal `error`, and `authorization_record_id` on the outcome record,
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

## 12. Status (informative)

| Part | Status on 2026-11-19 |
|---|---|
| Change hash | Two implementations agree on 13 vectors: the sandbox's, and a second written from the specification text alone by a separate automated coding agent that was not shown the expected hashes. |
| Server-issued flow | One sandbox implementation. 92 of the 96 tests pass; 4 cannot be automated on one machine (2 need several server instances, 1 a real browser, 1 external TLS). All tests ran against a single server instance. Exercised live in two clients of one client family: one headless, one hosted web app. |
| Grants and approval pages in the server-issued profile | Specified and implemented in one sandbox. Exercised live in the hosted web app only. |
| HTTP mapping | By the sandbox's own tests on one machine (in-process and over loopback), never by an independent client. |
| Signed-receipts flow | By the sandbox's own tests on one machine, never by an independent client. |
| Consumption across several instances | Not tested. The requirement for atomic consumption across instances (S13) has not been tested. |
| Human security review | None yet. |
| Independent server implementation | None yet. |

The specification, the sandbox and the tests were written by one author working with AI coding and
review models. Several AI models from different vendors reviewed the drafts. No human other than the
author has reviewed it. Every number in this table can be reproduced with the commands in the sandbox
README.

## 13. Open questions

1. The permanent `_meta` keys, HTTP header and problem type URI, and whether the MCP form belongs in an
   MCP extension.
2. How the MCP refusal should align with the open MCP proposals for asynchronous approval and for
   structured authorization denials.
3. Whether `preconditions` should be required for updates to existing records.
4. Partial failure in a batch: the receipt is consumed and the grant charged for the whole request. Is
   that the right rule?
5. Requests that are not JSON objects (multipart, form-encoded, arrays), and normalization of the HTTP
   request target.
6. More than one approver for one change.
7. Server defaults and side effects: should the server prepare the change first and hash the prepared
   result? It costs a second round trip.
8. A way for an organization's issuer to deposit a receipt at the server directly, for hosted
   connectors.
9. An agent can fill a principal's cap on open approval requests, so a person cannot get a new
   approval until records expire. Should the approval page let a person clear them?

## References

- [MCP] Model Context Protocol specification, revision 2026-07-28. https://modelcontextprotocol.io/specification/2026-07-28
- [MCP-TOOLS] same, Tools. https://modelcontextprotocol.io/specification/2026-07-28/server/tools
- [MCP-AUTHZ] same, Authorization. https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization
- [STUDY] J. Yao, Z. Yang, Z. Wang, Y. Zhou, W. Ye, "When Neither Side Confirms: Destructive Tool Approval Across MCP Servers and Hosts", arXiv:2611.02527, 2026.
- [AUDIT-TRAIL] draft-sharif-agent-audit-trail-10, 2026-11-17 (individual Internet-Draft, not by this author).
- RFC 2119, RFC 8174 (key words), RFC 8785 (JCS), RFC 9457 (Problem Details), RFC 3161 (timestamps).
