# Enforced Approval: Signed Receipts Profile (experimental)

**EXPERIMENTAL.** No client tested as of 2026-11-19 can carry a receipt on a tool call, so this profile
has been exercised in-process only.

Part of Draft 0.1, 2026-11-20. Author: Sharoze Iftikhar. Normative for a server that claims it. It extends the core document (`core.md`),
whose terms, change hash, verification steps, refusals and requirements apply here unchanged.

## 1. What this profile is

The organization runs or chooses the issuer: its own approval service or its policy engine. An
account administrator registers the issuer with the server. The issuer records the approver's
decision and signs a receipt. The client carries the receipt on the request, and the server verifies
it. Because one issuer can serve many servers, an organization can apply one approval rule across
servers from different vendors.

**Trust.** The server trusts a registered issuer to have applied I1 to I4. It cannot check them. In
particular, the server cannot check that a person saw the change. A stolen issuer key, or a dishonest
issuer, can approve anything the issuer is registered for. A receipt can be checked by anyone who holds
the issuer's public key, but it proves only what the issuer says.

## 2. Flow

1. The client sends the request without a receipt and receives `approval_required`.
2. The client sends the `change` object from the refusal to one of the listed issuers.
3. The issuer computes the change hash itself (I1), obtains the decision and returns a receipt.
4. The client sends the identical request again, carrying the receipt (Section 3).

**Refusal members.** For `approval_required`, the refusal also has `issuers`: the identifiers of the
issuers registered for this operation. Where `state_hash` or `resolved` is used, it also carries
`current` (for each record, the object that `state_hash` covers) or `records` (the array that
`manifest_hash` covers), so the issuer can check them against the hashes and show the approver the old
values and the selected records (I1). The server includes them only if the credential may read those
fields and records. If it may not, the operation cannot be approved through an organization's issuer.

## 3. Carrying a receipt

- MCP: the client puts the receipt in `params._meta` of the `tools/call` request, under a key with a
  vendor prefix, as the MCP specification requires for third-party keys [MCP-BASIC]. This draft uses
  `com.example.approval/receipt` until a permanent name exists. This is the preferred form: the tool
  schema does not change and the model does not see the receipt.
- MCP, for clients that cannot set `_meta` on a tool call: the server SHOULD also declare an optional
  string argument `approval_receipt`. The server removes it before hashing, as it does approval fields,
  so the change hash is the same in both forms.
- HTTP: the client sends the header `Approval-Receipt` with the receipt as its value.
- S5. A request with more than one receipt (a repeated or list-valued header, more than one receipt
  key in `_meta`, or a receipt in both `_meta` and the argument) MUST be refused with
  `approval_invalid`.

## 4. Default encoding

The core's receipt properties are what is normative. A server claims conformance per encoding it
accepts and documents how each encoding meets each property. This section defines the default encoding,
so that implementations can interoperate and be tested. The header and claim rules of S7 apply to it.

A receipt in the default encoding is a JWS in compact serialization (RFC 7515). Its payload is a JSON
object with these claims and no duplicate names:

| Claim | Type and meaning | Property |
|---|---|---|
| `iss` | String. Issuer identifier (a URL). | P6 |
| `aud` | String. The server identifier, equal to `audience` in the change object. | P2 |
| `iat`, `exp` | Integers, seconds since the epoch, `iat` less than `exp`. | P4 |
| `jti` | Non-empty string, unique per issuer. | P3 |
| `change_hash` | String. The change hash. | P1 |
| `approver` | Object with `type` (`person`, `grant` or `policy`) and a non-empty `id`. For `grant`, `id` is the person who made the grant. | P5 |
| `grant` | Present only for type `grant`: object with `id` (non-empty string), `max_records` (positive integer) and `expires` (integer, seconds since the epoch). | Section 7 |
| `policy` | Present only for type `policy`: object with `id` and `version_hash` (non-empty strings), and optionally `inputs`: an array of objects, each with `ref` and `hash`, for the inputs I4 allows. | Core Section 9 |

A receipt or grant is expired when the current time is equal to or later than its expiry. Claims and
members not listed here are ignored.

The protected header has exactly `alg`, `kid` and `typ`. `typ` is `approval-receipt+jwt` (explicit
typing, RFC 8725). `alg` is EdDSA or ES256 and equals the algorithm registered for the key.

## 5. Verifying a signed receipt

These requirements give the core's verification steps 4 to 9 their meaning for signed receipts.

- S7. The server MUST refuse a receipt that is malformed, in an encoding it does not claim, larger
  than the server's documented maximum size (at most 8 kilobytes), or, in the default encoding, in
  breach of Section 4: a missing, duplicate or wrongly typed claim, `grant` or `policy` not matching
  the approver type, an `alg` that is `none`, symmetric or different from the key's registered
  algorithm, or any header parameter other than `alg`, `kid` and `typ` (including `jwk`, `jku`, `x5u`,
  `x5c` and `crit`).
- S8. The server MUST verify the signature only with keys registered for the issuer and the account.
- S9. The server MUST refuse a receipt whose audience is not the server's own identifier.
- S10. The server MUST refuse an expired receipt, a receipt issued in the future, and a receipt whose
  lifetime exceeds the server's documented maximum. Allowed clock skew MUST NOT exceed 60 seconds.
- S11. The server MUST refuse a receipt whose change hash differs from the one it computed.
- S12. The server MUST refuse a receipt whose approver type the account does not allow for the
  operation, or whose issuer is not registered for that operation and approver type.

## 6. Issuer registration and keys

An account administrator registers each issuer with the server: the issuer identifier, its keys (each
with its algorithm) or a key set URL, and the operations and approver types it may approve. These are
settings under the core's S23.

- S26. The server MUST document how long it caches issuer keys (at most 24 hours) and how soon a removed
  issuer or key stops being accepted on every instance (at most 1 hour). Unknown `kid` values trigger
  at most one refresh of an issuer's keys per minute. A `kid` still unknown after the one permitted
  refresh is refused with `approval_invalid`. Within an account, a key MUST NOT be registered under
  more than one issuer identifier, so one approval cannot be spent under two names.

The case of no usable key source and no valid cached key is `approval_unavailable` (S15).

## 7. Grants issued by an issuer

A person creates a grant at the issuer (I3). The issuer then issues one receipt per change without
asking again, as long as the change is inside the grant. Each receipt carries the grant's `id`,
`max_records` and `expires`.

A grant object, as kept by the issuer, has `id`, `granted_by`, `principal`, `audience`, `account`,
`operations`, `fields`, `max_records`, `not_before` and `expires`. Its terms never change. A wider grant
is a new grant.

The server's counter (S18) decides. The issuer's own count in I3 only avoids issuing receipts that
will be refused. A grant revoked at the issuer stops working when the issuer stops issuing receipts
for it, and receipts already issued stay usable until they expire. Receipt lifetimes should be
minutes.

## 8. Issuer requirements

- I1. For a person, the issuer MUST compute the change hash itself from the change object it was given
  and MUST display the operation, the account, the principal and every argument value from that same
  object, never a summary written by the agent. Where the refusal carried `current` or `records`, it
  MUST check them against `state_hash` or `manifest_hash` and display them.
- I2. The issuer MUST authenticate the person on a channel the agent cannot operate, MUST check that
  the organization authorizes that person to approve this operation in this account, and MUST NOT
  issue a person receipt without that person's action on that change. Its record of the decision MUST
  hold when the change was displayed and when it was decided, so that approvals given without
  reading can be measured.
- I3. A grant MUST be created by a person under I1 and I2, with the grant's terms displayed in place of
  one change. Before issuing under a grant, the issuer MUST check the change object against every term
  of the grant: principal, audience, account, operations, fields, validity period and its own count of
  remaining records.
- I4. A policy receipt MUST come from evaluating a policy the organization registered with the issuer,
  and MUST carry that policy's identifier and version hash. The policy evaluates the change object. It
  MAY also use other inputs, but only inputs the issuer obtains itself from sources the organization
  registered with it (for example the current state of a record, or the principal's earlier changes).
  Nothing the agent or the client supplies, other than the change object, may be an input. The
  receipt MUST record each such input by a reference and a hash, so the audit shows what the policy
  saw without the policy itself being disclosed.

The issuer writes an audit record for each approval and each denial. The server finds the issuer's
decision record by `issuer` and `receipt_id`. Approval requests can be used to tire a person into
approving, so issuers should limit requests per principal.

## References

- [MCP-BASIC] Model Context Protocol specification, revision 2026-07-28, Base protocol, `_meta`. https://modelcontextprotocol.io/specification/2026-07-28/basic
- [RECEIPT-FORMAT] draft-schrock-ep-authorization-receipts-13, 2026-09-11 (individual Internet-Draft, not by this author). A receipt format that can meet the core's receipt properties; not a dependency.
- RFC 7515 (JWS), RFC 8725 (JWT best practices).
