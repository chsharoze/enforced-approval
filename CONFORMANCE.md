# Enforced Approval: Conformance Tests

Draft 0.1, 2026-11-20. Author: Sharoze Iftikhar. Tests for implementations that claim conformance to
the core and its profiles. Each test names the requirement it checks.

There are four groups. A server runs the Core tests and the tests of every profile it claims: the
Server-issued approval profile tests, or the Signed receipts profile tests (experimental), or both. An
issuer runs the Issuer tests.

## Setup

- One account with a guarded operation that updates records and a second guarded operation with a
  different tool name. A second account, and a second principal in the first account.
- "V1" and "receipts.person" refer to entries in the published test vector file. Each vector gives the
  arguments as sent (`request_arguments`) and the approval fields. For HTTP, or for another receipt
  encoding, build the equivalent request and issue equivalent receipts with the test key.
- Every test starts with an empty consumption store, or uses a fresh approval. Set the server clock to
  the vector `now`, or re-sign for the real time.
- A way to force a change in the system of record between the server's verification and its write (a
  test hook or a fixture that returns a version conflict), for tests 45 and 46.
- **No write** means the system of record is unchanged. **One write** means exactly one execution:
  count executions in the system of record's own change history or a test hook, because a repeated
  update leaves the same values as one update.

Signed receipts profile:

- The vector issuer registered with the key in the vector file (`issuer_jwks`), for the first
  operation and all approver types unless a test says otherwise.

Server-issued approval profile:

- Person P1, who has permission for the first operation in the first account. Person P2, who is
  authenticated but lacks that permission. Person P3, who has the same permission as P1. An account
  administrator A. Person P4, who is authenticated in the second account only. Person P5, who is in
  the first account but cannot read one field that V1 sets. A record in the first account that P1 is
  not permitted to change.
- The first operation is configured to offer grants, with administrator limits chosen by the tester
  (called the record cap and the time cap below), and with the "any record" shape enabled. Unless a
  test says otherwise, grants in tests 50 to 79 use the "any record" shape. The second operation does
  not offer grants. A third guarded operation creates records and is configured to offer grants, with
  the "any record" shape not enabled.
- **Approval for a change.** Where a Core test says "with a V1 receipt" or names a receipt, a
  server-issued implementation instead has P1 approve that change on the approval page before the
  request is sent.
- **Mismatch.** Where a Core test expects `approval_mismatch`, a server-issued implementation is
  expected instead to refuse with no write and to start a new approval request, because it finds
  approvals by change hash.
- **First refusal.** To see the `approval_required` refusal, send the request without declaring URL
  mode elicitation.

## Core

1. **Missing approval.** Send V1 with no approval. Expect `approval_required`, no write, `change_hash`
   equal to V1 and a `change` member equal to the V1 change object. On MCP the same object is present
   as JSON in a text block and in the result's `_meta`. (S1, S6)
2. **Approval field does nothing without an approval.** Send V2 (the approval field set) with no
   approval, once for each value the field allows. Expect the refusal and hash of test 1. (S2, S16)
3. **Approval field does nothing with an approval.** Send V2 with a V1 receipt, once for each value.
   Expect one write with a result identical to test 4. (S2)
4. **Valid approval runs once.** Send V1 with `receipts.person`. Expect one write, exactly the approved
   values in the system of record, a consumption record and an outcome record with approver type
   `person`, each linked to the previous record by hash. Where the server declares the
   `approval_receipt` argument, repeat with the receipt carried there: same hash, one write.
   (S4, S20, S24)
5. **Replay.** Send the request of test 4 again. Expect no second write: `approval_used` or the
   recorded outcome. (S13, S14)
6. **Concurrent replay.** With one fresh approval, send 20 identical requests at the same time across
   all server instances. Expect one write. (S13)
7. **Replay after restart and near expiry.** Consume an approval, restart every server instance, send
   the request again before the approval's expiry. Expect no write. Then consume an approval with the
   maximum lifetime, advance the clock to one second before its expiry, force any cleanup of the store
   and replay. Expect no write. (S13)
9. **Reordered members.** Send V3 with a V1 receipt. Expect one write. (S1)
10. **Other tool.** Send the V1 arguments to the second operation (V10) with a V1 receipt. Expect
    `approval_mismatch`. On HTTP, also change the method, the path and the query in turn. (S1, S11)
11. **Other account.** Send the V1 arguments with a credential for the second account and a V1
    receipt. Expect `approval_mismatch` and no write in either account. (S1, S11)
12. **Other principal.** Send V1 with the second principal's credential and a V1 receipt. Expect
    `approval_mismatch`. (S1, S11)
13. **Client-supplied target.** Send V1 with `_meta` members named `account`, `audience`, `principal`
    and `change_hash` carrying the values of another vector. Expect them to have no effect: the
    refusal of test 1 with the V1 hash. (S1)
14. **Input outside the change object.** For each header or setting that alters what the operation
    does, send an approved request with it changed. Expect a refusal, or a different change hash. For
    each value the server adds after hashing, check that it is fixed by configuration for the account
    and the operation; for each value that depends on the request or on record state, check that it
    is in the change object or covered by `preconditions`. (S4)
21. **Unsafe input.** Arguments that are an array; a lone surrogate in a string; and, where the request
    layer exposes them, a duplicate member name and the integer 9007199254740993. Expect a refusal with
    no change hash. The number 0.1 is accepted. (S3)
24. **Policy and grant are recorded as such.** Where the profile supports the policy type, send V1 with
    `receipts.policy`. Expect one write and an audit record with approver type `policy` and the policy
    identifier. Repeat for a grant. (S20)
27. **Counting.** A request naming the same record twice charges 2. A failed execution stays charged.
    A grant receipt for an operation whose count cannot be computed from the request is refused; in
    the server-issued profile, no grant is offered for it. (S19)
28. **Execution failure.** Make the write fail after consumption. Send the same request again with the
    same approval and the fault removed. Expect no write. (S13)
29. **Unknown outcome.** Make the system of record commit the write and drop the response. Expect at
    most one write, whatever the server and client retry. Then stop the server after consumption and
    before the write is sent; after restart expect no write without a new approval. (S25)
30. **Unavailable.** Make the consumption store unreachable. Where the signed-receipts profile is
    claimed, then make the issuer registry unreachable, then every key source for the issuer with no
    valid cached key. Expect `approval_unavailable` and no write each time. (S15)
31. **An approval is not a permission.** Use a credential without permission for the operation and a
    valid approval. Expect the ordinary permission refusal and the approval still unused. (S16)
32. **No opt-out.** Send unapproved requests with opt-out attempts in arguments and in `_meta` (for
    example `skipApproval: true`, a `dryRun: false` override, the refusal key echoed back). Expect the
    refusal of test 1. (S16)
33. **Refusals are recorded and leak nothing.** For every refusing test, check that an audit record
    with the `error` exists, that the response holds no part of the write's result and no receipt, and
    that server logs hold no receipt (its identifier is expected). Change one stored audit record, then
    remove one that is not the newest. Expect the server's chain check to report the broken link both
    times. (S17, S24)
38. **Settings are administrative.** Try to add an issuer, replace a key, remove an operation from the
    guarded list, change approver types or lifetimes, turn grants on for the second operation and
    raise the grant caps: through every MCP tool, with the agent's credential, and on the
    administrative surface as a non-administrator. Expect a refusal each time. (S23)

### Optional members (for operations that use them)

45. **Stale approval.** Obtain an approval for an update, change the record, then send the approved
    request. Expect `approval_mismatch` and a new change object with new `preconditions`. Approve a
    create with `absent: true`, create the record by another path, then send it: expect a conflict
    refusal and no write. Delete a record with an approved update: the same. Where the signed-
    receipts profile is claimed, the `current` object in the refusal hashes to `state_hash` (vector V12)
    and is absent for a credential that cannot read those fields. Where the system of record supports
    conditional writes, force a change between verification and the write: expect no write. Where it
    does not, the server's documentation says the check is not atomic. (S28)
46. **Update by query.** Approve an update by query that selects 3 records (vector V13). Where the
    signed-receipts profile is claimed, the refusal's `records` array hashes to `manifest_hash`.
    Send the approved request: exactly those 3 records change and a grant is charged 3. With a fresh
    approval, add a fourth matching record before sending: expect `approval_mismatch` and no write. Add
    a matching record between verification and the write: it is not changed. A selection over the
    server's limit is refused. (S19, S29)
47. **Partial batch failure.** Approve a 2-record change in which one record fails in the system of
    record. Send the failed record again with the same approval: expect no write. Send it as a new
    change with a new approval: exactly that record changes. (S25)

## Server-issued approval profile

34. **The connection cannot approve.** Without visiting the approval page: answer `accept`, answer a
    form mode elicitation, alter the echoed `requestState`, set the approval field. Retry. Expect no
    write. A client that did not declare URL mode elicitation receives `approval_required` with
    `approval_url`, never a form. (S21)
35. **Approved change only.** Approve on the page, then retry with one argument changed, then with the
    second principal's credential. Expect no write. Retry the original request: one write. Retry
    again: no second write. (S6, S11, S13)
36. **Approver permission.** P2 opens the approval page. Expect that P2 cannot approve. (S22)
37. **Pending records.** The documented expiry is at most 1 hour. A pending record approved after its
    expiry does not allow the write. An approval left unused past its stated time does not allow the
    write either. Requests beyond the per-principal cap create no further pending records. (S27)
48. **Client decline.** Approve on the page, then answer the elicitation with `decline`, and separately
    with `cancel`. Expect `approval_cancelled` and no write. Send the identical request again with no
    response: expect `approval_cancelled` again, no write and no new approval link, until the record
    expires. Send `decline` for a change that has no record: expect `approval_cancelled` and no
    pending record created. Ask, decline and ask with a changed argument until the cap is reached:
    expect `approval_limit_reached` with `retry_after`, `open` and `limit`, no approval link and no
    record created. Cancelled and denied refusals carry `retry_after`. (S27, S30)
49. **Denial.** Deny on the page. The page states that the change was denied, in different words from
    an approval. Retry: expect `approval_denied`, no write and no new approval link until the pending
    record expires. Retry with a `decline` response, then with none: still `approval_denied` and no
    new link. After expiry a new approval can be requested. (S31, S45)

### Grants

50. **Create.** P1 opens the approval page for a V1 change. Expect a grant option showing the
    principal, account, operation, selector values and field set of V1, with only the record limit
    and expiry editable. A record limit one over the record cap, and an expiry one second past the
    time cap, are refused. P2 is not offered a grant and a forged grant request from P2 is refused.
    The second operation offers no grant, and neither does an operation whose record count cannot be
    computed before execution. Sending `accept`, a form answer or a tool argument that claims a grant
    creates none. Creating a grant runs no write: the retried V1 runs under the grant and is charged
    to it. (S32, S33)
51. **Match.** After P1 grants on V1, send a change with the same principal, account, operation and
    selector values that sets the same fields to other values on another record. Expect one write, no
    elicitation and no approval link, and the counter charged. Send the same change with the second
    principal, with the second account, to the second operation, and with a different selector value
    (for example `delete` in place of `update`). Expect no write and the normal approval request each
    time. The server's documentation lists the selectors and field names of the operation. (S34, S35,
    S6)
52. **Field not covered.** Under the same grant, send a change that also sets one field outside the
    grant. Expect no write, the normal approval request and the counter unchanged. (S34)
53. **Limit.** With a record limit of 5 and 4 charged, send a 2-record change. Expect no write, the
    normal approval request and the counter at 4. Then send two different 1-record changes at the same
    time: expect one write under the grant and the normal approval request for the other. For an
    operation that uses `resolved`, a 3-record selection charges 3. (S35, S18, S19)
54. **Expiry.** Advance the clock to the grant's expiry. Send a covered change: expect no write and
    the normal approval request. One second earlier, the change runs. (S34, S35)
55. **Revoke.** P1 lists their grants and revokes one. The next covered request gets the normal
    approval request and no write. Writes made before the revocation remain. A revocation sent at the
    same time as a covered request leaves either the write charged before the revocation or no write,
    never a write after it. A can list and revoke P1's grants. P3 cannot see or revoke them. (S37)
56. **Audit type.** For a write under a grant, expect consumption and outcome records with approver
    type `grant`, the grant identifier and P1 as the person who made it, never type `person`. (S35,
    S20)
57. **Result text.** For a write under a grant, expect a text content block that says it ran under a
    grant and gives the grant identifier, the records remaining and the expiry. (S36)
58. **Unclassified input.** Under the grant, send a covered change with one extra argument the server
    does not document, then with one extra member inside a record entry. Expect no write and the normal
    approval request each time. (S34)
59. **Denial and cancellation first.** Deny a covered change on the page, then send it: expect
    `approval_denied` and no write, although a grant covers it. Repeat with a client `decline`: expect
    `approval_cancelled`. (S34)
68. **Authority at use.** P1 grants on V1. Send a covered change to the record P1 is not permitted to
    change: expect no write, the normal approval request and the counter unchanged. Remove P1's
    permission for the operation, then send a covered change to a record P1 could change before:
    expect the same. (S46)
69. **One change, one execution.** Under a grant, send a covered change and drop the response after the
    write. Send the identical request again. Expect one write, the counter charged once, and either no
    result or the recorded outcome. Where the operation uses `preconditions`, a new write to the same
    record has a different change hash and runs under the grant. (S35, S14)
70. **One unit.** Under a grant, make the charge fail inside the consumption transaction (a test hook).
    Expect no approved record, no consumption record, the counter unchanged, no write and the normal
    approval request. (S35)
71. **Selectors.** The server's documentation lists as selectors every argument of the first operation
    that chooses the kind of write. Where the server has an operation whose kind of write cannot be
    told from its arguments, expect no grant option on its approval page. (S47)
72. **Leaf field names.** The grant terms on the page and the documentation name only leaf fields.
    Under a grant on V1's fields, send a change that sets another child of the same parent, then one
    that sets the parent as a whole. Expect no write and the normal approval request each time. (S48)
73. **Finite limits.** The documentation states a finite record cap and time cap. On the
    administrative surface, try to set either cap to unlimited, empty or a value with no bound: expect
    a refusal. In an account with no caps configured, any grant offered has a finite record limit and
    expiry. (S49)
74. **Declines never match.** Under a grant, send a covered change that has no record, with a
    `decline` response, then with `cancel`. Expect `approval_cancelled`, no write and the counter
    unchanged each time. (S34)
75. **Decision finality.** Approve a record, then send a deny for it, then a grant: expect each refused
    and the approval unchanged. Send the same approve request twice, and the same grant request twice:
    expect the first result both times, one approval and one grant. Send approve and deny for one
    record at the same time: expect exactly one recorded. A decision for an expired or consumed record
    is refused. (S50)

### Approval page security

60. **Session.** Open the approval URL with no session: no change is shown and nothing can be decided
    until the person signs in. Present the agent's credential as a bearer token, and a value copied
    from the approval URL as a session cookie: expect neither to establish a session. The decision
    record names the signed-in person. (S38)
61. **Request forgery.** Send the decision, grant and revocation requests from another origin, and
    without the anti-forgery token or with a wrong one, using a valid session. Expect each to be
    refused and nothing recorded. (S39)
62. **Framing.** Every page response forbids framing by another origin. Embed the page in a frame on
    another origin: expect it not to display. (S40)
63. **Transport and caching.** Request each page and decision endpoint over plain HTTP: expect no page
    content and no decision recorded. Every response over TLS carries `Cache-Control: no-store`. (S41)
64. **Rendered from the stored record.** Open the approval URL with added query parameters, a fragment
    and a client-supplied summary that state other values. Expect the page to show only the values of
    the stored pending record. (S42)
65. **Displayed to that session.** P1 displays a record. P3, signed in, sends a decision for that
    record without displaying it: expect a refusal. P1 sends a decision naming another record they
    did not display: expect a refusal. The decision record holds the display time and the decision
    time. (S43)
66. **Approval URL identifier.** Collect 1,000 identifiers: expect no repeats and no visible sequence,
    and documentation stating at least 128 bits from a secure random source. Change one character of
    a valid identifier: expect nothing about the change to be shown. Knowing a valid identifier
    without a session lets no one decide. (S44)
67. **Decision page text.** After approve, deny and grant, expect three different statements. The
    approve page states until when the approval can be used. The grant page states the terms, the
    record limit and the expiry. (S45)
76. **Inert output.** Request a change whose field names, values and record identifiers contain markup
    and script. Expect the page to show them as text and run no script. Every page response carries a
    `Content-Security-Policy` that blocks inline and third-party script. (S51)
77. **Sign-in.** Note the session identifier before sign-in and compare it after: expect them to differ.
    Send the sign-in request from another origin, and without the anti-forgery token: expect no
    session. Start sign-in with a return location of another origin, then of a same-origin path the
    server did not generate: expect the person returned only to a path the server generated. (S52)
78. **Who may view.** Open a valid approval URL signed in as P4, then as P5. Expect nothing from the
    record to be shown either time. P1 sees the change. (S53)
79. **Referrer.** Every page response carries `Referrer-Policy: same-origin`. A form post from the page
    itself, sent as a browser sends it (with the page's own `Origin`), is accepted. The same post with
    `Origin: null` or another origin is refused. (S39, S52, S54)
80. **Shapes offered.** With "any record" disabled for the first operation, open the page for a V1
    change: expect only "these records", with the V1 record listed. Enable "any record": expect both,
    and the page names the shape chosen. A grant request naming a shape the page did not offer is
    refused and creates no grant. The third operation offers no grant until "any record" is enabled
    for it, and then offers only that shape. (S55, S32)
81. **These records.** P1 grants "these records" on V1. Send a covered change to the V1 record with
    other values: expect one write. Send it to another record, then to the V1 record and another
    record together: expect no write and the normal approval request each time. For an operation that
    uses `resolved`, grant on a 3-record selection, then send a selection with a fourth record: expect
    no write. (S55, S34)
82. **Shape is stated.** For a write under each shape, the consumption and outcome records and the
    result text state the shape. (S35, S36, S55)
83. **Retention.** Under a grant, run a covered change. Advance the clock to one second before the
    grant expires, force any cleanup of the store, and send the identical request again: expect no
    second write and the counter unchanged. (S35)

## Signed receipts profile (experimental)

8. **Changed argument.** Send V4 with the V1 receipt. Expect `approval_mismatch`, no write. (S11)
15. **Wrong audience.** Send V1 with `receipts.wrong_audience`. Expect `approval_invalid`. (S9)
16. **Times.** `receipts.expired`; `exp` passed by 61 seconds; `iat` 61 seconds in the future; a
    lifetime one second over the server maximum. Expect `approval_expired` each time. A receipt whose
    `iat` is in the future by half the server's configured skew is accepted. (S10)
17. **Tampered payload.** Send V4 with `receipts.tampered_payload`. Expect `approval_invalid`. (S8)
18. **Keys.** A receipt signed by an unknown key with the registered `iss`; an unregistered `iss`; a
    receipt valid for an issuer registered in the second account only. Expect `approval_invalid`. (S8)
19. **Malformed receipt fails closed.** Empty string; two segments; invalid base64url; a payload that
    is not a JSON object; each claim removed in turn; a duplicate claim; `exp` as a string; `iat`
    equal to `exp`; a `grant` member on a `person` receipt; wrong `typ`; `alg` of `none`; `alg` HS256
    keyed with the issuer's public key; ES256 on a key registered for EdDSA; a header with `jwk`,
    `jku`, `x5u` or `crit`; a receipt over the size limit (which is documented and at most 8
    kilobytes); a receipt in an encoding the server does not claim. Expect `approval_invalid` and no
    write each time. (S7)
20. **Two receipts.** A valid and an invalid receipt together, in both orders: two `_meta` receipt
    keys, a repeated header, a comma-joined header, and a receipt in both `_meta` and the
    `approval_receipt` argument. Expect `approval_invalid`. (S5)
22. **Approver type not allowed.** With the operation set to "person only", send V1 with
    `receipts.policy` and with `receipts.grant`. Expect `approver_not_authorized`. (S12)
23. **Issuer scope.** Register the issuer for the second operation only, then for `policy` only. Send
    V1 with `receipts.person`. Expect `approver_not_authorized` both times. (S12)
25. **Grant limit.** With `max_records` 50 and 49 charged, send a 2-record change. Expect
    `grant_exceeded`, no write, counter 49, and the receipt not marked used. Then send two different
    1-record changes with different fresh receipts at the same time. Expect one write. (S13, S18)
26. **Grant terms are fixed.** After a first receipt for a grant, send a receipt for the same grant
    `id` with a larger `max_records`, then a later `expires`. Expect a refusal. A receipt whose
    `grant.expires` has passed is refused. (S18)
39. **Key freshness.** The documented cache time is at most 24 hours and the removal time at most 1
    hour. Remove a key at the issuer: receipts signed with it are refused within the documented time on
    every instance. Remove the issuer: the same. Send 100 receipts with unknown `kid` values within a
    minute: expect at most one key refresh, and `approval_invalid` for each. Registering one key under
    a second issuer identifier in the same account is refused. (S26)

## Issuer

40. Give the issuer a change object and a different hash. The receipt carries the hash of the object.
    Give it `current` or `records` that do not match the hashes in the change object: no receipt.
    The approval page shows the operation, account, principal and every argument value of that
    object, and none of a summary supplied alongside it. (I1)
41. A request from the agent alone yields no person receipt. A person who is authenticated but not
    authorized by the organization for the operation cannot approve. The decision record holds the
    display time and the decision time. (I2)
42. A grant is created only by a person's action on the displayed terms. A change that differs from
    the grant in principal, audience, account, operation, field, period or remaining records, one
    term at a time, yields no receipt. (I3)
43. A policy receipt is issued only for a registered policy and carries its identifier and the hash
    of the version evaluated. Facts asserted by the agent or the client outside the change object do
    not change the decision. Where the policy uses a registered input beyond the change object, the
    receipt records that input by reference and hash, and changing the input changes the recorded
    hash. (I4)
44. Every approval and denial has a record that can be found by issuer and receipt identifier.
    (Signed receipts profile, Section 8)

84. **Any-record warning.** With "any record" enabled, open the approval page and choose that shape.
    The page says in plain words that the grant covers these fields on every record the person may
    change, and does not present the shown records as its limit. The confirmation page repeats it.
    A "these records" grant shows no such warning and lists its records. (S55)
85. **Undefined property.** Send a change that sets a property the system of record does not define.
    The approval page offers no grant for it. With a grant live for another field, the request does
    not match. (S48)
86. **Why no grant applied.** Use a grant up, let one expire, revoke one, and send a change outside
    one (another field, then another record). Each refusal carries the matching `grant_status` and a
    plain-words `message`. With no grant at all, `grant_status` is absent. (S56)
87. **Readable pages.** Every time on the approval, confirmation and grants pages is a date and time
    with its zone. The expiry is entered as a duration or a date and time. The grants list shows each
    grant's state in words with records used and remaining, and offers revocation only for active
    grants. (S57)
88. **Grant wording.** The result text of a write under a grant uses the word grant and says it is a
    standing permission, not an approval of this one change. (S36)

89. **Words, not identifiers.** On the approval, confirmation and grants pages, the operation and
    every field carry a name for people, with technical identifiers secondary. The value shown beside
    the expiry input is labelled as the latest possible expiry, and the confirmation page states the
    expiry actually set. A used-up, expired or revoked grant shows no remaining count. Each page has
    its own title. (S57)
90. **Readable errors.** Provoke each page error: an unknown or expired approval link, a second
    decision, a failed forgery check, a person without permission, a bad limit or expiry. Each
    response is a page that says what happened and what to do next, never an empty or bare response.
    (S58)
91. **Invalid input names its cause.** Send a change that sets an undefined property. The refusal is
    `invalid_input`, its `message` names the property, and it has no change hash and no approval
    link. (S3, S48)
92. **Reason on the elicitation.** With a used-up grant, send a covered change from a client that
    supports URL mode elicitation. The elicitation's message gives the reason. (S56)

93. **Decided links.** Approve one change, deny another and make a grant from a third. Open each
    link again. Each page states the recorded outcome and when, shows no decision form and does not
    present the change as open. (S50)
94. **Error wording.** Post a second decision to each of those three records: the page says which
    decision stands, and after the denial it does not say to send the request again. Open an invented
    link and an expired one: both get the same wording, which fits an unknown link and does not say
    the link ever existed. (S58)
95. **Messages for people.** No refusal message and no elicitation message contains a protocol member
    name such as `approval_url`. A refusal sent without an elicitation includes the link itself; one
    sent with an elicitation says to open the approval page. (S59)

96. **Outcome pages stay true.** Make a grant from a change and open its link: the page says the grant
    has not been used. Let the change run under the grant and open the link again: the page says the
    change ran under the grant, and when. Do the same for an approval before and after it is used.
    (S50)

## Coverage

| Requirement | Tests | Requirement | Tests | Requirement | Tests |
|---|---|---|---|---|---|
| S1 | 1, 9 to 13 | S16 | 2, 31, 32 | S31 | 49 |
| S2 | 2, 3 | S17 | 33 | S32 | 50, 80 |
| S3 | 21 | S18 | 25, 26, 53 | S33 | 50 |
| S4 | 4, 14 | S19 | 27, 46, 53 | S34 | 51, 52, 54, 58, 59, 74, 81 |
| S5 | 20 | S20 | 4, 24, 56 | S35 | 51, 53, 54, 56, 69, 70, 82, 83 |
| S6 | 1, 35, 51 | S21 | 34 | S36 | 57, 82, 88 |
| S7 | 19 | S22 | 36 | S37 | 55 |
| S8 | 17, 18 | S23 | 38 | S38 | 60 |
| S9 | 15 | S24 | 4, 33 | S39 | 61 |
| S10 | 16 | S25 | 29, 47 | S40 | 62 |
| S11 | 8, 10 to 12, 35 | S26 | 39 | S41 | 63 |
| S12 | 22, 23 | S27 | 37, 48 | S42 | 64 |
| S13 | 5, 6, 7, 25, 28, 35 | S28 | 45 | S43 | 65 |
| S14 | 5, 69 | S29 | 46 | S44 | 66 |
| S15 | 30, 39 | S30 | 48 | S45 | 49, 67 |
| S46 | 68 | S49 | 73 | S52 | 77 |
| S47 | 71 | S50 | 75, 93, 96 | S53 | 78 |
| S48 | 72, 85, 91 | S51 | 76 | S54 | 79 |
| S55 | 80 to 82, 84 | S56 | 86, 92 | S57 | 87, 89 |
| S58 | 90, 94 | S59 | 95 | | |
| I1 | 40 | I2 | 41 | I3, I4 | 42, 43 |

Not testable from outside, and so not claimed by passing these tests: that the consumption record is
durable before execution starts in every crash window (S24), and the SHOULD items (anchoring the chain
head, showing configured values to the approver, sign-in through the organization's identity provider,
the `approval_receipt` argument).
