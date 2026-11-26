# Enforced Approval: Conformance Tests

Draft 0.2, 2026-11-26. Author: Sharoze Iftikhar. Tests for implementations that claim conformance to
the core and its profiles. Each test names the requirement it checks.

The tests fall into six groups. A server runs the Core tests, the tests of every profile it claims
(the Server-issued approval profile tests, the Signed receipts profile tests (experimental), or
both), the Draft 0.2 tests for the profile rules it claims, and the Settings and deployment record
tests. An issuer runs the Issuer tests. The groups are headed "Core", "Server-issued approval
profile", "Signed receipts profile (experimental)", "Issuer", "Draft 0.2 tests", and "Settings and
deployment record".

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
- Draft 0.2 fixtures: a non-reader, a reader, a covered and a non-covered operation, a distinguishing
  argument, and a permission source that can answer neither yes nor no. Draft 0.2 hooks: a clock, a
  lost outcome, holding an execution after consumption, HMAC key replacement, and a count of reads
  against the system of record.
- Further Draft 0.2 fixtures: a query operation with a partly readable domain, an operation that
  copies a record-derived value, a version-token operation, and a system of record that treats a
  repeat as the same write. A further Draft 0.2 hook: one that lists approval records and contexts
  with their state.
- Draft 0.2 fixtures for results and identifiers: a principal with a write permission scoped by
  record, a system of record that returns record content and error text on a write, a read that
  fails, and a system of record that resolves a merged identifier to another record.

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
  approvals by change hash or, for a covered operation, in the request key's context (S67).
- **First refusal.** To see the `approval_required` refusal, send the request without declaring URL
  mode elicitation.

## Core

1. **Missing approval.** Send V1 with no approval, for an operation that is not covered (V1 has neither `preconditions` nor `resolved` and copies no value derived from record state). Expect `approval_required`, no write, `change_hash`
   equal to V1 and a `change` member equal to the V1 change object (both recomputed for `v` 2). On MCP the same object is present
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
5. **Replay.** Send the request of test 4 again. Expect no second write: the recorded outcome while the
   server holds it (S80), otherwise `approval_used`. (S13, S14, S80)
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
    valid approval. Expect the step 1 refusal, `permission_denied` with status 403 on HTTP, and the approval still unused. (S16)
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

45. **Stale approval.** Where the server-issued profile is claimed. Run for a principal that may read the record. Obtain an approval for an update, change the record, then send the approved request. Expect no write, no consumption, and `approval_required` carrying the fresh change object and change hash. Approve a create, create the record by another path, then send the approved request: a `conflict` refusal before approval is accepted but not required. Delete a record with an approved update, then send it: the same rule applies. The `state_hash` in the `preconditions` of the first refusal, before the record is changed, equals the value in V12, computed with the HMAC test key published with the vectors. Where the system of record supports conditional writes, force a change between verification and the write: expect no write. Where it does not, the server's documentation says the check is not atomic. (S28, S61, S64, S68(3))
46. **Update by query.** Where the server-issued profile is claimed. Run for a principal that may read. Approve an update by query that selects 3 records (vector V13). `manifest_hash`, computed as S61 defines with the HMAC test key published with the vectors over the approved arguments and the three selected records, equals the value in V13. Send the approved request: exactly those 3 records change and a grant is charged 3. With a fresh approval for a request that has a new value of the distinguishing argument (S69(4)), add a fourth matching record before sending: the approval is not consumed, and the answer is `approval_required` carrying the fresh change object and change hash, with no write. Add a matching record between verification and the write: it is not changed. A selection over the server's limit is refused. (S19, S29, S61, S68(3), S69(4))
47. **Partial batch failure.** Approve a 2-record change in which one record fails in the system of
    record. The request is answered with the result outcome `partial`, a result and not a refusal,
    carrying each entry's outcome: the written entry `success`, the failed one `execution_failed`.
    Send the failed record again with the same approval: expect no write. Send it as a new change
    with a new approval: exactly that record changes. (S25, S77)

## Server-issued approval profile

34. **The connection cannot approve.** Without visiting the approval page: answer `accept`, answer a
    form mode elicitation, alter the echoed `requestState`, set the approval field. Retry. Expect no
    write. A client that did not declare URL mode elicitation receives `approval_required` with
    `approval_url`, never a form. (S21)
35. **Approved change only.** Approve on the page, then retry with one argument changed, then with the
    second principal's credential. Expect no write. Retry the original request: one write. Retry
    again: no second write. (S6, S11, S13)
36. **Approver permission.** P2 opens the approval page. Expect that P2 cannot approve. (S22)
37. **Pending records.** The documented expiry is at most 1 hour where the administrator has not set a longer one, and never more than 24 hours. A pending record approved after its
    expiry does not allow the write. An approval left unused past its stated time does not allow the
    write either. Requests beyond the per-principal cap create no further pending records. (S27)
48. **Client decline.** Approve on the page, then answer the elicitation with `decline`, and separately
    with `cancel`. Expect `approval_cancelled` and no write. Send the identical request again with no
    response: expect `approval_cancelled` again, no write and no new approval link, until the record
    expires or one hour has passed since the cancellation, whichever is sooner. Send `decline` for a change that has no record: expect `approval_cancelled` and no
    pending record created. Ask, decline and ask with a changed argument until the cap is reached:
    expect `approval_limit_reached` with `retry_after`, `open` and `limit`, no approval link and no
    record created. Cancelled and denied refusals carry `retry_after`. (S27, S30)
49. **Denial.** Deny on the page. The page states that the change was denied, in different words from
    an approval. Retry: expect `approval_denied`, no write and no new approval link until the pending
    record expires or one hour has passed since the denial, whichever is sooner. Retry with a `decline` response, then with none: still `approval_denied` and no
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
    write. Send the identical request again. Expect one write, the counter charged once, and the recorded
    outcome while the server holds it (S80). For a covered operation, a new write to the same record is sent
    with a new value of the distinguishing argument and then runs under the grant. (S35, S14, S69)
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
    refused and nothing recorded. Valid identity assertion, no session cookie, foreign Origin, valid display token: refused; the same with a matching Origin and a display token bound to another person: refused; the same with no Origin header and a valid display token: refused. (S39, S75)
62. **Framing.** Every page response forbids framing by another origin. Embed the page in a frame on
    another origin: expect it not to display. (S40)
63. **Transport and caching.** Request each page and decision endpoint over plain HTTP: expect no page
    content and no decision recorded. Every response over TLS carries `Cache-Control: no-store`. Where a
    proxy or edge terminates TLS, also send plain HTTP to the public address of the agent's endpoint and
    of each page, and send a plain HTTP request whose own URL or client-settable headers claim https: expect a
    refusal or a redirect, no page content, no decision recorded and no guarded request executed.
    (S41, S79)
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
    server did not generate: expect the person returned only to a path the server generated. Where a
    proxy performs sign-in (S75): a request with no assertion, an expired one and one for another
    audience is refused, and the server redirects only to paths it generated. (S52, S75)
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
    link. Applies to a principal established to see every definition of the object type. (S3, S48)
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

40. Give the issuer a change object of an operation that is not covered and a different hash. The receipt carries the hash of the object.
    The approval page shows the operation, account, principal and every argument value of that
    object, and none of a summary supplied alongside it. (I1) (The Draft 0.1 clause on `current` and
    `records` is withdrawn; see S66.)
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
    hash. Register two sources and a model; change one source so that the computed value changes: the recorded hash changes. Change the model version: the recorded reference changes. (I4)
44. Every approval and denial has a record that can be found by issuer and receipt identifier.
    (Signed receipts profile, Section 8)

## Draft 0.2 tests

Tests 97 to 146 cover the Draft 0.2 additions. A test that exercises a covered operation, `preconditions`, `resolved`, an approval context or a request key belongs to the experimental part of this draft (core Section 12); a server that offers no covered operation does not run it. A "non-reader" is a principal for which S60(a) does not hold; a "reader" is a principal for which it holds. "Covered operation" is as S67 defines it. "Off" states what must fail when the protection is switched off. Test 104 and the first case of test 102 are for the signed-receipts profile, test 109 is for issuers and the change object, tests 139, 144, 145 and 146 are for the core, test 143 is for the core and, for its page clause, the server-issued profile, and the other tests, including the second case of test 102, are for the server-issued profile.

97. **Refusals without hash for non-readers.** Non-reader, covered operation: `approval_required`, `approval_denied`, `approval_cancelled`, `approval_limit_reached`, `conflict` and `execution_failed` carry no `change` and no `change_hash`; the approval record and audit record hold the hash. Off: a hash or `change` is returned. (S63, S68(1))
98. **Keyed state and manifest hashes.** Where the server has a reader. With the HMAC test key published with the vectors: (a) the SHA-256 of the same input without the key is not `state_hash`; (b) two records holding the same value have different `state_hash`; (c) two change objects that differ only in `arguments` have different `manifest_hash`. Off: an unkeyed hash fails (a); a record that is not bound into the hash fails (b); arguments not bound fails (c). (S61)
99. **Same answer for missing and existing records.** Non-reader: an update on a missing record and an update on an existing record are answered `approval_required`, and the two answers have the same members, status and `message`, differing only in values that follow from the request and in clock values. Applies where the write permission is not scoped by record. Off: `conflict` before approval. (S60, S64)
100. **No version or absent member.** Non-reader: a create on an existing identifier and a create on a free identifier are answered alike, as in test 99. Reader: no entry of `preconditions` has a `version` or `absent` member. Off: the two non-reader answers differ, or an entry has `version` or `absent`. (S62, S64)
101. **Conflict after approval.** Non-reader: an approval is given for an update on a missing record. The next request consumes the approval; the write does not take effect, and `conflict`, `execution_failed` or an unknown outcome reported as S69(3) states is accepted as the server documents. Off: the write takes effect, or `conflict` is returned before approval to a non-reader. (S64, S69(3))
102. **Signed receipts only.** A covered operation on a server that offers only signed receipts for it, and on a server whose account allows no approver type for it in the server-issued profile: every request is answered `approver_not_authorized` with no `change_hash`, the same whether or not the record exists. Off: `change_hash` is returned. (S66)
103. **Rejection by record state after approval.** Non-reader: a request that the system of record rejects because of record state is answered `approval_required` before approval. After approval it is answered `execution_failed`, writes nothing, and the audit record shows the failure. Its `message` names no record-state reason. Off: `invalid_input` before approval. (S65)
104. **No issuers for covered operations.** Covered operation, reader and non-reader: the refusal lists no `issuers`, and a receipt presented for it is refused with `approver_not_authorized`. Off: `issuers` is listed. (S66)
105. **Key rotation.** After the key is replaced and the previous key retired, an approved record for an operation that uses `preconditions` or `resolved` no longer matches. Off: it still matches, because the hash is not keyed. (S61)
106. **Permission source undecided.** The permission source answers neither yes nor no: the principal is treated as a non-reader, as in test 97. Off: `change` is present. (S60)
107. **Version token withdrawn.** Where the server has a reader. Reader, operation relying on a version token: the entry has `record` and `state_hash` only, and a new token gives a new hash. Off: the entry carries `version` or `absent`, or two tokens give the same hash. (S62)
108. **Missing record shown to the approver.** The approval page for an update on a missing record tells an approver who may read the record that it is missing, and shows nothing from the record to one who may not (S53). Off: the approver who may read the record is not told it is missing, or the page shows record content to one who may not. (S64)
109. **Version 2 only.** Every change object has `v` 2. An issuer that implements only `v` 2 refuses a change object with `v` 1. Off: an issuer accepts `v` 1. (Section 5 and I5)
110. **Copied record value.** Non-reader, operation that copies a record-derived value into `arguments`: no `change`; after the record changes the repeat is identical. Off: `change` is present, or the answer differs. (S67, S4)
111. **Refusal stable while pending.** Non-reader: a request is refused; the record changes; the repeat is identical in body, status and headers apart from clock values; exactly one open record exists, and by the time the approval page is displayed, or at step 2, the first is kept as superseded and the open record is built from the changed state. Off: the link or another member differs, two open records exist, or the first record is still open when the page is displayed. (S67, S68(2), S68(3))
112. **Query needs read permission.** A principal whose read permission on a filter field is not established for the whole domain sends an update by query: it is refused at step 1 without the query being run, with the same answer whatever the records hold, including for a filter built so that the selection would cross the limit only if a guess about an unreadable field is right. Off: the query is run, or the answer differs with record state. (S72)
113. **Limit does not depend on the change.** Non-reader at the open-request limit: the record changes and the repeat is still answered from the context, not `approval_limit_reached`; another request key is refused at the limit the same way before and after the change. Off: the limit answer depends on the change. (S70, S27)
114. **Denial is stable.** Non-reader: after a denial the record changes; repeats are answered `approval_denied` until the context expires or one hour has passed since the denial, whichever is sooner, and while the lockout lasts `retry_after` keeps counting down from it and does not become 0. With a pending lifetime above one hour the context outlives the lockout, and after one hour a new approval can be requested. Off: a repeat after the change is answered differently, has `retry_after` 0, or opens a new approval request. (S68(5), S70)
115. **Cancellation is stable.** As test 114 after a cancellation, with `approval_cancelled` in place of `approval_denied`. Off: a repeat after the change is answered differently, or opens a new approval request. (S68(5), S70)
116. **Stale approval is not a write.** Non-reader. A request is approved; the record changes; the repeat writes nothing, consumes nothing and is identical to the answer before approval; the approved record is kept as stale; restoring the record and repeating does not execute. Off: the answer differs, or the last repeat executes. (S68(3), S68(7), S60(f))
117. **Old approval page.** An approver opens the page; the record changes and the agent repeats; the approver submits the old form: no decision is recorded and the page shows the current request. Repeating a decision already recorded returns the first result. Off: the superseded record is approved. (S68(4), S43, S50)
118. **Grant closes the pending record.** A request is pending; the person makes a grant on the page, after which the record is no longer open; the record changes; the identical retry executes under the grant; the old page shows the recorded grant and offers no decision. Off: the retry is refused, or the old record can still be approved. (S68(3), S70, S50, S33 to S35)
119. **One context under concurrency.** Two simultaneous first requests for one request key, and two simultaneous requests against a stale approved record, each produce one open record in one context and identical answers. Off: two open records. (S67)
120. **Identical request after consumption.** Reader and non-reader: a write executes under an approval; someone else changes the record; the identical request does not execute, opens no approval record and returns the recorded outcome, marked as the outcome of an earlier attempt with its recorded time, the same as when the record is unchanged. Off: `approval_required` is returned, or a new pending record exists. (S69(1), S69(2))
121. **Repeat under a grant.** Reader and non-reader. As test 120 for a write under a grant: the identical request does not execute and is not charged. Off: it executes again. (S69(1), S34, S35)
122. **Distinguishing argument.** Under one grant, two requests that differ only in the distinguishing argument both execute and both are charged; a covered request without the argument follows the normal flow. Off (argument classified or unclassified for grants): the second request matches no grant. (S69(4))
123. **Unknown outcome.** Reader and non-reader. An approval is consumed and the outcome is lost: where the system of record does not treat a repeat as the same write, the identical request does not execute and is answered that the outcome is unknown, the same whether or not the record changed; when the outcome is learned, the answer becomes the recorded one. Where the system of record does treat the repeat as the same write and the server sends it again, the answer says so and gives the recovered outcome. Off: the identical request executes as an additional write, or the answer depends on whether the record changed. (S69(3), S25)
124. **Outcome of a consumed approval.** Reader and non-reader. An approval is consumed and the write is answered `conflict` or `execution_failed`: the identical request returns that outcome as its `error`, with `recorded_outcome` giving the outcome and its time, opens no approval record, and no open record of the context remains approvable. Off: the identical request opens an approval record, or an open record stays approvable. (S69, S64, S65, S68(6))
125. **Consumed contexts do not count.** Contexts whose approval was consumed do not count toward the limit; an approved, unconsumed context does. Off: a consumed context counts toward the limit, or an unconsumed approved context does not. (S70, S27)
126. **Reader refusal.** Where the server has a reader. Reader: the `approval_required` refusal carries `change` and `change_hash`, and the one-open-record rule holds. Off: the refusal omits `change` or `change_hash`, or two open records exist. (S63, S68)
127. **Same wording for unseen requests.** For a person not permitted to see the request, an unknown link, an expired link and a valid token whose context has no open record get the same wording. Off: the three answers differ in wording. (S58, S70)
128. **Grant status in a repeat.** Non-reader with a pending request: a grant is made for the same operation that does not cover the record; the repeat carries `grant_status: outside` and the message that goes with it, and is otherwise identical. Off: the repeat is refused without `grant_status`, or other members differ. (S68(2), S56)
129. **Selection growth after consumption.** Where the server has a reader. Reader. After a consumed update by query, the selection grows past the limit: the identical request returns the recorded outcome, not the limit refusal. Off: the limit refusal is returned. (S69, S29)
130. **Replay is marked.** Reader and non-reader: after a write executed, the identical request is answered with the recorded outcome, which identifies itself in `recorded_outcome` and in its `message` as the outcome of an earlier attempt, gives its recorded time and says that nothing was sent now and that a new write needs a new value of the distinguishing argument; this is run with a record that a person set back to its earlier value after the write; the answer is the same whether or not the record changed. Off: the answer can be read as the result of a new write. (S69(2))
131. **Unused approval is shown.** A person permitted to see the request approves it; the approval is closed as stale: the page of the context says that the earlier approval was not used because it no longer matched and shows the current request for a decision. After the current request is decided, the page shows no decision form. The notice is also correct where the approval stopped matching because the HMAC key was retired. Off: the page is silent about the unused approval, or offers a second decision. (S70, S50, S68(3))
132. **Repeat without a read.** Non-reader with no grant for the operation: a request is refused and not yet displayed; the record changes; a repeat may be answered without a read of the system of record and is identical; when the approval page is first rendered it shows the record built from the changed state, not the previously stored snapshot. Off: the page shows the previously stored snapshot. (S68(3), S42)
133. **Read is not skipped where it matters.** Non-reader: with an unexpired, unrevoked grant for the principal and operation, or after the open record was displayed, a repeat reads record state and is handled as S34 and S68(3) state; with a cancel response it is handled as S30 states. In none of these cases is the stored refusal returned from the context. Off: the stored refusal is returned and the grant, the cancellation or the supersession is missed. (S68(3), S30, S34)
134. **Approval of a change, not of a state.** For an operation that is not covered, the approval page says that the approval is for the change as requested and not for the state of the record when the write runs. Where the server shows current values, they are marked as current values that may change and are shown only to a person permitted to read them. Off: the page is silent, or current values appear as part of the approved change. (S71, S53)

135. **Repeat while in progress.** Two simultaneous identical requests to a covered operation under a grant: the first is held after consumption until the second has been answered; the second is answered as in progress, sends nothing and opens no approval record. Off: it executes, or is answered as an unknown outcome. (S69(5))
136. **Approval within its context.** An approval whose own expiry would fall after the context's expiry is usable only until the context expires, and the page states that time. With a consumed record kept for longer than the context, a repeat after the context has expired is still answered from that record, and no new context is created while it is kept. Off: the approval is usable after the context expires, or a repeat after expiry creates a new context. (S67)
137. **Earlier request shown.** The approval page for a request that differs only in the distinguishing argument from one denied earlier says so, while the server still holds that record. Off: the page is silent about the earlier denial. (S69(4))
138. **Filter is a selector.** Under one grant made for a request with one filter, a request with another filter that selects the same records, with every other condition of the grant met, matches no grant. Off: the request with the other filter matches the grant. (S73, S34)
139. **Results carry no record content.** Non-reader, under an approval and under a grant: the result and its replay carry no value read from the system of record other than the identifier of a record the write created, no value the server derived from record state, and no error text of the system of record. Off: such content is returned. (S77)
140. **Missing record under a record-scoped permission.** Non-reader. With a write permission scoped by record, an update on a missing record and on a record the principal may not write get step 1 refusals that are identical apart from values taken from the request and clock values; a create still reaches `approval_required`. Off: the two refusals differ, or the create is refused. (S60)
141. **Absent record and failed read.** A record that does not exist is answered as any other change, not `approval_unavailable`; a system of record that times out is answered `approval_unavailable` and nothing is superseded, closed or consumed. Off: the absent record is answered `approval_unavailable`, or after the timeout a record is superseded, closed or consumed. (S67)
142. **Other records close at consumption.** A person's pending record for a change is closed as superseded when a grant consumes the same change, and approving its old page does nothing. Off: the record can still be approved. (S35, S68(6))
143. **Identifier that resolves to another record.** A write to an identifier that the system of record resolves to another record does not take effect on that record where the system of record offers a conditional write or refuses, and is answered as S64 provides after consumption; for a covered operation the entry uses the `absent` kind, so an approval given before the merge is stale; before consumption the answers for a merged and a missing identifier are identical for a non-reader; the approval page states the resolution to a person permitted to see it and offers no approval. Off: the surviving record changes, or the answers differ. (S78)
144. **Identifier format.** An identifier from the system of record that is over-long or outside the documented character set does not appear in the result, in a per-record entry, in a replayed outcome or in a `message`; the result says it was withheld. Off: it appears. (S77)
145. **Recorded outcome for every guarded operation.** For an operation that is not covered, after a write that succeeded and after one that failed, the identical request returns the recorded outcome, says that it is the outcome of an earlier attempt with its time, and says that nothing was sent now. Off: a bare `approval_used` is returned while the server holds the outcome. (S80, S14)
146. **Redirected identifier on an operation that is not covered.** For an operation that is not covered, under a person's approval and under a grant, a write to an identifier that resolves to another record is not sent after the read before the write finds the difference, where the system of record offers neither a conditional write nor a refusal. Where the resolution appears only after that read, the entry's outcome is `misdirected`, the audit record holds the identifier the write was applied to, and the result to a non-reader does not carry it. Off: the write is sent, or the outcome is reported as success. (S78, S77)

## Settings and deployment record

Tests 190 to 198 cover core Section 11, and test 199 covers S90 of the server-issued profile. Numbers 147 to 189 are used by the sandbox for its own tests and are not conformance tests. "Hard limit" and "default" are as the registry of core Section 11.1 states.

The sandbox's run of 2026-11-26 reports `SUMMARY: PASS=216 FAIL=0 NOT AUTOMATED=3 NOT IMPLEMENTED=0` over tests 1 to 219: 143 of tests 1 to 146 pass and 3 cannot be automated on one machine, all of tests 190 to 199 pass, and the sandbox's own tests 147 to 189 and 200 to 219 pass.

190. **Defaults.** On a deployment where no setting was made, every setting of the registry is at its default, and the deployment record says so. Make one setting unreadable: the server applies its default. Off: a setting starts at a looser value, or an unreadable setting is treated as loose. (S81, S87)
191. **Hard limits.** On the administrative surface, set each setting one step past its hard limit, then empty, then unlimited: each is refused, the value in force is unchanged and the refusal is recorded. Set a pending lifetime over 1 hour with no approver notification: refused. Off: a value past the limit is accepted. (S81, S27)
192. **Invariants at the limits.** Run the server's S82 invariant set at the default of every setting, then with each registry setting at its hard limit in turn. Each run gives the same results. Off: a test that passes at the default fails at a limit. (S82, S88)
193. **Scope.** The administrative surface offers no setting scoped by record content, for example a pending lifetime or an approver model that applies only to records holding some value. Off: such a scope exists. (S83)
194. **Tightening and loosening.** Lower the pending lifetime: an existing pending record expires at the new limit. Then raise it: a record that expired, was denied or was cancelled stays so, and an existing grant's terms are unchanged. Off: a lowered limit waits for new records, or a raised one revives a record or widens a grant. (S84)
195. **Configuration change voids a match.** Obtain an approval; change a value fixed by configuration for the operation (S4), and separately change the approver model so that the approver is no longer permitted; send the approved request each time: no write, no consumption and the normal approval request. Off: the approved request runs. (S85)
196. **Setting changes are audited.** Each change of a setting is in the audit chain with who made it, when, and the old and new values, and the chain check reports no broken link. Off: a change is missing from the chain. (S86)
197. **Deployment record and `config_hash`.** Compute `config_hash` from the deployment record: it equals the value in every consumption audit record made since the last change of a setting. Change a setting: the deployment record is recorded in the chain and later consumption records carry the new value. Off: a consumption record lacks `config_hash`, or carries a value that does not match the record in force. (S87)
198. **Notification for a longer pending lifetime.** With a pending lifetime over 1 hour and a notification channel set, each new pending record produces one logged notification to the approver, on a channel the agent's credential cannot read. Off: a pending record over 1 hour has no logged notification. (S27, S81)
199. **Poll and expiry members.** The `approval_required` refusal carries `pending_expires`, equal to the pending record's expiry (for a covered operation the context's), and `poll_interval`, shorter than `max_lifetime`. Sending the identical request every `poll_interval` seconds after a person approves runs the write once. Off: either member is missing, or the interval is not shorter than `max_lifetime`. (S90)

## Coverage

| Requirement | Tests | Requirement | Tests | Requirement | Tests |
|---|---|---|---|---|---|
| S1 | 1, 9 to 13 | S26 | 39 | S51 | 76 |
| S2 | 2, 3 | S27 | 37, 48, 113, 125, 191, 198 | S52 | 77, 79 |
| S3 | 21 | S28 | 45 | S53 | 78, 108, 134 |
| S4 | 4, 14, 110 | S29 | 46, 129 | S54 | 79 |
| S5 | 20 | S30 | 48, 133 | S55 | 80 to 82, 84 |
| S6 | 1, 35, 51 | S31 | 49 | S56 | 86, 92, 128 |
| S7 | 19 | S32 | 50, 80 | S57 | 87, 89 |
| S8 | 17, 18 | S33 | 50, 118 | S58 | 90, 94, 127 |
| S9 | 15 | S34 | 51, 52, 54, 58, 59, 74, 81, 118, 121, 133, 138 | S59 | 95 |
| S10 | 16 | S35 | 51, 53, 54, 56, 69, 70, 82, 83, 118, 121, 142 | S60 | 99, 106, 116, 140 |
| S11 | 8, 10 to 12, 35 | S36 | 57, 82, 88 | S61 | 45, 46, 98, 105 |
| S12 | 22, 23 | S37 | 55 | S62 | 100, 107 |
| S13 | 5, 6, 7, 25, 28, 35 | S38 | 60 | S63 | 97, 126 |
| S14 | 5, 69, 145 | S39 | 61, 79 | S64 | 45, 99, 100, 101, 108, 124 |
| S15 | 30 | S40 | 62 | S65 | 103, 124 |
| S16 | 2, 31, 32 | S41 | 63 | S66 | 102, 104 |
| S17 | 33 | S42 | 64, 132 | S67 | 110, 111, 119, 136, 141 |
| S18 | 25, 26, 53 | S43 | 65, 117 | S68 | 45, 46, 97, 111, 114, 115, 116, 117, 118, 124, 126, 128, 131, 132, 133, 142 |
| S19 | 27, 46, 53 | S44 | 66 | S69 | 46, 69, 101, 120, 121, 122, 123, 124, 129, 130, 135, 137 |
| S20 | 4, 24, 56 | S45 | 49, 67 | S70 | 113, 114, 115, 118, 125, 127, 131 |
| S21 | 34 | S46 | 68 | I1 | 40 |
| S22 | 36 | S47 | 71 | I2 | 41 |
| S23 | 38 | S48 | 72, 85, 91 | I3 | 42 |
| S24 | 4, 33 | S49 | 73 | I4 | 43 |
| S25 | 29, 47, 123 | S50 | 75, 93, 96, 117, 118, 131 | I5 | 109 |
|  |  |  |  | S71 | 134 |
|  |  |  |  | S72 | 112 |
|  |  |  |  | S73 | 138 |
|  |  |  |  | S74 | none yet |
|  |  |  |  | S75 | 61, 77 |
|  |  |  |  | S76 | none yet |
|  |  |  |  | S77 | 47, 139, 144, 146 |
|  |  |  |  | S78 | 143, 146 |
|  |  |  |  | S79 | 63 |
|  |  |  |  | S80 | 5, 69, 145 |
|  |  |  |  | S81 | 190, 191, 198 |
|  |  |  |  | S82 | 192 |
|  |  |  |  | S83 | 193 |
|  |  |  |  | S84 | 194 |
|  |  |  |  | S85 | 195 |
|  |  |  |  | S86 | 196 |
|  |  |  |  | S87 | 190, 197 |
|  |  |  |  | S88 | 192 |
|  |  |  |  | S89 | none yet |
|  |  |  |  | S90 | 199 |

Not testable from outside, and so not claimed by passing these tests: that the consumption record is
durable before execution starts in every crash window (S24), that a version token qualifies as S62 requires, and the SHOULD items (anchoring the chain
head, showing configured values to the approver, sign-in through the organization's identity provider,
the `approval_receipt` argument).

## Running these tests against a deployed server (informative)

A runner for a deployed server needs a base URL, an agent credential and an administrator credential, the fixtures listed in Setup, and the hooks listed there. Each test is marked with everything it needs: none (runs from outside as written), or one or more of clock, fault (a lost outcome or a storage failure), concurrency, and inside (it inspects stored records or the audit store and cannot run from outside). A server's claim to pass a test names the test numbers, the commit of this specification and the date.

A test that appears on more than one line below needs everything those lines name.

- none: tests 1 to 3, 5, 8 to 13, 15 to 23, 26, 31, 32, 34 to 36, 38, 40, 42, 43, 50 to 52, 57 to 59, 61 to 64, 66 to 68, 71 to 74, 76 to 81, 84, 85, 87 to 89, 91 to 93, 95, 96, 99 to 102, 104, 106 to 110, 113, 117, 118, 121, 122, 125, 128 to 130, 132, 134, 137 to 140, 142, 193 and 199.
- clock: tests 7, 37, 39, 48, 49, 54, 75, 83, 86, 90, 94, 114, 115, 127, 136 and 194.
- fault: tests 27 to 30, 47, 69, 70, 123, 141, 144, 145 and 146.
- concurrency: tests 6, 25, 45, 46, 53, 55, 75, 119 and 135.
- inside: tests 4, 7, 14, 24, 25, 29, 33, 39, 41, 44, 48, 56, 60, 65, 70, 82, 83, 97, 98, 103, 105, 111, 112, 116, 119, 120, 124, 126, 131, 133, 135, 136, 141, 143, 146, 190 to 192 and 194 to 198.

## Requirements not yet covered by a test

Entries are removed from this list as tests are written.

- S60 for an operation that is not covered.
- S61 acceptance under two keys and "MUST NOT mix keys".
- S63 "`change` is always included" where not covered.
- S64 create on an existing record after consumption and the pre-write check.
- S65 for a reader.
- S66 "without reading record state".
- S67 `request_key` value, presence and stability, and an approved record expiring unused.
- S68(6) by grant for a covered operation.
- S69(4) "MUST NOT require" and the notice for cancelled and consumed.
- S69(5) under a person's approval and its fall to item (3).
- S70 what the open record is bound to.
- S72 for a key lookup and for a configured filter.
- S73 second sentence.
- S74; S75 beyond tests 61 and 77, including the mapping of a person and the audience; S76, including what a permission model states separately.
- S75 maximum age of an assertion and the qualification of a subject by its proxy.
- S78 for a record the request only refers to, and at step 1 under a write permission scoped by record.
- S79 that requests are accepted only on an authenticated channel from the edge, and the handling of a credential received over plain HTTP.
- S80 for an unknown outcome and for an execution still in progress.
- S48 for a principal not established to see every definition.
- S62 `absent` kind and whole-record reader.
- S64 page notice for an existing record.
- S67 read begun earlier.
- S69(3) page notice.
- S70 "MUST NOT tell the agent".
- S77 for a reader and for an operation that is not covered.
- S56 `outside` for S46.
- S60(c) for delete and association.
- S77 reasons and `not_sent`.
- S88's "conformance tests are run ... again with each setting at its hard limit": the sandbox runs its S82 invariant set at each limit (test 192), not the whole suite at every configuration.
- S89, the disclosure of a deployment record, which is a claim about a deployment rather than a behaviour.
