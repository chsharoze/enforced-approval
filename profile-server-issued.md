# Enforced Approval: Server-issued Approval Profile

Draft 0.2, 2026-11-26. Author: Sharoze Iftikhar. Normative. It extends the core
document (`core.md`), whose terms, change hash, verification steps, refusals and requirements apply
here unchanged.

## 1. What this profile is

The server obtains the approval itself. When an agent asks for a guarded write that has no approval,
the server sends a person to its own approval page. The person signs in, sees the change and decides.
The client then sends the same request again. The client never carries a receipt.

In this profile the approval is a record in the same server that holds the credential. It is enforced
and audited, but it is not verifiable by an outside party.

What it gives:

- The agent cannot approve its own write (T1, T3). Only an authenticated person on a page the agent
  cannot operate can approve.
- An approval covers one exact change by one principal in one account (T4), and runs once (T2).
- Every approval, refusal and write is in the server's audit record (T5).
- It works with clients the organization does not control, because the client carries nothing. Where
  the organization controls neither the client nor the server, for example a business user's chat
  assistant reaching the system through a vendor's hosted connector, it is the only profile that works.

What it does not give:

- Proof to anyone outside the server. The evidence that a person approved is the server's own record,
  which the server's operator can change. Anchoring the chain head (S24) makes later rewriting
  detectable, not impossible.
- Protection against a compromised or dishonest server.
- One approval rule across servers from different vendors. Each server has its own page. The
  signed-receipts profile exists for that.

## 2. Flow

1. On a guarded request with no approved record and no matching grant (Section 5), the server stores
   a pending record for the change hash and directs a person to its approval page (Section 4).
2. The approval page authenticates the person, shows the change and records one decision: approve,
   deny, or grant (Section 5).
3. The client sends the identical request again. The server computes the change hash again. Because
   the hash covers the principal, only the same principal can match the record.
4. If an approved record exists, found by that hash for an operation that is not covered and in the
   request key's context for a covered operation (S67), the server continues from step 7 of the core's
   verification steps. Steps 4 to 6 are met by the lookup: the record is in the server's own store,
   and the server is both the issuer and the audience. For an operation that is not covered, the
   record is found by its change hash and step 8 holds by construction. For a covered operation the
   server finds the approved record in the request key's context (S67) and compares its change hash
   with the one it computed; a difference is handled as S68(3) states. Where the
   operation is not covered, a request for a different change finds no record and starts a new
   approval request.

**Retry.** Refusing the request and receiving the identical request again is the flow of this profile, and the server MUST support it. The host or orchestrator sends the identical request again; the agent need not be asked to. While the record is pending, the answer to the identical request is the same refusal with the same approval link, so a loop can poll the pending record by sending the identical request again. The approval page is for the person and is not a status for the agent (S38, S44).

*Note (informative).* A client that supports MCP Tasks could let a server hold the request as a task and run it after the decision. This draft defines no wire profile for that. A held request would be verified again from step 1 of the core's Section 6 when it runs.

An approval record is pending, approved, denied, cancelled, granted (a record on which a grant was made, S50, S70) or consumed, and it expires. A record can also be closed as superseded at consumption (S35); for a covered operation it can also be superseded on replacement, or stale (S68). The core's S6 applies: a
request runs only with an approved record. An approved record comes either from a person's approval on
the page or from a grant match (S35).

## 3. Requirements for the flow

- S21. The server MUST NOT treat anything received on the MCP connection (a form mode elicitation
  answer, an `accept` action, an echoed `requestState`, a tool argument) as the approval, and MUST NOT
  fall back to form mode elicitation. The approval is the decision its own approval page recorded for
  an authenticated person.
- S22. The approving person MUST hold, in the account, the permission to make the change themselves.
  The approval page SHOULD accept sign-in through the organization's own identity provider. Where the system of record cannot answer, see S76. Where the permission source is outside the server, see S74.
- S27. A pending record MUST expire within the server's documented limit. The limit is 1 hour where no
  limit is set, and at most 1 hour, except that an administrator MAY set a limit of up to 24 hours where the server notifies the approver of each pending record through a channel the agent cannot read
  and logs each notification; a pending record still counts toward the cap below until it expires. An approval
  on the page is usable only until its own expiry, at most the maximum receipt lifetime after the
  decision. The server MUST cap the number of unexpired pending, denied and cancelled records per
  principal, so that asking, declining and asking again, or asking again with a changed argument,
  cannot produce unlimited approval requests. At the cap it MUST refuse with `approval_limit_reached`,
  never `approval_required`, and MUST NOT create a record. For a covered operation, see S67 and S70.
- S30. If a request carries a `decline` or `cancel` response to the elicitation, the server MUST NOT
  execute it and MUST NOT create a pending record for it. It marks a pending or approved record for
  that change as cancelled, in the same atomic domain as consumption (S13), and refuses with
  `approval_cancelled`, as it does for later requests for that change until the record expires or one hour has passed since the cancellation, whichever is sooner. A
  denied record stays denied (S31). For a covered operation, see S70. Voiding from the connection is safe because it only restricts.
- S31. After a denial on the approval page, the server MUST refuse requests for that change with
  `approval_denied` and MUST NOT offer a new approval for it until the pending record expires or one hour has passed since the denial, whichever is sooner. No
  response on the connection changes that. A denial covers the exact change: a request with other
  arguments is another change, and S27 bounds how many of those a principal can raise. For a covered operation, see S68(5) and S70.
- S67. Covered operations and approval contexts. An operation is covered if it uses `preconditions` or `resolved`, or copies a value derived from record state into `arguments` under S4; such a value is treated as `preconditions` are for S60(a) and S63, and makes the operation a covered operation for S66 to S70. For a covered operation the server MUST compute a request key: the base64url encoding without padding of the SHA-256 digest of the RFC 8785 serialization of an object with exactly the members `v`, `audience`, `account`, `principal` and `operation` of the change object, and `arguments` as Section 5 of the core defines it before any value derived from record state is copied in. It never includes `preconditions` or `resolved`. The server groups the approval records of one request key into an approval context. A context has an unguessable token as S44 requires, a creation time and an expiry time; the creation time is fixed when its first record is created and the expiry time is as stated below. It holds at most one open (pending) record at any time. Creating a context, replacing its open record, replacing an approved record under S68(3), recording a decision or a grant, and closing a record or the context MUST each be one atomic step across all instances, in the same domain as S13, so that simultaneous requests cannot produce two contexts or two open records for one request key. The server finds an approved record (step 4 of Section 2) in the request key's context and compares its change hash. Internally the server works by change hash as the core provides and reads record state on every request, except where S66 forbids the read and where S69 answers a repeat of a consumed request key: that answer comes before the server rebuilds state or applies the selection limit of S29. S68(3) permits further cases. A context expires no later than its creation plus the pending lifetime in force: lowering that setting shortens an existing context at once and raising it never extends one (S84). No pending or approved record outlives its context: an approval is usable until the earlier of its own expiry and the context's expiry, and the page states that earlier time (S45). A consumed record is kept as S13, S35 and S69 require, also after its context has expired, and while it is kept no new context is created for that request key (S69(1)). When an approved record expires unused inside its context, a non-reader is answered as before the approval and a reader as S63 provides, a new pending record is created in the context on the next request, and the context still counts under S70. For a covered operation a refusal carries `request_key` wherever the server computed one, also for a principal for which S60(a) does not hold; it does not depend on record state. The audit record carries it. `request_key` is added to the refusal members listed in Section 7 of the core. Where a read of record state the server needs does not complete (the system of record is unreachable, times out or errors), the server MUST answer `approval_unavailable` (S15) and MUST NOT supersede, close as stale or consume anything; S68(2) does not apply to this answer. An answer that the record does not exist is a completed read (the `absent` kind), not a failure. A failure particular to one record is a difference in record state and is listed in Section 2. The server MUST NOT replace or close a record on the strength of a read of record state that began before the latest of: the creation of that record, its last rendering for a decision (S68(3)), and the recording of its decision; it reads again.
- S68. What a principal that may not read can see. For a covered operation and a principal for which S60(a) does not hold:
  (1) No refusal and no result carries `change` or `change_hash`, before or after consumption, including `conflict` and `execution_failed`. The server records the change hash in the approval record and the audit record.
  (2) The approval link and every other client-visible member, header and time value of a refusal are taken from the context, not from the approval record. While the context is unexpired and in the same state (open, denied, cancelled), every answer to a request with that request key MUST be identical in body, status and headers, apart from values that depend only on the current time and apart from what the exceptions (c) and (d) of S60 change, such as `grant_status`. An approved context is governed by item (3), and answers after consumption by S69.
  (3) Where no approved record matches and no grant matches (S34): whenever the change hash the server computes differs from that of the context's open record, the server MUST replace the open record: the old one is closed as superseded and kept as S50 and Section 10 require, the new one is created in the same context, and for a principal for which S60(a) does not hold the answer is unchanged. Whenever it differs from that of an approved, unconsumed record of the context, that record is closed as stale and kept, a new pending record is created in the same context, nothing is consumed, and for a principal for which S60(a) does not hold the answer is the one given before the approval. A principal for which S60(a) holds is answered with the new record's change object and change hash. After its ordinary permission checks and the handling of a decline or cancel response, the server MAY answer a repeat from a non-reader without reading record state while the context is unexpired and pending, provided that no unexpired, unrevoked grant exists for that principal and operation and that the open record has not yet been displayed for a decision. Under the same conditions it MAY also answer a repeat from a reader while the context is pending and its open record has not yet been displayed, answered with the stored `change`. Whenever it renders the approval page, the server MUST first read record state and apply this item, and it renders the resulting stored record (S42). Verification always reads record state, at step 2 of Section 6, before the comparison at step 8.
  (4) A decision posted from an approval page MUST name the record the page displayed. S50's rule for a repeated decision applies first. Otherwise, if the named record is no longer the context's open record, the server MUST refuse the decision, record no approval, denial or grant, and show the current request to a person permitted to see it.
  (5) After a denial or a cancellation, an identical request is answered `approval_denied` or `approval_cancelled` until one hour has passed since the decision or the context expires, whichever is sooner, whether or not record state changed (S30, S31).
  (6) When an approval is consumed for the request key, by a person's approval or by a grant, the context's open record, if any, is closed in the same atomic step as the consumption, whatever the outcome of the write. When an approval is consumed, by a person's approval or by a grant, every other pending or approved record for the same change hash, and for a covered operation for the same request key, is closed in the same atomic step. Such a record is closed as superseded; the clause of S50 on a record that is no longer pending covers it, and its page says that the change already ran under another approval.
  (7) A superseded or stale record is never matched again, also when record state returns to what it was.
  A principal for which S60(a) holds is answered as Section 7 of the core provides, with `change` and `change_hash`; the context, the one-open-record rule and items (3) to (7) apply to it as well.
- S74. Where the source that answers S22, S46 or S53 is outside the server and cannot be consulted inside the atomic step that records a decision, creates a grant, charges a grant or renders a page, the server MAY obtain the permission facts immediately before that step. It MUST obtain them for that step alone, never reusing facts obtained for an earlier render, decision, grant or write. The step MUST commit, or the page be sent, no more than a bound it documents after it first asked for them, and that bound MUST NOT exceed 5 seconds. The bound is elapsed time on the server's clock from the moment it sent the first query whose answer the step uses. How current the source's own answer is lies outside the bound. Where the facts cannot be obtained, or the bound has passed, the step MUST NOT proceed: this is a failed check: no decision, grant or consumption is recorded, nothing is charged or shown from the record, and under S35 the unit rolls back. The refusal of a guarded request is still recorded as S17 requires. The server MUST apply the facts inside the step, MUST record in the decision, grant or consumption record the time at which they were obtained, and MUST still check inside the step everything it holds itself: that the record is still pending, the grant's expiry, revocation and counter, and its own approver configuration. The clause of S35 that the server checks inside the unit that S46 holds, and the words 'at that moment' in S46, are met this way. For a render, the time is recorded with the display time of S43.

## 4. Refusals and mappings

**Refusal members.** A refusal in this profile has `approval_url` (the approval page for this change)
for `approval_required`, and a `message` in plain words that fits the error. For `approval_required`
the message says that the decision is made on the approval page, that the client carries nothing, and
that the same request is sent again afterwards. `approval_denied`, `approval_cancelled` and
`approval_limit_reached` carry `retry_after`: the seconds until a new approval can be requested, for
that change or, at the limit, for any change (0 when the server holds no record for the change).
For a covered operation, see S70.
`approval_required` also carries `pending_expires` and `poll_interval` (S90).
`approval_limit_reached` also carries `open` and `limit`: how many records count against the principal
now, and the cap. Its `message` says the same in plain words, including that declined and denied
requests count until they expire and that no approval prompt will appear before then.

- S59. The `message` is read by people as well as by models. It MUST NOT refer to protocol member names
  such as `approval_url`. Where the client was given the link through an elicitation, the message says
  to open the approval page; otherwise it includes the link itself.

- S90. An `approval_required` refusal in this profile MUST carry `pending_expires`, the time at which
  the pending record expires, in seconds since the epoch, and `poll_interval`, the number of seconds a
  client waits before it sends the identical request again. `poll_interval` MUST be shorter than
  `max_lifetime`, so that a client polling at that interval sends the request again while an approval
  is still usable. For a covered operation both are taken from the context (S68(2)), and
  `pending_expires` is the context's expiry.

A server that only uses this profile SHOULD NOT declare the `approval_receipt` argument of the
signed-receipts profile. Models that see it ask people for a receipt that does not exist.

**Capabilities.** The server reads the client's capabilities from each request, not from the
connection setup. A client's setup connections may declare less than its tool calls.

**MCP mapping.** If the client declared support for URL mode elicitation on that request (MCP revision
2026-07-28), the server answers a request with no approved record with an input-required result that
carries a URL mode elicitation for the approval page. URL mode exists for "out-of-band interactions
that must not pass through the MCP client" [MCP-ELICIT]. The client's next request carries the
elicitation response: `accept` is only a signal to look again (S21), and `decline` or `cancel` voids the
request (S30). If the client did not declare URL mode, the server returns the `approval_required`
refusal with `approval_url`. Refusals are encoded as the core states.

**HTTP mapping.** The server returns the `approval_required` refusal with `approval_url` and status 403.
The client sends the identical request again after the decision, or every `poll_interval` seconds until `pending_expires` (S90). `approval_limit_reached` uses status
429 with `Retry-After`. There is no elicitation response on HTTP, so S30 does not arise.

## 5. Grants

On the approval page, next to approve and deny, the person may grant further changes. The server fixes
the terms from the change being shown: the principal, the account, the operation, the set of fields
and, for the "these records" shape, the records (S55). The person chooses a shape among those offered
and sets only a record limit and an expiry, inside limits the account administrator
configured (S49). Which operations may offer grants at all is account configuration (S23). This
specification gives no method and no default for how wide a grant should be.

**Fields and selectors.** For each operation that offers grants, the server documents two things: its
selectors (S47) and how it names the fields a request sets (S48). For grant matching, the values of the
selectors are part of the operation. A grant covers a field set, not values. Which records it covers
depends on its shape (S55).

A grant record holds `id`, `granted_by`, `principal`, `audience`, `account`, `operation` (with its
selector values), `fields`, `shape`, `records` (for the "these records" shape only), `max_records`,
`expires`, the time it was made, its counter and its
revocation time, if any. Its terms never change. A wider grant is a new grant.

- S32. The server MUST offer a grant only for an operation the account configuration allows and whose
  record count can be computed before execution (S19). It MUST take the principal, account, operation,
  selector values and field set from the stored pending record being shown, and let the person set
  only the record limit and the expiry and choose a shape among those offered (S55). It MUST refuse a
  limit or an expiry outside the limits the administrator configured, and a shape it did not offer,
  and MUST display all terms, including the shape, before the person grants. For the distinguishing argument of a covered operation, see S69(4).
- S33. Creating a grant MUST require the same authentication and permission as approving (S22),
  including the permission to make changes to every field in the grant. A grant MUST be created only
  by a person's action on the approval page. Nothing received on the MCP connection creates, widens
  or extends a grant (S21). Creating a grant does not approve the change shown; the retried request is
  matched against the grant like any later request and is charged to it. Where the permission source is outside the server, see S74.
- S34. On a request with no approved record, the server MUST look for an unexpired, unrevoked grant with
  the same principal, account, operation and selector values, whose fields cover every field the
  request sets, and, for the "these records" shape, whose record set holds every record the request
  touches. A request that touches any record outside the set MUST NOT match. An input the server cannot classify as a selector, a field or a documented record
  identifier MUST mean no match. A denied or cancelled record for the change takes precedence: the
  server refuses as S30 and S31 require and does not look for a grant. A request that carries a
  `decline` or `cancel` response MUST NOT be matched to a grant; S30 already forbids executing it.
  When no grant matches, the request is treated as one with no approved record. For a covered operation, see S69 and S70; for its distinguishing argument, S69(4) applies in place of the sentence on an input the server cannot classify. For a query filter, see S73.
- S73. A query filter is a selector: a grant matches a later request only with the same filter. For the "these records" shape the record set of S55 is still checked against the records the request resolves.
- S35. On a match, the server MUST create an approved record for the change, with approver type
  `grant`, and consume it in the consumption transaction (S13). Creating the approved record, the
  grant checks, the charge and the consumption MUST commit or roll back as one unit. Inside that unit
  the server MUST check again that the grant is unexpired and unrevoked, that S46 holds, and that the
  charged records plus this change's record count (S19) do not exceed the record limit, and MUST
  charge the count to the grant's counter (S18). For an operation that uses `resolved`, the count is
  `resolved.count`. The consumption and outcome records MUST carry approver type `grant`, the grant
  identifier, the grant's shape and the person who made the grant (S20). If a check fails, the unit rolls back: nothing
  is created, charged or consumed, and the request is treated as one with no approved record. The
  write runs without an approval prompt. The approved record MUST be kept as consumed at least until
  the grant expires or is revoked and its last charged write has an outcome record, so that an
  identical retry never writes or charges again while the grant could still match. Where a grant could approve an identical request, the server MUST keep a consumed record, also one consumed under a person's approval, for at least the longer of the period S13 or the previous sentence requires and the pending limit of S27; this adds a floor and replaces none. A later request
  with the same change hash MUST be answered as the core's S14 says: it does not execute and is not
  charged again, and the server MAY return the recorded outcome. For what that answer states, see S80. For a covered operation, see S69. When an approval is consumed, by a person's approval or by a grant, every other pending or approved record for the same change hash, and for a covered operation for the same request key, is closed in the same atomic step. Such a record is closed as superseded; the clause of S50 on a record that is no longer pending covers it, and its page says that the change already ran under another approval. Where the permission source is outside the server, see S74.
- S36. The result of a write that ran under a grant MUST tell the client, in a text content block,
  that it ran under a grant, with the grant identifier, the grant's shape, the records remaining and
  the expiry. The text MUST call it a grant and say that it is a standing permission, not an approval
  of this one change.
- S37. The person who made a grant, and an account administrator, MUST be able to list and revoke
  grants on the server's own pages, under the same page security (Section 6). No one else can. A
  revocation MUST be recorded in the same atomic domain as consumption and take effect on the next
  request. It does not undo writes already made.
- S46. Each write under a grant MUST also be one that the person who made the grant is permitted to
  make at that moment, on those records (S22 applied at use). If it is not, no grant matches and the
  normal approval request follows. A grant never lets an agent change a record that its grantor could
  not change. Where the system of record cannot answer, see S76. Where the permission source is outside the server, see S74.
- S47. Every argument that chooses the kind of write, for example create, update or delete, or the
  object type, MUST be a selector. An operation whose kind of write cannot be told from its arguments
  MUST NOT offer grants. For the distinguishing argument of a covered operation, see S69(4).
- S48. The server MUST name fields at leaf level, for example as the JSON Pointer of each property
  written, with record positions left out. A parent name MUST NOT cover its children. The server MUST
  document the naming for each operation that offers grants. A field can be granted only if it
  is a property the system of record defines for that object type. A request that sets an undefined
  property is offered no grant and matches none. When the system of record rejects such a request,
  the refusal's `message` MUST name the property. For the distinguishing argument of a covered operation, see S69(4). For a principal not established to see every definition of the object type, a property that is not schema is answered the same whether it is undefined or restricted: the validation runs after consumption as S65 provides, and where the system of record rejects the property the answer is `execution_failed` and does not say which property was rejected; the sentence that the refusal's `message` names the property applies only to a principal established to see every definition of the object type. The approval page MAY tell a person permitted to see the definitions that a property the request names is not defined.
- S49. The administrator's maximum record limit and maximum expiry for grants MUST be finite and
  documented. There MUST be no unlimited default.
- S55. A grant has one of two shapes, and the grant record stores it.
  "These records" covers the grant's fields on exactly the records in the change shown. The server
  MUST fix the record set from the stored pending record (for an operation that uses `resolved`, the
  resolved identifiers) and store the record identifiers in the grant. This shape MUST be available
  for every operation that offers grants and names existing records.
  "Any record" covers the grant's fields on any record that the person who made the grant may change.
  S46 still applies at each use. The server MUST offer this shape only where the account
  administrator has enabled it for that operation (S23). It is the only shape possible for an
  operation that creates records, so a create can be granted only where it is enabled.
  The page MUST show which shape is being granted and, for "these records", list the records. The
  person chooses the shape only among those the server offers.
  Before a person grants "any record", the page MUST say in plain words that the grant covers these
  fields on every record that person may change, not only the records shown, and MUST NOT present
  the shown records as its limit. The page that confirms the grant MUST repeat it.

When a request falls outside every grant, or the grant is exhausted, expired or revoked, the normal
approval request follows (Section 2), and S27 applies to it.

- S56. When the principal holds a grant for the operation that did not apply, the refusal MUST carry
  `grant_status`, one of `used_up`, `expired`, `revoked` or `outside` (a field or record the grant does
  not cover), and its `message` MUST say so in plain words. When the server sends a URL mode
  elicitation for that request, the elicitation's message SHOULD give the same reason, because some
  clients show the person only that text. Where a grant did not apply because S46 does not hold or could not be established (S74), the value is `outside`.
- S57. Every page MUST show times as a date and time with its zone, and limits with their meaning,
  never as raw machine values alone. The person sets an expiry as a duration or as a date and time.
  The grants list MUST show each grant's state in words (active, used up, expired, revoked), with the
  records used and remaining, and MUST offer revocation only for active grants.
  Labels MUST be words a person who does not know the protocol can read: the operation and each field
  by a name the server documents for people, with any technical identifier secondary. A value the
  page cannot work out as the person types MUST be labelled for what it is (for example the latest
  possible expiry), and the page that confirms a grant MUST state the expiry actually set. A grant
  that is not active MUST NOT show a remaining count as if it were usable. Each page's title MUST say
  what that page is.
- S58. Every response from these pages, including a refusal or an error, MUST be a readable page that
  says what happened and what the person can do next. No empty or bare error responses. When a
  decision was already recorded, the page MUST say which one, and after a denial it MUST NOT tell the
  person to send the request again. For a link the server does not recognise, the page MUST use
  wording that fits an unknown link and does not reveal whether it ever existed; an expired link gets
  the same wording. For a covered operation, see S70.

**What a grant does not check.** Neither shape looks at values. A "these records" grant made while
setting one record's owner to one person also covers setting that record's owner to anyone, within
the record limit and the expiry. An "any record" grant goes further: it covers setting any owner, on
any record its grantor may change, to anyone. Neither shape checks the old values or whether the
change makes sense. A person who grants accepts every change that has those fields on the records the
shape covers. An organization can keep grants narrow only through which operations it allows to offer
grants, whether it enables the "any record" shape, and the limits it configures.

## 6. Approval page security

The approval page is a new surface on the internet, and an attacker who can drive it can approve
writes. These requirements apply to every page of this profile: showing a change, recording a
decision, creating a grant, and listing and revoking grants.

- S38. Every page MUST require an authenticated session bound to one person. The session MUST NOT be
  established from anything the agent or the client holds, such as the agent's credential or a value
  in the approval URL. For sign-in performed by a proxy, see S75.
- S39. Every request that records a decision, creates a grant or revokes one MUST be protected against
  cross-site request forgery, and the server MUST refuse it without recording anything when the
  protection fails. For sign-in performed by a proxy, see S75.
- S40. The pages MUST NOT be displayable inside a frame of another origin (for example by
  `Content-Security-Policy: frame-ancestors 'none'` [CSP]).
- S41. The pages and the decision requests MUST be served only over TLS [TLS]. Responses MUST NOT be
  stored by caches (`Cache-Control: no-store` [HTTP-CACHE]). For a server behind a proxy or edge, and for the agent's endpoint, see S79.
- S42. The change shown MUST be rendered from the server's stored pending record, never from anything
  in the URL or anything supplied by the client or the agent, such as a summary.
- S43. The server MUST accept a decision only for a record that was displayed to that session, and
  MUST record when it was displayed and when it was decided. For a covered operation, see S68(4). For sign-in performed by a proxy, see S75.
- S44. The identifier in the approval URL MUST be unguessable (at least 128 bits from a secure random
  source) and MUST carry no authority by itself: knowing it lets no one approve without S38 and S22.
- S45. After a decision, the page MUST state the decision it recorded, in different words for approve,
  deny and grant. For an approval it MUST state until when the approval can be used. For a grant it
  MUST state the terms, the record limit and the expiry.
- S50. The server MUST accept a decision or a grant only for a record that is still pending. The first
  decision recorded for a record wins. Repeating the same decision request MUST return the first
  result and MUST create nothing new: no second grant and no second approval. A request to view a
  record that is no longer pending MUST show the recorded outcome (approved, denied, or that a grant
  was made, with when) and MUST NOT show a decision form or present the change as still open. The
  outcome page MUST describe the state at the time it is viewed: for an approval, whether it has been
  used; for a grant, whether the change shown has since run under it. For a covered operation, a superseded or stale record is handled as S70 states. Recording a decision or a grant is one atomic step in the same domain as S13, and applies only if the record is still pending, and for a covered operation still the context's open record, at that step.
- S51. Everything shown from the change, including names, values and identifiers, MUST be rendered as
  inert text, never as markup or script. The pages MUST send a Content-Security-Policy [CSP] that
  blocks inline and third-party script.
- S52. The server MUST replace the session identifier when a person authenticates. The authentication
  request MUST be protected against cross-site request forgery. After sign-in the server MUST return
  the person only to a same-origin path that it generated, never to a location taken from the request. For a server that performs the sign-in redirect itself, a path it generated is a path it recorded before the authentication request. For sign-in performed by a proxy, see S75.
- S53. Before rendering a change, the server MUST check that the signed-in person belongs to the
  account and may read the records and fields shown. Otherwise the page MUST show nothing from the
  record. Where the system of record cannot answer, see S76. Where the permission source is outside the server, see S74.
- S71. For an operation that is not covered, the approval page MUST say that the approval is for the change as requested and not for the state of the record when the write runs. The server MAY show current record values beside the change to a person permitted to read them (S53). They are not part of the approved change, MUST be marked as current values that may change before the write, and showing them does not make the operation covered.
- S54. The pages MUST NOT disclose the approval URL to other origins in a referrer, and MUST send
  `Referrer-Policy: same-origin`. They MUST NOT send `no-referrer`: browsers then put `Origin: null` on
  the page's own form posts, which a correct origin check (S39, S52) refuses, so no person can sign in
  or decide.
- S75. Where sign-in is performed by a proxy before a request reaches the server, the server MUST verify, on every request to its pages, including each request that records a decision, creates a grant or revokes one, the identity assertion the proxy passes: its signature, against keys of a proxy that an administrator registered (S23); that its audience is a value an administrator registered for that proxy (S23), which the proxy issues for the server's pages alone; its expiry; and that it names one person who signed in interactively, never a service or an agent credential. A request without a valid assertion MUST be refused. The server MUST accept an assertion only on the channel from the registered proxy, which it authenticates, and MUST ignore identity values supplied by the client. This meets S38. Where the server issues no session identifier of its own, the replacement of the session identifier at sign-in (S52, first sentence) and the protection of the authentication request (S52, second sentence) are the proxy's, and the server MUST document how the proxy meets each. The server MUST NOT itself redirect to a location taken from the request, MUST link and redirect only to same-origin paths it generated, and MUST document that the return after sign-in is performed by the proxy and to which origins the proxy is configured to return. For S39, a server that issues no session cookie MUST check both the Origin header, against its configured public origin, and a per-display token bound to the verified identity and to the record or grant displayed; one of the two is not enough, and an absent or null Origin is refused. That token meets S43 for the identity: a decision is accepted only for a record whose token was issued to that identity. The server MUST accept an assertion only under an audience for which the proxy is configured to issue assertions after interactive sign-in alone, never for a client authorisation or a service token, MUST NOT serve the agent's endpoint under that audience, and MUST document that configuration. The assertion's signature does not authenticate the channel. The server maps the person named to a member of the account by a join identifier it documents, such as an email address. The server MUST establish the mapping anew for each request that renders a page, records a decision, or creates or revokes a grant, never reusing an earlier mapping; where the member source is outside the server the bound and the failure rule of S74 apply to it. It MUST record in the decision or grant record both the proxy's stable subject identifier, qualified by the registered proxy that issued it, and the system of record's stable member identifier; a consumption record carries those of the decision or grant it consumes. Where it has recorded a subject identifier for a member before and a request now maps a different subject identifier, or the same one from another registered proxy, to that member, it SHOULD refuse the step until an administrator confirms the change. A changed subject is not by itself evidence that the join identifier was reassigned: a person can sign in through another identity provider or method that the proxy allows. The refusal is lifted by an administrator's confirmation, and the server records that confirmation: who confirmed, when, and the old and new subject identifiers. These checks do not address an agent that operates the person's own signed-in browser (Section 2). The server MUST NOT accept an assertion issued longer ago than a bound it documents, measured from the issue time the assertion carries or, where it carries none, its authentication time.
- S76. Some systems of record cannot say whether a given person may read or change a given field on a given record. A server in front of such a system documents the model it applies instead, as S60 allows: for example membership of the account, an approver list that the account administrator configures, and a read scope per agent credential. S22, S46 and S53 are then answered against that model, whose settings are settings under S23. The model MAY name who may approve an operation, for example by an approver list; such a list only narrows S22 and never widens it, so a person it names still holds, in the account, the permission to make the change themselves. The documentation MUST say which answers come from the server's own model and which from the system of record, and a principal or person the model has not affirmed MUST be treated as not permitted. For a principal, membership of the account means that the credential is affirmatively bound to the account, by the system of record or by the model; the principal need not be a user of the system of record. A model that grants by object type and field answers for every record of that type, and so can establish S60(a) and the domain of S72. Where the system of record can answer for a principal or person, its answer governs and the model MUST NOT affirm what it denies. The model MUST state separately what a person may change (S22, S33, S46), what a person may see (S53), what a principal may read (S60(a), S72, S77), which definitions of an object type a principal may see (S48, S65), and what a principal may write (step 1 of Section 6 of the core); an answer to one is not an answer to another. Where the system of record cannot answer for the principal, a model that grants by object type affirms reading for every record of that type, whatever narrower scope the system of record applies to its own users; the server MUST document this. "Cannot answer" means that the system of record offers no such answer, which the server documents. A query that times out, errors or returns an indeterminate answer is not this case: the principal or person is treated as not permitted (S60, S74).

- S70. Clauses restated for covered operations. The clauses of S30 and S31 that look up a denied or cancelled record "for that change" are lookups of the context by request key. A context counts toward the limit from its creation until it is consumed or expires, whatever the state of its records. A record on which a grant was made is decided (S50): it is closed with that outcome and kept, and it is not open. Where a later request is not matched by the grant, a new pending record is created in the same context; this adds nothing to the count. The context then answers as S68(2) states for an open context, and its page shows the new pending record for a decision and the earlier grant as history. The clause of S50 on a record that is no longer pending also covers a superseded and a stale record, whose page says that the request changed or, for a record closed at consumption (S68(6)), that the change already ran under another approval. Where an approved record was closed as stale, the page of the context MUST tell a person permitted to see the request that the earlier approval was not used because it no longer matched, and MUST show the current request for a decision only while that request is pending; otherwise the rest of S50 governs. The page shown after an approval of a covered operation SHOULD say that the approval is not used if the record changes before the request is sent again. The server MAY notify the approver, by a channel the agent cannot read, that an approval was closed as stale; it MUST NOT tell the agent. A record that changes often can be approved and go stale more than once in one context: another approval by a person needs another decision, a grant that comes to match is governed by S34 and S35, and the context's expiry ends the sequence. The clause of S43 on what a decision applies to is as S68(4) states. The clause of S58 on an unknown or expired link also covers a valid token whose context has no open record, for a person not permitted to see the request. The lockout of S30 and S31 that those answers report lasts at most one hour from the decision, even where the context outlives it, and `retry_after` counts down to that moment (S68(5)). The `retry_after` of `approval_denied` and `approval_cancelled` (Section 4) is computed from the context, and that of `approval_limit_reached` from the contexts and records that count toward the limit; neither is computed from a record found by the change hash. For a covered operation the approval page MUST show, to a person permitted to read them, what the open record is bound to: whether the record exists, the current values of the fields the request sets, and for a query the selected identifiers or their count. Any record value the page shows that the open record is not bound to MUST be marked as not part of what the approval is bound to.

The clauses that S64, S67 to S70 and S73 to S76 restate, in one place. The last four rows apply to every guarded operation, covered or not:

| Clause | Restated for covered operations by |
|---|---|
| S4 (core) | S67, S69(4) |
| S14 (core) | S69 |
| S27 | S67, S70 |
| S28 (core) | S64, S67, S69 |
| S29 (core) | S67, S68(3), S69 |
| S30, S31 | S68(5), S70 |
| S32, S47, S48 | S69(4) |
| S34, S35 | S69, S70 |
| S34 (query filter) | S73 |
| S43 | S68(4), S70 |
| S50 | S68(4), S70 |
| S58 | S70 |
| Section 4, `retry_after` | S68(2), S70 |
| S90 (`pending_expires`, `poll_interval`) | S68(2) |
| S22, S33, S35, S46, S53 (permission source outside the server) | S74 |
| S38, S39, S43, S52 (sign-in performed by a proxy) | S75 |
| S22, S46, S53 (the server's own permission model) | S76 |
| S48 (a property whose definition is not visible to every member) | S65, and the definition of schema in Section 3 of the core |

## References

- [MCP-ELICIT] Model Context Protocol specification, revision 2026-07-28, Elicitation. https://modelcontextprotocol.io/specification/2026-07-28/client/elicitation
- [TLS] RFC 8446, The Transport Layer Security (TLS) Protocol Version 1.3.
- [HTTP-CACHE] RFC 9111, HTTP Caching.
- [CSP] W3C, Content Security Policy Level 3.
