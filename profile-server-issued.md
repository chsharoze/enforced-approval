# Enforced Approval: Server-issued Approval Profile

Draft 0.1, 2026-11-20. Author: Sharoze Iftikhar. Normative. It extends the core
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
4. If an approved record exists for that hash, the server continues from step 7 of the core's
   verification steps. Steps 4 to 6 are met by the lookup: the record is in the server's own store,
   and the server is both the issuer and the audience. Step 8 holds by construction, because the
   record is found by its change hash. A request for a different change finds no record and starts a
   new approval request.

A record is pending, approved, denied, cancelled or consumed, and it expires. The core's S6 applies: a
request runs only with an approved record. An approved record comes either from a person's approval on
the page or from a grant match (S35).

## 3. Requirements for the flow

- S21. The server MUST NOT treat anything received on the MCP connection (a form mode elicitation
  answer, an `accept` action, an echoed `requestState`, a tool argument) as the approval, and MUST NOT
  fall back to form mode elicitation. The approval is the decision its own approval page recorded for
  an authenticated person.
- S22. The approving person MUST hold, in the account, the permission to make the change themselves.
  The approval page SHOULD accept sign-in through the organization's own identity provider.
- S27. A pending record MUST expire within the server's documented limit (at most 1 hour). An approval
  on the page is usable only until its own expiry, at most the maximum receipt lifetime after the
  decision. The server MUST cap the number of unexpired pending, denied and cancelled records per
  principal, so that asking, declining and asking again, or asking again with a changed argument,
  cannot produce unlimited approval requests. At the cap it MUST refuse with `approval_limit_reached`,
  never `approval_required`, and MUST NOT create a record.
- S30. If a request carries a `decline` or `cancel` response to the elicitation, the server MUST NOT
  execute it and MUST NOT create a pending record for it. It marks a pending or approved record for
  that change as cancelled, in the same atomic domain as consumption (S13), and refuses with
  `approval_cancelled`, as it does for later requests for that change until the record expires. A
  denied record stays denied (S31). Voiding from the connection is safe because it only restricts.
- S31. After a denial on the approval page, the server MUST refuse requests for that change with
  `approval_denied` and MUST NOT offer a new approval for it until the pending record expires. No
  response on the connection changes that. A denial covers the exact change: a request with other
  arguments is another change, and S27 bounds how many of those a principal can raise.

## 4. Refusals and mappings

**Refusal members.** A refusal in this profile has `approval_url` (the approval page for this change)
for `approval_required`, and a `message` in plain words that fits the error. For `approval_required`
the message says that the decision is made on the approval page, that the client carries nothing, and
that the same request is sent again afterwards. `approval_denied`, `approval_cancelled` and
`approval_limit_reached` carry `retry_after`: the seconds until a new approval can be requested, for
that change or, at the limit, for any change (0 when the server holds no record for the change).
`approval_limit_reached` also carries `open` and `limit`: how many records count against the principal
now, and the cap. Its `message` says the same in plain words, including that declined and denied
requests count until they expire and that no approval prompt will appear before then.

- S59. The `message` is read by people as well as by models. It MUST NOT refer to protocol member names
  such as `approval_url`. Where the client was given the link through an elicitation, the message says
  to open the approval page; otherwise it includes the link itself.

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
The client sends the identical request again after the decision. `approval_limit_reached` uses status
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
  and MUST display all terms, including the shape, before the person grants.
- S33. Creating a grant MUST require the same authentication and permission as approving (S22),
  including the permission to make changes to every field in the grant. A grant MUST be created only
  by a person's action on the approval page. Nothing received on the MCP connection creates, widens
  or extends a grant (S21). Creating a grant does not approve the change shown; the retried request is
  matched against the grant like any later request and is charged to it.
- S34. On a request with no approved record, the server MUST look for an unexpired, unrevoked grant with
  the same principal, account, operation and selector values, whose fields cover every field the
  request sets, and, for the "these records" shape, whose record set holds every record the request
  touches. A request that touches any record outside the set MUST NOT match. An input the server cannot classify as a selector, a field or a documented record
  identifier MUST mean no match. A denied or cancelled record for the change takes precedence: the
  server refuses as S30 and S31 require and does not look for a grant. A request that carries a
  `decline` or `cancel` response MUST NOT be matched to a grant; S30 already forbids executing it.
  When no grant matches, the request is treated as one with no approved record.
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
  identical retry never writes or charges again while the grant could still match. A later request
  with the same change hash MUST be answered as the core's S14 says: it does not execute and is not
  charged again, and the server MAY return the recorded outcome. Where an operation uses
  `preconditions`, a genuinely new write has a different change hash.
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
  not change.
- S47. Every argument that chooses the kind of write, for example create, update or delete, or the
  object type, MUST be a selector. An operation whose kind of write cannot be told from its arguments
  MUST NOT offer grants.
- S48. The server MUST name fields at leaf level, for example as the JSON Pointer of each property
  written, with record positions left out. A parent name MUST NOT cover its children. The server MUST
  document the naming for each operation that offers grants. A field can be granted only if it
  is a property the system of record defines for that object type. A request that sets an undefined
  property is offered no grant and matches none. When the system of record rejects such a request,
  the refusal's `message` MUST name the property.
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
  clients show the person only that text.
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
  the same wording.

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
  in the approval URL.
- S39. Every request that records a decision, creates a grant or revokes one MUST be protected against
  cross-site request forgery, and the server MUST refuse it without recording anything when the
  protection fails.
- S40. The pages MUST NOT be displayable inside a frame of another origin (for example by
  `Content-Security-Policy: frame-ancestors 'none'` [CSP]).
- S41. The pages and the decision requests MUST be served only over TLS [TLS]. Responses MUST NOT be
  stored by caches (`Cache-Control: no-store` [HTTP-CACHE]).
- S42. The change shown MUST be rendered from the server's stored pending record, never from anything
  in the URL or anything supplied by the client or the agent, such as a summary.
- S43. The server MUST accept a decision only for a record that was displayed to that session, and
  MUST record when it was displayed and when it was decided.
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
  used; for a grant, whether the change shown has since run under it.
- S51. Everything shown from the change, including names, values and identifiers, MUST be rendered as
  inert text, never as markup or script. The pages MUST send a Content-Security-Policy [CSP] that
  blocks inline and third-party script.
- S52. The server MUST replace the session identifier when a person authenticates. The authentication
  request MUST be protected against cross-site request forgery. After sign-in the server MUST return
  the person only to a same-origin path that it generated, never to a location taken from the request.
- S53. Before rendering a change, the server MUST check that the signed-in person belongs to the
  account and may read the records and fields shown. Otherwise the page MUST show nothing from the
  record.
- S54. The pages MUST NOT disclose the approval URL to other origins in a referrer, and MUST send
  `Referrer-Policy: same-origin`. They MUST NOT send `no-referrer`: browsers then put `Origin: null` on
  the page's own form posts, which a correct origin check (S39, S52) refuses, so no person can sign in
  or decide.

## References

- [MCP-ELICIT] Model Context Protocol specification, revision 2026-07-28, Elicitation. https://modelcontextprotocol.io/specification/2026-07-28/client/elicitation
- [TLS] RFC 8446, The Transport Layer Security (TLS) Protocol Version 1.3.
- [HTTP-CACHE] RFC 9111, HTTP Caching.
- [CSP] W3C, Content Security Policy Level 3.
