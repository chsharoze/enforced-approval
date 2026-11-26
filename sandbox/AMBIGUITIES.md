# Implementation notes

The readings the sandbox chose where the specification leaves a choice, and the limits of what its
tests cover.

## Core and receipts

- Account/target mismatch fixtures first establish permission and issuer scope. Unknown keys/signatures are invalid; unavailable registries/caches are unavailable. Receipt expiry is exclusive with configured skew; grants/pending records have none.
- Preconditions (only with VA_PRECONDITIONS=1, experimental and off by default) hash changed properties and enforce versions; creates require absence. Queries bind selected IDs. Read proofs require permission. Static keys are authoritative; offline providers model refresh. No network JWKS retrieval occurs.
- Tests 6/39 cannot establish every deployment instance; 62/63 retain browser-framing/external-TLS limits. Loopback models the tunnel backend. HTTPS origins require TLS or an overwritten trusted proxy header and add HSTS; public plaintext enforcement belongs to the tunnel.
- Restart tests cannot establish every power-loss window. Used IDs/counters persist indefinitely. Parsed MCP hides duplicate JSON names. Policy registration is needed after restart. Audit failure cannot audit itself; tail deletion/full rewriting need external anchoring.
- Authentication is synthetic. The sign-in shell reveals no change. Revocation linearizes at consumption; previously charged work may finish.

## Grants

- The grant shapes on the wire are these_records/any_record; anyRecord enables the latter. Fixed IDs are sorted/unique and allow subsets; duplicate entries still count. Missing finite caps disable grants.
- Fields are escaped JSON Pointer leaves. Objects merge by leaf; empty containers/scalar replacements name only their parent. Arrays/deletion require ordinary approval.
- First decisions are immutable; exact authorized retries return their first result only while unexpired/unconsumed. Test 75 takes precedence afterward. Reservations permit concurrent veto; approval, checks, charge, used ID and consumption audit commit together. Failed charges exclude that grant for the attempt.
- Record/field permissions inherit operation permission; membership is separate. Maker authority is rechecked during consumption. Sign-in return paths are server-stored. Test 76 checks escaping/CSP structurally.
- Undefined fields fail before any approval exists, following the stronger reading of the requirement even though test 85 mentions an approval page. Definitions whitelist exact leaves per object type, including legacy fixture fields. Legacy requests without objectType use contact definitions; parent definitions never authorize children.
- Newest means insertion order among grants for the same account, principal and operation. Reasons prioritize revoked, expired, insufficient remaining allowance, then outside. Outside identifies uncovered fields first; selector, audience and current-authority mismatches use the record/scope explanation because no separate status exists.
- Fractional minutes round to the nearest whole second. Retries with the same normalized duration retain the first expiry. Protocol times use ISO UTC; numeric business-field values remain unchanged.
- The grants list shows a remaining count only for active grants; used-up, expired and revoked grants show "-", and only active grants offer revocation (S57's "records used and remaining" is read as records used always, remaining only while usable).

## Pages and messages

- Script-free CSS expands only the selected shape's details. Trusted inline styling is allowed while scripts remain blocked. HTTP tests verify structure and forms; visual layout is unverified because no browser is available.
- S57 asks for a duration or a date and time; the form uses duration (minutes) only, which the requirement permits ("or").
- One time form on the pages: every page time is "D Mon YYYY, HH:MM UTC" inside <time>, including the "Grant record" details block, so no page carries an ISO timestamp. The only permitted ISO location, the collapsed "Raw saved change" details, contains no timestamps in the saved change. The MCP tool result text keeps ISO + UTC as a protocol surface, not a page. Raw epoch numbers are absent from pages.
- The name map lives in src/presentation.mjs (OPERATION_NAMES, SELECTOR_NAMES, FIELD_NAMES). An unmapped defined property falls back to a tidied form of its JSON Pointer path (words split on /, _, - and capitalized). Technical identifiers stay visible, small and in parentheses after the readable name; test 89 asserts the exact "readable <small>(technical)</small>" rendering.
- Unknown and expired approval links share one page, "This approval link is not valid or is no longer active" (S58), because the page layer cannot tell them apart; its next step tells the person to ask the assistant to request the change again if it is still needed. The wording fits an unknown link and does not reveal whether the link ever existed. All page errors use status 403 (404 for unknown paths, 426 for plaintext on HTTPS origins), and every error page is static text: the internal code goes to the page log, never the page, so error pages leak nothing from the record.
- The page request log is one JSON line per request reaching the page handler, including PATCH /records and unknown paths as kind "other". The identifier is the first 8 characters of the approval or grant id in the URL, absent when the URL carries none. Internal error codes logged are the exception message (for example "expired", "permission_denied", "grant limits"), the refusal error for /records, or not_found/tls_required. Nothing is logged when VA_LOG is unset, so in-process runner tests write no page log; the combined server and the e2e suites set VA_LOG.
- invalid_input's `invalid` member lists JSON Pointer leaf paths, matching the field naming the server documents; the message names them in the same form. Other invalid-input causes reuse the underlying serialization error to say what kind was refused (not a JSON object, lone surrogate, duplicate member name, unsafe integer). Every invalid_input, including the effects-header refusal (S4) and an unparseable PATCH body, is given before any hash is computed and any record is read: it has `error` and `message` and no `change_hash` (S63).
- The URL mode elicitation's message is the refusal's plain `message` verbatim, so the approval-page advice and any grant reason both appear where a client shows only that text.
- Plurals: record counts render "1 record"/"N records" for the limit, used and remaining on the approval, confirmation and grants pages and in the tool result text; the approval-cap message pluralizes "approval request(s)". The grants table's used cell reads "0 of 1 record".
- Message durations are for people only: the wording is "about N minutes (until HH:MM UTC)", computed from the refusal time plus retry_after, and below one minute it reads "under a minute", so no message or elicitation text contains a digit-plus-seconds count; the numeric retry_after member is unchanged in the refusal object.

## Decided links and outcome pages

- A second, different decision posted to a decided record returns the outcome page with status 403 and lead-in "A decision was already recorded for this change"; an identical retry keeps returning the stored first result with 200 while the record is unexpired and unconsumed, and after consumption the outcome page states the approval was already used. A decided record accepts no new decision at all, even from a session that never displayed it.
- A request whose client already answered this change's elicitation (an approve inputResponse is present) is read as already having been given the link, so its refusal message also omits "Approval page:"; this keeps the elicitation text byte-equal to the following refusal message (test 92) and matches S59's "do not repeat the link". Clients that never declared URL mode and the HTTP mapping get the link appended to the message.
- Cancelled records have no page decision to show, so their links use the not-valid page like expired ones; S50's outcome page covers only approved, denied and grant. Grant-decided records keep their outcome page after the retry deletes the pending row and after cleanup, because page_decisions rows and grant-claimed identities are retained.
- The outcome page shows only the decision, its time, its current state and a next step (plus the grants link for grants), never the change: S50 forbids presenting the change as open or old values as current, so nothing from the record is rendered and no read-permission distinction arises (S53).
- Outcome pages describe the state when viewed (S50, test 96). A grant-decided link reads "A standing grant was made from this change on <time>. It has not been used yet." until the shown change itself runs under that grant, then "... This change ran under that grant on <time>." An approval reads "It can be used until <time>" while unused and "It has already been used, on <time>, so it will not run again" afterwards. Use moments come from the consumption audit row (person approvals, keyed by receipt id) and the retained consumed pending row's claims (grants, keyed by the shown change's hash plus the grant id); the shown change's hash is stored in the page decision result to make that lookup possible. A grant charged by other changes but not by the shown change still reads "not used yet", which is what the wording claims.

## Draft 0.2: operations that are not covered (S60 to S80)

- The runnable servers run with preconditions off in every mode unless VA_PRECONDITIONS=1
  is set. Before this build the server-issued mode turned them on by default, so a
  principal that may write but may not read could learn record state from the answer
  before any approval was consumed (S60, S62, S63, S64), and an identical request after
  consumption was not answered with the recorded outcome when the record had changed
  (S80). An operation that uses preconditions is a covered operation
  (profile-server-issued S67). The sandbox implements covered operations behind
  VA_PRECONDITIONS=1 (approval contexts, request keys, S67 to S70); they are experimental
  in Draft 0.2 (core Section 12) and off by default.
- S63 now says only an approval_required refusal carries `change`; the sandbox previously
  included `change` on every refusal and now includes it only on approval_required. Test 145
  checks this.
- A recorded unknown outcome is answered as a result carrying `recorded_outcome.outcome:
  'unknown'` (S14's "a result" plus S77's outcome list); a recorded conflict or
  execution_failed remains a refusal with the same error. Where the outcome was lost
  after the write was sent, the initial answer is still execution_failed (the existing
  assertion in test 29) while the recorded outcome is unknown, and the replay says so.
  A bare approval_used is never given because used identifiers and outcomes are kept
  indefinitely, beyond the S13/S35 minimum.
- Test 100's reader clause ("no entry of preconditions has a version or absent member")
  is vacuous for an operation that is not covered: the sandbox builds no preconditions
  for one, so the test runs the non-reader clause and asserts the absence of the member.
- Test 118's "after which the record is no longer open": a grant decision seals the page
  immediately (the page shows the grant outcome and no decision form) and closes the
  pending record as `granted` in the transaction that records the grant, in the default
  mode as well as for a covered operation (S50, S70; tests 188, 203). The closed record no
  longer counts toward the pending cap (test 51).
- A decline response replayed at a consumed change still answers approval_cancelled
  (S30's veto only restricts); S80's recorded-outcome answer governs plain repeats.
- S35/S50 supersession is one atomic step with the consumption: a person's open record
  for a change is closed as superseded inside the grant charge transaction (grants.charge),
  so a charge that fails and rolls back leaves it pending. Test 142's charge-failure case
  checks this. A concurrent identical grant request that reaches the charge after the change was
  consumed is answered with the recorded outcome, or with an unknown outcome while the
  first execution is still in progress (S80), never with a bare approval_used.
- not_sent (S77): where the server sends nothing for a request because one entry of a
  batch failed its pre-write check, that entry's outcome is conflict and every OTHER
  entry's outcome is not_sent; the per-entry outcomes are recorded in the outcome audit.
  The request-level answer is the S64 conflict refusal and no per-entry member is
  carried on a refusal; per-record entries appear in results only for misdirected
  writes. No outcome reason member is offered: the closed documented list is empty.
- permission_denied is the ordinary step 1 refusal, and the core's refusal table (Section 7)
  lists it. The sandbox keeps the existing code and refusals; the conformance text of test
  140 compares only for equality between the two cases.
- An execution the server knows is still in progress is answered as a result saying so
  (S80, for every guarded operation). Test 145 runs the in-progress case for an operation
  that is not covered; test 135 runs the covered, two-simultaneous-requests form, where the
  first request is held after consumption while the second is answered as in progress. Both
  pass.
- The identifier the write was misdirected to is content read from the system of record
  (S77): it is returned only where the write created that record, the identifier conforms to
  the documented format `^[A-Za-z0-9_-]{1,64}$`, and a principal is established to read that
  record; otherwise it is withheld with an explicit `identifier_withheld` marker.
- S78's identifier comparison runs on every read of record state the server makes,
  including the step 1 read of the record-scoped write check (S60(c)): an identifier
  that resolves to another record is treated as one that names no record, so a scoped
  non-reader gets the same step 1 refusal as for a missing record or a record out of
  scope, which is an observable answer before consumption. Test 140 checks this. A failed read at any point before consumption — an ordinary
  error or a timeout, with or without a code — is approval_unavailable (S60(i)), and
  nothing it gated is superseded, closed or consumed; test 141 checks this.

## Milestone 1: the single functions and the readings they fix

- One permission decision (src/authorize.mjs). `authorize(sor, subject, request, purpose,
  stateAccess)` is the only reader of the permission tables; its purposes are the
  separate answers S76 lists (write, read, approve, grant, view, issuer). Every dimension
  fails closed: a subject without a membership row, an operation row, or (under a record
  write scope) a record row is not permitted. Membership is required of a principal as
  well as of a person (`Sor.permission` records it for both).
- One merge-resolution read (`resolveIdentifier`). Every read of a record the server
  makes for a request, a page or read_record goes through it; the canonical form of an
  identifier is its exact string (S78).
- A record write scope binds approvers and grant makers as it binds the agent (S22, S46):
  under a scope only a record with an affirmed row may be changed. Without a scope the
  model grants by object type and only an explicit denial refuses.
- Reader (S60(a), S62). A request that sets no field on a record (a delete, or
  `properties: {}`) depends on the record itself, so only a principal with no field-level
  read denial for the operation is a reader of it. A delete uses the `fields` kind over
  every field of the record, not the `version` kind: the sandbox's version counter starts
  again at 1 when a record is replaced or created again, so it does not qualify under S62.
- Unknown members are kept, not refused. S34 ("An input the server cannot classify as a
  selector, a field or a documented record identifier MUST mean no match") and
  CONFORMANCE tests 32 and 58 ("Expect no write and the normal approval request each
  time") require the normal approval request for a request with an undocumented member,
  so `shapeRequest` refuses only a documented member of the wrong type. It never removes a
  member: over MCP the guard passes the arguments exactly as received, and the tool
  schemas are passthrough objects at every level.
- Duplicate member names and integers beyond 2^53-1 (S3: "Where its request layer exposes
  them") are detected only on the HTTP mapping, which hands the core the body as text.
  Over MCP, stdio and the connector alike, the SDK has parsed the JSON-RPC message before
  the server sees the arguments, so a duplicate name is already collapsed and an unsafe
  integer already rounded; the server cannot detect either there.
- Order of steps 1 and 2 (Section 6: "the server performs these steps in order and stops
  at the first failure"). The operation-level permission check is answered before the
  input check: a principal that may not use the operation gets `permission_denied` also
  for an unparseable body. `shapeRequest` itself runs first and reads nothing; only its
  refusal is given at step 2. The field-level write check and the record-scope check need
  the arguments and follow the input check.
- Replay before the record scope (S69, S80). In the server-issued profile the recorded
  outcome of an identical request is found by the request key (for an operation that is
  not covered, the change hash) before the one step 1 check that reads record state. In
  the signed-receipts profile a receipt is its own identity: its recorded outcome is
  given at step 10, after the receipt is verified, so step 1 including the record-scope
  check comes first there, as Section 6 orders it.
- Outcomes. The consumption transaction writes the outcome as `unknown`; `recordOutcome`
  moves it on by compare-and-set together with the outcome audit record. Outcome rows are
  kept indefinitely. If the outcome record cannot be written after a write ran, the
  request is answered with the write's result and the durable outcome stays `unknown`
  (a write that ran is never recorded as failed).
- Pages for a person not permitted (S53, S58, S70). S70 states the unknown-link rule for
  a covered operation's context; the sandbox applies it to every token of either mode,
  pending or decided, GET and POST, as the least disclosing reading where the text is
  silent for operations that are not covered. What a person may see is decided from the
  stored request and the permission model, never from current record values.
- Merge resolution on a page (S78, S53). That an identifier now refers to another record
  is told, with the other identifier, only to a person who may read that other record;
  any other person permitted to see the request is told only that the change can no
  longer be decided here. Neither is offered approval or a grant.
- Signed-receipt grants and S46. S46 is a requirement of the server-issued profile; the
  signed-receipts profile leaves the grant maker's permission to the issuer (I3). The
  sandbox additionally refuses a grant receipt with `grant_exceeded` (step 10: "If a
  grant check fails, refuse with `grant_exceeded` ... and record nothing as used") where
  its own permission model holds an answer about the maker (a membership row) and does
  not permit the write at that moment. A maker the model does not know is the issuer's
  to vouch for (CONFORMANCE test 24 runs a grant receipt of such a person). The sandbox's
  own issuer checks the maker at issue through the same `authorize`.
- Context expiry (S67: "No pending or approved record outlives its context"). The sandbox
  has no timer; every entry into the server-issued profile first closes the records of
  each context that is due. A row read directly from the database between two entries
  can still show the earlier status.
- A read that began before a record was created, rendered or decided (S67) is ordered by
  a counter in the database (`read_epoch`, `pending.touched`); a request whose read is
  older than the record it would replace reads again, at most twice, and is then
  answered `approval_unavailable`.

## End-to-end runs

- To exercise a genuinely expired link over real HTTP, e2e-server-issued raises pendingCap to 50 for its decided-links block (earlier flows in the same run leave pending records counting against the principal) and briefly sets pendingLifetime to 1 second through the administrative settings surface; both are runtime configuration, not code paths.
- e2e-server-issued restores pendingLifetime to 600 for its outcome-page block because the decided-links block set it to 1 second. The outcome checks rerun the exact change shown on the link (with a field older grants in the same run do not cover, so the grant made from that change is the one that matches) before and after it runs. Runner test 96 checks that outcome() accounts for grant use.

## Milestone 2: settings and the decided behaviour changes

The decisions recorded for this build are settled; it implements the behavioural ones and
the settings registry. The readings below are the ones a reader needs.

- S50, S70: in the default mode a grant decision now closes its pending
  record in the same transaction that records the grant, not on the next request. This is
  the one place where a covered-mode rule is applied to an operation that is not covered;
  S70 states it for a covered operation and S50's "one atomic step ... applies only if the
  record is still pending" supports the default mode. Test 51 changed
  because the closed record no longer counts toward the pending cap.
- S69, S65: a recorded `conflict` or `execution_failed` is answered to the
  identical request as the recorded value, with the replay marker `recorded_outcome`, its
  time and "Nothing was sent now", for an operation that is not covered too; CONFORMANCE
  test 124 (covered) is turned on and a matching test 200 covers the default mode.
- S17, S77: a request whose entries partly succeed has the result outcome
  `partial`, a result and not a refusal, with each entry's outcome (success, misdirected,
  execution_failed or not_sent for an entry never sent); `execution_failed` is only for a
  request in which no entry succeeded. The system of record's write now reports a failure
  after a written entry (a real store can do this); a single-entry write is unchanged.
  Test 47 changed because a two-entry batch with one rejection is now a partial result.
  `partial` is one of S77's named outcomes and the request-level outcome the sandbox
  documents; two entries for the same record are each reported by position (test 201).
- Section 2: `read_record` answers a record the principal may not read, at
  record and operation level, exactly as an absent identifier (`null`); the field-level
  `withheld` list is kept for a readable record. Tests 50, 157, 170, 204 and 213, and the
  e2e-nondisclosure checks changed from `permission_denied` to the absent answer.
- S13, S35: a consumed record is kept for at least the longer of the
  S13/S35 period (maxLifetime + skew) and the pending lifetime, measured from consumption,
  so an identical retry is still answered and never matches the grant again while the grant
  could still apply. The registry's `retention_floor_seconds` can only raise this floor.
- The approver model (S22, S76): `approver_model` selects the source of an approver among
  `permission` (the default: the documented permission model alone, which names every
  approver when it can answer), `named` and `administrators`. S22 is unchanged in every
  model: the approving person must hold, in the account, the permission to make the change
  themselves. The `named` list narrows S22 — a person may approve only if on the account's
  named list AND passing S22 (test 214) — and `administrators` restricts to the account's
  administrators; where a list is empty the permission model decides, as before. A person
  who fails S22 cannot approve even if named.
- The settings registry (`src/settings.mjs`) holds every setting the release exposes: the
  seven of the first release together with the maximum lifetime, the skew, the grant-record
  and grant-second limits, the key-cache period and the retention-floor ceiling.
  An unknown setting (`make_it_easy`) and an out-of-range value are refused at the admin
  call and at start; a stored value outside its range is never used (the default applies),
  so a corrupted store cannot loosen a setting. The documented name
  (`pending_lifetime_seconds`) and the sandbox's storage key (`pendingLifetime`) are both
  accepted where a value is written; the documented name wins. The setting-to-member map is
  in the registry, not in the documentation, so the two cannot drift.
- Binding (S85): each approval stores `effect_hash`, the hash of the
  effect-changing settings in force when it was made. A change to one before consumption
  makes the approval not match and the normal approval request follows; a change to a
  setting that cannot change the write does not. The effect hash is never part of the change
  hash the agent sees.
- The deployment record (`node src/deployment-record.mjs`, and `core.admin(VA_ADMIN,
  'deploymentRecord')`) prints the canonical RFC 8785 JSON of the settings in force and the
  account's configuration with its `config_hash`. Every consumption and outcome audit
  record carries the `config_hash` in force. The `retention_floor_applied_seconds` member is
  the floor actually applied (the longer of the S13 floor and the pending lifetime). A
  deployment's own initial configuration (its grant limits and administrators, set at start
  on a fresh database) is not recorded as an administrator's change; it is disclosed by the
  deployment record, so the settings audit holds only the changes an administrator makes on
  a running deployment.
- Settings: conformance tests 190 to 199 cover the settings registry and the deployment
  record (core Section 11); the author also checks each setting at its default and its
  ceiling in internal test suites.


## Reconciliation of the settings build and the text

The milestone 2 build and the milestone 3 text were reconciled. These are the readings it
fixes.

- **S30/S31 lockout.** A denial or a cancellation now locks the change until the record
  expires or one hour has passed, whichever is sooner. The sandbox stores
  `locked_until = min(expires, decided_at + 3600)`, uses it for `retry_after`, and moves the
  change hash aside once it has passed so a new approval can be requested; the record still
  counts toward the cap until it expires (S27). A covered operation follows the same rule
  (S68(5), S70): the context stores its own `locked_until`, and after one hour the change is
  answered afresh even though the context (whose expiry is creation plus the pending
  lifetime in force, S67) has not expired.
- **S84 tightening.** Lowering `pending_lifetime_seconds` re-expires an existing record that
  is not in a context at the new limit measured from the change (now plus the new lifetime).
  A context expires no later than its creation plus the new lifetime (S67, S84), and every
  record in it gives up an expiry later than the context's, so a person cannot approve into
  a context the new limit has already closed (test 210). Raising the setting
  rewrites no record, extends no context, revives nothing and changes no grant's terms.
- **S81 empty values.** A missing value still means the default, but an explicit empty
  (`''`) or `null` value on the administrative surface is refused and recorded. "Unlimited"
  is any value outside the entry's range or values, and is refused the same way.
- **S85 effect scope.** The effect hash covers the approver model, the operation's approver
  types and `preconditions` (a value fixed by configuration under S4). It does not cover
  `audience`, `maxLifetime`, `skew`, the caps or the selection limit: those change the
  change hash or the times, not what a write does or who may approve.
- **S87 deployment record.** The record is one JSON object with a member for each setting of
  the core's table, plus `principal_model`, the account configuration and `deviations`; its
  `config_hash` hashes that object without the hash member. `principal_model` is a further
  documented setting (`delegated`, `dedicated`, `service_account`; the sandbox's default is
  `dedicated`, a credential with its own scope). Each change also records the new deployment
  record in the audit chain.
- **S27/S81 notification.** When the pending lifetime is over one hour and
  `approver_notification` is on, each new pending record writes one row to the
  `notifications` table for each approver the account names (approvers and page
  administrators). No tool, refusal or result exposes the table, and a repeat of the same
  request writes no second row.
- **S90 members.** `pending_expires` and `poll_interval` are added to every
  `approval_required` refusal in the server-issued profile; `poll_interval` is
  `min(30, max_lifetime - 1)`, so it is always shorter than `max_lifetime`.
- **S81 read tool setting.** This release offers one value for the read tool answer,
  `absent` (Section 2, decided): the read tool answers a record the principal may not read
  exactly as an absent identifier. The other value the earlier draft named, `not_permitted`,
  is refused at the admin call and at start, so code, registry and documentation agree.
- **S81 retention floor direction.** The default is the S13 period (the maximum approval
  lifetime plus the skew). A longer floor is a tightening and is allowed up to the
  documented one-year upper bound; a shorter floor is the loosening and is refused below
  the S13 period.
- **Test 192.** In-process the server runs its S82 invariant set at the default and at each
  setting's hard limit. Running every conformance test at every limit inside `npm test`
  would put the run well past its time bound, so S88's whole-suite-at-every-limit claim is
  an open gap (CONFORMANCE.md), not met by the run.
- **S89.** It is a disclosure claim about a deployment and has no behaviour to test; the
  coverage table keeps "none yet".
