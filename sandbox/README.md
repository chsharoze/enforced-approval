# Enforced Approval sandbox
A test server for the core (`../core.md`) and both profiles: Server-issued approval
(`../profile-server-issued.md`) and Signed receipts, experimental
(`../profile-signed-receipts.md`). Tests are numbered as in `../CONFORMANCE.md`;
the `spec` link points to the repository root. VA_MODE=organization selects the
Signed receipts profile and verifies receipts against the operator's issuer public key.
Node 24; installed MCP SDK 2.4.0; no added dependencies. Run inside this directory:
```sh
node test/run.mjs
node test/blackbox.mjs
node test/e2e-server-issued.mjs
node test/e2e-http.mjs
node test/e2e-origin.mjs
node test/e2e-nondisclosure.mjs
```
RESULTS.md covers 219 cases: 1 to 146 are numbered as in `../CONFORMANCE.md`, 147 to
189 are the sandbox's own (171 to 189 are the milestone 1 items), 190 to 199 are the
CONFORMANCE.md settings and S90 tests, 200 to 208 are the sandbox's milestone 2 tests, and
209 to 219 are the release-fix tests. The author maintains additional internal test suites.
Tests 6/39/62 retain deployment/browser limits. The runner refuses a run whose environment sets a start
setting (VA_PRECONDITIONS and the others it would leak into the servers it starts); run with
VA_REPORT=0 to skip writing RESULTS.md. E2E uses real loopback TCP, no public service.
One process serves MCP and pages on 127.0.0.1:8787 for an existing HTTPS tunnel:
```sh
export VA_ADMIN='choose-a-synthetic-test-credential'
export VA_PATH_TOKEN="$(node -e "console.log(require('node:crypto').randomBytes(24).toString('hex'))")"
VA_BASE_URL=https://YOUR-TUNNEL-HOST VA_DB="$PWD/stage2.sqlite" node src/mcp-http.mjs
VA_MODE=organization VA_ISSUER_PUBLIC_KEY="$(cat issuer-public.jwk)" VA_BASE_URL=https://YOUR-TUNNEL-HOST VA_DB="$PWD/stage2-org.sqlite" node src/mcp-http.mjs
```
Organization mode requires the operator's issuer public key in VA_ISSUER_PUBLIC_KEY: a
JSON JWK in the form the issuer registry stores, for example
`{"kty":"OKP","crv":"Ed25519","x":"...","kid":"org-key-1","alg":"EdDSA"}`. The built-in
test key in src/receipt.mjs is accepted only when VA_TEST_ISSUER=1 is set; a test suite
that needs it sets that variable. With neither the operator key nor VA_TEST_ISSUER=1,
organization mode refuses to start, and the stdio server and the connector both exit
non-zero with the reason. Connector: https://YOUR-TUNNEL-HOST/mcp/<VA_PATH_TOKEN>. Token: at least 24 URL-safe
characters; other /mcp paths return 404. HTTP mode defaults to server-issued.
VA_PRECONDITIONS=1 turns record-state preconditions on for a new database; an existing
database keeps the value recorded when it was created, and a start whose
VA_PRECONDITIONS disagrees with it refuses to start (use a new database file or set
the variable to match). Any other setting given at start that disagrees with the value an
existing database stores also refuses to start with a clear message; a matching value starts
as before. `preconditions` cannot be changed on a live database through the administrative
surface, only with a new database. An operation that uses preconditions is a covered operation
(profile-server-issued S67). The sandbox implements covered operations behind this
setting (approval contexts and request keys, S67 to S70); they are experimental in
Draft 0.2 (core Section 12) and off in every mode unless set. With preconditions on, the
server holds a 256-bit HMAC key for `state_hash` and `manifest_hash` (S61); it generates one
when the database has none, and a configured key shorter than 256 bits is refused at start.
Every permission decision is made by `authorize` and every record read resolved by
`resolveIdentifier` (src/authorize.mjs); every request is parsed once by `shapeRequest`
(src/shape.mjs); `Core.handle` (src/core.mjs) lists the one order of steps every guarded
request takes. AMBIGUITIES.md, "Milestone 1", records the readings these fix.
PORT overrides 8787. VA_BASE_URL supplies public approval links. VA_LOG defaults to
./requests.log: client capabilities, revision, full tool arguments, _meta,
inputResponses and outcomes (a refused tools/call line also carries grant_status
when the refusal does); one line per page request (time, method, kind of page
(approve, signin, grants, revoke or other), the first 8 characters of any approval or
grant identifier, the status code, and for errors the internal error code; never
cookies, tokens or form values); receipt strings/copies are redacted to lengths.
The page handler logs only when VA_LOG is set; the combined server always sets it.
A request refused because it reached an HTTPS origin over a plain client connection
(S79) is recorded in the audit store (phase security, outcome disclosed) and reported on
this log as one security line naming the account's page administrators; the refusal
answer is unchanged.
Draft 0.2 permissions and results for operations that are not covered (core S60 to
S80; covered operations are implemented behind VA_PRECONDITIONS=1 and remain experimental):
- Readers and non-readers (S60). sor.permission(account, principal, operation, read,
  write) models what a principal may read and write; a value of null models a permission
  source that answers neither yes nor no and is treated as not permitted. A principal
  with any write-scoped row (sor.recordWriteScope(account, principal), grants per record
  via sor.recordPermission) has its write permission scoped by record: for an update or
  delete, a missing record gets the same step 1 permission refusal as a record outside
  the scope, while a create still reaches the approval flow. Before an approval is
  consumed the answer to a principal that may not read never depends on the state or
  existence of a record; after consumption, conflict and execution_failed are permitted
  answers. Read permission is re-established for every answer after consumption.
  The permission source is inside the server (the Sor itself), so S74 does not arise;
  its model states separately what a principal may read and what a principal may write,
  and an answer it does not give is treated as not permitted (S76). The default
  permissions for the principal and test persons are granted only when the database is
  created; a later start on the same file keeps the operator's read, field, record and
  write-scope settings.
- Definitions (S48, S65). A principal established to see every definition of an object
  type (sor.established; any principal is established until a restricted definition
  exists, and sor.seeDefinitions marks a principal who may see restricted ones) is told
  what is undefined before approval. For any other principal the validation runs after
  consumption and the answer is execution_failed naming no property.
- Systems of record (S64, S78, S25). The default system refuses a write whose record is
  missing or already exists, and a write to an identifier merged under another
  identifier (sor.merge removes the merged-from record and resolves reads to the
  surviving one; the canonical form of an identifier is its exact string). Setting
  sor.conditional=false models a system that offers nothing: the server then reads each
  named record immediately before the write and sends nothing where the read finds a
  conflict or another identifier — the check is documented as not atomic with the write.
  A write that still reached the surviving record is outcome misdirected, recorded in the
  audit record with the identifier it was applied to. Setting sor.idempotent=true models a
  system that treats a repeat keyed by the receipt identifier as the same write (S25):
  where an outcome is unknown the server may send it again and reports the recovered
  outcome. sor.inject('before-get', fn) models a read that does not complete; the answer
  is approval_unavailable and nothing is consumed (S60(i)).
- Results and identifiers (S77). A write's result carries only what the request sent and
  the count changed, never record content, values the server derived from record state or
  the system of record's own text; per-record entries appear only for misdirected writes.
  Outcomes are success, conflict, execution_failed, unknown, not_sent, misdirected (S78),
  in_progress (an execution still running) or partial (a request in which at least one
  entry succeeded and at least one did not); a result, not a refusal, carries partial and
  in_progress. not_sent is recorded internally for entries blocked by another entry's
  pre-write check, and no reason member is offered (the closed list the server documents is
  empty). An
  identifier returned by the system of record is checked against ^[A-Za-z0-9_-]{1,64}$
  before it is returned or placed in a message, shown only to a principal established to
  read that record, and withheld (the result says so) otherwise.
- Recorded outcomes (S14, S25, S80). While the server holds the consumed record (the
  sandbox keeps used identifiers and outcomes indefinitely, beyond the S13/S35 minimum),
  an identical request never executes, opens no approval record or matches no grant, and
  is answered with the recorded outcome, marked in a client-visible member and in its
  message as the outcome of an earlier attempt with its time and the words that nothing
  was sent now. A recorded conflict or execution_failed remains a refusal (409/500); a
  recorded success, misdirected, unknown, partial or in_progress outcome is a result (200).
  Where the outcome is not
  known the answer says so; an execution the server knows is still in progress is
  answered as in progress with nothing sent. A bare approval_used is given only where the
  server no longer holds the outcome. core.learnOutcome(change_hash, {outcome, changed})
  is the test hook for a system of record that later reports the outcome of a lost write.
- Supersession (S35, S50). Recording a decision or a grant is one atomic step that
  applies only if the record is still pending. When an approval is consumed, every other
  pending or approved record for the same change hash is closed as superseded in the
  same transaction; its page says the change already ran under another approval and a
  decision posted to it records nothing.
- The approval page (S64, S71, S78). Every approval page says the approval is for the
  change as requested and not for the state of the record when the write runs, and marks
  current values as current values that may change. To a person permitted to read, the
  page says a named record is missing, a created record already exists, or an identifier
  resolves to another record; in the last case it offers no approval or grant.
Separate stdio and page processes can share one database:
```sh
VA_MODE=server VA_DB="$PWD/server.sqlite" node src/mcp-server.mjs
VA_MODE=server VA_DB="$PWD/server.sqlite" node src/http.mjs
VA_MODE=organization VA_DB="$PWD/org.sqlite" node src/mcp-server.mjs
```
VA_ACCOUNT/VA_PRINCIPAL simulate credentials; VA_NOW fixes time. VA_SIGNIN_SECRET sets
the page sign-in secret; unset, the server generates one. The entry points that serve the
approval pages (mcp-http.mjs and http.mjs) print it once on stderr at start; the stdio
server never prints it, because its stderr goes to the MCP client. VA_EDGE_MARKER names how
the server learns the client's scheme: unset for direct TLS on its own socket, or
"header-name=value" for a trusted edge marker that is accepted only when the server is
configured behind that edge. VA_ADMIN is trusted
bootstrap only, never an MCP tool. PATCH /records accepts JSON and Approval-Receipt and
requires `Authorization: Bearer <VA_PATH_TOKEN>`, the connector's path token, compared in
constant time; without it the answer is 401, nothing is read and no approval record is
opened. The standalone http.mjs entry point takes VA_PATH_TOKEN too; when it is unset it
generates one at start and prints it once on the operator's console.
Only synthetic data belongs here; the organization issuer key is public RFC material.
JWS cap 8192 bytes; lifetime 300s; skew 0; selection 100; pending 3600s/cap 10.
Provider cache 3600s; unknown-kid refresh at most once/minute; local revocation immediate.
State hashes/conditional writes are used only under VA_PRECONDITIONS=1. Audit heads are unanchored. No execution retries; consumed records are kept at least the retention floor (see Settings).
core.admin(VA_ADMIN, 'settings', {grantConfig: {[account]: {[operation]:
{maxRecords, maxSeconds, anyRecord}}}, pageAdministrators: {[account]: ['test-admin']}})
controls eligibility, finite positive integer caps, any-record enablement and page admins.
No configured caps means no grant. Fresh runtimes use 100 records/3600s, enable
manage_records with anyRecord:true and create_record with anyRecord:false.
Existing databases retain configuration. Agents cannot administer these settings.
manage_records selectors: explicit objectType and action (update/create); IDs are
record identifiers. update_by_query selectors: objectType and exact filter; the tool
fixes update. create_record selectors: objectType and create fixed by its tool name.
Unknown kind/arguments, omitted action, deletion, or arrays in written values offer no grant.
Fields are JSON Pointer leaf paths under properties (or query set), without record
positions: /owner, /profile/name; ~ and / in keys escape as ~0 and ~1. A parent
never covers its children. Nested objects merge by leaf; normal arrays replace.
Defined contact properties: owner, lifecycle_stage, notes, email, phone, company;
name/group/extra/uncovered/markup-field and explicit owner/profile leaves support fixtures.
Deal definitions are name/amount/closed/note. Undefined properties are invalid before approval.
Record/field permissions inherit operation permission unless explicitly denied;
account membership is separate. The maker's current authority is rechecked per use.
these_records stores the exact shown IDs (resolved IDs for queries); a subset may
match, an outside ID cannot. any_record needs anyRecord:true and is the only create
shape. Both shapes cover any values only within the granted leaf fields and caps.
Only displayed shapes may be selected. Any-record warnings accompany the choice and confirmation.
Forms use max_records and minutes (fractional, rounded to seconds); page times use one form, "D Mon YYYY, HH:MM UTC", and the ISO form appears only inside the collapsed "Raw saved change" details. Counts read "1 record"/"3 records" wherever a limit, used or remaining count is shown.
Refusals explain newest grants via grant_status: used_up, expired, revoked or outside.
After consumption, conflict reads "The approved change was not made because it no
longer fits the records now. The approval has been used and will not run again. If the
change is still wanted, ask for it again as a new change, which needs a new approval."
and execution_failed reads "The approved change could not be carried out." followed by
the same advice; neither names a record-state reason. A replayed outcome appends "This
is the recorded outcome of an earlier attempt, made at <time>. Nothing was sent now.",
in the message and in a recorded_outcome member, and an unknown outcome says so.
A GET on a decided link shows an outcome page (S50) describing the state when viewed,
never a decision or grant form and never the change as open: "This change was approved
on <time>. It can be used until <time>." or "It has already been used, on <time>, so it will
not run again.", "This change was denied on <time>. It will not run." or "A standing
grant was made from this change on <time>." followed by "It has not been used yet."
or "This change ran under that grant on <time>." with a link to the grants page; the
titles are Change approved, Change denied and Grant created. A superseded record's
page says "This change already ran under another approval, so this link can no longer
be decided." under the title Change already run, and a record whose identifier
resolves to another record gets "This change can no longer be decided" with the
resolution, no decision form and no grant offer. A second
decision posted to a decided record returns that same outcome page saying which decision
stands (403), and after a denial it never tells the person to send the request again.
An unknown link and an expired link get the same page, "This approval link is not valid
or is no longer active" with "Ask the assistant to request the change again if it is
still needed."; nothing on it reveals whether the link ever existed.
A write the system of record rejects for undefined properties is refused as
invalid_input carrying `invalid` (the JSON Pointer property names) and a message
naming them; other unserializable input (arrays, lone surrogates, duplicate
members, unsafe integers) gets a message naming the kind; never a change hash or
approval link. The URL mode elicitation's message is the refusal's plain message,
so a client that shows only that text still shows the reason a grant did not apply.
No refusal message and no elicitation message names a protocol member such as
approval_url, grant_status, retry_after or change_hash (S59). approval_required reads
"This change needs a person's approval. Open the approval page, review the change, and
approve or deny it there. Nothing needs to be copied or pasted back. Then continue
here." A refusal sent without an elicitation (the client did not declare URL mode,
or it already answered this request's elicitation, or the HTTP mapping) appends
"Approval page: <link>" to the message; an elicitation carries the link in its own
member and the message never repeats it. Durations in messages are for people only, for
example "for about 6 minutes (until 18:12 UTC)"; no message or elicitation text contains
a raw second count, while the numeric retry_after member stays in the refusal object.
Pages use people-readable names (S57): operations ("Update records", "Create
record", "Update records matching a filter", "Delete records"), selectors
("Object type", "Action", "Filter") and fields ("Owner", "Lifecycle stage",
"Notes", "Email", "Phone", "Company"); the technical identifier follows in
parentheses, and an unmapped defined property falls back to a tidied form of its
name. Times read like "19 Nov 2026, 15:29 UTC", the one form used on every page. The value beside the minutes input is
labelled "Latest possible expiry" and says it is the maximum; the grant
confirmation states the expiry actually set, the record limit and the shape in
words, and repeats the any-record warning when that shape was granted. /grants
shows remaining records only for active grants ("-" otherwise). Each page has its
own title: Review change, Change approved, Change denied, Grant created, Your
grants, Grant revoked, Sign in, Problem. Every thrown error or refusal on a page
route is an HTML page (S58) with a plain-words heading and one line on what to do
next, keeping every security header; the internal error code goes to the page
log, never the page.
Charge uses batch entries or resolved.count; /grants lists states, usage and active-only revocation.
Approved grant creation, permission checks, charge and consumption share one transaction.
Duplicate entries and failed execution are charged; identical consumed hashes never
execute/charge again. With preconditions, changed state produces a different hash.
The page uses fake named-person sign-in, not an identity provider. The server generates
a random sign-in secret at start, or takes VA_SIGNIN_SECRET, and the page-serving entry
points print it once on the operator's console (stderr); it never appears in an HTTP
answer, a page, a log line or an MCP answer, and the stdio server never prints it. GET the sign-in shell first; POST its CSRF token, a test person name and
the secret with its anonymous cookie. A missing or wrong secret is the same failed
sign-in as an unknown name: no session is created and no record state is shown. Sign-in
rotates the ID and returns to a server-stored path; return locations in requests are
ignored.
First page decision wins; exact retries return its stored result while unexpired
and unconsumed. A grant seals the page without approving the shown change.
GET /grants lists/revokes creator/admin grants with CSRF protection. Page admin:
test-admin. Sessions, CSRF and approval IDs use crypto.randomBytes(24), 192 bits.
Viewing requires membership and read permission on every shown record/field.
All data is escaped. CSP blocks all script and framing; no-store and same-origin referrer policy
apply to all page responses. HTTPS origins add HSTS and require the client's scheme to
come from a source the client cannot set: direct TLS on the server's own socket, or the
VA_EDGE_MARKER configured edge marker (for example x-forwarded-proto=https). The edge
must terminate TLS, strip any client-sent copy of that marker, add its own, reject or
redirect public plaintext and forward only to loopback. The same check applies to the
agent's MCP endpoint. HTTP origins serve
local harnesses only. No external tunnel or browser embedding was tested here.

## Settings
The settings registry (`src/settings.mjs`) is the one place that says which values a
deployment may configure, what each defaults to, how far it may go, which way is looser,
and the requirement it parameterises (S23; core Section 11.1 to 11.5). A
setting configures the parameters of the guarantee — who, how long, how many, which
operations — never its logic: no value turns a check off. The first release is exactly:

| Setting | Default | Range / values | Looser | Requirement |
|---|---|---|---|---|
| `pending_lifetime_seconds` | 3600 | 1 to 86400; above 3600 only with `approver_notification` on | a longer lifetime | S27 |
| `approver_notification` | off | true / false | adding a channel | S27 |
| `pending_cap` | 10 | 1 to 100 | a higher cap | S27 |
| `selection_limit` | 100 | 1 to 1000 | a higher limit | S29 |
| `max_lifetime_seconds` | 300 | 2 to 86400 | a longer lifetime | S10, S27, S35, S60, S90 |
| `skew_seconds` | 0 | 0 to 60 | a larger skew; raising it never revives an approval already expired | S10, S84 |
| `grant_charge_limit` | 100 | 1 to 1000 | a higher limit; a tightening applies to existing grants | S18, S35 |
| `grant_seconds_limit` | 3600 | 1 to 31536000 | a longer lifetime; a tightening applies to existing grants | S18, S35 |
| `key_cache_seconds` | 3600 | 1 to 86400 | a longer period | S15, S26 |
| `retention_floor_seconds` | S13 floor (max lifetime + skew) | at least the S13 floor and at most one year | a shorter floor, down to the S13 floor; a longer floor is a tightening, allowed up to one year | S13, S35 |
| `read_tool_denied_answer` | `absent` | `absent` (this release offers only the absent answer) | none | Section 2 |
| `approver_model` | `permission` | `permission`, `named`, `administrators` | adding a model | S22, S76 |

The deployment record also states the principal model in force (`delegated`, `dedicated` or
`service_account`; the sandbox's default is `dedicated`, a credential with its own scope), as
S87 requires. `VA_PRINCIPAL_MODEL` sets it at start.

Rules every setting follows: the default is a safe starting value, the hard limit bounds it, and a missing value means
the default; an unknown or out-of-range value is refused at the admin call and at start
(see below); a setting is scoped by account, never by record content; a tightening applies
at once and a loosening never revives a denied or expired request or widens an existing
grant; a setting that changes what the write does or who may approve is bound into every
approval record as an `effect_hash`, so a change to it before consumption makes the
approval not match and the normal approval request follows; every change is audited with
who and the old and new values; the agent can never change a setting.

The approver model is `permission` by default: the documented permission model alone names
every approver. In `named` the account's named-approver list narrows S22 — a person may
approve only if on that list AND holding the permission to make the change — and
`administrators` restricts decisions to the account's page administrators. A person who
fails S22 cannot approve under any model, and an empty list leaves the permission model to
decide.

Change a setting with the administrative surface only (`core.admin`), never through a
guarded tool or the agent's credential:
```js
core.admin(VA_ADMIN, 'settings', { pending_lifetime_seconds: 3600, approver_model: 'named' })
```
An operator may also set `VA_PENDING_LIFETIME`, `VA_PENDING_CAP`, `VA_SELECTION_LIMIT`,
`VA_RETENTION_FLOOR`, `VA_MAX_LIFETIME`, `VA_SKEW`, `VA_GRANT_CHARGE_LIMIT`,
`VA_GRANT_SECONDS_LIMIT`, `VA_KEY_CACHE`, `VA_APPROVER_NOTIFICATION` (0/1) and
`VA_APPROVER_MODEL` at start; an out-of-range value makes the server exit non-zero with its
reason on stderr before any request is served.

**Deployment record.** `node src/deployment-record.mjs` prints, for the database `VA_DB`
names, one JSON object with a member for each setting in force, the principal model, the
account's configuration and where each setting differs from its default, with its SHA-256
`config_hash` (the same object `core.admin(VA_ADMIN, 'deploymentRecord')` returns on the admin
path). The `config_hash` is the base64url SHA-256 of the RFC 8785 serialization of that
object (S87). Every consumption and outcome audit record carries the `config_hash` in force,
each change of a setting and each new deployment record is in the audit chain (S86, S87), and
the hash is not part of the change hash the agent sees.

**Notifications.** With `approver_notification` on and a pending lifetime over one hour, each
new pending record writes one row to the `notifications` table for each approver the account
names: a channel the agent's credential cannot read, since no tool, result or refusal exposes
it (S27, S81).
```sh
VA_DB="$PWD/stage2.sqlite" node src/deployment-record.mjs
```
