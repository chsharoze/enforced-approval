# Enforced Approval sandbox
A test server for the core (`../core.md`) and both profiles: Server-issued approval
(`../profile-server-issued.md`) and Signed receipts, experimental
(`../profile-signed-receipts.md`). Tests are numbered as in `../CONFORMANCE.md`;
the `spec` link points to the repository root. VA_MODE=organization selects the
Signed receipts profile, with an organization-issued test issuer.
Node 24; installed MCP SDK 2.4.0; no added dependencies. Run inside this directory:
```sh
node test/run.mjs
node test/mutations.mjs
node test/blackbox.mjs
node test/e2e-server-issued.mjs
node test/e2e-http.mjs
node test/e2e-origin.mjs
```
RESULTS.md covers 96 cases; MUTATIONS.md covers 52 mutations. Tests 6/39/62/63
retain deployment/browser/TLS limits. E2E uses real loopback TCP, no public service.
One process serves MCP and pages on 127.0.0.1:8787 for an existing HTTPS tunnel:
```sh
export VA_ADMIN='choose-a-synthetic-test-credential'
export VA_PATH_TOKEN="$(node -e "console.log(require('node:crypto').randomBytes(24).toString('hex'))")"
VA_BASE_URL=https://YOUR-TUNNEL-HOST VA_DB="$PWD/stage2.sqlite" node src/mcp-http.mjs
VA_MODE=organization VA_BASE_URL=https://YOUR-TUNNEL-HOST VA_DB="$PWD/stage2-org.sqlite" node src/mcp-http.mjs
```
Connector: https://YOUR-TUNNEL-HOST/mcp/<VA_PATH_TOKEN>. Token: at least 24 URL-safe
characters; other /mcp paths return 404. HTTP mode defaults to server-issued.
PORT overrides 8787. VA_BASE_URL supplies public approval links. VA_LOG defaults to
./requests.log: client capabilities, revision, full tool arguments, _meta,
inputResponses and outcomes (a refused tools/call line also carries grant_status
when the refusal does); one line per page request (time, method, kind of page
(approve, signin, grants, revoke or other), the first 8 characters of any approval or
grant identifier, the status code, and for errors the internal error code; never
cookies, tokens or form values); receipt strings/copies are redacted to lengths.
The page handler logs only when VA_LOG is set; the combined server always sets it.
Separate stdio and page processes can share one database:
```sh
VA_MODE=server VA_DB="$PWD/server.sqlite" node src/mcp-server.mjs
VA_MODE=server VA_DB="$PWD/server.sqlite" node src/http.mjs
VA_MODE=organization VA_DB="$PWD/org.sqlite" node src/mcp-server.mjs
```
VA_ACCOUNT/VA_PRINCIPAL simulate credentials; VA_NOW fixes time. VA_ADMIN is trusted
bootstrap only, never an MCP tool. PATCH /records accepts JSON and Approval-Receipt.
Only synthetic data belongs here; the organization issuer key is public RFC material.
JWS cap 8192 bytes; lifetime 300s; skew 0; selection 100; pending 600s/cap 10.
Provider cache 3600s; unknown-kid refresh at most once/minute; local revocation immediate.
Server runtime uses state hashes/conditional writes. Audit heads are unanchored. No execution retries; consumed grant hashes retained forever.
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
A GET on a decided link shows an outcome page (S50) describing the state when viewed,
never a decision or grant form and never the change as open: "This change was approved
on <time>. It can be used until <time>." or "It has already been used, on <time>, so it will
not run again.", "This change was denied on <time>. It will not run." or "A standing
grant was made from this change on <time>." followed by "It has not been used yet."
or "This change ran under that grant on <time>." with a link to the grants page; the
titles are Change approved, Change denied and Grant created. A second
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
The page uses fake named-person sign-in, not an identity provider. GET the sign-in
shell first; POST its CSRF token with its anonymous cookie. Sign-in rotates the ID
and returns to a server-stored path; return locations in requests are ignored.
First page decision wins; exact retries return its stored result while unexpired
and unconsumed. A grant seals the page without approving the shown change.
GET /grants lists/revokes creator/admin grants with CSRF protection. Page admin:
test-admin. Sessions, CSRF and approval IDs use crypto.randomBytes(24), 192 bits.
Viewing requires membership and read permission on every shown record/field.
All data is escaped. CSP blocks all script and framing; no-store and same-origin referrer policy
apply to all page responses. HTTPS origins add HSTS and require TLS or the trusted
tunnel's overwritten X-Forwarded-Proto: https header. The tunnel must terminate TLS,
reject/redirect public plaintext and forward only to loopback. HTTP origins serve
local harnesses only. No external tunnel or browser embedding was tested here.
