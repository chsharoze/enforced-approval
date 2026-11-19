# Enforced Approval: Notes

Draft 0.1, 2026-11-20. Author: Sharoze Iftikhar. Informative. Nothing in this
document is a requirement.

## 1. Migrating from an AI-set confirmation argument

1. Declare the argument an approval field (S2). Keep it in the schema so existing clients still work,
   and ignore it for authorization.
2. Run in report-only mode: compute the change hash, log what would be refused, refuse nothing.
3. Let each account turn enforcement on, per operation.
4. Deprecate the argument.

The instruction to the model to show the change stays useful as user experience.

## 2. Worked example of the AI-set confirmation pattern

A records system exposes one write tool that creates and updates records. Its documentation says the
tool shows a summary of the proposed changes and needs explicit user confirmation before it writes.
The tool's schema has a confirmation argument with two values. One says the user confirmed. The other
says confirmation was waived for the rest of the session. The model fills in the argument. Nothing on
the server can tell whether a person saw the change. This is the pattern in Section 2 of the core, and
the waiver value is case T2.

Under this specification, the confirmation argument becomes an approval field (S2) and no longer
affects authorization. An account that turns enforcement on gets the server-issued flow. The server
answers a create or update with a link to its own approval page. The person sees the old and new
values there, and the retried call runs once. A session waiver becomes a grant on the approval page:
the same principal, operation and fields, with a record limit and an expiry that the person sets
inside the administrator's limits. The audit record shows it as a grant.

## 3. Limits and security considerations

**What this does not stop.** An approver who approves without reading. A grant or policy that is too
wide. A compromised server. A stolen issuer key or a dishonest issuer. Writes through another path to
the same data: the guard has to sit on every path the agent's credential can reach. Reads. Side
effects the system of record adds to an approved write. A change that was correct when approved and
wrong when executed because the record changed in between, unless the operation uses `preconditions`.

**Other considerations.** The change hash covers the server, the account and the principal, so an
approval cannot be replayed elsewhere or by another principal. Agents that share one credential are
one principal, so they can spend each other's approvals. Single use needs a shared store on the write
path. Server-issued approval is the smaller change for one server. Signed receipts are what
lets one organization apply one approval rule across servers from different vendors.

## 4. Client observations (2026-11-19)

Two clients were tested. Both come from one client family. No client from another family has been
tested yet, so these are observations, not general facts.

**Client A: a command-line coding agent**, run headless over stdio against a throwaway server.

- It negotiated MCP revision 2026-07-28 and declared both elicitation modes (form and URL).
- It offered no supported way to add a key to `params._meta` of a tool call. A pre-tool-use hook could
  add an argument, which reached the server even though the tool schema did not declare it. Obtaining
  a receipt and injecting it this way has not been tested end to end.
- From a refusal it passed only the text block to the model and to hooks. The result's `_meta` reached
  neither.
- It completed the URL mode round trip. Headless, it answered `cancel` without showing the URL. A hook
  could answer `accept` with no person visiting the URL. This is why S21 does not treat `accept` as
  approval.

**Client B: a hosted chat web application** with a custom connector, against a sandbox server. Its tool
calls arrived from the same family's agent runtime, on revision 2026-07-28.

- Its tool calls declared URL mode elicitation. Its setup connections did not. This is why capabilities
  are read per request.
- It showed the approval link in a card with decline, continue and open buttons, and waited for the
  person. Choosing continue without opening the link sent `accept`. The server refused.
- It sent `decline` when the person declined after approving on the page. This is why S30 forbids
  executing such a request.
- The model set the confirmation argument to its confirmed value on every write, including one the
  person had not confirmed. The server ignored it.
- No receipt could be carried. Every tool call had the same five `_meta` keys, and none was an approval
  key.
- After a refusal the model asked the person for a receipt, which the server-issued profile does not
  have. The `message` member and the advice not to declare the receipt argument address this.
- In a further test, decline, denial, single execution and the cap on open approval requests all held.
  At the cap, a plain `approval_required` with no link led the model to tell the person an approval
  was pending. This is why the server answers `approval_limit_reached` at the cap.

These observations are the reason for the `approval_receipt` argument and for repeating the refusal in
a text block.

## 5. Test vectors

The test vectors are published with this draft as one JSON file, generated by a script with no
dependencies. They use placeholders only. The base vector:

```
{"account":"acct-EXAMPLE-0001","arguments":{"action":"update","objectType":"contact","records":[{"id":"rec-EXAMPLE-42","properties":{"lifecycle_stage":"customer","owner":"user-EXAMPLE-7"}}]},"audience":"https://mcp.crm.example/mcp","operation":"mcp:tools/call:manage_records","principal":"agent-EXAMPLE-sync","v":1}
change hash: gdTr35hU7NHRlWWwpztLe-mPxr0Lhh37XPYGnimiFIU
```

The file also has: the same call with the approval field set and with members reordered (same hash);
a changed argument, and a different account, server, principal and tool (different hashes); a call with
no arguments; the HTTP mapping; non-ASCII text with a non-integer number; `preconditions` and
`resolved` examples; and signed receipts for each approver type, plus expired, wrong-audience and
tampered receipts, with the issuer's public key. Each vector records the arguments as sent and the
approval fields removed. Two implementations agree on all 13 vectors: the sandbox's, and a second written from the
specification text alone by a separate automated coding agent that was not shown the expected hashes.
