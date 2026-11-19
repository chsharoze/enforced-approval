# Enforced Approval

Server-side approval of exact agent actions.

This is a draft specification for servers that write to a system of record on behalf of an AI agent.
The server refuses a guarded write unless a person, a grant or a policy approved that exact change.
The check runs on the server, so it holds even when the client does not ask anyone.
The release has the specification, conformance tests, test vectors and a sandbox server.
Draft 0.1, dated 2026-11-20. Author: Sharoze Iftikhar.

> **The sandbox is a test harness, not a product.** Its sign-in accepts a typed test name, its data is
> synthetic and its key is public test material. Do not put it in front of a real system or real data.

## Why this is open

This specification came out of work on governance for AI agents that act through MCP. That work needed a foundation that did not exist: a way for the server itself to enforce approval of the exact action. So it was written down, built and tested here. It is published so that others can build on the same foundation.

## The problem

Many write tools ask for approval in two ways only. They tell the model to show the change and ask.
They also have an argument the model fills in to say that approval happened. The server cannot tell
an approved call from an unapproved one. The party that proposes the change also reports the approval.
A headless agent, a mistake or a prompt injection can set that argument. An approval can also be reused
for a later, different change, and afterwards nobody can show who approved what.

## How it works

1. **Hash of the exact change.** The server builds a change object from the request, the server, the
   account and the principal (the identity taken from the agent's credential), and computes its hash.
   Approval fields (arguments that only claim approval happened) are left out.
2. **Refusal.** A guarded write with no approval for that hash does not run. The server returns a
   refusal that says what is needed.
3. **Approval page.** In the server-issued approval profile (a profile is a separate document that
   defines how the approval is obtained), the refusal links to the server's own
   page. A person signs in, sees the change and approves or denies it. The agent sends the same
   request again.
4. **Single use.** An approval authorizes at most one execution, and it expires.
5. **Grants.** On the approval page, a person can approve a bounded set of future changes. The server
   fixes the scope from the change shown: the principal (the agent's credential), the account, the
   operation and the fields, for either the records shown or, where an administrator has enabled it,
   any record the person may change. The person sets only a record limit and an expiry.
6. **Audit.** The server writes a hash-chained record of each refusal, each consumption of an approval
   and each outcome, naming the approver.

The server-issued approval profile is the one that works today. The client carries nothing, so it
works with any client, including ones the organization does not control.

The signed-receipts profile is experimental and included for comment. In it, an issuer registered by
the organization signs a receipt that the client carries on the request. No client tested so far can
carry a receipt, so it has been exercised only by the sandbox's own tests.

## Status

| Part | Specified | Implemented | Tested, and by what |
|---|---|---|---|
| Change hash | Yes | Two implementations: the sandbox's, and a second written from the specification text alone by a separate automated coding agent that was not shown the expected hashes | Both agree on all 13 test vectors |
| Server-issued approval | Yes | One sandbox server | 96 conformance cases: 92 pass, 4 not automated, 0 fail (last recorded run), all against a single server instance. 52 mutation checks (see below), none survive. End-to-end runs over loopback TCP. Live in two clients of one client family: one headless, one hosted web app |
| Grants and approval pages | Yes | Same sandbox | Same suites, plus live runs in the hosted web app only |
| HTTP mapping | Yes | Same sandbox | By the sandbox's own tests on one machine (in-process and over loopback), never by an independent client |
| Signed receipts (experimental) | Yes | Same sandbox | By the sandbox's own tests on one machine, never by an independent client |

Who made these checks: the specification, the sandbox and the tests were written by one author
working with AI coding and review models. The second implementation of the change hash was written
from the specification text alone by a separate automated coding agent that was not shown the
expected hashes. Several AI models from different vendors reviewed it. No human other than
the author has reviewed it. Every number here can be reproduced with the commands in
`sandbox/README.md`.

All tests ran against a single server instance. The requirement that consumption is atomic across
several server instances (S13) has not been tested.

Each mutation check switches off one named protection in the sandbox and shows that the tests notice
when that protection is missing. The mutations are listed in `sandbox/MUTATIONS.md`. This is not a
proof of correctness, and the author chose the list.

What is NOT done:
- No independent server implementation.
- No human security review.
- No test with more than one server instance sharing a store.
- The clients tested live so far all come from one family.
- The signed-receipts profile has no working client carriage: no tested client can carry a receipt.

## Repository layout
| Path | Contents |
|---|---|
| `core.md` | Core: change hash, verification, refusals, consumption, audit |
| `profile-server-issued.md` | Server-issued approval profile |
| `profile-signed-receipts.md` | Signed receipts profile (experimental) |
| `CONFORMANCE.md` | Conformance tests, numbered, each citing its requirement |
| `NOTES.md` | Informative notes: migration, limits, client observations |
| `vectors/` | Test vectors and the script that generates them |
| `sandbox/` | Sandbox server and its test suites |

## Running the sandbox tests

You need Node 24 or later. Run `npm install` in `sandbox/`, then, inside `sandbox/`:

```sh
node test/run.mjs
node test/mutations.mjs
node test/blackbox.mjs
node test/e2e-server-issued.mjs
node test/e2e-http.mjs
node test/e2e-origin.mjs
```
The same commands are available as npm scripts. See `sandbox/README.md` for settings.

## Background

The observations that motivated this work are described in a separate paper.

## Feedback
Open an issue in this repository. Say which document and which requirement or test number you mean.

## How to cite
Sharoze Iftikhar. Enforced Approval: Server-side approval of the exact change, for
MCP and HTTP. Draft 0.1, 2026-11-20. DOI: DOI-PENDING. See also `CITATION.cff`.

## Licences
The specification text is licensed under CC BY 4.0. The code, everything under `sandbox/` and
`vectors/`, is licensed under the Apache License 2.0. See `LICENSE.md`.
