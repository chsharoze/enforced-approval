# Enforced Approval

Server-side approval of exact agent actions.

[![DOI](https://zenodo.org/badge/1464578191.svg)](https://doi.org/10.5281/zenodo.24379987)

This is a draft specification for servers that write to a system of record on behalf of an AI agent.
The server refuses a guarded write unless a person, a grant or a policy approved that exact change.
The check runs on the server, so it holds even when the client does not ask anyone.
The release has the specification, conformance tests, test vectors and a sandbox server.
Draft 0.2, dated 2026-11-26. Author: Sharoze Iftikhar.

Draft 0.2 replaces Draft 0.1. In Draft 0.1 a refusal could disclose record state to the agent. See
`SECURITY.md` and the "Changes from Draft 0.1" section of `core.md`.

> **The sandbox is a test harness, not a product.** Its sign-in accepts a typed test name, its data is
> synthetic and its key is public test material. Do not put it in front of a real system or real data.

## Why this is open

This specification came out of work on governance for AI agents that act through MCP. That work
needed the server itself to enforce approval of the exact action, for any write and not for one kind
of transaction.

The parts are not new. An IETF individual draft on payment mandates
(`draft-craig-oauth-rar-payment-mandates-00`) binds an approval to a digest of the canonical form of
a payment and makes it usable once. In the MCP repository, SEP-2672 (closed without being merged)
proposed approval by passkey for each tool call, bound to a hash of the tool name, its canonical
arguments and the server. SEP-2848 (open) proposes asynchronous approval of tool calls, and SEP-2643
(open) proposes structured authorization denials. A second IETF individual draft, on execution
finality for agent actions (`draft-das-ai-agent-cyberattack-effect-finality-00`), binds a single-use
execution handle to the exact bytes that are committed, for actions in general. A 2026 paper
(arXiv:2609.21081) shows attacks on approval flows in which what a person approved and what ran
differ. These states are as of 2026-11-23.

What this specification adds is a general profile, enforced by the server that executes the write,
for MCP tool calls and HTTP writes. It combines three things: an approval bound to the exact change,
an approval consumed at most once, and rules on what an agent may learn before an approval is
consumed. As far as the author knows, none of the works above combines all three. The closest general
one, the execution-finality draft, has the first two and no rule on what the agent may learn. It is
published so that others can build on it and check it.

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
carry a receipt, so it has been exercised only by the sandbox's conformance tests.

## Status

| Part | Specified | Implemented | Tested, and by what |
|---|---|---|---|
| Change hash (`v` 2) | Yes | One public implementation: the sandbox's | 14 test vectors, generated and checked by the sandbox. The independent second implementation recorded for Draft 0.1 has not been repeated for `v` 2 |
| Server-issued approval, operations that are not covered | Yes | One sandbox server | Conformance tests 1 to 146: 143 pass, 3 not automated, 0 fail, 0 not implemented, all against a single server instance. Conformance tests 190 to 199 also pass. The Draft 0.2 sandbox has not been run live in a client; the Draft 0.1 sandbox was, in two clients of one client family |
| Covered operations (experimental) | Yes | Same sandbox | The conformance tests that exercise covered operations pass, run with covered operations turned on. See Section 12 of `core.md` |
| Settings registry and deployment record (S81 to S89), S90 | Yes | Same sandbox | Conformance tests 190 to 199 pass. The `partial` outcome is covered by conformance test 47 |
| Grants and approval pages | Yes | Same sandbox | The conformance tests that exercise grants and approval pages pass. Not run live under Draft 0.2 |
| HTTP mapping | Yes | Same sandbox | Conformance tests 10, 20 and 31 pass over the in-process mapping and over loopback on one machine, never from an independent client |
| Signed receipts (experimental) | Yes | Same sandbox | Conformance tests 8 to 39 pass on one machine, never from an independent client |

Who made these checks: the specification, the sandbox and the tests were written by one author
working with AI coding and review models. The second implementation of the change hash was written
from the specification text alone by a separate automated coding agent that was not shown the
expected hashes; that check was made for Draft 0.1 and has not been repeated for Draft 0.2.
Several AI models from different vendors reviewed it. No human other than
the author has reviewed it. Every number here can be reproduced with the commands in
`sandbox/README.md`.

All tests ran against a single server instance. The requirement that consumption is atomic across
several server instances (S13) has not been tested.

The author maintains additional internal test suites.

What is NOT done:
- No live run of the Draft 0.2 sandbox in any client.
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
node test/blackbox.mjs
node test/e2e-server-issued.mjs
node test/e2e-http.mjs
node test/e2e-origin.mjs
node test/e2e-nondisclosure.mjs
```
These commands are available as npm scripts. See `sandbox/README.md` for settings.

## Background

The observations that motivated this work are described in a separate paper.

## Feedback
Open an issue in this repository. Say which document and which requirement or test number you mean.

## How to cite
Sharoze Iftikhar. Enforced Approval: Server-side approval of exact agent actions. Draft 0.2, 2026.
Zenodo. https://doi.org/10.5281/zenodo.24379987

That DOI always points to the latest archived version. Draft 0.1 is
https://doi.org/10.5281/zenodo.24379988. See also `CITATION.cff`.

## Licence
Everything in this repository, the specification text and the code, is licensed under the
Apache License 2.0. Draft 0.1 kept its specification text under CC BY 4.0. See `LICENSE.md`.
