# Reporting a problem

This is a draft specification about approval and enforcement, so flaws in it matter.

- **A flaw in the specification** (a way a conforming server would still run an unapproved or altered
  action, or two requirements that contradict each other): report it privately with the
  "Report a vulnerability" button under this repository's Security tab. If the flaw is already
  public knowledge or is a matter of wording, an ordinary issue is fine.
- **A bug in the sandbox**: open an ordinary issue. The sandbox is a test harness with a fake sign-in
  and synthetic data. It is not meant to be deployed, so its bugs are not vulnerabilities in anyone's
  system.

Please include the draft number, the requirement identifiers involved (for example S13 or S50) and the
shortest sequence of requests that shows the problem.

There is no bounty. Reports are credited in the notes of the next draft unless you ask otherwise.

## Known issue in Draft 0.1

Draft 0.1 lets a refusal disclose record state to the agent. An `approval_required` refusal carries
the full change object, including `state_hash`, an unkeyed hash of current field values, so an agent
can name a field it may not read and recover a low-entropy value by guessing. `change_hash`,
`resolved.count`, a conflict refused before approval and a repeated request also disclose state, and
the signed-receipts profile's `current` and `records` give values in clear.

An implementation of Draft 0.1 can be affected where the server's credential can read more than the
agent's principal should. Until it moves to Draft 0.2, it should omit `change`, `current` and
`records` from what it returns to such a principal, and keep the full change in its pending record
and on its approval page. That advice does not stop guessing through `change_hash` itself; Draft 0.2
specifies the fix for that channel.

Draft 0.2 is in development and specifies the fix in new requirements (S60 to S80). The author found
the first of these issues while reviewing an implementation; the others were found in the review that
followed.
