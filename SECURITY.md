# Reporting a problem

This is a draft specification about approval and enforcement, so flaws in it matter.

- **A flaw in the specification** (a way a conforming server would still run an unapproved or altered
  action, or two requirements that contradict each other): report it privately with the
  "Report a vulnerability" button under this repository's Security tab. If the flaw is already
  public knowledge or is a matter of wording, an ordinary issue is fine.
- **Anything that lets a write run without approval, or discloses record state before approval**,
  whether in the specification or in the sandbox: report it privately the same way. Products are built
  on this specification, so a pattern found in the sandbox can matter elsewhere.
- **Any other bug in the sandbox**: open an ordinary issue. The sandbox is a test harness with a fake
  sign-in and synthetic data and is not meant to be deployed.

Please include the draft number, the requirement identifiers involved (for example S13 or S50) and the
shortest sequence of requests that shows the problem.

A private report is acknowledged within 14 days, usually sooner. Please allow up to 90 days for a fix
before disclosing publicly; a disclosure date is agreed with you. Research done in good faith against
your own deployment or the sandbox, and reported privately, is welcome.

There is no bounty. Reports are credited in the notes of the next draft unless you ask otherwise.

## Supported versions

Draft 0.2 is the current draft. Draft 0.1 is superseded and receives no fixes beyond the notice below.

# Security history

- **Draft 0.1: a refusal could disclose record state to the agent.** The fix is specified in Draft 0.2. The sandbox implements and tests the parts of S60 to S80 that apply to it (S60 to S73 and S76 to S80), for operations that are not covered and for covered operations; it does not implement S74 (a permission source outside the server) or S75 (sign-in performed by a proxy) (see Section 12 of `core.md`). The "Changes
  from Draft 0.1" section of `core.md` says what leaked, who is affected and what an implementation of
  Draft 0.1 should do until it moves to Draft 0.2. Draft 0.1 remains published as it was released.
