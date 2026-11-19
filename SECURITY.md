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
