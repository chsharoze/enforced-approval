Surviving mutations (holes): none

Baseline: SUMMARY: PASS=92 FAIL=0 NOT AUTOMATED=4

| Mutation | Result | Failed tests | Credited tests |
|---|---|---|---|
| skip-hash-compare | KILLED | 8, 10, 11, 12, 45, 46, 47 | 8, 10, 11, 12, 45, 46, 47 |
| skip-audience | KILLED | 15 | 15 |
| skip-expiry | KILLED | 16, 33, 37 | 16, 33, 37 |
| skip-signature | KILLED | 17, 18 | 17, 18 |
| accept-alg-none | KILLED | 19 | 19 |
| skip-single-use | KILLED | 5, 6, 7, 28, 29, 35, 47 | 5, 7, 28, 29, 35, 47 |
| skip-issuer-scope | KILLED | 23 | 23 |
| skip-approver-type | KILLED | 22 | 22 |
| skip-grant-limit | KILLED | 25 | 25 |
| approval-field-authorizes | KILLED | 2 | 2 |
| principal-not-in-hash | KILLED | 1, 12, 35, 51, 86 | 1, 12, 35, 51, 86 |
| accept-connection-accept | KILLED | 34, 50, 92, 95 | 34, 50, 92, 95 |
| skip-precondition-refill | KILLED | 45, 69 | 45, 69 |
| requery-at-execution | KILLED | 46 | 46 |
| ignore-decline | KILLED | 48 | 48 |
| decline-erases-denial | KILLED | 49 | 49 |
| veto-creates-pending | KILLED | 48, 74 | 48, 74 |
| cap-counts-pending-only | KILLED | 48, 49 | 48, 49 |
| cancel-not-sticky | KILLED | 48, 59 | 48, 59 |
| cap-refuses-as-required | KILLED | 20, 37, 48, 49, 95 | 20, 37, 48, 49, 95 |
| grant-ignores-field-cover | KILLED | 52, 53, 61, 72, 86 | 52, 53, 61, 72, 86 |
| grant-ignores-selector | KILLED | 51 | 51 |
| grant-ignores-limit | KILLED | 53, 86, 92, 95 | 53, 86, 92, 95 |
| grant-ignores-revocation | KILLED | 53, 55, 86, 89, 95 | 53, 55, 86, 89, 95 |
| grant-ignores-expiry | KILLED | 54, 86, 95 | 54, 86, 95 |
| grant-from-connection | KILLED | 50 | 50 |
| grant-skips-permission | KILLED | 50 | 50 |
| page-no-csrf | KILLED | 61, 90 | 61, 90 |
| page-decision-without-display | KILLED | 65 | 65 |
| page-session-from-url | KILLED | 49, 60, 66, 77, 89 | 49, 60, 66, 77, 89 |
| grant-ignores-record-set | KILLED | 81, 86, 95 | 81, 86, 95 |
| grant-any-record-without-config | KILLED | 80 | 80 |
| grant-skips-authority-at-use | KILLED | 68 | 68 |
| grant-double-execution | KILLED | 69, 74, 83 | 69, 74, 83 |
| decision-replay-creates-second | KILLED | 75, 87 | 75, 87 |
| page-renders-markup | KILLED | 76 | 76 |
| page-view-without-permission | KILLED | 78 | 78 |
| signin-keeps-session | KILLED | 77 | 77 |
| signin-open-return | KILLED | 77 | 77 |
| any-record-no-warning | KILLED | 84, 89 | 84, 89 |
| grant-on-undefined-property | KILLED | 85 | 85 |
| no-grant-reason | KILLED | 86, 92 | 86, 92 |
| grants-list-revoke-on-inactive | KILLED | 87 | 87 |
| page-error-bare-response | KILLED | 89, 90, 94 | 89, 90, 94 |
| invalid-input-no-reason | KILLED | 91, 95 | 91, 95 |
| inactive-grant-shows-remaining | KILLED | 89 | 89 |
| elicitation-drops-reason | KILLED | 92, 95 | 92, 95 |
| decided-link-shows-form | KILLED | 93, 96 | 93, 96 |
| error-page-hides-decision | KILLED | 94 | 94 |
| unknown-link-says-expired | KILLED | 90, 94 | 90, 94 |
| message-names-member | KILLED | 95 | 95 |
| grant-outcome-stale | KILLED | 96 | 96 |

MUTATIONS SUMMARY: total=52 killed=52 surviving=0

Only baseline PASS tests can receive mutation kill credit. NOT AUTOMATED cases never count as kills.
