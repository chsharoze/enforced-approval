| Test | Short name | Status | Reason |
|---|---|---|---|
| 1 | Missing receipt | PASS |  |
| 2 | Approval field without receipt | PASS |  |
| 3 | Approval field with receipt | PASS |  |
| 4 | Valid receipt | PASS |  |
| 5 | Replay | PASS |  |
| 6 | Concurrent replay | NOT AUTOMATED | 20 calls across two SQLite connections pass; synchronous in-process dispatch does not exercise simultaneous processes or every deployment instance. |
| 7 | Restart and expiry | PASS |  |
| 8 | Changed argument | PASS |  |
| 9 | Reordered members | PASS |  |
| 10 | Other tool and HTTP target | PASS |  |
| 11 | Other account | PASS |  |
| 12 | Other principal | PASS |  |
| 13 | Untrusted target metadata | PASS |  |
| 14 | Outside inputs | PASS |  |
| 15 | Wrong audience | PASS |  |
| 16 | Times | PASS |  |
| 17 | Tampered payload | PASS |  |
| 18 | Keys | PASS |  |
| 19 | Malformed receipts | PASS |  |
| 20 | Two receipts | PASS |  |
| 21 | Unsafe input | PASS |  |
| 22 | Approver type | PASS |  |
| 23 | Issuer scope | PASS |  |
| 24 | Recorded approver | PASS |  |
| 25 | Grant limit and atomic rollback | PASS |  |
| 26 | Fixed grant terms | PASS |  |
| 27 | Counting | PASS |  |
| 28 | Execution failure | PASS |  |
| 29 | Unknown outcome | PASS |  |
| 30 | Unavailable | PASS |  |
| 31 | Ordinary permissions | PASS |  |
| 32 | No opt-out | PASS |  |
| 33 | Audit and chain tampering | PASS |  |
| 34 | Connection cannot approve | PASS |  |
| 35 | Approved change only | PASS |  |
| 36 | Approver permission | PASS |  |
| 37 | Pending cap and expiry | PASS |  |
| 38 | Administrative settings | PASS |  |
| 39 | Key freshness | NOT AUTOMATED | Cache bounds, refresh throttling and immediate revocation pass on two connections; every instance in a deployment cannot be exercised here. |
| 40 | Issuer object and proofs | PASS |  |
| 41 | Person action and timing | PASS |  |
| 42 | Grant terms | PASS |  |
| 43 | Registered policy | PASS |  |
| 44 | Decision lookup | PASS |  |
| 45 | Stale and conditional writes | PASS |  |
| 46 | Resolved query | PASS |  |
| 47 | Partial batch failure | PASS |  |
| 48 | Client decline and sticky cancellation | PASS |  |
| 49 | Sticky page denial | PASS |  |
| 50 | Create server grant | PASS |  |
| 51 | Match server grant | PASS |  |
| 52 | Field coverage | PASS |  |
| 53 | Server grant limit | PASS |  |
| 54 | Server grant expiry | PASS |  |
| 55 | Server grant revocation | PASS |  |
| 56 | Grant audit type | PASS |  |
| 57 | Grant result text | PASS |  |
| 58 | Unclassified grant input | PASS |  |
| 59 | Denial/cancellation precede grants | PASS |  |
| 60 | Page session | PASS |  |
| 61 | Page request forgery | PASS |  |
| 62 | Page framing | NOT AUTOMATED | All page/decision headers forbid framing; actual embedding at another origin requires a browser and is not exercised in-process. |
| 63 | Page transport/cache | NOT AUTOMATED | Trusted loopback headers and HTTPS-origin HSTS/no-store are checked; no TLS tunnel or public plaintext endpoint is available to establish end-to-end transport. |
| 64 | Stored rendering | PASS |  |
| 65 | Session display binding | PASS |  |
| 66 | Approval identifiers | PASS |  |
| 67 | Decision messages | PASS |  |
| 68 | Grantor authority at use | PASS |  |
| 69 | One grant execution per change | PASS |  |
| 70 | Atomic grant consumption | PASS |  |
| 71 | All kind selectors | PASS |  |
| 72 | Leaf fields | PASS |  |
| 73 | Finite grant maxima | PASS |  |
| 74 | Declines bypass grants | PASS |  |
| 75 | First decision and replay | PASS |  |
| 76 | Inert change output | PASS |  |
| 77 | Protected sign-in and rotation | PASS |  |
| 78 | Page account/read authority | PASS |  |
| 79 | Same-origin referrer | PASS |  |
| 80 | Offered grant shapes | PASS |  |
| 81 | Fixed record sets | PASS |  |
| 82 | Shape in audit/result | PASS |  |
| 83 | Consumed grant retention | PASS |  |
| 84 | Any-record scope warning | PASS |  |
| 85 | Defined properties only | PASS |  |
| 86 | Grant refusal reasons | PASS |  |
| 87 | Readable pages and states | PASS |  |
| 88 | Standing grant result wording | PASS |  |
| 89 | Words, not identifiers | PASS |  |
| 90 | Readable error pages | PASS |  |
| 91 | Invalid input names its cause | PASS |  |
| 92 | Reason on the elicitation | PASS |  |
| 93 | Decided links show their outcome | PASS |  |
| 94 | Error wording on decided and unknown links | PASS |  |
| 95 | Messages for people | PASS |  |
| 96 | Outcome pages stay true | PASS |  |

SUMMARY: PASS=92 FAIL=0 NOT AUTOMATED=4
