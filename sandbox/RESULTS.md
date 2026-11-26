| Test | Short name | Status | Reason |
|---|---|---|---|
| 1 | Missing approval | PASS |  |
| 2 | Approval field does nothing without an approval | PASS |  |
| 3 | Approval field does nothing with an approval | PASS |  |
| 4 | Valid approval runs once | PASS |  |
| 5 | Replay | PASS |  |
| 6 | Concurrent replay | NOT AUTOMATED | 20 calls across two SQLite connections pass; synchronous in-process dispatch does not exercise simultaneous processes or every deployment instance. |
| 7 | Replay after restart and near expiry | PASS |  |
| 8 | Changed argument | PASS |  |
| 9 | Reordered members | PASS |  |
| 10 | Other tool | PASS |  |
| 11 | Other account | PASS |  |
| 12 | Other principal | PASS |  |
| 13 | Client-supplied target | PASS |  |
| 14 | Input outside the change object | PASS |  |
| 15 | Wrong audience | PASS |  |
| 16 | Times | PASS |  |
| 17 | Tampered payload | PASS |  |
| 18 | Keys | PASS |  |
| 19 | Malformed receipt fails closed | PASS |  |
| 20 | Two receipts | PASS |  |
| 21 | Unsafe input | PASS |  |
| 22 | Approver type not allowed | PASS |  |
| 23 | Issuer scope | PASS |  |
| 24 | Policy and grant are recorded as such | PASS |  |
| 25 | Grant limit | PASS |  |
| 26 | Grant terms are fixed | PASS |  |
| 27 | Counting | PASS |  |
| 28 | Execution failure | PASS |  |
| 29 | Unknown outcome | PASS |  |
| 30 | Unavailable | PASS |  |
| 31 | An approval is not a permission | PASS |  |
| 32 | No opt-out | PASS |  |
| 33 | Refusals are recorded and leak nothing | PASS |  |
| 34 | The connection cannot approve | PASS |  |
| 35 | Approved change only | PASS |  |
| 36 | Approver permission | PASS |  |
| 37 | Pending records | PASS |  |
| 38 | Settings are administrative | PASS |  |
| 39 | Key freshness | NOT AUTOMATED | Cache bounds, refresh throttling and immediate revocation pass on two connections; every instance in a deployment cannot be exercised here. |
| 40 | Issuer object and proofs | PASS |  |
| 41 | Person action and timing | PASS |  |
| 42 | Grant terms | PASS |  |
| 43 | Registered policy | PASS |  |
| 44 | Decision lookup | PASS |  |
| 45 | Stale approval | PASS |  |
| 46 | Update by query | PASS |  |
| 47 | Partial batch failure | PASS |  |
| 48 | Client decline | PASS |  |
| 49 | Denial | PASS |  |
| 50 | Create | PASS |  |
| 51 | Match | PASS |  |
| 52 | Field not covered | PASS |  |
| 53 | Limit | PASS |  |
| 54 | Expiry | PASS |  |
| 55 | Revoke | PASS |  |
| 56 | Audit type | PASS |  |
| 57 | Result text | PASS |  |
| 58 | Unclassified input | PASS |  |
| 59 | Denial and cancellation first | PASS |  |
| 60 | Session | PASS |  |
| 61 | Request forgery | PASS |  |
| 62 | Framing | NOT AUTOMATED | All page/decision headers forbid framing; actual embedding at another origin requires a browser and is not exercised in-process. |
| 63 | Transport and caching | PASS |  |
| 64 | Rendered from the stored record | PASS |  |
| 65 | Displayed to that session | PASS |  |
| 66 | Approval URL identifier | PASS |  |
| 67 | Decision page text | PASS |  |
| 68 | Authority at use | PASS |  |
| 69 | One change, one execution | PASS |  |
| 70 | One unit | PASS |  |
| 71 | Selectors | PASS |  |
| 72 | Leaf field names | PASS |  |
| 73 | Finite limits | PASS |  |
| 74 | Declines never match | PASS |  |
| 75 | Decision finality | PASS |  |
| 76 | Inert output | PASS |  |
| 77 | Sign-in | PASS |  |
| 78 | Who may view | PASS |  |
| 79 | Referrer | PASS |  |
| 80 | Shapes offered | PASS |  |
| 81 | These records | PASS |  |
| 82 | Shape is stated | PASS |  |
| 83 | Retention | PASS |  |
| 84 | Any-record warning | PASS |  |
| 85 | Undefined property | PASS |  |
| 86 | Why no grant applied | PASS |  |
| 87 | Readable pages | PASS |  |
| 88 | Grant wording | PASS |  |
| 89 | Words, not identifiers | PASS |  |
| 90 | Readable errors | PASS |  |
| 91 | Invalid input names its cause | PASS |  |
| 92 | Reason on the elicitation | PASS |  |
| 93 | Decided links | PASS |  |
| 94 | Error wording | PASS |  |
| 95 | Messages for people | PASS |  |
| 96 | Outcome pages stay true | PASS |  |
| 97 | Refusals without hash for non-readers | PASS |  |
| 98 | Keyed state and manifest hashes | PASS |  |
| 99 | Same answer for missing and existing records | PASS |  |
| 100 | No version or absent member | PASS |  |
| 101 | Conflict after approval | PASS |  |
| 102 | Signed receipts only | PASS |  |
| 103 | Rejection by record state after approval | PASS |  |
| 104 | No issuers for covered operations | PASS |  |
| 105 | Key rotation | PASS |  |
| 106 | Permission source undecided | PASS |  |
| 107 | Version token withdrawn | PASS |  |
| 108 | Missing record shown to the approver | PASS |  |
| 109 | Version 2 only | PASS |  |
| 110 | Copied record value | PASS |  |
| 111 | Refusal stable while pending | PASS |  |
| 112 | Query needs read permission | PASS |  |
| 113 | Limit does not depend on the change | PASS |  |
| 114 | Denial is stable | PASS |  |
| 115 | Cancellation is stable | PASS |  |
| 116 | Stale approval is not a write | PASS |  |
| 117 | Old approval page | PASS |  |
| 118 | Grant closes the pending record | PASS |  |
| 119 | One context under concurrency | PASS |  |
| 120 | Identical request after consumption | PASS |  |
| 121 | Repeat under a grant | PASS |  |
| 122 | Distinguishing argument | PASS |  |
| 123 | Unknown outcome | PASS |  |
| 124 | Outcome of a consumed approval | PASS |  |
| 125 | Consumed contexts do not count | PASS |  |
| 126 | Reader refusal | PASS |  |
| 127 | Same wording for unseen requests | PASS |  |
| 128 | Grant status in a repeat | PASS |  |
| 129 | Selection growth after consumption | PASS |  |
| 130 | Replay is marked | PASS |  |
| 131 | Unused approval is shown | PASS |  |
| 132 | Repeat without a read | PASS |  |
| 133 | Read is not skipped where it matters | PASS |  |
| 134 | Approval of a change, not of a state | PASS |  |
| 135 | Repeat while in progress | PASS |  |
| 136 | Approval within its context | PASS |  |
| 137 | Earlier request shown | PASS |  |
| 138 | Filter is a selector | PASS |  |
| 139 | Results carry no record content | PASS |  |
| 140 | Missing record under a record-scoped permission | PASS |  |
| 141 | Absent record and failed read | PASS |  |
| 142 | Other records close at consumption | PASS |  |
| 143 | Identifier that resolves to another record | PASS |  |
| 144 | Identifier format | PASS |  |
| 145 | Recorded outcome for every guarded operation | PASS |  |
| 146 | Redirected identifier on an operation that is not covered | PASS |  |
| 147 | Full read model at step 1 | PASS |  |
| 148 | Delete as declared by the operation | PASS |  |
| 149 | Non-string record identifiers refused | PASS |  |
| 150 | Query refused by S66 in the default mode | PASS |  |
| 151 | Null properties refused | PASS |  |
| 152 | Read with field-level denials | PASS |  |
| 153 | Read through a merged alias | PASS |  |
| 154 | Organization issuer key | PASS |  |
| 155 | Read with a withheld field does not leak | PASS |  |
| 156 | Stdio never prints the sign-in secret | PASS |  |
| 157 | Restart keeps the operator's denials | PASS |  |
| 158 | HTTP mapping requires its token | PASS |  |
| 159 | Copy through a merged source | PASS |  |
| 160 | Approval page of a copy | PASS |  |
| 161 | State hash covers the set leaves only | PASS |  |
| 162 | Request key after its context expired | PASS |  |
| 163 | Approval expires inside its context | PASS |  |
| 164 | Next record after a grant | PASS |  |
| 165 | Record scope for query and copy | PASS |  |
| 166 | Earlier write outcome on the page | PASS |  |
| 167 | Request key on early refusals | PASS |  |
| 168 | Record values that cannot be serialized | PASS |  |
| 169 | Page for a person not permitted | PASS |  |
| 170 | Read through an unreadable alias | PASS |  |
| 171 | Record write scope for approvers and grant makers | PASS |  |
| 172 | Field write denial of the principal at step 1 | PASS |  |
| 173 | Copy validation needs a reader | PASS |  |
| 174 | Unknown-link page for a person not permitted | PASS |  |
| 175 | Invalid input before any hash | PASS |  |
| 176 | One reader decision | PASS |  |
| 177 | Request key in every audit record | PASS |  |
| 178 | Sibling notice and page of a copy | PASS |  |
| 179 | Query page marks unbound values | PASS |  |
| 180 | Late read does not replace a newer record | PASS |  |
| 181 | MCP never strips a member | PASS |  |
| 182 | Grant status does not reveal definitions | PASS |  |
| 183 | S66 before any record read | PASS |  |
| 184 | Recorded outcome before the record scope | PASS |  |
| 185 | Grant matching before the pending cap | PASS |  |
| 186 | Unknown outcome recorded at consumption | PASS |  |
| 187 | Page access from permissions only | PASS |  |
| 188 | Records close with their decision and context | PASS |  |
| 189 | Organization approvers are authorized | PASS |  |
| 190 | Defaults | PASS |  |
| 191 | Hard limits | PASS |  |
| 192 | Invariants at the limits | PASS |  |
| 193 | Scope | PASS |  |
| 194 | Tightening and loosening | PASS |  |
| 195 | Configuration change voids a match | PASS |  |
| 196 | Setting changes are audited | PASS |  |
| 197 | Deployment record and `config_hash` | PASS |  |
| 198 | Notification for a longer pending lifetime | PASS |  |
| 199 | Poll and expiry members | PASS |  |
| 200 | Recorded conflict or failure is replayed (default mode) | PASS |  |
| 201 | Partial outcome for a partly succeeded request | PASS |  |
| 202 | Consumed record retained for the floor | PASS |  |
| 203 | Grant closes its record in the default mode | PASS |  |
| 204 | Read tool answers a denied record as absent | PASS |  |
| 205 | Approver model | PASS |  |
| 206 | Settings registry rules | PASS |  |
| 207 | Binding and the deployment record | PASS |  |
| 208 | Denial and cancellation lock at most one hour | PASS |  |
| 209 | Approver-rule change voids a match | PASS |  |
| 210 | Tightening the pending lifetime reaches a covered context | PASS |  |
| 211 | Registry completeness and bounded values | PASS |  |
| 212 | config_hash covers every setting in force | PASS |  |
| 213 | The read tool answers a denied record as absent only | PASS |  |
| 214 | The named approver model narrows S22 | PASS |  |
| 215 | The applied-to identifier is returned only where S77 permits | PASS |  |
| 216 | A recorded refusal carries a message in recorded_outcome | PASS |  |
| 217 | A short configured state key is refused at start | PASS |  |
| 218 | A start value that disagrees with the store is refused; preconditions cannot be changed live | PASS |  |
| 219 | An MCP schema fault reaches the core as invalid_input | PASS |  |

SUMMARY: PASS=216 FAIL=0 NOT AUTOMATED=3 NOT IMPLEMENTED=0
