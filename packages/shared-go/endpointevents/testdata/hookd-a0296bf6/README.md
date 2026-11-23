# hookd a0296bf6 real wire fixtures (F-EVSRC)

Captured, not hand-written. Source: github.com/yangjiyj/agent-security-platform
commit a0296bf653d55bb0d56038ce5d30954cf944a05a (`git archive a0296bf6`), hookd module.

Generator: a throwaway test `zz_g1_evsrc_fixture_test.go` (not committed anywhere)
placed in `hookd/internal/adapter/claudecode`. It drives the production path
`claudecode.Process -> queue.Append -> uploader.Run(once=true)` against an httptest
server that gunzips the POST body of `/agent/v1/events` and writes it byte-for-byte.
Only hookd's own existing test doubles are used (recordingAuthorizer,
approvalDecisionClient, approvalTestOptions); no payload field is written by hand.

| file | scenario | events | sha256 |
|---|---|---|---|
| batch-a-cc-t13-deny.json | claude-code, block mode, trusted authorization required; Read ok (server allow) + Read denied by T13 -> `local_decision.source=agent_authorization` | 8 (7 ordinary + 1 agent_authorization) | af0b0c0d54876bd91aaf84c2007339a165693549bd8fc209e73fe200951458e8 |
| batch-b-cc-t15-reject.json | claude-code, T15 approval rejected on Write -> `local_decision.source=agent_approval` | 6 | 6d5dd8acc7ae6e6a9643bbc769430f7d950008adfac06c418ec1d7b21283f0ca |

Timestamps are from capture time (2026-09-28T21:53Z). Contract tests validate with
`now = sent_at`; gateway/control-plane tests shift every timestamp by the same offset
so the wall-clock 30d/24h window keeps accepting them. No other field is altered.
