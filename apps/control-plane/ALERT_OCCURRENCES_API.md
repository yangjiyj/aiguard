# Alert occurrence API (frontend contract, 2026-09-18)

GET `/admin/v1/security/alert-occurrences` under the existing authenticated admin API.
Permission: `security_events:read`; tenant and department/project row scopes still apply.
Backend worktree: `/home/dev/jjdguard-worktrees/alert-occurrences-20260918`, branch `feat/alert-occurrences-20260918`.
Integration: additive route in `cmd/server/main.go`, permission resolver entry, and dependency only. No `semantic_config.go` edits.

Query: `limit` (default 20, max 100), `offset` (default 0), `severity`, `category`, `request_id`, `conversation_key`, `session_id`, `user_id`, `project_id`, `start_time`, `end_time` (RFC3339), `include_suppressed` (default false), `include_raw` (default false).

Response: `{items: AlertOccurrence[], total: number, limit: number, offset: number, counts: {total: number, active: number, suppressed: number, critical: number, high: number, medium: number, low: number}, operational: {event_count: number, count_unit: "security_events", list_url: string}}`.
`total` is the filtered visible occurrence total. `counts` covers the same filters before `include_suppressed`; severity counts are active occurrences. Counts never count conversations.

Each item has:
- `id`, `event_id`, `request_id`, `project_id`, `created_at`, `finding_index` (zero-based, null for legacy event-level evidence), `duplicate_count`, `rule_ids`.
- `type`, `category`, `severity`, `rule_id`, `rule_name`, `action_taken`, `event_action_taken`, `suppressed`, `suppression_reason`, `review_state`, `disposition_status`, `alert_group_id`.
- `message_index` (number or null; zero is valid), `attachment_index` (number or null), `message_role`, `content_source`, `stage`, `matched_location`, `location_status` (`available` or `missing`).
- `reason`, `reason_status` (`available`, `missing`, `restricted`), `evidence_kind`, `redacted_evidence`, `evidence_status` (`available`, `missing`, `restricted`), `raw_evidence`, `evidence_context`, and `matched_text_preview` (omitted unless `include_raw=true` and existing content permission permits), `raw_evidence_status` (`available`, `missing`, `restricted`, `not_requested`). Raw fields are the stored finding's original windows, never substituted with another message or request. A historical preview stays a preview; it is never promoted into a full raw window.
- `actor_user_id`, `actor_name`, `actor_department_id`, `actor_department_name`, `key_owner_user_id`, `key_owner_name`, `department_id`, `department_name`, `agent_type`, `credential_id`, `credential_name`, `principal_key`, `identity_source`, `identity_reliability`, `source_ip`, `access_direction`.
- `conversation_key`, `conversation_id`, `session_id`, `conversation_source`, `conversation_reliability`. These are associations only, never row-group keys; missing anchors remain empty/unknown, and recorded session/conversation keys are not asserted to prove an exact conversation.

Default list has one effective security finding per request/message/location/type/category/stage. Only a known message + known location allows repeated-rule deduplication across events; unlocated findings remain distinct. A duplicate row keeps one deterministic representative's own severity/evidence/reason; event or conversation max severity is never inherited by a finding. Deterministic ID derives from event ID plus original finding index. Different turns, attachment positions, stages, sources and categories remain distinct.

An explicit `findings` array is authoritative even when empty: `findings: []` and arrays whose findings all have `counts_as_security_finding=false` yield zero occurrences, regardless of stale root severity/category/evidence. Legacy fallback is allowed only for an absent/non-array `findings` value with an explicit root risk type/category, rule, or recorded hit evidence. Event type, severity, and action by themselves are insufficient.

Review labels are advisory metadata. An active finding remains visible even when a finding, event, or model triage label says `likely_false_positive`, `false_positive`, `benign`, `suppressed`, or `review_pending`; its own severity, action and evidence are retained. Only an explicit audit/group disposition, policy exception, finding suppression flag, or authoritative `counts_as_security_finding=false` controls suppression/non-counting. `review_state` alone is never proof that a finding is cleared. Runtime and passive observation exclusions still apply.

Runtime/engine faults, capacity errors, findings explicitly marked `counts_as_security_finding=false`, and passive agent inventory observations never enter the list or counts, including mixed events. Legacy event-level records remain visible with explicit missing anchors. No alert-group membership requirement and no database migration/backfill.

Operational extension (2026-09-19): `operational.event_count` separately counts recorded inspection-gap **events**, including runtime failures, engine_runtime findings, regex/custom-scan timeouts, capacity errors, and explicit incomplete/unavailable/failed inspection or semantic status. Normal non-counting observations and successful inspection telemetry are not gaps. A mixed event contributes its real findings to the attack list and one event to this operational count; these totals must not be added together. Zero recorded gaps does not establish complete inspection coverage.

The operational count uses the same tenant/department/project, time, request, recorded session/conversation and actor scope as the list. Attack `severity/category` and suppression filters do not apply to this separate count. Counts and the finding page are calculated in one SQL statement/snapshot.

`operational.list_url` links to `GET /admin/v1/security/alert-occurrences/operational`, preserving only those metadata filters. This endpoint uses the same permission and pagination (`limit/offset`) and returns `{items: AlertOperationalEvent[], total, limit, offset, count_unit: "security_events"}`. Each metadata-only item contains `event_id, request_id, project_id, event_type, action_taken, stage, classification: "operational_gap", created_at`. It exposes no raw diagnostic or source text, and has no attack severity. Passing attack `severity/category` filters returns 400. The default attack list remains one finding per row.

Raw evidence permission uses the existing authenticated content-evidence role check. Metadata readers receive redacted evidence only and no free-text reason (stored reasons can quote raw input). `include_raw=true` without permission returns 404. All joins are tenant bound; project filtering happens before expansion and all totals use the same scope.
