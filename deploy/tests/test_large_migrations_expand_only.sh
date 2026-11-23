#!/usr/bin/env bash
set -Eeuo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

! grep -Eiq '^[[:space:]]*UPDATE[[:space:]]' "$ROOT/deploy/migrations/146_environment_scope_retention.sql"
! grep -Eiq '^[[:space:]]*UPDATE[[:space:]]' "$ROOT/deploy/migrations/148_access_content_logs_schema_repair.sql"
! grep -Eiq 'SET[[:space:]]+NOT[[:space:]]+NULL' "$ROOT/deploy/migrations/148_access_content_logs_schema_repair.sql"
! grep -Eiq 'CREATE[[:space:]]+(UNIQUE[[:space:]]+)?INDEX' "$ROOT/deploy/migrations/148_access_content_logs_schema_repair.sql"
! grep -Eiq '^[[:space:]]*UPDATE[[:space:]]' "$ROOT/deploy/migrations/816_security_event_delivery_disposition.sql"
! grep -Eiq '^[[:space:]]*UPDATE[[:space:]]' "$ROOT/deploy/migrations/090_usage_rollup_latency_count_first_priced.sql"
grep -Fq 'NOT VALID' "$ROOT/deploy/migrations/816_security_event_delivery_disposition.sql"
! grep -Fq 'WITH affected_chains AS' "$ROOT/deploy/migrations/819_repair_evidence_run_agent_projection.sql"
grep -Fq 'customer_environment_scope_v1' "$ROOT/deploy/migrations/836_customer_environment_scope_backfill.sql"
grep -Fq 'CREATE INDEX CONCURRENTLY' "$ROOT/deploy/migrations/837_customer_environment_scope_indexes.sql"
grep -Fq 'evidence_agent_projection_v1' "$ROOT/deploy/migrations/838_evidence_agent_projection_backfill.sql"
grep -Fq 'CREATE INDEX CONCURRENTLY' "$ROOT/deploy/migrations/839_security_event_delivery_backfill_index.sql"
grep -Fq 'security_event_delivery_v1' "$ROOT/deploy/migrations/840_security_event_delivery_backfill.sql"
grep -Fq 'CREATE INDEX CONCURRENTLY' "$ROOT/deploy/migrations/841_evidence_title_noise_backfill_index.sql"
grep -Fq 'evidence_title_noise_v1' "$ROOT/deploy/migrations/842_evidence_title_noise_backfill.sql"
grep -Fq 'workbuddy_identity_v1' "$ROOT/deploy/migrations/843_workbuddy_identity_backfill.sql"
grep -Fq 'usage_rollup_dimensions_v1' "$ROOT/deploy/migrations/844_usage_rollup_dimensions_backfill.sql"
grep -Fq 'agent_ua_identity_v1' "$ROOT/deploy/migrations/991_agent_ua_identity_backfill.sql"
grep -Fq 'semantic_policy_block_v1' "$ROOT/deploy/migrations/993_semantic_policy_block.sql"
# 993 只新增能力目录行与可空列：绝不改写存量策略的动作（升级后语义命中仍是记录并告警）。
! grep -Eiq '^[[:space:]]*(UPDATE|DELETE)[[:space:]]' "$ROOT/deploy/migrations/993_semantic_policy_block.sql"
grep -Fq 'semantic_context_capability_v1' "$ROOT/deploy/migrations/995_semantic_context_capability.sql"
! grep -Eiq '^[[:space:]]*(UPDATE|DELETE)[[:space:]]' "$ROOT/deploy/migrations/995_semantic_context_capability.sql"
grep -Fq 'CREATE TABLE IF NOT EXISTS content_raw_evidence' "$ROOT/deploy/migrations/994_content_raw_evidence.sql"
! grep -Eq '^(UPDATE|DELETE FROM|ALTER TABLE) (request_logs|content_logs|content_log_entries|security_events)' "$ROOT/deploy/migrations/994_content_raw_evidence.sql"
grep -Fq "task_version=1 AND state='completed'" "$ROOT/deploy/migrations/845_security_event_delivery_reconcile.sql"
grep -Fq 'customer_environment_scope_v1' "$ROOT/deploy/docker-compose/customer-environment-scope-repair.sql"
! grep -Fq 'UPDATE request_logs' "$ROOT/deploy/docker-compose/customer-environment-scope-repair.sql"
# 992 只插入缺失的默认策略且固定 audit：升级不得改动、删除客户已有的策略动作
! grep -Eiq '^[[:space:]]*(UPDATE|DELETE)[[:space:]]' "$ROOT/deploy/migrations/992_profanity_abuse_policy.sql"
grep -Fq "'audit'," "$ROOT/deploy/migrations/992_profanity_abuse_policy.sql"
grep -Fq 'policy_severity_override_v1' "$ROOT/deploy/migrations/996_builtin_override_severity.sql"
! grep -Eiq '^[[:space:]]*(UPDATE|DELETE)[[:space:]]' "$ROOT/deploy/migrations/996_builtin_override_severity.sql"
# 997 是数据更新迁移：只改 rules.severity（按旧级别匹配、写备份表可回滚），不动动作和启用状态
migration_997="$ROOT/deploy/migrations/997_relevel_preloaded_policy_severity.sql"
grep -Fq 'policy_severity_relevel_v1' "$migration_997"
grep -Fq 'AND r.severity = relevel.old_severity' "$migration_997"
# SET 子句只有 severity 一列，且独占一行、下一行紧接 FROM relevel
awk '/^[[:space:]]*SET severity = relevel\.new_severity[[:space:]]*$/{f=1;next} f{if($0 ~ /^[[:space:]]*FROM relevel[[:space:]]*$/)ok=1;exit} END{exit !ok}' "$migration_997"
# 除 UPDATE rules 与备份表 INSERT 外没有别的写操作（含 DELETE、其它表的 UPDATE）
write_ops_997=$(grep -v '^[[:space:]]*--' "$migration_997" | tr '\n' ' ' \
  | grep -Eoi '(UPDATE|DELETE|INSERT|TRUNCATE|MERGE)([[:space:]]+(INTO|FROM))?[[:space:]]+[a-z_]+' | tr -s ' ' | tr 'A-Z' 'a-z')
[ "$write_ops_997" = "update rules
insert into policy_severity_relevel_backup" ]
# 998 是数据清理迁移：只改 security_events.matched_summary 、alert_groups / alert_inbox 的 body_json 与 request_logs 的 input/output_audit_result，不建备份表（备份会把私钥片段再存一份），不可回滚
migration_998="$ROOT/deploy/migrations/998_scrub_private_key_evidence_context.sql"
grep -Fq 'private_key_context_scrub_v1' "$migration_998"
write_ops_998=$(grep -v '^[[:space:]]*--' "$migration_998" | tr '\n' ' ' \
  | grep -Eoi '(UPDATE|DELETE|INSERT|TRUNCATE|MERGE|CREATE TABLE)([[:space:]]+(INTO|FROM))?[[:space:]]+"?[a-z_]+"?' | tr -s ' ' | tr 'A-Z' 'a-z' | sort -u)
[ "$write_ops_998" = "update alert_groups
update alert_inbox
update request_logs
update security_events" ]
printf 'large_migrations_expand_only=ok\n'
