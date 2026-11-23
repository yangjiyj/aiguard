-- deploy/migrations/rollback/1006_alert_retention_dirty_triggers.sql
-- 删除 1006 新加的留存预算列置空触发器。1006 对 1003 触发器的改动（同名触发器重定义、jjd_alert_case_dirty_access_rows）
-- 不在这里撤回：要撤回就接着执行 rollback/1003（顺序见该文件），只回滚 1006 时登记触发器仍是 1006 的定义。
-- 本文件不删除 schema_migrations 里 1006 的记录：回滚后如需再升级，先手工执行
--   DELETE FROM schema_migrations WHERE version = '1006_alert_retention_dirty_triggers.sql';
-- 再运行升级（同时回滚了 1003 时按 rollback/1003 的说明一起删 1003 的记录）。
BEGIN;
DROP TRIGGER IF EXISTS trg_retention_summary_stale_entries_insert ON content_log_entries;
DROP TRIGGER IF EXISTS trg_retention_summary_stale_entries_update ON content_log_entries;
DROP TRIGGER IF EXISTS trg_retention_summary_stale_entries_delete ON content_log_entries;
DROP TRIGGER IF EXISTS trg_retention_summary_stale_legacy_insert ON content_logs_legacy;
DROP TRIGGER IF EXISTS trg_retention_summary_stale_legacy_update ON content_logs_legacy;
DROP TRIGGER IF EXISTS trg_retention_summary_stale_legacy_delete ON content_logs_legacy;
DROP TRIGGER IF EXISTS trg_retention_summary_stale_access_insert ON access_content_logs;
DROP TRIGGER IF EXISTS trg_retention_summary_stale_access_update ON access_content_logs;
DROP TRIGGER IF EXISTS trg_retention_summary_stale_access_delete ON access_content_logs;
DROP TRIGGER IF EXISTS trg_retention_summary_stale_event_insert ON security_events;
DROP TRIGGER IF EXISTS trg_retention_summary_stale_event_delete ON security_events;
DROP TRIGGER IF EXISTS trg_retention_summary_stale_event_update ON security_events;
DROP TRIGGER IF EXISTS trg_retention_summary_stale_request ON request_logs;
DROP FUNCTION IF EXISTS jjd_retention_summary_stale_content();
DROP FUNCTION IF EXISTS jjd_retention_summary_stale_access();
DROP FUNCTION IF EXISTS jjd_retention_summary_stale_event_rows();
DROP FUNCTION IF EXISTS jjd_retention_summary_stale_event_update();
DROP FUNCTION IF EXISTS jjd_retention_summary_stale_request();
COMMIT;
-- 1006 改过的告警案件登记触发器不在这里撤回，见文件开头。
