-- deploy/migrations/rollback/998_scrub_private_key_evidence_context.sql
-- 998 不可回滚：它删掉的是不该存进告警库的私钥正文片段，没有备份。
-- 影响范围：security_events.matched_summary、alert_groups.body_json、alert_inbox.body_json，
-- 以及 request_logs.input_audit_result / output_audit_result（仅 created_at >= 2026-10-20 的行）。
-- 回退应用版本不需要对数据库做任何事，被截短的 evidence_context 对旧版本无影响。
-- 如需在回退后再次升级，不必删除 schema_migrations 里的 998 记录；重复执行也不会改变数据。
SELECT 1;
