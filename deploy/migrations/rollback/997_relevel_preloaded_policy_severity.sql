-- 回滚迁移 997（预置策略重新定级，policy_severity_relevel_v1）。
-- 先回退应用版本，再执行本文件。只还原仍保持迁移后级别的行；迁移后被人工改过的不动。
-- 996 新增的 builtin_rule_overrides.severity 列按规格保留，不回滚。
-- 本文件不删除 schema_migrations 里 997 的记录：回滚后直接再升级，迁移运行器会认为 997 已执行而跳过
-- （级别停在旧值，备份表也已删除）。回滚后如需再升级，先手工执行
--   DELETE FROM schema_migrations WHERE version = '997_relevel_preloaded_policy_severity.sql';
-- 再运行升级。
BEGIN;

UPDATE rules r
SET severity = b.old_severity
FROM policy_severity_relevel_backup b
WHERE r.id = b.rule_id
  AND r.severity = b.new_severity;

DROP TABLE IF EXISTS policy_severity_relevel_backup;

COMMIT;
