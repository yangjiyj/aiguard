-- 回滚迁移 996（预置策略级别覆盖，policy_severity_override_v1）。
-- 先回退应用版本（控制面、安全引擎），再执行本文件。
-- 客户在页面改过的预置策略级别随回滚丢失，回滚后按预置级别告警。
-- 本文件不删除 schema_migrations 里 996 的记录：回滚后直接再升级，迁移运行器会认为 996 已执行而跳过
-- （severity 列不会重建）。回滚后如需再升级，先手工执行
--   DELETE FROM schema_migrations WHERE version = '996_builtin_override_severity.sql';
-- 再运行升级。
BEGIN;

DELETE FROM builtin_rule_overrides
WHERE severity IS NOT NULL
  AND action IS NULL
  AND enabled IS NULL
  AND capability_categories IS NULL
  AND redaction_json IS NULL
  AND semantic_action IS NULL;

ALTER TABLE builtin_rule_overrides DROP CONSTRAINT IF EXISTS ck_builtin_rule_overrides_has_value;
ALTER TABLE builtin_rule_overrides DROP CONSTRAINT IF EXISTS ck_builtin_rule_overrides_severity;
ALTER TABLE builtin_rule_overrides DROP COLUMN IF EXISTS severity;
ALTER TABLE builtin_rule_overrides ADD CONSTRAINT ck_builtin_rule_overrides_has_value
    CHECK (
        action IS NOT NULL OR enabled IS NOT NULL OR capability_categories IS NOT NULL
        OR redaction_json IS NOT NULL OR semantic_action IS NOT NULL
    );

COMMIT;
