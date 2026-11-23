-- 预置策略级别可由租户修改（policy_severity_override_v1）。
--
-- builtin_rule_overrides 增加可空列 severity。NULL = 未覆盖，沿用 rules.severity。
-- 只新增可空列与约束，不改写任何存量行。新增 CHECK 先以 NOT VALID 加上，
-- 提交后再单独 VALIDATE CONSTRAINT，避免长时间锁表。
-- 回滚：deploy/migrations/rollback/996_builtin_override_severity.sql。
BEGIN;

ALTER TABLE builtin_rule_overrides ADD COLUMN IF NOT EXISTS severity VARCHAR(16);
ALTER TABLE builtin_rule_overrides DROP CONSTRAINT IF EXISTS ck_builtin_rule_overrides_severity;
ALTER TABLE builtin_rule_overrides ADD CONSTRAINT ck_builtin_rule_overrides_severity
    CHECK (severity IS NULL OR severity IN ('low','medium','high','critical')) NOT VALID;
ALTER TABLE builtin_rule_overrides DROP CONSTRAINT IF EXISTS ck_builtin_rule_overrides_has_value;
ALTER TABLE builtin_rule_overrides ADD CONSTRAINT ck_builtin_rule_overrides_has_value
    CHECK (
        action IS NOT NULL OR enabled IS NOT NULL OR capability_categories IS NOT NULL
        OR redaction_json IS NOT NULL OR semantic_action IS NOT NULL OR severity IS NOT NULL
    ) NOT VALID;

COMMIT;

ALTER TABLE builtin_rule_overrides VALIDATE CONSTRAINT ck_builtin_rule_overrides_severity;
ALTER TABLE builtin_rule_overrides VALIDATE CONSTRAINT ck_builtin_rule_overrides_has_value;
