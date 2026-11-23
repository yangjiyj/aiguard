-- 回滚迁移 993（语义裁判拦截由控制台策略决定，semantic_policy_block_v1）。
-- 先回退应用版本（控制面、安全引擎），再执行本文件。
--
-- 1. 删除只设置了「智能分析命中时」的预置策略覆盖行（其它字段全空）：旧约束不允许这种行；
-- 2. 删除 semantic_action 列，恢复 950 的 ck_builtin_rule_overrides_has_value 约束；
-- 3. 去掉租户自建策略 scope_json 里的 semantic_action 键（旧版本不认识该键）；
-- 4. 删除 993 登记、且未被任何策略绑定的语义能力目录行（已绑定的保留，避免策略失去能力）。
-- 客户在页面设置的「智能分析命中时：拦截/仅记录」随回滚丢失，回滚后语义命中按记录并告警处理。
BEGIN;

DELETE FROM builtin_rule_overrides
WHERE semantic_action IS NOT NULL
  AND action IS NULL
  AND enabled IS NULL
  AND capability_categories IS NULL
  AND redaction_json IS NULL;

ALTER TABLE builtin_rule_overrides DROP CONSTRAINT IF EXISTS ck_builtin_rule_overrides_has_value;
ALTER TABLE builtin_rule_overrides DROP CONSTRAINT IF EXISTS ck_builtin_rule_overrides_semantic_action;
ALTER TABLE builtin_rule_overrides DROP COLUMN IF EXISTS semantic_action;
ALTER TABLE builtin_rule_overrides ADD CONSTRAINT ck_builtin_rule_overrides_has_value
    CHECK (action IS NOT NULL OR enabled IS NOT NULL OR capability_categories IS NOT NULL OR redaction_json IS NOT NULL);

UPDATE rules
SET scope_json = scope_json - 'semantic_action'
WHERE jsonb_typeof(scope_json) = 'object' AND scope_json ? 'semantic_action';

DELETE FROM security_capabilities
WHERE metadata_json->>'catalog' = 'semantic_policy_block'
  AND NOT EXISTS (
      SELECT 1 FROM rule_capability_bindings b
      WHERE b.capability_id = security_capabilities.id
  );

COMMIT;
