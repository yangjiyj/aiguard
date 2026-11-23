-- 回滚迁移 995（上下文语义裁判结论可由页面策略绑定，semantic_context_capability_v1）。
-- 先回退应用版本（安全引擎），再执行本文件。
--
-- 删除 995 登记的「上下文语义攻击（智能分析）」能力目录行，但只删未被任何策略引用的行：
-- - 被 rule_capability_bindings 绑定（租户自建策略或预置策略默认绑定），或
-- - 被 builtin_rule_overrides.capability_categories 选中（租户对预置策略改过能力），
-- 都明确跳过并以 NOTICE 说明，避免策略失去检测能力；需要时先在页面解除绑定再回滚。
-- 本迁移不改写策略，回滚也不改写策略。
BEGIN;

DO $$
DECLARE
    referenced_count integer;
BEGIN
    SELECT COUNT(*) INTO referenced_count
    FROM security_capabilities capability
    WHERE capability.metadata_json->>'catalog' = 'semantic_context_capability'
      AND (
          EXISTS (SELECT 1 FROM rule_capability_bindings binding
                  WHERE binding.capability_id = capability.id)
          OR EXISTS (SELECT 1 FROM builtin_rule_overrides override_row
                     WHERE override_row.capability_categories ? capability.category)
      );
    IF referenced_count > 0 THEN
        RAISE NOTICE '995 回滚：上下文语义攻击能力仍被 % 处策略引用，已跳过删除该能力目录行', referenced_count;
    END IF;
END $$;

DELETE FROM security_capabilities capability
WHERE capability.metadata_json->>'catalog' = 'semantic_context_capability'
  AND NOT EXISTS (SELECT 1 FROM rule_capability_bindings binding
                  WHERE binding.capability_id = capability.id)
  AND NOT EXISTS (SELECT 1 FROM builtin_rule_overrides override_row
                  WHERE override_row.capability_categories ? capability.category);

COMMIT;
