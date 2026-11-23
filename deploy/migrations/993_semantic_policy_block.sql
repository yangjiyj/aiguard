-- 语义裁判（智能分析）拦截由控制台策略决定（semantic_policy_block_v1）。
--
-- 1. 把裁判的全部类别登记为管理员可选能力（允许 audit/block，仅输入侧）。已存在的
--    semantic_roleplay / semantic_instruction_override 不改动（ON CONFLICT DO NOTHING）。
-- 2. 预置策略的租户覆盖表增加「智能分析命中时」semantic_action。NULL = 未覆盖，
--    沿用预置定义（缺省 audit）。租户自建策略存放在 rules.scope_json.semantic_action。
--
-- 只新增目录行与可空列，不改写任何存量策略：升级后所有策略的语义命中仍是记录并告警，
-- 只有管理员在页面把某条策略的「智能分析命中时」改成拦截才会生效。
--
-- 新增 CHECK 先以 NOT VALID 加上（只锁表很短时间、不扫存量行），提交后再单独
-- VALIDATE CONSTRAINT（只持 SHARE UPDATE EXCLUSIVE 锁，不阻塞读写）。
-- 回滚：deploy/migrations/rollback/993_semantic_policy_block.sql。
BEGIN;

INSERT INTO security_capabilities (
    id, category, name, capability_kind, component, selector_json,
    supported_stages, allowed_actions, mask_capable, enabled, metadata_json
)
SELECT
    'cap.dynamic.' || category,
    category,
    name,
    'dynamic',
    'security-engine.semantic',
    jsonb_build_object('category', category),
    '["input"]'::jsonb,
    '["audit","block"]'::jsonb,
    FALSE,
    TRUE,
    '{"catalog":"semantic_policy_block","catalog_version":1}'::jsonb
FROM (VALUES
    ('semantic_jailbreak', '语义越狱（智能分析）'),
    ('semantic_exfil_induce', '语义数据外泄诱导（智能分析）'),
    ('semantic_harassment', '语义骚扰（智能分析）'),
    ('semantic_threat', '语义威胁（智能分析）'),
    ('semantic_hate', '语义仇恨（智能分析）')
) AS catalog(category, name)
ON CONFLICT (category) DO NOTHING;

ALTER TABLE builtin_rule_overrides ADD COLUMN IF NOT EXISTS semantic_action VARCHAR(16);
ALTER TABLE builtin_rule_overrides DROP CONSTRAINT IF EXISTS ck_builtin_rule_overrides_semantic_action;
ALTER TABLE builtin_rule_overrides ADD CONSTRAINT ck_builtin_rule_overrides_semantic_action
    CHECK (semantic_action IS NULL OR semantic_action IN ('audit','block','observe')) NOT VALID;
ALTER TABLE builtin_rule_overrides DROP CONSTRAINT IF EXISTS ck_builtin_rule_overrides_has_value;
ALTER TABLE builtin_rule_overrides ADD CONSTRAINT ck_builtin_rule_overrides_has_value
    CHECK (
        action IS NOT NULL OR enabled IS NOT NULL OR capability_categories IS NOT NULL
        OR redaction_json IS NOT NULL OR semantic_action IS NOT NULL
    ) NOT VALID;

COMMIT;

ALTER TABLE builtin_rule_overrides VALIDATE CONSTRAINT ck_builtin_rule_overrides_semantic_action;
ALTER TABLE builtin_rule_overrides VALIDATE CONSTRAINT ck_builtin_rule_overrides_has_value;
