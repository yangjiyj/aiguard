-- 上下文语义裁判结论可由页面策略绑定（semantic_context_capability_v1）。
--
-- 部署的上下文裁判（jjdguard-context-judge-v1，input_contract=context-v1）只判断攻击/正常，
-- 结论统一为 prompt_input_semantic_risk、置信度固定 0.9。引擎把它视为同时命中全部语义裁判
-- 能力（绑定任一语义能力即可），这里再把它登记为可单独选择的语义能力（仅输入侧，允许
-- audit/block）。
--
-- 只新增目录行，不改写任何存量策略：升级后语义命中仍是记录并告警，只有管理员在页面把
-- 策略的「智能分析命中时」改成拦截才会生效。
BEGIN;

INSERT INTO security_capabilities (
    id, category, name, capability_kind, component, selector_json,
    supported_stages, allowed_actions, mask_capable, enabled, metadata_json
)
VALUES (
    'cap.dynamic.prompt_input_semantic_risk',
    'prompt_input_semantic_risk',
    '上下文语义攻击（智能分析）',
    'dynamic',
    'security-engine.semantic',
    '{"category":"prompt_input_semantic_risk"}'::jsonb,
    '["input"]'::jsonb,
    '["audit","block"]'::jsonb,
    FALSE,
    TRUE,
    '{"catalog":"semantic_context_capability","catalog_version":1}'::jsonb
)
ON CONFLICT (category) DO NOTHING;

COMMIT;
