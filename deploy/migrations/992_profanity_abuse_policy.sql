-- 内置“辱骂脏话”检测能力（content_profanity_abuse）。
--
-- 1) 登记能力：content_profanity_abuse（新词表检测）与 harassment_profanity_cn
--    （旧的“操你妈”强辱骂组合规则，此前没有登记，无法被策略接管）。
--    两者支持 input/output，动作 audit/block，不支持 mask。
-- 2) 存量租户：给每个已采用内置策略目录的规则集补一条“辱骂脏话”策略，动作固定为 audit。
--    升级不得让客户突然被拦截；客户在策略中心自行改成 block。
--    新租户走 control-plane 的默认策略目录（rules.go），动作与同类内容安全一致（block）。
-- 3) 已存在同 policy_code 的行不动（幂等；客户改过动作、删过绑定都不被覆盖或恢复）。
--
-- 下面两个 JSON 块同时被仓库契约测试读取（policy_capability_catalog_test.go），
-- 必须与 policy_capability_catalog.go 的 exactPolicyCapabilityBindings 保持一致。
BEGIN;

WITH capability_seed AS (
    SELECT *
    FROM jsonb_to_recordset(
$added_policy_capabilities$
[
  {"category":"content_profanity_abuse","name":"辱骂脏话","component":"security-engine.content-safety","supported_stages":["input","output"],"allowed_actions":["audit","block"],"mask_capable":false},
  {"category":"harassment_profanity_cn","name":"中文强辱骂组合","component":"security-engine.content-safety","supported_stages":["input","output"],"allowed_actions":["audit","block"],"mask_capable":false}
]
$added_policy_capabilities$::jsonb
    ) AS x(
        category TEXT,
        name TEXT,
        component TEXT,
        supported_stages JSONB,
        allowed_actions JSONB,
        mask_capable BOOLEAN
    )
)
INSERT INTO security_capabilities (
    id, category, name, capability_kind, component, selector_json,
    supported_stages, allowed_actions, mask_capable, enabled, metadata_json
)
SELECT
    'cap.static.' || category,
    category,
    name,
    'static',
    component,
    jsonb_build_object('category', category),
    supported_stages,
    allowed_actions,
    mask_capable,
    TRUE,
    '{"catalog":"content_profanity","catalog_version":1}'::jsonb
FROM capability_seed
ON CONFLICT (category) DO NOTHING;

-- 存量租户：只补缺失的，且一律 audit。插入与绑定在同一条语句里，只给本次新插入的行绑能力，
-- 不会替客户恢复他们删除过的绑定。
WITH policy_seed AS (
    SELECT *
    FROM jsonb_to_recordset(
$added_exact_policy_capability_bindings$
[
  {
    "policy_code": "builtin.content_safety.ffbbdfb2e823022d",
    "rule_type": "content_safety",
    "name": "辱骂脏话",
    "capability_categories": ["content_profanity_abuse", "harassment_profanity_cn"],
    "binding_mode": "any"
  }
]
$added_exact_policy_capability_bindings$::jsonb
    ) AS x(
        policy_code TEXT,
        rule_type TEXT,
        name TEXT,
        capability_categories JSONB,
        binding_mode TEXT
    )
),
inserted AS (
    INSERT INTO rules (
        id, rule_set_id, policy_code, rule_type, name, priority, severity,
        scope_json, action, enabled, description
    )
    SELECT
        'rule_' || gen_random_uuid()::text,
        rs.id,
        seed.policy_code,
        seed.rule_type,
        seed.name,
        0,
        'medium',
        '{"catalog":"default_policy","catalog_version":1}'::jsonb,
        'audit',
        TRUE,
        '检测对人的辱骂、脏话与侮辱性称呼，覆盖谐音、拼音缩写、字间空格等变形；废物利用、垃圾分类等正常用语不会命中，引用或讨论某个脏话词不拦'
    FROM rule_sets rs
    CROSS JOIN policy_seed seed
    WHERE EXISTS (
            SELECT 1 FROM rules adopted
            WHERE adopted.rule_set_id = rs.id AND adopted.policy_code LIKE 'builtin.%'
        )
      AND NOT EXISTS (
            SELECT 1 FROM rules present
            WHERE present.rule_set_id = rs.id AND present.policy_code = seed.policy_code
        )
    RETURNING id, policy_code
)
INSERT INTO rule_capability_bindings (rule_id, capability_id, binding_mode, priority, config_json)
SELECT inserted.id, capability.id, seed.binding_mode, 0, '{}'::jsonb
FROM inserted
JOIN policy_seed seed ON seed.policy_code = inserted.policy_code
CROSS JOIN LATERAL jsonb_array_elements_text(seed.capability_categories) category(value)
JOIN security_capabilities capability ON capability.category = category.value
ON CONFLICT (rule_id, capability_id) DO NOTHING;

COMMIT;
