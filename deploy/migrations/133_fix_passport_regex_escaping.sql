-- 修正迁移 132 的反斜杠转义：数据库中必须保存单个 \d 正则转义。
UPDATE rules AS rule
SET match_config_json = jsonb_set(
    COALESCE(rule.match_config_json, '{}'::jsonb),
    '{regex}',
    to_jsonb($passport_regex$(?<![A-Za-z0-9])[EGPSDK]\d{8}(?![A-Za-z0-9])$passport_regex$::text),
    TRUE
)
FROM rule_sets AS rule_set
WHERE rule.rule_set_id = rule_set.id
  AND rule_set.id = 'ruleset_builtin_generic'
  AND rule_set.tenant_id = 'tenant_system'
  AND rule_set.source_type = 'builtin'
  AND rule.id = 'rule_g_passport';
