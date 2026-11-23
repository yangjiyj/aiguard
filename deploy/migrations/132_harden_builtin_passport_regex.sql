-- 收紧护照号规则：仅识别大写前缀，避免小写内部标识符误报。
UPDATE rules AS rule
SET match_config_json = jsonb_set(COALESCE(rule.match_config_json, '{}'::jsonb), '{regex}', to_jsonb('(?<![A-Za-z0-9])[EGPSDK]\\d{8}(?![A-Za-z0-9])'::text), TRUE)
FROM rule_sets AS rule_set
WHERE rule.rule_set_id = rule_set.id
  AND rule_set.id = 'ruleset_builtin_generic'
  AND rule_set.tenant_id = 'tenant_system'
  AND rule_set.source_type = 'builtin'
  AND rule.id = 'rule_g_passport';
