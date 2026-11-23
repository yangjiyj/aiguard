-- Keep the five shipped generic PII matchers in the data-leak scene. Migration
-- 113 changed their runtime type to regex; without an explicit scene both the
-- policy center and fixed-reply routing would incorrectly fall back to regex /
-- custom policy.
UPDATE rules AS rule
SET scope_json = jsonb_set(
    COALESCE(rule.scope_json, '{}'::jsonb),
    '{scene}',
    '"data_leak"'::jsonb,
    TRUE
)
FROM rule_sets AS rule_set
WHERE rule.rule_set_id = rule_set.id
  AND rule_set.id = 'ruleset_builtin_generic'
  AND rule_set.tenant_id = 'tenant_system'
  AND rule_set.source_type = 'builtin'
  AND rule.id IN (
    'rule_g_idcard',
    'rule_g_phone',
    'rule_g_bankcard',
    'rule_g_email',
    'rule_g_passport'
  );
