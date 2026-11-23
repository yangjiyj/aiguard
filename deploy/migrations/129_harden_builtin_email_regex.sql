-- Eliminate rule_g_email backtracking on large agent contexts. RFC length
-- bounds limit invalid candidates; atomic groups are supported by the Python
-- regex runtime and prevent candidate-internal backtracking.
UPDATE rules AS rule
SET match_config_json = jsonb_set(
    COALESCE(rule.match_config_json, '{}'::jsonb),
    '{regex}',
    to_jsonb('(?<=(?P<email_local>(?a:\b)(?>[A-Za-z0-9._%+-]{1,64})))@(?:(?>[A-Za-z0-9-]{1,63})\.)+(?>[A-Za-z]{2,63})(?a:\b)'::text),
    TRUE
)
FROM rule_sets AS rule_set
WHERE rule.rule_set_id = rule_set.id
  AND rule_set.id = 'ruleset_builtin_generic'
  AND rule_set.tenant_id = 'tenant_system'
  AND rule_set.source_type = 'builtin'
  AND rule.id = 'rule_g_email';
