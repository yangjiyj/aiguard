-- 收紧系统内置手机号/银行卡号边界；银行卡候选由引擎继续执行 IIN + Luhn 校验。
UPDATE rules AS rule
SET match_config_json = jsonb_set(
    COALESCE(rule.match_config_json, '{}'::jsonb),
    '{regex}',
    to_jsonb(
        CASE rule.id
            WHEN 'rule_g_phone'
                THEN $phone_regex$(?<!\d)1[3-9]\d{9}(?!\d)$phone_regex$
            WHEN 'rule_g_bankcard'
                THEN $bankcard_regex$(?<!\d)[3-6]\d{15,18}(?!\d)$bankcard_regex$
        END::text
    ),
    TRUE
)
FROM rule_sets AS rule_set
WHERE rule.rule_set_id = rule_set.id
  AND rule_set.id = 'ruleset_builtin_generic'
  AND rule_set.tenant_id = 'tenant_system'
  AND rule_set.source_type = 'builtin'
  AND rule.id IN ('rule_g_phone', 'rule_g_bankcard')
;
