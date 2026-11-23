-- Normalize the five shipped generic PII rules to the executable regex type.
-- Scope is intentionally limited by rule-set, stable IDs, and the legacy type
-- so tenant rules and later operator changes are never rewritten.
UPDATE rules
SET rule_type = 'regex'
WHERE rule_set_id = 'ruleset_builtin_generic'
  AND rule_type = 'pii'
  AND id IN (
    'rule_g_idcard',
    'rule_g_phone',
    'rule_g_bankcard',
    'rule_g_email',
    'rule_g_passport'
  );
