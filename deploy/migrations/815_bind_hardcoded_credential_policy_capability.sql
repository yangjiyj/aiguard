-- Add the audited exact detector binding without modifying frozen migration 125.
-- code_leak_password_in_code supports audit/block and is intentionally not mask-capable.
WITH added_bindings AS (
    SELECT *
    FROM jsonb_to_recordset(
$added_exact_policy_capability_bindings$
[
  {
    "policy_code": "builtin.code_security.9640acf0d1083905",
    "rule_type": "code_security",
    "name": "硬编码凭据示例",
    "capability_categories": ["code_leak_password_in_code"],
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
expanded AS (
    SELECT
        binding.policy_code,
        binding.binding_mode,
        category.value #>> '{}' AS category
    FROM added_bindings binding
    CROSS JOIN LATERAL jsonb_array_elements(binding.capability_categories) category(value)
)
INSERT INTO rule_capability_bindings(
    rule_id, capability_id, binding_mode, priority, config_json
)
SELECT
    policy.id,
    capability.id,
    expanded.binding_mode,
    0,
    '{}'::jsonb
FROM expanded
JOIN rules policy ON policy.policy_code = expanded.policy_code
JOIN security_capabilities capability ON capability.category = expanded.category
WHERE capability.allowed_actions @> '["block"]'::jsonb
  AND NOT capability.mask_capable
ON CONFLICT(rule_id, capability_id) DO NOTHING;
