-- Tenant-scoped detector binding overrides for shipped system policies.
-- NULL capability_categories means inherit the product binding. An explicit
-- JSON [] means this tenant intentionally clears the product binding.
ALTER TABLE builtin_rule_overrides
    ADD COLUMN IF NOT EXISTS capability_categories JSONB,
    ADD COLUMN IF NOT EXISTS binding_mode VARCHAR(8);

ALTER TABLE builtin_rule_overrides
    DROP CONSTRAINT IF EXISTS ck_builtin_rule_overrides_capability_shape;

ALTER TABLE builtin_rule_overrides
    ADD CONSTRAINT ck_builtin_rule_overrides_capability_shape
    CHECK (
        (capability_categories IS NULL AND binding_mode IS NULL)
        OR (
            capability_categories IS NOT NULL
            AND jsonb_typeof(capability_categories) = 'array'
            AND jsonb_array_length(capability_categories) <= 32
            AND binding_mode IS NOT NULL
            AND binding_mode IN ('any', 'all')
        )
    );

-- Migration 126 rejected rows with neither action nor enabled. A detector-only
-- tenant override is now meaningful, including an explicit empty JSON array.
ALTER TABLE builtin_rule_overrides
    DROP CONSTRAINT IF EXISTS ck_builtin_rule_overrides_has_value;

ALTER TABLE builtin_rule_overrides
    ADD CONSTRAINT ck_builtin_rule_overrides_has_value
    CHECK (
        action IS NOT NULL
        OR enabled IS NOT NULL
        OR capability_categories IS NOT NULL
    );

COMMENT ON COLUMN builtin_rule_overrides.capability_categories IS
    'NULL inherits product capability bindings; JSON [] explicitly clears them for this tenant';
COMMENT ON COLUMN builtin_rule_overrides.binding_mode IS
    'Tenant binding mode used whenever capability_categories is non-NULL';
