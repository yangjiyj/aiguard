-- Enable the bundled semantic cascade for fresh installs and untouched legacy defaults.
-- Rows changed after migration 114 are operator choices and must remain unchanged.
WITH legacy_defaults(key, old_value, new_value) AS (
    VALUES
        ('semantic_enabled', 'false', 'true'),
        ('semantic_input_enabled', 'false', 'true'),
        ('semantic_agent_enabled', 'false', 'true'),
        ('semantic_total_timeout', '6', '9')
),
migration_114 AS (
    SELECT applied_at
    FROM schema_migrations
    WHERE version = '114_semantic_runtime_defaults.sql'
)
UPDATE system_settings AS s
SET value = d.new_value,
    updated_at = NOW()
FROM legacy_defaults AS d
CROSS JOIN migration_114 AS m
WHERE s.key = d.key
  AND s.value = d.old_value
  AND s.updated_at <= m.applied_at;

INSERT INTO system_settings (key, value, updated_at)
VALUES
    ('semantic_enabled', 'true', NOW()),
    ('semantic_input_enabled', 'true', NOW()),
    ('semantic_agent_enabled', 'true', NOW()),
    ('semantic_output_enabled', 'false', NOW()),
    ('security_audit_only', 'true', NOW()),
    ('semantic_total_timeout', '9', NOW()),
    ('judge_backend', 'bundled', NOW()),
    ('judge_timeout', '8', NOW()),
    ('tier1_enabled', 'true', NOW()),
    ('tier1_low_threshold', '0.30', NOW()),
    ('tier1_high_threshold', '0.70', NOW())
ON CONFLICT (key) DO NOTHING;
