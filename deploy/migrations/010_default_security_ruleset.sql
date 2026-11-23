-- Migration 010: Default Security Ruleset
-- Ensures the private deployment bootstrap tenant has a stable default ruleset id.

INSERT INTO rule_sets (id, tenant_id, name, version, source_type, published, created_by)
SELECT
    'ruleset_default',
    'tenant_default',
    '默认安全策略',
    '1.0.0',
    'system',
    TRUE,
    'user_admin'
WHERE EXISTS (
    SELECT 1 FROM tenants WHERE id = 'tenant_default'
)
ON CONFLICT (id) DO NOTHING;
