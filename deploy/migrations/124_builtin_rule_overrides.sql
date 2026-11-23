-- Tenant-scoped action overrides for executable system industry rules.
-- Additive and rollback-safe: dropping this table restores built-in defaults.
CREATE TABLE IF NOT EXISTS builtin_rule_overrides (
    tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    rule_id TEXT NOT NULL REFERENCES rules(id) ON DELETE CASCADE,
    action TEXT NOT NULL CHECK (action IN ('audit', 'mask', 'block')),
    enabled BOOLEAN,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, rule_id)
);

CREATE INDEX IF NOT EXISTS idx_builtin_rule_overrides_rule
    ON builtin_rule_overrides(rule_id);
