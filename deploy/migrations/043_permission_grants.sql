-- 043_permission_grants.sql
CREATE TABLE IF NOT EXISTS permission_grants (
    id VARCHAR(64) PRIMARY KEY,
    tenant_id VARCHAR(64) NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    user_id VARCHAR(64) NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    scope_type VARCHAR(16) NOT NULL,
    scope_id VARCHAR(64) NOT NULL,
    role VARCHAR(64) NOT NULL,
    granted_by VARCHAR(64),
    granted_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    UNIQUE (user_id, scope_type, scope_id, role)
);
CREATE INDEX IF NOT EXISTS idx_grants_user ON permission_grants(user_id);
CREATE INDEX IF NOT EXISTS idx_grants_tenant ON permission_grants(tenant_id);
CREATE INDEX IF NOT EXISTS idx_grants_scope ON permission_grants(scope_type, scope_id);
COMMENT ON COLUMN permission_grants.role IS 'references system_roles.name; 8 builtin roles';
