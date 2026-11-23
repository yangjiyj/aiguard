-- 039_routing_policies.sql
-- 路由策略配置（两层：model 层 + provider 层）

CREATE TABLE IF NOT EXISTS routing_policies (
    id VARCHAR(64) PRIMARY KEY,
    tenant_id VARCHAR(64) NOT NULL REFERENCES tenants(id),
    scope_type VARCHAR(16) NOT NULL,
    scope_ref VARCHAR(64),
    layer VARCHAR(16) NOT NULL,
    strategy VARCHAR(32) NOT NULL,
    config_json JSONB NOT NULL DEFAULT '{}',
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_routing_policies_scope ON routing_policies(tenant_id, scope_type, scope_ref);
COMMENT ON COLUMN routing_policies.layer IS 'model | provider';
COMMENT ON COLUMN routing_policies.strategy IS 'single|fallback|lb|conditional|prompt_aware|canary|model_param';
