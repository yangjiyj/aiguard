-- Migration 009: Tool Risk Config Table
-- Stores tenant-scoped tool risk policies used by Skills/MCP audit and blocking.

CREATE TABLE IF NOT EXISTS tool_risk_config (
    id VARCHAR(64) PRIMARY KEY,
    tenant_id VARCHAR(64) NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    tool_name VARCHAR(128) NOT NULL,
    tool_type VARCHAR(32) NOT NULL,
    risk_level VARCHAR(16) NOT NULL DEFAULT 'medium',
    action VARCHAR(16) NOT NULL DEFAULT 'audit',
    description TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    UNIQUE (tenant_id, tool_name)
);

CREATE INDEX IF NOT EXISTS idx_tool_risk_config_tenant ON tool_risk_config(tenant_id);
CREATE INDEX IF NOT EXISTS idx_tool_risk_config_tool_type ON tool_risk_config(tool_type);
CREATE INDEX IF NOT EXISTS idx_tool_risk_config_risk_level ON tool_risk_config(risk_level);
