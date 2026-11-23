-- Migration 008: Tool Sandbox
-- Create tool_risk_config table for tool call risk management

-- 1. Create tool_risk_config table
CREATE TABLE IF NOT EXISTS tool_risk_config (
    id VARCHAR(32) PRIMARY KEY DEFAULT 'tr_' || substr(gen_random_uuid()::text, 1, 8),
    tenant_id VARCHAR(32) NOT NULL,
    tool_name VARCHAR(128) NOT NULL,
    tool_type VARCHAR(32) NOT NULL,
    risk_level VARCHAR(16) DEFAULT 'medium',
    action VARCHAR(16) DEFAULT 'audit',
    description TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 2. Create indexes
CREATE INDEX IF NOT EXISTS idx_tool_risk_config_tenant ON tool_risk_config(tenant_id);
CREATE INDEX IF NOT EXISTS idx_tool_risk_config_tool ON tool_risk_config(tool_name);
CREATE UNIQUE INDEX IF NOT EXISTS idx_tool_risk_config_tenant_tool ON tool_risk_config(tenant_id, tool_name);

-- 3. Comments
COMMENT ON TABLE tool_risk_config IS '工具调用风险分级配置';
COMMENT ON COLUMN tool_risk_config.risk_level IS '风险级别: low, medium, high, critical';
COMMENT ON COLUMN tool_risk_config.action IS '处理动作: allow, audit, block';
COMMENT ON COLUMN tool_risk_config.tool_type IS '工具类型: file, network, database, mcp, system';

-- 4. System settings for default action
INSERT INTO system_settings (key, value)
VALUES ('proxy_default_action', 'audit')
ON CONFLICT (key) DO NOTHING;