-- Migration 004: Tool Call Audit Log
-- Creates tool_call_logs table for tracking Skills/MCP tool invocations

-- 1. Create tool_call_logs table
CREATE TABLE IF NOT EXISTS tool_call_logs (
    id VARCHAR(64) PRIMARY KEY DEFAULT 'tc_' || substr(gen_random_uuid()::text, 1, 12),
    request_id VARCHAR(64) NOT NULL,
    session_id VARCHAR(64),
    tenant_id VARCHAR(64) NOT NULL,
    user_id VARCHAR(64),
    tool_name VARCHAR(128) NOT NULL,
    tool_type VARCHAR(32) NOT NULL,  -- file, network, database, mcp, system
    risk_level VARCHAR(16) NOT NULL DEFAULT 'low',  -- low, medium, high, critical
    parameters JSONB DEFAULT '{}',
    result TEXT,
    status VARCHAR(16) NOT NULL DEFAULT 'success',  -- success, failed, blocked
    matched_policy_id VARCHAR(64),
    matched_policy_name VARCHAR(255),
    matched_action VARCHAR(32),
    match_reason TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 2. Add indexes for efficient querying
CREATE INDEX IF NOT EXISTS idx_tool_call_logs_session ON tool_call_logs(session_id);
CREATE INDEX IF NOT EXISTS idx_tool_call_logs_risk ON tool_call_logs(risk_level);
CREATE INDEX IF NOT EXISTS idx_tool_call_logs_type ON tool_call_logs(tool_type);
CREATE INDEX IF NOT EXISTS idx_tool_call_logs_created ON tool_call_logs(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_tool_call_logs_tenant ON tool_call_logs(tenant_id);
CREATE INDEX IF NOT EXISTS idx_tool_call_logs_user ON tool_call_logs(user_id);

-- 3. Add system setting for tool_audit_enabled
INSERT INTO system_settings (key, value)
VALUES ('tool_audit_enabled', 'false')
ON CONFLICT (key) DO NOTHING;

COMMENT ON TABLE tool_call_logs IS '工具调用审计日志，记录 Agent 的 Skills/MCP 工具调用行为';
COMMENT ON COLUMN tool_call_logs.tool_type IS '工具类型：file(文件操作)、network(网络请求)、database(数据库操作)、mcp(MCP调用)、system(系统命令)';
COMMENT ON COLUMN tool_call_logs.risk_level IS '风险级别：low(低风险)、medium(中等)、high(高危)、critical(极高危)';
COMMENT ON COLUMN tool_call_logs.status IS '执行状态：success(成功)、failed(失败)、blocked(被阻止)';
