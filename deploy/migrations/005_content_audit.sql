-- Migration 003: Content Audit Log
-- Creates content_logs table and adds content_audit_enabled setting

-- 1. 新增 content_logs 表
CREATE TABLE IF NOT EXISTS content_logs (
    id VARCHAR(64) PRIMARY KEY DEFAULT 'cl_' || substr(gen_random_uuid()::text, 1, 12),
    request_id VARCHAR(64) NOT NULL REFERENCES request_logs(id) ON DELETE CASCADE,
    tenant_id VARCHAR(64) NOT NULL,
    user_id VARCHAR(64),
    session_id VARCHAR(64),
    role VARCHAR(16) NOT NULL,  -- user, assistant, system
    content TEXT NOT NULL,
    tokens INT DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_content_logs_tenant ON content_logs(tenant_id);
CREATE INDEX IF NOT EXISTS idx_content_logs_user ON content_logs(user_id);
CREATE INDEX IF NOT EXISTS idx_content_logs_session ON content_logs(session_id);
CREATE INDEX IF NOT EXISTS idx_content_logs_created ON content_logs(created_at DESC);

-- 2. 系统设置新增 content_audit_enabled
INSERT INTO system_settings (key, value)
VALUES ('content_audit_enabled', 'false')
ON CONFLICT (key) DO NOTHING;

COMMENT ON TABLE content_logs IS '内容审计日志，记录 AI 对话的完整 prompt 和 response';
COMMENT ON COLUMN content_logs.role IS '消息角色：user(用户输入)、assistant(AI响应)、system(系统提示)';