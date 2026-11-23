-- +goose Up
-- +goose StatementBegin

-- ============================================================
-- Private Deployment Migration
-- Adds features required for private/enterprise deployment mode
-- ============================================================

-- 1. users 表增加 phone 列
ALTER TABLE users ADD COLUMN IF NOT EXISTS phone VARCHAR(32);

-- 2. 创建默认租户（如果不存在）
INSERT INTO tenants (id, name, edition, status, config_json)
SELECT 'tenant_default', '默认单位', 'enterprise', 'active', '{}'
WHERE NOT EXISTS (SELECT 1 FROM tenants WHERE id = 'tenant_default');

-- 3. 创建默认应用（如果不存在）
INSERT INTO projects (id, tenant_id, name, code, environment, owner_user_id, status)
SELECT 'project_default', 'tenant_default', '默认应用', 'private', 'production', 'user_admin', 'active'
WHERE NOT EXISTS (SELECT 1 FROM projects WHERE id = 'project_default');

-- 4. 审计操作表
CREATE TABLE IF NOT EXISTS audit_operations (
    id VARCHAR(64) PRIMARY KEY,
    user_id VARCHAR(64) NOT NULL REFERENCES users(id),
    action_type VARCHAR(64) NOT NULL,
    action_detail JSONB DEFAULT '{}',
    target_type VARCHAR(64),
    target_id VARCHAR(64),
    ip_address VARCHAR(64),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_audit_ops_user ON audit_operations(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_ops_type ON audit_operations(action_type);
CREATE INDEX IF NOT EXISTS idx_audit_ops_created ON audit_operations(created_at);

-- 5. 项目-用户多对多关联表
CREATE TABLE IF NOT EXISTS project_users (
    project_id VARCHAR(64) NOT NULL REFERENCES projects(id),
    user_id VARCHAR(64) NOT NULL REFERENCES users(id),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    PRIMARY KEY (project_id, user_id)
);

-- 6. 系统设置表
CREATE TABLE IF NOT EXISTS system_settings (
    key VARCHAR(128) PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- 插入默认系统设置
INSERT INTO system_settings (key, value) VALUES
    ('session_ttl', '24h'),
    ('log_retention_days', '90'),
    ('system_name', 'AI算力安全网关'),
    ('allow_registration', 'false')
ON CONFLICT (key) DO NOTHING;

-- 7. 升级历史表
CREATE TABLE IF NOT EXISTS upgrade_history (
    id VARCHAR(64) PRIMARY KEY,
    version_from VARCHAR(32),
    version_to VARCHAR(32),
    status VARCHAR(32) NOT NULL DEFAULT 'pending',
    backup_path VARCHAR(512),
    release_notes TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    completed_at TIMESTAMP WITH TIME ZONE
);

-- Note: Down migrations are not executed in Docker entrypoint
-- They are only used by goose migration tool for rollback
