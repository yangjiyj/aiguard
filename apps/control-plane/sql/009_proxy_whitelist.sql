-- Migration 009: Legacy Forward Proxy Policy
-- Create legacy proxy_whitelist table for compatibility with older deployments

CREATE TABLE IF NOT EXISTS proxy_whitelist (
    id VARCHAR(32) PRIMARY KEY DEFAULT 'pw_' || substr(gen_random_uuid()::text, 1, 8),
    tenant_id VARCHAR(32) NOT NULL,
    host_pattern VARCHAR(256) NOT NULL,
    port INT DEFAULT 443,
    audit_enabled BOOLEAN DEFAULT true,
    description TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_proxy_whitelist_tenant ON proxy_whitelist(tenant_id);
CREATE INDEX IF NOT EXISTS idx_proxy_whitelist_host ON proxy_whitelist(host_pattern);
CREATE UNIQUE INDEX IF NOT EXISTS idx_proxy_whitelist_tenant_host_port ON proxy_whitelist(tenant_id, host_pattern, port);

COMMENT ON TABLE proxy_whitelist IS '正向代理历史域名策略表，当前不参与访问放行判定';
COMMENT ON COLUMN proxy_whitelist.host_pattern IS '历史域名模式，保留用于兼容旧版本配置';

-- 正向代理当前采用公网全域放行策略，不再插入默认域名策略。
