-- 012_proxy_usage_logs.sql
-- 正向代理流量统计

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

CREATE INDEX IF NOT EXISTS idx_proxy_whitelist_tenant
    ON proxy_whitelist(tenant_id);
CREATE INDEX IF NOT EXISTS idx_proxy_whitelist_host
    ON proxy_whitelist(host_pattern);
CREATE UNIQUE INDEX IF NOT EXISTS idx_proxy_whitelist_tenant_host_port
    ON proxy_whitelist(tenant_id, host_pattern, port);

COMMENT ON TABLE proxy_whitelist IS '正向代理历史域名策略表，当前不参与访问放行判定';
COMMENT ON COLUMN proxy_whitelist.host_pattern IS '历史域名模式，保留用于兼容旧版本配置';

CREATE TABLE IF NOT EXISTS proxy_usage_logs (
    id BIGSERIAL PRIMARY KEY,
    tenant_id VARCHAR(32) NOT NULL DEFAULT 'tenant_default',
    host VARCHAR(256) NOT NULL,
    port INT NOT NULL DEFAULT 443,
    bytes_sent BIGINT DEFAULT 0,
    bytes_received BIGINT DEFAULT 0,
    started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    ended_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_proxy_usage_logs_tenant_host
    ON proxy_usage_logs(tenant_id, host);
CREATE INDEX IF NOT EXISTS idx_proxy_usage_logs_started_at
    ON proxy_usage_logs(started_at);

COMMENT ON TABLE proxy_usage_logs IS '正向代理流量日志';
COMMENT ON COLUMN proxy_usage_logs.bytes_sent IS '客户端发送到目标的字节数';
COMMENT ON COLUMN proxy_usage_logs.bytes_received IS '目标返回给客户端的字节数';

-- 正向代理当前采用公网全域放行策略，不再插入默认域名策略。
