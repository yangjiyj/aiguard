-- 013_reverse_proxy_routes.sql
-- 路径型反向代理规则

CREATE TABLE IF NOT EXISTS reverse_proxy_routes (
    id VARCHAR(32) PRIMARY KEY DEFAULT 'rpr_' || substr(gen_random_uuid()::text, 1, 8),
    tenant_id VARCHAR(32) NOT NULL DEFAULT 'tenant_default',
    name VARCHAR(128) NOT NULL,
    path_prefix VARCHAR(256) NOT NULL,
    target_url VARCHAR(512) NOT NULL,
    target_path_prefix VARCHAR(256) DEFAULT '',
    security_enabled BOOLEAN DEFAULT true,
    stats_enabled BOOLEAN DEFAULT true,
    status VARCHAR(32) NOT NULL DEFAULT 'active',
    description TEXT DEFAULT '',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_reverse_proxy_routes_tenant_path
    ON reverse_proxy_routes(tenant_id, path_prefix);

COMMENT ON TABLE reverse_proxy_routes IS '反向代理路由规则';
COMMENT ON COLUMN reverse_proxy_routes.path_prefix IS '网关接收请求的路径前缀，例如 /proxy/doubao';
COMMENT ON COLUMN reverse_proxy_routes.target_url IS '上游目标地址，例如 https://ark.cn-beijing.volces.com';
