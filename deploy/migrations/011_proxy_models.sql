-- 011_proxy_models.sql
-- 免 Token 代理模型功能：数据库迁移

-- 1. models 表新增 proxy_config 字段
ALTER TABLE models ADD COLUMN IF NOT EXISTS proxy_config jsonb DEFAULT '{}'::jsonb;
COMMENT ON COLUMN models.proxy_config IS '代理访问配置: {enabled, auth_mode, ip_allowlist, origin_allowlist, rpm_per_ip, rpm_global, daily_cap}';

-- 2. 代理访问密钥表（可选轻量级密钥）
CREATE TABLE IF NOT EXISTS proxy_access_keys (
    id varchar(64) PRIMARY KEY,
    tenant_id varchar(64) NOT NULL REFERENCES tenants(id),
    proxy_key_hash varchar(128) NOT NULL,
    proxy_key_prefix varchar(8) NOT NULL,
    model_ids jsonb DEFAULT '[]'::jsonb,
    rpm_limit int DEFAULT 60,
    daily_cap int DEFAULT 1000,
    expires_at timestamptz,
    last_used_at timestamptz,
    status varchar(32) NOT NULL DEFAULT 'active',
    created_at timestamptz DEFAULT now(),
    UNIQUE (proxy_key_hash)
);
COMMENT ON TABLE proxy_access_keys IS '代理访问密钥：轻量级密钥用于代理模型访问';
COMMENT ON COLUMN proxy_access_keys.model_ids IS '允许访问的模型 ID 列表，空数组表示允许所有启用了代理的模型';

-- 3. 代理每日用量统计（用于硬上限检查）
CREATE TABLE IF NOT EXISTS proxy_usage_daily (
    date date NOT NULL,
    model_id varchar(64) NOT NULL REFERENCES models(id),
    request_count bigint DEFAULT 0,
    input_tokens bigint DEFAULT 0,
    output_tokens bigint DEFAULT 0,
    PRIMARY KEY (date, model_id)
);
COMMENT ON TABLE proxy_usage_daily IS '代理模型每日用量统计：用于硬上限检查和监控';
