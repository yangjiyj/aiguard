-- 024_notify_channels.sql
-- 告警通道插件化配置。type: email | webhook | dingtalk | wecom | feishu

CREATE TABLE IF NOT EXISTS notify_channels (
    id VARCHAR(64) PRIMARY KEY,
    tenant_id VARCHAR(64) NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    type VARCHAR(32) NOT NULL,
    name VARCHAR(128) NOT NULL,
    config_json JSONB NOT NULL,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_notify_channels_tenant ON notify_channels(tenant_id);
CREATE INDEX IF NOT EXISTS idx_notify_channels_type ON notify_channels(type);

COMMENT ON COLUMN notify_channels.config_json IS
    '通道配置：email {host,port,username,password,from,to[]}；webhook {url,method,headers}；dingtalk {access_token,secret}';
