-- 023_alert_inbox.sql
-- 系统内消息中心，私有化默认通道（不依赖公网）。

CREATE TABLE IF NOT EXISTS alert_inbox (
    id VARCHAR(64) PRIMARY KEY,
    tenant_id VARCHAR(64) NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    severity VARCHAR(16) NOT NULL,
    type VARCHAR(64) NOT NULL,
    title VARCHAR(256) NOT NULL,
    body_json JSONB NOT NULL,
    target_url VARCHAR(512),
    read_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_alert_inbox_tenant_unread
    ON alert_inbox(tenant_id, created_at DESC) WHERE read_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_alert_inbox_tenant_created
    ON alert_inbox(tenant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_alert_inbox_type ON alert_inbox(type);

COMMENT ON COLUMN alert_inbox.severity IS 'info | warning | high | critical';
