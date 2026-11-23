-- 025_pause_log.sql
-- pause_key 操作流水（持久化解封历史，配合 Redis pause:{key} 短时态）

CREATE TABLE IF NOT EXISTS pause_log (
    id VARCHAR(64) PRIMARY KEY,
    key_prefix VARCHAR(32) NOT NULL,
    tenant_id VARCHAR(64) NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    paused_by VARCHAR(64),
    paused_reason VARCHAR(512),
    paused_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    unpaused_by VARCHAR(64),
    unpaused_at TIMESTAMP WITH TIME ZONE
);

CREATE INDEX IF NOT EXISTS idx_pause_log_key ON pause_log(key_prefix);
CREATE INDEX IF NOT EXISTS idx_pause_log_tenant_paused
    ON pause_log(tenant_id, paused_at DESC);
CREATE INDEX IF NOT EXISTS idx_pause_log_active
    ON pause_log(key_prefix) WHERE unpaused_at IS NULL;

COMMENT ON COLUMN pause_log.paused_by IS 'user_id 或 system（系统自动暂停时）';
