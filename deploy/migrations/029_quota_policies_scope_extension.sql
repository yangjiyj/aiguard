-- 029_quota_policies_scope_extension.sql
-- quota_policies.scope_type 扩展：tenant | team | project | user | key
-- 现有 project_id 字段保留，scope_ref 用于 team_id；新增 user_id 和 key_prefix

ALTER TABLE quota_policies
    ADD COLUMN IF NOT EXISTS user_id VARCHAR(64) REFERENCES users(id) ON DELETE CASCADE;
ALTER TABLE quota_policies
    ADD COLUMN IF NOT EXISTS key_prefix VARCHAR(32);

CREATE INDEX IF NOT EXISTS idx_quota_policies_user ON quota_policies(user_id)
    WHERE user_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_quota_policies_key ON quota_policies(key_prefix)
    WHERE key_prefix IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_quota_policies_scope ON quota_policies(tenant_id, scope_type);

COMMENT ON COLUMN quota_policies.scope_type IS
    'tenant | team | project | user | key';
COMMENT ON COLUMN quota_policies.scope_ref IS
    'team scope 用 team_id；其他 scope 配合 project_id / user_id / key_prefix 字段';
COMMENT ON COLUMN quota_policies.user_id IS 'user scope 时填，其他 scope 为 NULL';
COMMENT ON COLUMN quota_policies.key_prefix IS 'key scope 时填，其他 scope 为 NULL';
