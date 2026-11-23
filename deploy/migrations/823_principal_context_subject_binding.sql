BEGIN;

ALTER TABLE request_logs
    ADD COLUMN IF NOT EXISTS actor_user_id VARCHAR(64),
    ADD COLUMN IF NOT EXISTS principal_context_json JSONB;

CREATE INDEX IF NOT EXISTS idx_request_logs_tenant_actor_created
    ON request_logs(tenant_id, actor_user_id, created_at DESC)
    WHERE actor_user_id IS NOT NULL;

COMMENT ON COLUMN request_logs.actor_user_id IS
    '可信本次操作者；不得由 internal_keys.user_id 或客户端身份头推断';
COMMENT ON COLUMN request_logs.principal_context_json IS
    '服务端构造的版本化 PrincipalContext；不包含密钥或凭据';

COMMIT;
