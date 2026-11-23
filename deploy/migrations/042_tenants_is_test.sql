-- 042_tenants_is_test.sql
-- +goose Up
ALTER TABLE tenants ADD COLUMN IF NOT EXISTS is_test BOOLEAN NOT NULL DEFAULT FALSE;
CREATE INDEX IF NOT EXISTS idx_tenants_is_test ON tenants(is_test) WHERE is_test = TRUE;
COMMENT ON COLUMN tenants.is_test IS 'E2E 测试租户标记，看板默认过滤';

-- +goose Down
DROP INDEX IF EXISTS idx_tenants_is_test;
ALTER TABLE tenants DROP COLUMN IF EXISTS is_test;
