-- 100_internal_keys_name.sql
-- chat-portal 集成（G2）：internal_keys 补 name 列（员工/用途标识），审计"按人追溯"锚点。
-- 影响面：仅加列 NOT NULL DEFAULT ''。gateway-core 零影响（其 SELECT 为显式列清单，见 auth.go:276-281）；
-- expires_at 列 001 已有、数据面过期拦截已生效（auth.go:147-150），本迁移不动它。
-- 全部语句幂等，可安全重跑。

ALTER TABLE internal_keys
  ADD COLUMN IF NOT EXISTS name VARCHAR(128) NOT NULL DEFAULT '';

COMMENT ON COLUMN internal_keys.name IS 'key 名称/备注（如"张三/研发部"）；chat-portal 发放 key 时写入，审计按人追溯用';
