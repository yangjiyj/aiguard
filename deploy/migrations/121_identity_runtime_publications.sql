-- +goose Up
-- +goose StatementBegin

-- 兼容 120 之前已试运行过身份表的环境：CREATE TABLE IF NOT EXISTS 不会为旧表补约束。
-- id 已是全局主键，新增 (tenant_id, id) 唯一约束不会改变数据，只为租户复合外键提供锚点。
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1
    FROM pg_constraint
    WHERE conname = 'uq_identity_sources_tenant_id'
      AND conrelid = 'identity_sources'::regclass
      AND contype = 'u'
  ) THEN
    ALTER TABLE identity_sources
      ADD CONSTRAINT uq_identity_sources_tenant_id UNIQUE (tenant_id, id);
  END IF;
END
$$;

-- 旧版仅约束 identity_source_id，会允许租户字段与身份源租户不一致；升级时补齐复合约束。
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1
    FROM pg_constraint
    WHERE conname = 'fk_idm_source_tenant'
      AND conrelid = 'identity_dept_mappings'::regclass
      AND contype = 'f'
  ) THEN
    ALTER TABLE identity_dept_mappings
      ADD CONSTRAINT fk_idm_source_tenant
      FOREIGN KEY (tenant_id, identity_source_id)
      REFERENCES identity_sources(tenant_id, id) ON DELETE CASCADE;
  END IF;
END
$$;

ALTER TABLE identity_sources
  ADD COLUMN IF NOT EXISTS runtime_alias varchar(64),
  ADD COLUMN IF NOT EXISTS config_digest varchar(128),
  ADD COLUMN IF NOT EXISTS applied_version integer,
  ADD COLUMN IF NOT EXISTS publish_status varchar(32) NOT NULL DEFAULT 'not_published',
  ADD COLUMN IF NOT EXISTS last_publish_error text,
  ADD COLUMN IF NOT EXISTS last_published_at timestamptz,
  ADD COLUMN IF NOT EXISTS last_runtime_checked_at timestamptz;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1
    FROM pg_constraint
    WHERE conname = 'chk_identity_sources_publish_status'
      AND conrelid = 'identity_sources'::regclass
  ) THEN
    ALTER TABLE identity_sources
      ADD CONSTRAINT chk_identity_sources_publish_status
      CHECK (publish_status IN ('not_published', 'publishing', 'active', 'error', 'drifted', 'disabled'));
  END IF;
END
$$;

CREATE TABLE IF NOT EXISTS identity_publication_events (
  id bigserial PRIMARY KEY,
  tenant_id varchar(64) NOT NULL REFERENCES tenants(id),
  identity_source_id varchar(64) NOT NULL,
  source_version integer NOT NULL CHECK (source_version > 0),
  action varchar(32) NOT NULL CHECK (action IN ('publish', 'disable', 'reconcile', 'rollback', 'status_check')),
  actor_user_id varchar(64),
  result varchar(32) NOT NULL CHECK (result IN ('started', 'succeeded', 'failed')),
  config_digest varchar(128),
  error_code varchar(64),
  created_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT fk_identity_publication_source
    FOREIGN KEY (tenant_id, identity_source_id)
    REFERENCES identity_sources(tenant_id, id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_identity_publication_events_tenant_created
  ON identity_publication_events(tenant_id, created_at DESC);

COMMENT ON COLUMN identity_sources.publish_status IS 'JJDGuard 身份配置运行态发布状态';
COMMENT ON COLUMN identity_sources.config_digest IS '已发布规范化配置摘要，不包含凭据';
COMMENT ON TABLE identity_publication_events IS 'JJDGuard 身份配置发布审计事件';

-- +goose StatementEnd
-- +goose Down
-- +goose StatementBegin

DROP TABLE IF EXISTS identity_publication_events;
ALTER TABLE identity_sources
  DROP CONSTRAINT IF EXISTS chk_identity_sources_publish_status,
  DROP COLUMN IF EXISTS last_runtime_checked_at,
  DROP COLUMN IF EXISTS last_published_at,
  DROP COLUMN IF EXISTS last_publish_error,
  DROP COLUMN IF EXISTS publish_status,
  DROP COLUMN IF EXISTS applied_version,
  DROP COLUMN IF EXISTS config_digest,
  DROP COLUMN IF EXISTS runtime_alias;

-- +goose StatementEnd
