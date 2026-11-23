-- W9 9.2：多身份源并存。
--
-- 之前每租户只能有一个身份源（运行态 alias 固定为 enterprise），库里的多行记录是
-- 同一身份源的不同版本（active 当前版 + draft/tested 下一版）。现在以运行态 alias
-- 作为"身份源"的稳定标识，版本语义不变、按 alias 分组：
--   * 历史/默认身份源沿用 alias 'enterprise'（已登记的回调地址与门户 kc_idp_hint 不变）；
--   * 新增身份源使用服务端派生的 'jjd-<source id>'，发布到独立的运行态对象，互不覆盖。
-- 约束从"每租户一条 active / 一条待发布"改为"每租户每 alias 一条 active / 一条待发布"。
BEGIN;

-- 既有记录全部属于历史默认身份源。
UPDATE identity_sources
SET runtime_alias = 'enterprise'
WHERE runtime_alias IS NULL OR btrim(runtime_alias) = '';

ALTER TABLE identity_sources
  ALTER COLUMN runtime_alias SET DEFAULT 'enterprise',
  ALTER COLUMN runtime_alias SET NOT NULL;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'chk_identity_sources_runtime_alias'
  ) THEN
    ALTER TABLE identity_sources
      ADD CONSTRAINT chk_identity_sources_runtime_alias
      CHECK (runtime_alias = 'enterprise' OR runtime_alias ~ '^jjd-[a-z0-9_-]{1,56}$');
  END IF;
END
$$;

CREATE UNIQUE INDEX IF NOT EXISTS uq_identity_sources_active_per_alias
  ON identity_sources(tenant_id, runtime_alias) WHERE status = 'active';
CREATE UNIQUE INDEX IF NOT EXISTS uq_identity_sources_pending_per_alias
  ON identity_sources(tenant_id, runtime_alias) WHERE status IN ('draft', 'tested');

DROP INDEX IF EXISTS uq_identity_sources_active_per_tenant;
DROP INDEX IF EXISTS uq_identity_sources_pending_per_tenant;

COMMENT ON COLUMN identity_sources.runtime_alias IS
  'W9 9.2 身份源稳定标识（运行态 alias）；enterprise 为历史默认，其余为 jjd-<id>，同 alias 的多行是同一身份源的不同版本';

COMMIT;
