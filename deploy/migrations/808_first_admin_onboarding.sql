-- +goose Up
-- +goose StatementBegin
-- Fresh-install onboarding is armed explicitly by the installer. Merely running
-- this migration during an upgrade never expands a customer's authorization.

ALTER TABLE teams
  ADD COLUMN IF NOT EXISTS model_access_mode VARCHAR(16) NOT NULL DEFAULT 'allowlist';

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conname = 'ck_teams_model_access_mode'
      AND conrelid = 'teams'::regclass
  ) THEN
    ALTER TABLE teams ADD CONSTRAINT ck_teams_model_access_mode
      CHECK (model_access_mode IN ('deny_all', 'allowlist', 'all_active'));
  END IF;
END
$$;

CREATE UNIQUE INDEX IF NOT EXISTS uq_teams_system_key
  ON teams(tenant_id, system_key)
  WHERE system_key IS NOT NULL;

ALTER TABLE projects
  ADD COLUMN IF NOT EXISTS system_key VARCHAR(64);

CREATE UNIQUE INDEX IF NOT EXISTS uq_projects_system_key
  ON projects(tenant_id, system_key)
  WHERE system_key IS NOT NULL;

CREATE TABLE IF NOT EXISTS tenant_identity_defaults (
  tenant_id VARCHAR(64) PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
  default_department_id VARCHAR(64) NOT NULL,
  fallback_source_types VARCHAR(16)[] NOT NULL DEFAULT ARRAY['oidc','ldap','ad']::VARCHAR(16)[],
  enabled BOOLEAN NOT NULL DEFAULT TRUE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT fk_tenant_identity_default_department
    FOREIGN KEY (tenant_id, default_department_id)
    REFERENCES teams(tenant_id, id) ON DELETE RESTRICT,
  CONSTRAINT ck_tenant_identity_default_sources CHECK (
    fallback_source_types <@ ARRAY['oidc','ldap','ad']::VARCHAR(16)[]
    AND cardinality(fallback_source_types) > 0
  )
);

CREATE TABLE IF NOT EXISTS deployment_initializations (
  tenant_id VARCHAR(64) NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  initialization_key VARCHAR(64) NOT NULL,
  status VARCHAR(16) NOT NULL DEFAULT 'pending',
  fresh_install BOOLEAN NOT NULL DEFAULT TRUE,
  attempt_count INTEGER NOT NULL DEFAULT 0,
  requested_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  started_at TIMESTAMPTZ,
  completed_at TIMESTAMPTZ,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  actor_user_id VARCHAR(64),
  last_error_code VARCHAR(64) NOT NULL DEFAULT '',
  last_error_at TIMESTAMPTZ,
  details_json JSONB NOT NULL DEFAULT '{}'::JSONB,
  PRIMARY KEY (tenant_id, initialization_key),
  CONSTRAINT ck_deployment_initialization_status
    CHECK (status IN ('pending', 'running', 'completed', 'failed')),
  CONSTRAINT ck_deployment_initialization_attempts CHECK (attempt_count >= 0)
);

CREATE INDEX IF NOT EXISTS idx_deployment_initializations_status
  ON deployment_initializations(status, updated_at);

COMMENT ON TABLE deployment_initializations IS
  'Installer-armed, login-triggered idempotent initialization; upgrades do not seed rows';
COMMENT ON TABLE tenant_identity_defaults IS
  'Fallback department for unmapped OIDC/LDAP/AD employees; conflicts remain fail-closed';
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS deployment_initializations;
DROP TABLE IF EXISTS tenant_identity_defaults;
DROP INDEX IF EXISTS uq_projects_system_key;
ALTER TABLE projects DROP COLUMN IF EXISTS system_key;
DROP INDEX IF EXISTS uq_teams_system_key;
ALTER TABLE teams
  DROP CONSTRAINT IF EXISTS ck_teams_model_access_mode,
  DROP COLUMN IF EXISTS model_access_mode;
-- +goose StatementEnd
