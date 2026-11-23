-- +goose Up
-- +goose StatementBegin

-- Operational prerequisite: run this migration in a maintenance window.
-- Pause IAM writes before migration, backup the database, and verify users and team_members counts before and after.
-- The projection convergence and unique index creation take locks; this is not an online, lock-free migration.

-- Enterprise identity uses users.department_id as the single department authority.
-- team_members remains a one-row compatibility projection for existing readers.
ALTER TABLE teams
  ADD COLUMN IF NOT EXISTS is_system boolean NOT NULL DEFAULT false,
  ADD COLUMN IF NOT EXISTS system_key varchar(64);

CREATE UNIQUE INDEX IF NOT EXISTS uq_teams_unassigned_per_tenant
  ON teams(tenant_id, system_key)
  WHERE system_key = 'unassigned';

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conname = 'uq_teams_tenant_id'
      AND conrelid = 'teams'::regclass
  ) THEN
    ALTER TABLE teams
      ADD CONSTRAINT uq_teams_tenant_id UNIQUE (tenant_id, id);
  END IF;
END
$$;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conname = 'uq_users_tenant_id'
      AND conrelid = 'users'::regclass
  ) THEN
    ALTER TABLE users
      ADD CONSTRAINT uq_users_tenant_id UNIQUE (tenant_id, id);
  END IF;
END
$$;

DO $$
BEGIN
  IF EXISTS (
    SELECT 1
    FROM teams
    WHERE name = '未分配部门'
      AND system_key IS DISTINCT FROM 'unassigned'
  ) THEN
    RAISE EXCEPTION 'ordinary department named 未分配部门 exists; rename it before migration';
  END IF;
END
$$;

-- The system department is created without model, application, or budget bindings.
INSERT INTO teams (id, tenant_id, name, path, is_system, system_key)
SELECT
  'team_unassigned_' || substr(md5(t.id), 1, 32),
  t.id,
  '未分配部门',
  '/team_unassigned_' || substr(md5(t.id), 1, 32),
  true,
  'unassigned'
FROM tenants t
WHERE NOT EXISTS (
  SELECT 1
  FROM teams existing
  WHERE existing.tenant_id = t.id
    AND existing.system_key = 'unassigned'
);

CREATE OR REPLACE FUNCTION ensure_tenant_unassigned_department()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  IF EXISTS (
    SELECT 1
    FROM teams
    WHERE tenant_id = NEW.id
      AND name = '未分配部门'
      AND system_key IS DISTINCT FROM 'unassigned'
  ) THEN
    RAISE EXCEPTION 'ordinary department named 未分配部门 exists for tenant %; rename it first', NEW.id;
  END IF;

  INSERT INTO teams (id, tenant_id, name, path, is_system, system_key)
  SELECT
    'team_unassigned_' || substr(md5(NEW.id), 1, 32),
    NEW.id,
    '未分配部门',
    '/team_unassigned_' || substr(md5(NEW.id), 1, 32),
    true,
    'unassigned'
  WHERE NOT EXISTS (
    SELECT 1 FROM teams
    WHERE tenant_id = NEW.id AND system_key = 'unassigned'
  );
  RETURN NEW;
END
$$;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_trigger
    WHERE tgname = 'trg_tenants_ensure_unassigned_department'
      AND tgrelid = 'tenants'::regclass
      AND NOT tgisinternal
  ) THEN
    CREATE TRIGGER trg_tenants_ensure_unassigned_department
      AFTER INSERT ON tenants
      FOR EACH ROW
      EXECUTE FUNCTION ensure_tenant_unassigned_department();
  END IF;
END
$$;

CREATE SEQUENCE IF NOT EXISTS users_department_version_seq AS bigint;

ALTER TABLE users
  ADD COLUMN IF NOT EXISTS department_id varchar(64),
  ADD COLUMN IF NOT EXISTS department_assignment_mode varchar(32) NOT NULL DEFAULT 'unassigned',
  ADD COLUMN IF NOT EXISTS department_assignment_source varchar(32) NOT NULL DEFAULT 'migration',
  ADD COLUMN IF NOT EXISTS department_assignment_rule_id varchar(64),
  ADD COLUMN IF NOT EXISTS department_resolved_at timestamptz,
  ADD COLUMN IF NOT EXISTS department_version bigint;

UPDATE users
SET department_version = nextval('users_department_version_seq')
WHERE department_version IS NULL;

ALTER TABLE users
  ALTER COLUMN department_version SET DEFAULT nextval('users_department_version_seq'),
  ALTER COLUMN department_version SET NOT NULL;

CREATE OR REPLACE FUNCTION advance_user_department_version()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  IF TG_OP = 'INSERT'
     OR OLD.department_id IS DISTINCT FROM NEW.department_id
     OR OLD.department_assignment_mode IS DISTINCT FROM NEW.department_assignment_mode
     OR OLD.department_assignment_source IS DISTINCT FROM NEW.department_assignment_source
     OR OLD.department_assignment_rule_id IS DISTINCT FROM NEW.department_assignment_rule_id
     OR OLD.department_resolved_at IS DISTINCT FROM NEW.department_resolved_at THEN
    NEW.department_version := nextval('users_department_version_seq');
  END IF;
  RETURN NEW;
END
$$;

DROP TRIGGER IF EXISTS trg_users_advance_department_version ON users;
CREATE TRIGGER trg_users_advance_department_version
  BEFORE INSERT OR UPDATE OF department_id, department_assignment_mode,
    department_assignment_source, department_assignment_rule_id, department_resolved_at
  ON users
  FOR EACH ROW
  EXECUTE FUNCTION advance_user_department_version();

WITH membership_summary AS (
  SELECT
    u.id AS user_id,
    count(t.id)::integer AS valid_department_count,
    min(t.id) AS only_department_id
  FROM users u
  LEFT JOIN team_members tm ON tm.user_id = u.id
  LEFT JOIN teams t
    ON t.id = tm.team_id
   AND t.tenant_id = u.tenant_id
  WHERE u.department_assignment_mode <> 'emergency'
  GROUP BY u.id
)
UPDATE users u
SET department_id = CASE
      WHEN summary.valid_department_count = 1 THEN summary.only_department_id
      ELSE unassigned.id
    END,
    department_assignment_mode = CASE
      WHEN summary.valid_department_count = 1 THEN 'automatic'
      ELSE 'unassigned'
    END,
    department_assignment_source = 'migration',
    department_assignment_rule_id = CASE
      WHEN summary.valid_department_count = 0 THEN 'migration:no_team_membership'
      WHEN summary.valid_department_count = 1 THEN 'migration:single_membership'
      ELSE 'migration:multiple_memberships'
    END,
    department_resolved_at = now()
FROM membership_summary summary, teams unassigned
WHERE summary.user_id = u.id
  AND unassigned.tenant_id = u.tenant_id
  AND unassigned.system_key = 'unassigned'
  AND u.department_id IS NULL
  AND u.department_assignment_mode <> 'emergency';

DELETE FROM team_members tm
USING users u
WHERE tm.user_id = u.id
  AND tm.team_id IS DISTINCT FROM u.department_id
  AND u.department_assignment_mode <> 'emergency';

INSERT INTO team_members (team_id, user_id, role)
SELECT u.department_id, u.id, 'member'
FROM users u
WHERE u.department_id IS NOT NULL
  AND u.department_assignment_mode <> 'emergency'
ON CONFLICT (team_id, user_id) DO NOTHING;

CREATE UNIQUE INDEX IF NOT EXISTS uq_team_members_user
  ON team_members(user_id);

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conname = 'chk_users_department_assignment_mode'
      AND conrelid = 'users'::regclass
  ) THEN
    ALTER TABLE users
      ADD CONSTRAINT chk_users_department_assignment_mode
      CHECK (department_assignment_mode IN ('automatic', 'manual', 'unassigned', 'emergency'));
  END IF;
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conname = 'chk_users_department_assignment_source'
      AND conrelid = 'users'::regclass
  ) THEN
    ALTER TABLE users
      ADD CONSTRAINT chk_users_department_assignment_source
      CHECK (department_assignment_source IN ('local', 'oidc', 'ldap', 'ad', 'admin', 'migration'));
  END IF;
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conname = 'chk_users_department_required'
      AND conrelid = 'users'::regclass
  ) THEN
    ALTER TABLE users
      ADD CONSTRAINT chk_users_department_required
      CHECK (department_id IS NOT NULL OR department_assignment_mode = 'emergency');
  END IF;
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conname = 'fk_users_department'
      AND conrelid = 'users'::regclass
  ) THEN
    ALTER TABLE users
      ADD CONSTRAINT fk_users_department
      FOREIGN KEY (department_id) REFERENCES teams(id) ON DELETE RESTRICT;
  END IF;
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conname = 'fk_users_department_tenant'
      AND conrelid = 'users'::regclass
  ) THEN
    ALTER TABLE users
      ADD CONSTRAINT fk_users_department_tenant
      FOREIGN KEY (tenant_id, department_id)
      REFERENCES teams(tenant_id, id) ON DELETE RESTRICT;
  END IF;
END
$$;

CREATE OR REPLACE FUNCTION default_user_unassigned_department()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  IF NEW.department_id IS NULL
     AND NEW.department_assignment_mode <> 'emergency' THEN
    SELECT id INTO NEW.department_id
    FROM teams
    WHERE tenant_id = NEW.tenant_id
      AND system_key = 'unassigned';
    NEW.department_assignment_mode := 'unassigned';
    IF NEW.department_assignment_source IS NULL
       OR btrim(NEW.department_assignment_source) = '' THEN
      NEW.department_assignment_source := 'migration';
    END IF;
    IF NEW.department_assignment_rule_id IS NULL THEN
      NEW.department_assignment_rule_id := 'migration:legacy_insert';
    END IF;
    NEW.department_resolved_at := COALESCE(NEW.department_resolved_at, now());
  END IF;
  RETURN NEW;
END
$$;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_trigger
    WHERE tgname = 'trg_users_default_unassigned_department'
      AND tgrelid = 'users'::regclass
      AND NOT tgisinternal
  ) THEN
    CREATE TRIGGER trg_users_default_unassigned_department
      BEFORE INSERT OR UPDATE OF tenant_id, department_id, department_assignment_mode
      ON users
      FOR EACH ROW
      EXECUTE FUNCTION default_user_unassigned_department();
  END IF;
END
$$;

CREATE OR REPLACE FUNCTION project_user_department_to_team_members()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  IF NEW.department_assignment_mode = 'emergency'
     OR NEW.department_id IS NULL THEN
    DELETE FROM team_members WHERE user_id = NEW.id;
  ELSE
    INSERT INTO team_members (team_id, user_id, role)
    VALUES (NEW.department_id, NEW.id, 'member')
    ON CONFLICT (user_id) DO UPDATE
    SET team_id = EXCLUDED.team_id,
        role = CASE
          WHEN team_members.team_id IS DISTINCT FROM EXCLUDED.team_id THEN 'member'
          ELSE team_members.role
        END;
  END IF;
  RETURN NEW;
END
$$;

CREATE OR REPLACE FUNCTION validate_team_member_projection()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
  expected_department_id varchar(64);
  expected_assignment_mode varchar(32);
BEGIN
  SELECT department_id, department_assignment_mode
  INTO expected_department_id, expected_assignment_mode
  FROM users
  WHERE id = NEW.user_id;

  IF NOT FOUND
     OR expected_assignment_mode = 'emergency'
     OR expected_department_id IS NULL
     OR NEW.team_id IS DISTINCT FROM expected_department_id THEN
    RAISE EXCEPTION 'team_members must match the non-emergency users.department_id projection';
  END IF;
  RETURN NEW;
END
$$;

CREATE OR REPLACE FUNCTION restore_team_member_projection()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
  expected_department_id varchar(64);
  expected_assignment_mode varchar(32);
BEGIN
  SELECT department_id, department_assignment_mode
  INTO expected_department_id, expected_assignment_mode
  FROM users
  WHERE id = OLD.user_id;

  IF FOUND
     AND expected_department_id IS NOT NULL
     AND expected_assignment_mode <> 'emergency' THEN
    INSERT INTO team_members (team_id, user_id, role)
    VALUES (expected_department_id, OLD.user_id, OLD.role)
    ON CONFLICT (user_id) DO UPDATE
    SET team_id = EXCLUDED.team_id,
        role = CASE
          WHEN team_members.team_id IS DISTINCT FROM EXCLUDED.team_id THEN 'member'
          ELSE team_members.role
        END;
  END IF;
  RETURN OLD;
END
$$;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_trigger
    WHERE tgname = 'trg_team_members_validate_projection'
      AND tgrelid = 'team_members'::regclass
      AND NOT tgisinternal
  ) THEN
    CREATE TRIGGER trg_team_members_validate_projection
      BEFORE INSERT OR UPDATE ON team_members
      FOR EACH ROW
      EXECUTE FUNCTION validate_team_member_projection();
  END IF;

  IF NOT EXISTS (
    SELECT 1 FROM pg_trigger
    WHERE tgname = 'trg_team_members_restore_projection'
      AND tgrelid = 'team_members'::regclass
      AND NOT tgisinternal
  ) THEN
    CREATE TRIGGER trg_team_members_restore_projection
      AFTER DELETE ON team_members
      FOR EACH ROW
      EXECUTE FUNCTION restore_team_member_projection();
  END IF;

  IF NOT EXISTS (
    SELECT 1 FROM pg_trigger
    WHERE tgname = 'trg_users_project_department'
      AND tgrelid = 'users'::regclass
      AND NOT tgisinternal
  ) THEN
    CREATE TRIGGER trg_users_project_department
      AFTER INSERT OR UPDATE OF department_id, department_assignment_mode ON users
      FOR EACH ROW
      EXECUTE FUNCTION project_user_department_to_team_members();
  END IF;
END
$$;

CREATE TABLE IF NOT EXISTS user_identity_links (
  id varchar(64) PRIMARY KEY,
  tenant_id varchar(64) NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  user_id varchar(64) NOT NULL,
  issuer varchar(512) NOT NULL,
  source_type varchar(32) NOT NULL
    CHECK (source_type IN ('local', 'oidc', 'ldap', 'ad')),
  source_id varchar(64) NOT NULL DEFAULT '',
  external_subject varchar(512) NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT fk_user_identity_links_user_tenant
    FOREIGN KEY (tenant_id, user_id)
    REFERENCES users(tenant_id, id) ON DELETE CASCADE,
  CONSTRAINT chk_user_identity_links_issuer_nonempty
    CHECK (btrim(issuer) <> ''),
  CONSTRAINT chk_user_identity_links_directory_source
    CHECK (
      source_type NOT IN ('ldap', 'ad')
      OR (btrim(source_id) <> '' AND source_id = issuer)
    ),
  UNIQUE (tenant_id, issuer, source_type, external_subject)
);

CREATE INDEX IF NOT EXISTS idx_user_identity_links_user
  ON user_identity_links(tenant_id, user_id);

ALTER TABLE audit_operations
  ADD COLUMN IF NOT EXISTS tenant_id varchar(64);

UPDATE audit_operations audit
SET tenant_id = users.tenant_id
FROM users
WHERE audit.tenant_id IS NULL
  AND audit.user_id = users.id;

CREATE INDEX IF NOT EXISTS idx_audit_operations_tenant
  ON audit_operations(tenant_id, created_at DESC);

CREATE TABLE IF NOT EXISTS identity_department_mappings (
  id varchar(64) PRIMARY KEY,
  tenant_id varchar(64) NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  source_kind varchar(32) NOT NULL CHECK (source_kind IN ('oidc', 'ldap', 'ad')),
  source_id varchar(64) NOT NULL DEFAULT '',
  match_type varchar(32) NOT NULL CHECK (match_type IN ('department', 'ou', 'member_of', 'groups')),
  match_value varchar(2048) NOT NULL,
  target_department_id varchar(64) NOT NULL,
  priority integer NOT NULL DEFAULT 100,
  enabled boolean NOT NULL DEFAULT true,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT fk_identity_department_target_tenant
    FOREIGN KEY (tenant_id, target_department_id)
    REFERENCES teams(tenant_id, id) ON DELETE CASCADE,
  UNIQUE (tenant_id, source_kind, source_id, match_type, match_value)
);

CREATE INDEX IF NOT EXISTS idx_identity_department_mappings_lookup
  ON identity_department_mappings(tenant_id, source_kind, source_id, enabled, priority);

COMMENT ON COLUMN identity_department_mappings.source_id IS
  'Empty source_id is a tenant-level legacy fallback; prefer exact source_id before empty fallback';

INSERT INTO identity_department_mappings (
  id, tenant_id, source_kind, source_id, match_type, match_value,
  target_department_id, priority, enabled, created_at, updated_at
)
SELECT
  'idm_oidc_' || substr(md5(legacy.id), 1, 32),
  legacy.tenant_id,
  'oidc',
  legacy.identity_source_id,
  'department',
  legacy.match_value,
  legacy.mapped_team_id,
  legacy.priority,
  legacy.enabled,
  legacy.created_at,
  legacy.updated_at
FROM identity_dept_mappings legacy
JOIN teams target
  ON target.id = legacy.mapped_team_id
 AND target.tenant_id = legacy.tenant_id
WHERE legacy.mapped_team_id IS NOT NULL
ON CONFLICT DO NOTHING;

INSERT INTO identity_department_mappings (
  id, tenant_id, source_kind, source_id, match_type, match_value,
  target_department_id, priority, enabled, created_at, updated_at
)
SELECT
  'idm_group_' || substr(md5(legacy.id), 1, 32),
  legacy.tenant_id,
  'oidc',
  '',
  CASE
    WHEN lower(legacy.match_type) IN ('group', 'groups') THEN 'groups'
    ELSE 'department'
  END,
  legacy.match_value,
  legacy.gateway_team_id,
  legacy.priority,
  legacy.enabled,
  legacy.created_at,
  legacy.updated_at
FROM group_mapping_rules legacy
JOIN teams target
  ON target.id = legacy.gateway_team_id
 AND target.tenant_id = legacy.tenant_id
WHERE legacy.gateway_team_id IS NOT NULL
ON CONFLICT DO NOTHING;

INSERT INTO identity_department_mappings (
  id, tenant_id, source_kind, source_id, match_type, match_value,
  target_department_id, priority, enabled, created_at, updated_at
)
SELECT
  'idm_directory_' || substr(md5(legacy.id), 1, 32),
  legacy.tenant_id,
  source.kind,
  legacy.directory_source_id,
  'member_of',
  legacy.external_object_id,
  legacy.mapped_team_id,
  legacy.priority,
  legacy.enabled,
  legacy.created_at,
  legacy.updated_at
FROM directory_group_mappings legacy
JOIN directory_sources source
  ON source.id = legacy.directory_source_id
 AND source.tenant_id = legacy.tenant_id
JOIN teams target
  ON target.id = legacy.mapped_team_id
 AND target.tenant_id = legacy.tenant_id
WHERE legacy.mapped_team_id IS NOT NULL
ON CONFLICT DO NOTHING;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conname = 'uq_directory_sources_tenant_id'
      AND conrelid = 'directory_sources'::regclass
  ) THEN
    ALTER TABLE directory_sources
      ADD CONSTRAINT uq_directory_sources_tenant_id UNIQUE (tenant_id, id);
  END IF;
END
$$;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conname = 'uq_directory_sync_runs_tenant_id'
      AND conrelid = 'directory_sync_runs'::regclass
  ) THEN
    ALTER TABLE directory_sync_runs
      ADD CONSTRAINT uq_directory_sync_runs_tenant_id UNIQUE (tenant_id, id);
  END IF;
END
$$;

CREATE TABLE IF NOT EXISTS identity_cache_invalidation_outbox (
  id varchar(64) PRIMARY KEY,
  tenant_id varchar(64) NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  user_id varchar(64) NOT NULL,
  old_department_id varchar(64) NOT NULL DEFAULT '',
  new_department_id varchar(64) NOT NULL DEFAULT '',
  status varchar(16) NOT NULL DEFAULT 'pending'
    CHECK (status IN ('pending', 'processing', 'failed', 'processed', 'dead_letter')),
  attempt_count integer NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
  next_attempt_at timestamptz NOT NULL DEFAULT now(),
  locked_at timestamptz,
  locked_by varchar(128) NOT NULL DEFAULT '',
  last_error varchar(512) NOT NULL DEFAULT '',
  processed_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT fk_identity_cache_outbox_user_tenant
    FOREIGN KEY (tenant_id, user_id)
    REFERENCES users(tenant_id, id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_identity_cache_invalidation_due
  ON identity_cache_invalidation_outbox(status, next_attempt_at, locked_at, created_at)
  WHERE status IN ('pending', 'processing', 'failed');

CREATE TABLE IF NOT EXISTS directory_sync_previews (
  id varchar(64) PRIMARY KEY,
  tenant_id varchar(64) NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  directory_source_id varchar(64) NOT NULL,
  source_version integer NOT NULL CHECK (source_version > 0),
  config_digest varchar(128) NOT NULL DEFAULT '',
  status varchar(24) NOT NULL CHECK (status IN ('running', 'succeeded', 'failed', 'activated', 'expired')),
  scanned_count integer NOT NULL DEFAULT 0,
  created_count integer NOT NULL DEFAULT 0,
  updated_count integer NOT NULL DEFAULT 0,
  disabled_count integer NOT NULL DEFAULT 0,
  conflict_count integer NOT NULL DEFAULT 0,
  unassigned_count integer NOT NULL DEFAULT 0,
  error_code varchar(128) NOT NULL DEFAULT '',
  actor_user_id varchar(64) NOT NULL DEFAULT '',
  expires_at timestamptz NOT NULL,
  activated_at timestamptz,
  activated_run_id varchar(64),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT fk_directory_sync_preview_source_tenant
    FOREIGN KEY (tenant_id, directory_source_id)
    REFERENCES directory_sources(tenant_id, id) ON DELETE CASCADE,
  CONSTRAINT fk_directory_sync_preview_run_tenant
    FOREIGN KEY (tenant_id, activated_run_id)
    REFERENCES directory_sync_runs(tenant_id, id) ON DELETE SET NULL (activated_run_id),
  UNIQUE (tenant_id, id)
);

CREATE INDEX IF NOT EXISTS idx_directory_sync_previews_source
  ON directory_sync_previews(tenant_id, directory_source_id, created_at DESC);

CREATE TABLE IF NOT EXISTS directory_sync_preview_entries (
  id varchar(64) PRIMARY KEY,
  tenant_id varchar(64) NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  preview_id varchar(64) NOT NULL,
  external_subject varchar(512) NOT NULL,
  content_digest varchar(128) NOT NULL,
  action varchar(24) NOT NULL CHECK (action IN ('create', 'update', 'restore', 'disable', 'skip', 'conflict')),
  username varchar(255) NOT NULL DEFAULT '',
  display_name varchar(255) NOT NULL DEFAULT '',
  department_match_type varchar(32) NOT NULL DEFAULT '',
  department_match_value varchar(2048) NOT NULL DEFAULT '',
  resolution_status varchar(32) NOT NULL DEFAULT '',
  error_code varchar(128) NOT NULL DEFAULT '',
  created_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT fk_directory_sync_preview_entry_preview_tenant
    FOREIGN KEY (tenant_id, preview_id)
    REFERENCES directory_sync_previews(tenant_id, id) ON DELETE CASCADE,
  UNIQUE (preview_id, external_subject)
);

CREATE INDEX IF NOT EXISTS idx_directory_sync_preview_entries_preview
  ON directory_sync_preview_entries(tenant_id, preview_id);

ALTER TABLE directory_sources
  ADD COLUMN IF NOT EXISTS runtime_reconciliation_required boolean NOT NULL DEFAULT false,
  ADD COLUMN IF NOT EXISTS runtime_reconciliation_reason varchar(64) NOT NULL DEFAULT '';

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conname = 'chk_directory_runtime_reconciliation'
      AND conrelid = 'directory_sources'::regclass
  ) THEN
    ALTER TABLE directory_sources
      ADD CONSTRAINT chk_directory_runtime_reconciliation
      CHECK (
        (NOT runtime_reconciliation_required AND runtime_reconciliation_reason = '')
        OR
        (runtime_reconciliation_required AND runtime_reconciliation_reason ~ '^[a-z][a-z0-9_]{0,63}$')
      );
  END IF;
END
$$;

-- Final schema contract: directory filters accept the validated 4096-byte maximum.
ALTER TABLE directory_sources
  ALTER COLUMN user_filter TYPE varchar(4096);

-- +goose StatementEnd
-- +goose Down
-- +goose StatementBegin

-- Forward-only: reverting would discard identity bindings and unique department assignments.
SELECT 1;

-- +goose StatementEnd
