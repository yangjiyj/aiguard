-- +goose Up
-- +goose StatementBegin

CREATE TABLE IF NOT EXISTS directory_sources (
    id varchar(64) PRIMARY KEY,
    tenant_id varchar(64) NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    kind varchar(16) NOT NULL CHECK (kind IN ('ad', 'ldap')),
    display_name varchar(128) NOT NULL,
    connection_url varchar(512) NOT NULL,
    bind_dn varchar(512) NOT NULL,
    bind_password_enc text NOT NULL,
    base_dn varchar(512) NOT NULL DEFAULT '',
    users_dn varchar(512) NOT NULL DEFAULT '',
    user_filter varchar(1024) NOT NULL DEFAULT '',
    stable_id_attribute varchar(64) NOT NULL,
    username_attribute varchar(64) NOT NULL,
    email_attribute varchar(64) NOT NULL DEFAULT '',
    name_attribute varchar(64) NOT NULL DEFAULT '',
    status varchar(24) NOT NULL DEFAULT 'draft' CHECK (status IN ('draft', 'tested', 'active', 'disabled')),
    version integer NOT NULL DEFAULT 1,
    runtime_component_id varchar(128) NOT NULL DEFAULT '',
    config_digest varchar(128) NOT NULL DEFAULT '',
    last_tested_at timestamptz,
    last_test_result jsonb,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_directory_sources_tenant ON directory_sources(tenant_id, status);
CREATE UNIQUE INDEX IF NOT EXISTS uq_directory_sources_active_per_tenant ON directory_sources(tenant_id) WHERE status='active';
CREATE UNIQUE INDEX IF NOT EXISTS uq_directory_sources_pending_per_tenant ON directory_sources(tenant_id) WHERE status IN ('draft', 'tested');

CREATE TABLE IF NOT EXISTS directory_sync_runs (
    id varchar(64) PRIMARY KEY,
    tenant_id varchar(64) NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    directory_source_id varchar(64) NOT NULL REFERENCES directory_sources(id) ON DELETE CASCADE,
    source_version integer NOT NULL,
    run_kind varchar(16) NOT NULL CHECK (run_kind IN ('preview', 'full', 'changed')),
    status varchar(16) NOT NULL CHECK (status IN ('running', 'succeeded', 'failed')),
    started_at timestamptz NOT NULL DEFAULT now(),
    finished_at timestamptz,
    scanned_count integer NOT NULL DEFAULT 0,
    created_count integer NOT NULL DEFAULT 0,
    updated_count integer NOT NULL DEFAULT 0,
    restored_count integer NOT NULL DEFAULT 0,
    disabled_count integer NOT NULL DEFAULT 0,
    conflict_count integer NOT NULL DEFAULT 0,
    skipped_count integer NOT NULL DEFAULT 0,
    error_code varchar(128) NOT NULL DEFAULT '',
    actor_user_id varchar(64) NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_directory_sync_runs_source ON directory_sync_runs(tenant_id, directory_source_id, started_at DESC);

CREATE TABLE IF NOT EXISTS directory_user_links (
    id varchar(64) PRIMARY KEY,
    tenant_id varchar(64) NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    directory_source_id varchar(64) NOT NULL REFERENCES directory_sources(id) ON DELETE CASCADE,
    external_object_id varchar(512) NOT NULL,
    source_dn varchar(2048) NOT NULL DEFAULT '',
    user_id varchar(64) NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    last_seen_run_id varchar(64) REFERENCES directory_sync_runs(id) ON DELETE SET NULL,
    last_seen_at timestamptz NOT NULL DEFAULT now(),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS uq_directory_user_external ON directory_user_links(tenant_id, directory_source_id, external_object_id);

CREATE TABLE IF NOT EXISTS directory_group_mappings (
    id varchar(64) PRIMARY KEY,
    tenant_id varchar(64) NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    directory_source_id varchar(64) NOT NULL REFERENCES directory_sources(id) ON DELETE CASCADE,
    external_object_id varchar(512) NOT NULL,
    display_path varchar(2048) NOT NULL,
    mapped_team_id varchar(64) REFERENCES teams(id) ON DELETE SET NULL,
    priority integer NOT NULL DEFAULT 100,
    enabled boolean NOT NULL DEFAULT true,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS uq_directory_group_mapping ON directory_group_mappings(tenant_id, directory_source_id, external_object_id);

-- +goose StatementEnd
-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS directory_group_mappings;
DROP TABLE IF EXISTS directory_user_links;
DROP TABLE IF EXISTS directory_sync_runs;
DROP TABLE IF EXISTS directory_sources;
-- +goose StatementEnd
