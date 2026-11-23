BEGIN;

-- Additive source type for authenticated Kubernetes collectors. Existing
-- agent_endpoint and identity_event identities and routes remain unchanged.
ALTER TABLE agent_asset_source_refs
    DROP CONSTRAINT IF EXISTS agent_asset_source_refs_source_type_check;
ALTER TABLE agent_asset_source_refs
    ADD CONSTRAINT agent_asset_source_refs_source_type_check
    CHECK (source_type IN ('agent_endpoint','identity_event','kubernetes_cluster'));

CREATE UNIQUE INDEX IF NOT EXISTS uq_agent_endpoints_tenant_id
    ON agent_endpoints (tenant_id, id);

CREATE TABLE IF NOT EXISTS agent_kubernetes_clusters (
    id text PRIMARY KEY,
    tenant_id varchar(64) NOT NULL,
    display_name varchar(128) NOT NULL,
    cluster_label varchar(128) NOT NULL,
    created_by text NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    UNIQUE (tenant_id, id),
    UNIQUE (tenant_id, cluster_label)
);

CREATE TABLE IF NOT EXISTS agent_kubernetes_namespace_registrations (
    id text PRIMARY KEY,
    tenant_id varchar(64) NOT NULL,
    cluster_registration_id text NOT NULL,
    endpoint_id text NOT NULL,
    namespace_name varchar(63) NOT NULL,
    namespace_uid varchar(128) NOT NULL,
    active boolean NOT NULL DEFAULT true,
    next_run_sequence bigint NOT NULL DEFAULT 0 CHECK (next_run_sequence >= 0),
    created_by text NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    revoked_by text NOT NULL DEFAULT '',
    revoked_at timestamptz,
    UNIQUE (tenant_id, id),
    UNIQUE (tenant_id, id, endpoint_id),
    FOREIGN KEY (tenant_id, cluster_registration_id)
        REFERENCES agent_kubernetes_clusters (tenant_id, id),
    FOREIGN KEY (tenant_id, endpoint_id)
        REFERENCES agent_endpoints (tenant_id, id)
);
CREATE INDEX IF NOT EXISTS idx_agent_k8s_namespace_registration_cluster
    ON agent_kubernetes_namespace_registrations (tenant_id, cluster_registration_id, active);
CREATE UNIQUE INDEX IF NOT EXISTS uq_agent_k8s_active_endpoint_registration
    ON agent_kubernetes_namespace_registrations (tenant_id, endpoint_id)
    WHERE active;
CREATE UNIQUE INDEX IF NOT EXISTS uq_agent_k8s_active_namespace_uid_registration
    ON agent_kubernetes_namespace_registrations (tenant_id, cluster_registration_id, namespace_uid)
    WHERE active;

CREATE TABLE IF NOT EXISTS agent_kubernetes_snapshot_runs (
    id text PRIMARY KEY,
    tenant_id varchar(64) NOT NULL,
    namespace_registration_id text NOT NULL,
    endpoint_id text NOT NULL,
    request_id text NOT NULL,
    sequence bigint NOT NULL CHECK (sequence > 0),
    issued_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    expires_at timestamptz NOT NULL,
    UNIQUE (tenant_id, id),
    UNIQUE (tenant_id, namespace_registration_id, sequence),
    UNIQUE (tenant_id, namespace_registration_id, request_id),
    UNIQUE (tenant_id, id, namespace_registration_id),
    FOREIGN KEY (tenant_id, namespace_registration_id, endpoint_id)
        REFERENCES agent_kubernetes_namespace_registrations (tenant_id, id, endpoint_id),
    FOREIGN KEY (tenant_id, endpoint_id)
        REFERENCES agent_endpoints (tenant_id, id),
    CHECK (expires_at > issued_at)
);
CREATE INDEX IF NOT EXISTS idx_agent_k8s_snapshot_runs_registration
    ON agent_kubernetes_snapshot_runs (tenant_id, namespace_registration_id, sequence DESC);

-- One immutable receipt per issued run; raw object payloads live in the
-- existing unified-asset observations and are not duplicated here.
CREATE TABLE IF NOT EXISTS agent_kubernetes_snapshot_receipts (
    id text PRIMARY KEY,
    tenant_id varchar(64) NOT NULL,
    namespace_registration_id text NOT NULL,
    run_id text NOT NULL,
    run_sequence bigint NOT NULL CHECK (run_sequence > 0),
    report_id varchar(71) NOT NULL,
    content_digest varchar(71) NOT NULL,
    source_observed_at timestamptz NOT NULL,
    received_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    collection_status text NOT NULL CHECK (collection_status IN ('complete','partial')),
    resource_coverage jsonb NOT NULL,
    observation_gaps jsonb NOT NULL,
    projection_status text NOT NULL CHECK (projection_status IN ('projected','history_only_stale','history_only_expired','receipt_only_scope_unverified')),
    UNIQUE (tenant_id, id),
    UNIQUE (tenant_id, namespace_registration_id, run_id),
    FOREIGN KEY (tenant_id, namespace_registration_id)
        REFERENCES agent_kubernetes_namespace_registrations (tenant_id, id),
    FOREIGN KEY (tenant_id, run_id, namespace_registration_id)
        REFERENCES agent_kubernetes_snapshot_runs (tenant_id, id, namespace_registration_id),
    CHECK (report_id ~ '^sha256:[0-9a-f]{64}$'),
    CHECK (content_digest = report_id)
);
CREATE INDEX IF NOT EXISTS idx_agent_k8s_snapshot_receipts_history
    ON agent_kubernetes_snapshot_receipts (tenant_id, namespace_registration_id, received_at DESC);

CREATE TABLE IF NOT EXISTS agent_kubernetes_resource_watermarks (
    tenant_id varchar(64) NOT NULL,
    namespace_registration_id text NOT NULL,
    namespace_uid varchar(128) NOT NULL,
    resource_kind varchar(32) NOT NULL,
    last_run_sequence bigint NOT NULL DEFAULT 0,
    last_status text NOT NULL DEFAULT 'pending'
        CHECK (last_status IN ('pending','complete','partial','forbidden','limited','failed')),
    last_report_id varchar(71) NOT NULL DEFAULT '',
    last_complete_sequence bigint NOT NULL DEFAULT 0,
    last_complete_at timestamptz,
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (tenant_id, namespace_registration_id, namespace_uid, resource_kind),
    FOREIGN KEY (tenant_id, namespace_registration_id)
        REFERENCES agent_kubernetes_namespace_registrations (tenant_id, id),
    CHECK (last_complete_sequence <= last_run_sequence OR last_run_sequence = 0)
);

COMMIT;
