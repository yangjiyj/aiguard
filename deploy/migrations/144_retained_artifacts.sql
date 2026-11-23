CREATE TABLE IF NOT EXISTS retained_artifacts (
    id varchar(64) PRIMARY KEY,
    tenant_id varchar(64) NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    source_request_id varchar(64) REFERENCES request_logs(request_id) ON DELETE SET NULL,
    provider varchar(64),
    source_reference_hash varchar(64),
    kind varchar(16) NOT NULL CHECK (kind IN ('image', 'file')),
    display_name text,
    media_type varchar(255),
    byte_size bigint,
    sha256 varchar(64),
    retention_status varchar(32) NOT NULL
        CHECK (retention_status IN ('retained', 'reference_only', 'failed', 'oversize_unretained')),
    original_object_key text,
    preview_object_key text,
    storage_backend varchar(32),
    failure_code varchar(64),
    retention_until timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS access_content_artifact_links (
    id varchar(64) PRIMARY KEY,
    tenant_id varchar(64) NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    request_id varchar(64) NOT NULL REFERENCES request_logs(request_id) ON DELETE CASCADE,
    artifact_id varchar(64) NOT NULL REFERENCES retained_artifacts(id) ON DELETE CASCADE,
    direction varchar(16) NOT NULL CHECK (direction IN ('input', 'output')),
    ordinal integer NOT NULL CHECK (ordinal >= 0),
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, request_id, artifact_id, direction)
);

CREATE INDEX IF NOT EXISTS idx_retained_artifacts_tenant_provider_reference
    ON retained_artifacts (tenant_id, provider, source_reference_hash)
    WHERE source_reference_hash IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_access_content_artifact_links_request_direction_ordinal
    ON access_content_artifact_links (tenant_id, request_id, direction, ordinal);
