-- 147: prepare environment-scope columns before creating retention indexes.
ALTER TABLE request_logs
    ADD COLUMN IF NOT EXISTS environment_scope VARCHAR(32);
ALTER TABLE access_content_logs
    ADD COLUMN IF NOT EXISTS environment_scope VARCHAR(32);
ALTER TABLE content_logs
    ADD COLUMN IF NOT EXISTS environment_scope VARCHAR(32);
ALTER TABLE retained_artifacts
    ADD COLUMN IF NOT EXISTS environment_scope VARCHAR(32);
ALTER TABLE access_content_artifact_links
    ADD COLUMN IF NOT EXISTS environment_scope VARCHAR(32);

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_request_logs_tenant_scope_created
    ON request_logs (tenant_id, environment_scope, created_at DESC);

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_access_content_logs_tenant_scope_created
    ON access_content_logs (tenant_id, environment_scope, created_at DESC);

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_content_logs_tenant_scope_created
    ON content_logs (tenant_id, environment_scope, created_at DESC);

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_retained_artifacts_tenant_scope_created
    ON retained_artifacts (tenant_id, environment_scope, created_at DESC);

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_access_content_artifact_links_tenant_scope_created
    ON access_content_artifact_links (tenant_id, environment_scope, created_at DESC);
