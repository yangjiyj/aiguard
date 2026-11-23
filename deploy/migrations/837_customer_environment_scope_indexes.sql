-- +goose NO TRANSACTION
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
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_access_content_logs_turn
    ON access_content_logs (tenant_id, conversation_id, section_id, created_at DESC, request_id)
    WHERE conversation_id IS NOT NULL;
