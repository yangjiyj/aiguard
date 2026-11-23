-- +goose NO TRANSACTION
-- +goose Up
-- Kept separate from transactional inventory/schema reconciliation.
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_model_catalog_runs_provider
ON model_catalog_sync_runs(tenant_id,provider_id,finished_at DESC);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_tool_call_logs_endpoint_hook_identity
 ON tool_call_logs(tenant_id,endpoint_id,session_id,tool_call_id)
 WHERE attribution_mode='endpoint_hook';
CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS uq_internal_keys_active_agent
 ON internal_keys(tenant_id,agent_instance_id) WHERE status='active' AND agent_instance_id IS NOT NULL;
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_request_logs_tenant_agent_created ON request_logs(tenant_id,agent_instance_id,created_at DESC);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_security_events_tenant_agent_created ON security_events(tenant_id,agent_instance_id,created_at DESC);
-- +goose Down
-- Keep sync audit index for compatible application rollback.
