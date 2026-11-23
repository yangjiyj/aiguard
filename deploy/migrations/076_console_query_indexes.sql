-- 076_console_query_indexes.sql
-- Console/audit query acceleration indexes for GW-20260621-06 query rewrites.
--
-- Manual execution only: CREATE INDEX CONCURRENTLY cannot run inside an
-- explicit transaction block, and this DDL should be applied after DBA review.

CREATE EXTENSION IF NOT EXISTS pg_trgm;

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_content_logs_tenant_role_request
    ON content_logs (tenant_id, role, request_id, created_at);

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_content_logs_tenant_created
    ON content_logs (tenant_id, created_at DESC);

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_content_logs_content_trgm
    ON content_logs USING gin (content gin_trgm_ops);

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_security_events_tenant_request
    ON security_events (tenant_id, request_id);

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_agent_sessions_tenant_last_request
    ON agent_sessions (tenant_id, last_request_at DESC);
