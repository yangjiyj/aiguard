-- +goose NO TRANSACTION
-- Online support indexes for keyset backfills. The runner executes this file
-- outside a transaction and records the ledger only after every index commits.
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_request_logs_backfill_cursor
    ON request_logs(created_at, id);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_content_logs_projection_lookup
    ON content_logs(tenant_id, request_id, role);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_access_content_logs_projection_lookup
    ON access_content_logs(tenant_id, request_id);

