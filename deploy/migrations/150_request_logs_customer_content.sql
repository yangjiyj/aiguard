-- 150_request_logs_customer_content.sql
-- Keep the broad audit-retention flag for internal evidence, and add a
-- separately indexed customer-visible content projection for high-concurrency
-- list and run queries. Existing rows are populated by the control-plane
-- risk-column backfill after this schema change.

ALTER TABLE request_logs
    ADD COLUMN IF NOT EXISTS has_customer_content BOOLEAN;

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_request_logs_tenant_customer_content_created
    ON request_logs (tenant_id, created_at DESC)
    WHERE has_customer_content;
