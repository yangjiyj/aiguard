-- 153_content_logs_customer_text_index.sql
-- Make customer-visible presence probes indexable without removing internal
-- runtime context from content_logs or changing the audit retention policy.

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_content_logs_customer_text
    ON content_logs (tenant_id, request_id, role, created_at, id)
    WHERE role IN ('user', 'assistant')
      AND jjdguard_customer_content_text(content);
