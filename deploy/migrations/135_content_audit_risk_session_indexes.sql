-- Accelerate content-risk session discovery without indexing retained content bodies.
-- The partial index stays small because only real user turns participate in fallback grouping.
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_content_logs_tenant_session_user_created
    ON content_logs (tenant_id, session_id, created_at)
    WHERE role = 'user'
      AND session_id IS NOT NULL;

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_content_logs_tenant_request_session_latest
    ON content_logs (tenant_id, request_id, created_at DESC)
    INCLUDE (session_id, user_id)
    WHERE session_id IS NOT NULL;
