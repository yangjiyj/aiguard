-- Optional upstream time-to-first-token for streaming route observations.
ALTER TABLE request_logs
    ADD COLUMN IF NOT EXISTS upstream_ttft_ms bigint;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'chk_request_logs_upstream_ttft_nonnegative'
          AND conrelid = 'request_logs'::regclass
    ) THEN
        ALTER TABLE request_logs
            ADD CONSTRAINT chk_request_logs_upstream_ttft_nonnegative
            CHECK (upstream_ttft_ms IS NULL OR upstream_ttft_ms >= 0) NOT VALID;
    END IF;
END $$;

-- Validation is separate from constraint creation so the initial metadata lock
-- stays short on a hot request_logs table.
ALTER TABLE request_logs
    VALIDATE CONSTRAINT chk_request_logs_upstream_ttft_nonnegative;

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_request_logs_route_metrics
    ON request_logs (tenant_id, created_at DESC, model_id, provider_id);
