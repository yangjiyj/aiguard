-- 066 Eval integration request correlation fields.
-- Stores evaluation-platform correlation IDs on the existing request_logs row
-- so LSE can query redacted gateway evidence without introducing a parallel log path.

ALTER TABLE request_logs
    ADD COLUMN IF NOT EXISTS trace_id VARCHAR(128),
    ADD COLUMN IF NOT EXISTS lse_eval_run_id VARCHAR(128),
    ADD COLUMN IF NOT EXISTS lse_task_id VARCHAR(128),
    ADD COLUMN IF NOT EXISTS lse_sample_id VARCHAR(128),
    ADD COLUMN IF NOT EXISTS lse_target_id VARCHAR(128);

CREATE INDEX IF NOT EXISTS idx_request_logs_lse_eval_run_id
    ON request_logs (tenant_id, lse_eval_run_id, created_at DESC)
    WHERE lse_eval_run_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_request_logs_lse_task_id
    ON request_logs (tenant_id, lse_task_id, created_at DESC)
    WHERE lse_task_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_request_logs_lse_sample_id
    ON request_logs (tenant_id, lse_sample_id, created_at DESC)
    WHERE lse_sample_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_request_logs_trace_id
    ON request_logs (tenant_id, trace_id, created_at DESC)
    WHERE trace_id IS NOT NULL;

COMMENT ON COLUMN request_logs.trace_id IS 'External trace correlation ID supplied by LSE or other evaluation clients.';
COMMENT ON COLUMN request_logs.lse_eval_run_id IS 'LSE evaluation run correlation ID from X-LSE-Eval-Run-Id.';
COMMENT ON COLUMN request_logs.lse_task_id IS 'LSE task correlation ID from X-LSE-Task-Id.';
COMMENT ON COLUMN request_logs.lse_sample_id IS 'LSE sample correlation ID from X-LSE-Sample-Id.';
COMMENT ON COLUMN request_logs.lse_target_id IS 'LSE target correlation ID from X-LSE-Target-Id.';
