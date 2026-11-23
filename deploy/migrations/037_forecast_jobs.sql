-- 037_forecast_jobs.sql
CREATE TABLE IF NOT EXISTS forecast_jobs (
    id VARCHAR(64) PRIMARY KEY,
    tenant_id VARCHAR(64) NOT NULL,
    status VARCHAR(16) NOT NULL DEFAULT 'pending',
    params_json JSONB NOT NULL,
    result_json JSONB,
    error TEXT,
    created_by VARCHAR(64),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    finished_at TIMESTAMP WITH TIME ZONE
);
CREATE INDEX IF NOT EXISTS idx_forecast_jobs_tenant ON forecast_jobs(tenant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_forecast_jobs_status ON forecast_jobs(status) WHERE status IN ('pending','running');
COMMENT ON COLUMN forecast_jobs.status IS 'pending|running|done|failed';
