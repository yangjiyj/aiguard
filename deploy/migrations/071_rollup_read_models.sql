-- Migration: 071_rollup_read_models
-- Purpose: hourly read models for high-volume console statistics.

CREATE TABLE IF NOT EXISTS usage_rollup_hourly (
    tenant_id VARCHAR(64) NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    bucket_start TIMESTAMP WITH TIME ZONE NOT NULL,
    project_id VARCHAR(64) NOT NULL DEFAULT '',
    user_id VARCHAR(64) NOT NULL DEFAULT '',
    client_id VARCHAR(64) NOT NULL DEFAULT '',
    provider_id VARCHAR(64) NOT NULL DEFAULT '',
    model_id VARCHAR(64) NOT NULL DEFAULT '',
    request_count INTEGER NOT NULL DEFAULT 0 CHECK (request_count >= 0),
    success_count INTEGER NOT NULL DEFAULT 0 CHECK (success_count >= 0),
    priced_request_count INTEGER NOT NULL DEFAULT 0 CHECK (priced_request_count >= 0),
    input_tokens BIGINT NOT NULL DEFAULT 0 CHECK (input_tokens >= 0),
    output_tokens BIGINT NOT NULL DEFAULT 0 CHECK (output_tokens >= 0),
    total_cost DECIMAL(18,6) NOT NULL DEFAULT 0,
    latency_ms_sum BIGINT NOT NULL DEFAULT 0 CHECK (latency_ms_sum >= 0),
    first_seen_at TIMESTAMP WITH TIME ZONE,
    last_seen_at TIMESTAMP WITH TIME ZONE,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, bucket_start, project_id, user_id, client_id, provider_id, model_id)
);

CREATE INDEX IF NOT EXISTS idx_usage_rollup_hourly_tenant_bucket
    ON usage_rollup_hourly(tenant_id, bucket_start DESC);

CREATE INDEX IF NOT EXISTS idx_usage_rollup_hourly_project_bucket
    ON usage_rollup_hourly(tenant_id, project_id, bucket_start DESC);

CREATE INDEX IF NOT EXISTS idx_usage_rollup_hourly_model_bucket
    ON usage_rollup_hourly(tenant_id, model_id, bucket_start DESC);

CREATE TABLE IF NOT EXISTS access_rollup_hourly (
    tenant_id VARCHAR(64) NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    bucket_start TIMESTAMP WITH TIME ZONE NOT NULL,
    access_direction VARCHAR(32) NOT NULL DEFAULT '',
    access_type VARCHAR(64) NOT NULL DEFAULT '',
    provider VARCHAR(128) NOT NULL DEFAULT '',
    target_host VARCHAR(255) NOT NULL DEFAULT '',
    risk_state VARCHAR(32) NOT NULL DEFAULT '',
    request_count INTEGER NOT NULL DEFAULT 0 CHECK (request_count >= 0),
    normal_count INTEGER NOT NULL DEFAULT 0 CHECK (normal_count >= 0),
    risk_count INTEGER NOT NULL DEFAULT 0 CHECK (risk_count >= 0),
    blocked_count INTEGER NOT NULL DEFAULT 0 CHECK (blocked_count >= 0),
    llm_count INTEGER NOT NULL DEFAULT 0 CHECK (llm_count >= 0),
    ai_ide_count INTEGER NOT NULL DEFAULT 0 CHECK (ai_ide_count >= 0),
    normal_public_count INTEGER NOT NULL DEFAULT 0 CHECK (normal_public_count >= 0),
    retained_content_count INTEGER NOT NULL DEFAULT 0 CHECK (retained_content_count >= 0),
    forward_count INTEGER NOT NULL DEFAULT 0 CHECK (forward_count >= 0),
    reverse_count INTEGER NOT NULL DEFAULT 0 CHECK (reverse_count >= 0),
    device_count INTEGER NOT NULL DEFAULT 0 CHECK (device_count >= 0),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, bucket_start, access_direction, access_type, provider, target_host, risk_state)
);

CREATE INDEX IF NOT EXISTS idx_access_rollup_hourly_tenant_bucket
    ON access_rollup_hourly(tenant_id, bucket_start DESC);

CREATE INDEX IF NOT EXISTS idx_access_rollup_hourly_provider_bucket
    ON access_rollup_hourly(tenant_id, provider, bucket_start DESC);

CREATE INDEX IF NOT EXISTS idx_access_rollup_hourly_target_bucket
    ON access_rollup_hourly(tenant_id, target_host, bucket_start DESC);

COMMENT ON TABLE usage_rollup_hourly IS 'Hourly usage and cost read model for console statistics.';
COMMENT ON TABLE access_rollup_hourly IS 'Hourly access-retention summary read model for console statistics.';
