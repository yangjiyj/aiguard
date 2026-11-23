-- Expand-only active monitoring. Historical billing/request rows are unchanged.
CREATE TABLE IF NOT EXISTS model_ops_configs (
    tenant_id TEXT PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
    version BIGINT NOT NULL DEFAULT 1 CHECK (version > 0),
    enabled BOOLEAN NOT NULL DEFAULT FALSE,
    interval_seconds INTEGER NOT NULL DEFAULT 300 CHECK (interval_seconds BETWEEN 60 AND 86400),
    concurrency INTEGER NOT NULL DEFAULT 2 CHECK (concurrency BETWEEN 1 AND 5),
    timeout_seconds INTEGER NOT NULL DEFAULT 15 CHECK (timeout_seconds BETWEEN 1 AND 60),
    max_targets INTEGER NOT NULL DEFAULT 50 CHECK (max_targets BETWEEN 1 AND 100),
    max_output_tokens INTEGER NOT NULL DEFAULT 128 CHECK (max_output_tokens BETWEEN 1 AND 1024),
    protocols TEXT[] NOT NULL DEFAULT ARRAY['chat','responses','messages']::TEXT[] CHECK (cardinality(protocols) BETWEEN 1 AND 3 AND protocols <@ ARRAY['chat','responses','messages']::TEXT[]),
    failure_threshold INTEGER NOT NULL DEFAULT 3 CHECK (failure_threshold BETWEEN 1 AND 10),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_by TEXT NOT NULL DEFAULT '',
    cost_confirmed_at TIMESTAMPTZ,
    cost_confirmed_by TEXT NOT NULL DEFAULT '',
    cursor_key TEXT NOT NULL DEFAULT '',
    next_batch_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CHECK (NOT enabled OR (cost_confirmed_at IS NOT NULL AND cost_confirmed_by <> ''))
);

CREATE TABLE IF NOT EXISTS model_ops_leases (
    tenant_id TEXT PRIMARY KEY REFERENCES model_ops_configs(tenant_id) ON DELETE CASCADE,
    epoch BIGINT NOT NULL DEFAULT 0,
    token TEXT NOT NULL DEFAULT '',
    owner TEXT NOT NULL DEFAULT '',
    config_version BIGINT NOT NULL DEFAULT 1,
    expires_at TIMESTAMPTZ NOT NULL DEFAULT '-infinity'
);

CREATE TABLE IF NOT EXISTS model_ops_target_schedule (
    tenant_id TEXT NOT NULL REFERENCES model_ops_configs(tenant_id) ON DELETE CASCADE,
    target_key TEXT NOT NULL,
    identity_digest TEXT NOT NULL,
    next_probe_at TIMESTAMPTZ NOT NULL DEFAULT '-infinity',
    last_probe_at TIMESTAMPTZ,
    claim_epoch BIGINT NOT NULL DEFAULT 0,
    claim_token TEXT NOT NULL DEFAULT '',
    dispatch_deadline TIMESTAMPTZ NOT NULL DEFAULT '-infinity',
    PRIMARY KEY (tenant_id,target_key)
);

CREATE TABLE IF NOT EXISTS model_ops_probe_history (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    model_id TEXT NOT NULL,
    model_name TEXT NOT NULL,
    provider_id TEXT NOT NULL,
    provider_name TEXT NOT NULL,
    upstream_model_id TEXT NOT NULL,
    protocol TEXT NOT NULL CHECK (protocol IN ('chat','responses','messages')),
    config_digest TEXT NOT NULL,
    identity_digest TEXT NOT NULL,
    source TEXT NOT NULL CHECK (source IN ('manual','scheduled')),
    actor TEXT NOT NULL,
    config_version BIGINT NOT NULL,
    epoch BIGINT NOT NULL DEFAULT 0,
    invocation_id TEXT NOT NULL DEFAULT '',
    success BOOLEAN NOT NULL,
    http_status INTEGER NOT NULL CHECK (http_status BETWEEN 0 AND 599),
    body_validated BOOLEAN NOT NULL,
    latency_ms BIGINT NOT NULL CHECK (latency_ms >= 0),
    error_kind TEXT NOT NULL CHECK (error_kind IN ('','unauthorized','not_deployed','rate_limited','upstream_error','timeout','cancelled','invalid_request','invalid_body','transport_error','config_changed','unavailable','unsupported')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CHECK (NOT success OR (body_validated AND http_status BETWEEN 200 AND 299 AND error_kind=''))
);
CREATE INDEX IF NOT EXISTS idx_model_ops_history_tenant_cursor ON model_ops_probe_history(tenant_id,created_at DESC,id DESC);
CREATE INDEX IF NOT EXISTS idx_model_ops_history_target ON model_ops_probe_history(tenant_id,model_id,provider_id,protocol,identity_digest,created_at DESC);
CREATE INDEX IF NOT EXISTS idx_model_ops_history_invocation ON model_ops_probe_history(tenant_id,invocation_id,created_at,id);

CREATE TABLE IF NOT EXISTS model_ops_alerts (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    model_id TEXT NOT NULL,
    model_name TEXT NOT NULL,
    provider_id TEXT NOT NULL,
    provider_name TEXT NOT NULL,
    upstream_model_id TEXT NOT NULL,
    protocol TEXT NOT NULL CHECK (protocol IN ('chat','responses','messages')),
    config_digest TEXT NOT NULL,
    identity_digest TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('open','resolved')),
    failure_count INTEGER NOT NULL CHECK (failure_count > 0),
    last_error TEXT NOT NULL,
    opened_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    resolved_at TIMESTAMPTZ,
    acknowledged_at TIMESTAMPTZ,
    acknowledged_by TEXT NOT NULL DEFAULT '',
    CHECK ((state='open' AND resolved_at IS NULL) OR (state='resolved' AND resolved_at IS NOT NULL))
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_model_ops_alert_open ON model_ops_alerts(tenant_id,model_id,provider_id,protocol,identity_digest) WHERE state='open';
CREATE INDEX IF NOT EXISTS idx_model_ops_alert_cursor ON model_ops_alerts(tenant_id,opened_at DESC,id DESC);

CREATE TABLE IF NOT EXISTS model_ops_config_audit (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    previous_version BIGINT NOT NULL,
    version BIGINT NOT NULL,
    actor TEXT NOT NULL,
    config_json JSONB NOT NULL,
    cost_confirmed BOOLEAN NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (tenant_id,version)
);

CREATE TABLE IF NOT EXISTS model_operations_jobs (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES model_ops_configs(tenant_id) ON DELETE CASCADE,
    actor TEXT NOT NULL,
    request_key TEXT NOT NULL,
    request_sha256 TEXT NOT NULL,
    request_json JSONB NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('queued','running','completed','failed','cancelled','interrupted')),
    result_json JSONB NOT NULL DEFAULT '{}'::JSONB,
    error_code TEXT NOT NULL DEFAULT '',
    cancel_requested BOOLEAN NOT NULL DEFAULT FALSE,
    owner_token TEXT NOT NULL DEFAULT '',
    lease_until TIMESTAMPTZ NOT NULL DEFAULT '-infinity',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at TIMESTAMPTZ,
    UNIQUE (tenant_id,actor,request_key)
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_model_operations_jobs_active ON model_operations_jobs(tenant_id) WHERE state IN ('queued','running');

CREATE TABLE IF NOT EXISTS model_ops_manual_claims (
    tenant_id TEXT NOT NULL REFERENCES model_ops_configs(tenant_id) ON DELETE CASCADE,
    invocation_id TEXT NOT NULL,
    target_key TEXT NOT NULL,
    identity_digest TEXT NOT NULL,
    config_version BIGINT NOT NULL,
    owner_token TEXT NOT NULL DEFAULT '',
    completed BOOLEAN NOT NULL DEFAULT FALSE,
    dispatch_deadline TIMESTAMPTZ NOT NULL,
    claimed_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (tenant_id,invocation_id,target_key)
);
