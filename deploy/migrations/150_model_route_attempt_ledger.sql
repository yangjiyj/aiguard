CREATE TABLE IF NOT EXISTS model_route_attempts (
    attempt_id TEXT PRIMARY KEY,
    logical_request_id TEXT NOT NULL,
    client_retry_id TEXT NOT NULL DEFAULT '',
    tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    provider_id TEXT REFERENCES providers(id) ON DELETE SET NULL,
    model_id TEXT REFERENCES models(id) ON DELETE SET NULL,
    endpoint_type TEXT NOT NULL,
    started_at TIMESTAMPTZ NOT NULL,
    finished_at TIMESTAMPTZ,
    dispatch_state TEXT NOT NULL CHECK (dispatch_state IN ('not_dispatched','dispatch_started','dispatched','unknown')),
    upstream_outcome TEXT NOT NULL DEFAULT 'pending' CHECK (upstream_outcome IN ('pending','success','http_error','network_error','timeout','canceled','protocol_error','unknown')),
    result_unknown BOOLEAN NOT NULL DEFAULT FALSE,
    downstream_commit_state TEXT NOT NULL DEFAULT 'not_started',
    delivery_outcome TEXT NOT NULL DEFAULT 'pending' CHECK (delivery_outcome IN ('pending','completed','aborted','not_started','client_canceled','unknown')),
    usage_evidence_json JSONB NOT NULL DEFAULT '{}'::jsonb,
    cost_evidence_json JSONB NOT NULL DEFAULT '{}'::jsonb,
    ledger_schema_version SMALLINT NOT NULL DEFAULT 1,
    rollout_marker TEXT NOT NULL DEFAULT 'forwarding-governance-v1',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_model_route_attempts_logical_request
    ON model_route_attempts (tenant_id, logical_request_id, started_at, attempt_id);
CREATE INDEX IF NOT EXISTS idx_model_route_attempts_reconcile
    ON model_route_attempts (upstream_outcome, delivery_outcome, started_at)
    WHERE finished_at IS NULL OR delivery_outcome='pending';

COMMENT ON TABLE model_route_attempts IS
    'Attempt facts begin at forwarding-governance-v1; older request history is intentionally not reconstructed.';
