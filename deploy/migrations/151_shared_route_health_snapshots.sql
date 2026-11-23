CREATE TABLE IF NOT EXISTS model_route_health_snapshots (
    tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    model_name TEXT NOT NULL,
    provider_id TEXT NOT NULL REFERENCES providers(id) ON DELETE CASCADE,
    state TEXT NOT NULL CHECK (state IN ('unknown','healthy','degraded','unhealthy')),
    version BIGINT NOT NULL,
    observed_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    source_instance TEXT NOT NULL,
    failure_category TEXT NOT NULL DEFAULT '',
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, model_name, provider_id)
);

CREATE INDEX IF NOT EXISTS idx_model_route_health_snapshots_active
    ON model_route_health_snapshots (expires_at, tenant_id, model_name);
