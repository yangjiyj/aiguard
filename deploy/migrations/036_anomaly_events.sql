-- 036_anomaly_events.sql
CREATE TABLE IF NOT EXISTS anomaly_events (
    id VARCHAR(64) PRIMARY KEY,
    tenant_id VARCHAR(64) NOT NULL,
    detected_date DATE NOT NULL,
    dimension VARCHAR(32) NOT NULL,
    scope_type VARCHAR(16),
    scope_id VARCHAR(64),
    baseline DECIMAL(18,6),
    actual DECIMAL(18,6),
    severity VARCHAR(16) NOT NULL,
    detail_json JSONB,
    acked_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    UNIQUE (tenant_id, detected_date, dimension, scope_type, scope_id)
);
CREATE INDEX IF NOT EXISTS idx_anomaly_tenant_date ON anomaly_events(tenant_id, detected_date DESC);
COMMENT ON COLUMN anomaly_events.dimension IS 'absolute_spike|yoy|dod|new_model|key_surge';
