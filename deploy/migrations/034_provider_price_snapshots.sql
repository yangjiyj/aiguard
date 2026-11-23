-- 034_provider_price_snapshots.sql
CREATE TABLE IF NOT EXISTS provider_price_snapshots (
    id BIGSERIAL PRIMARY KEY,
    snapshot_date DATE NOT NULL,
    provider_id VARCHAR(64) NOT NULL,
    model_id VARCHAR(64) NOT NULL,
    input_price DECIMAL(18,6),
    output_price DECIMAL(18,6),
    currency VARCHAR(8),
    UNIQUE (snapshot_date, provider_id, model_id)
);
CREATE INDEX IF NOT EXISTS idx_provider_price_date ON provider_price_snapshots(snapshot_date DESC);
COMMENT ON TABLE provider_price_snapshots IS '每日 provider×model 价格快照，议价节省口径用';
