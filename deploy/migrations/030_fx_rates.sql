-- +goose Up
-- +goose StatementBegin

CREATE TABLE IF NOT EXISTS fx_rates (
    id BIGSERIAL PRIMARY KEY,
    base_currency VARCHAR(8) NOT NULL DEFAULT 'USD',
    target_currency VARCHAR(8) NOT NULL DEFAULT 'CNY',
    rate DECIMAL(18,6) NOT NULL,
    effective_at TIMESTAMP WITH TIME ZONE NOT NULL,
    created_by VARCHAR(64),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_fx_rates_effective ON fx_rates(effective_at DESC);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS fx_rates;
-- +goose StatementEnd
