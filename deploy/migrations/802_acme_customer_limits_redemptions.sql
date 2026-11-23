-- +goose Up
-- +goose StatementBegin
-- New API compatible customer-side caps and one-time redemption cards. These
-- tables remain exclusive to the Acme customer branch (800-849 range).
ALTER TABLE billing_reservations
    ADD COLUMN IF NOT EXISTS reserved_tokens BIGINT NOT NULL DEFAULT 0;
ALTER TABLE billing_reservations DROP CONSTRAINT IF EXISTS ck_billing_reservation_amount;
ALTER TABLE billing_reservations ADD CONSTRAINT ck_billing_reservation_amount CHECK (
    reserved_micros >= 0 AND reserved_tokens >= 0 AND (reserved_micros > 0 OR reserved_tokens > 0)
);
CREATE TABLE IF NOT EXISTS billing_customer_limits (
    tenant_id VARCHAR(64) NOT NULL, user_id VARCHAR(64) NOT NULL,
    daily_amount_micros BIGINT NOT NULL DEFAULT 0, monthly_amount_micros BIGINT NOT NULL DEFAULT 0,
    daily_token_limit BIGINT NOT NULL DEFAULT 0, monthly_token_limit BIGINT NOT NULL DEFAULT 0,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), PRIMARY KEY (tenant_id, user_id),
    CONSTRAINT fk_billing_customer_limit_user FOREIGN KEY (user_id, tenant_id) REFERENCES users(id, tenant_id),
    CONSTRAINT ck_billing_customer_limits_nonnegative CHECK (
        daily_amount_micros >= 0 AND monthly_amount_micros >= 0 AND daily_token_limit >= 0 AND monthly_token_limit >= 0
    )
);
CREATE TABLE IF NOT EXISTS billing_limit_counters (
    tenant_id VARCHAR(64) NOT NULL, user_id VARCHAR(64) NOT NULL, period_kind VARCHAR(8) NOT NULL, period_start DATE NOT NULL,
    settled_amount_micros BIGINT NOT NULL DEFAULT 0, reserved_amount_micros BIGINT NOT NULL DEFAULT 0,
    settled_tokens BIGINT NOT NULL DEFAULT 0, reserved_tokens BIGINT NOT NULL DEFAULT 0, updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, user_id, period_kind, period_start),
    CONSTRAINT fk_billing_limit_counter_user FOREIGN KEY (user_id, tenant_id) REFERENCES users(id, tenant_id),
    CONSTRAINT ck_billing_limit_counter_kind CHECK (period_kind IN ('daily', 'monthly')),
    CONSTRAINT ck_billing_limit_counter_values CHECK (
        settled_amount_micros >= 0 AND reserved_amount_micros >= 0 AND settled_tokens >= 0 AND reserved_tokens >= 0
    )
);
CREATE INDEX IF NOT EXISTS idx_billing_limit_counters_user_period ON billing_limit_counters(tenant_id, user_id, period_start DESC);
CREATE TABLE IF NOT EXISTS billing_redemption_codes (
    id VARCHAR(64) PRIMARY KEY, tenant_id VARCHAR(64) NOT NULL REFERENCES tenants(id), code_hash CHAR(64) NOT NULL,
    code_hint VARCHAR(32) NOT NULL, label VARCHAR(80) NOT NULL, amount_micros BIGINT NOT NULL,
    status VARCHAR(16) NOT NULL DEFAULT 'active', expires_at TIMESTAMPTZ, created_by VARCHAR(64),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), redeemed_at TIMESTAMPTZ,
    CONSTRAINT uq_billing_redemption_code UNIQUE (tenant_id, code_hash),
    CONSTRAINT ck_billing_redemption_amount CHECK (amount_micros > 0),
    CONSTRAINT ck_billing_redemption_status CHECK (status IN ('active', 'disabled', 'redeemed'))
);
CREATE INDEX IF NOT EXISTS idx_billing_redemption_codes_tenant_status ON billing_redemption_codes(tenant_id, status, created_at DESC);
CREATE TABLE IF NOT EXISTS billing_redemption_uses (
    id VARCHAR(64) PRIMARY KEY, tenant_id VARCHAR(64) NOT NULL, code_id VARCHAR(64) NOT NULL,
    user_id VARCHAR(64) NOT NULL, wallet_id VARCHAR(64) NOT NULL, amount_micros BIGINT NOT NULL,
    redeemed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_billing_redemption_use_code UNIQUE (tenant_id, code_id),
    CONSTRAINT fk_billing_redemption_use_code FOREIGN KEY (code_id) REFERENCES billing_redemption_codes(id),
    CONSTRAINT fk_billing_redemption_use_wallet FOREIGN KEY (wallet_id, tenant_id) REFERENCES billing_wallets(id, tenant_id),
    CONSTRAINT ck_billing_redemption_use_amount CHECK (amount_micros > 0)
);
CREATE INDEX IF NOT EXISTS idx_billing_redemption_uses_user ON billing_redemption_uses(tenant_id, user_id, redeemed_at DESC);
ALTER TABLE billing_ledger_entries DROP CONSTRAINT IF EXISTS ck_billing_ledger_event;
ALTER TABLE billing_ledger_entries ADD CONSTRAINT ck_billing_ledger_event CHECK (
    event_type IN ('credit', 'adjustment', 'redemption', 'reserve', 'settle', 'release', 'refund')
);
ALTER TABLE billing_ledger_entries DROP CONSTRAINT IF EXISTS ck_billing_ledger_delta_shape;
ALTER TABLE billing_ledger_entries ADD CONSTRAINT ck_billing_ledger_delta_shape CHECK (
    (event_type IN ('credit', 'redemption', 'refund') AND balance_delta_micros > 0 AND reserved_delta_micros = 0) OR
    (event_type = 'adjustment' AND balance_delta_micros <> 0 AND reserved_delta_micros = 0) OR
    (event_type = 'reserve' AND balance_delta_micros = 0 AND reserved_delta_micros > 0) OR
    (event_type = 'settle' AND balance_delta_micros <= 0 AND reserved_delta_micros < 0) OR
    (event_type = 'release' AND balance_delta_micros = 0 AND reserved_delta_micros < 0)
);
-- +goose StatementEnd
-- +goose Down
ALTER TABLE billing_ledger_entries DROP CONSTRAINT IF EXISTS ck_billing_ledger_delta_shape;
ALTER TABLE billing_ledger_entries DROP CONSTRAINT IF EXISTS ck_billing_ledger_event;
ALTER TABLE billing_ledger_entries ADD CONSTRAINT ck_billing_ledger_event CHECK (
    event_type IN ('credit', 'adjustment', 'reserve', 'settle', 'release', 'refund')
);
ALTER TABLE billing_ledger_entries ADD CONSTRAINT ck_billing_ledger_delta_shape CHECK (
    (event_type IN ('credit', 'refund') AND balance_delta_micros > 0 AND reserved_delta_micros = 0) OR
    (event_type = 'adjustment' AND balance_delta_micros <> 0 AND reserved_delta_micros = 0) OR
    (event_type = 'reserve' AND balance_delta_micros = 0 AND reserved_delta_micros > 0) OR
    (event_type = 'settle' AND balance_delta_micros <= 0 AND reserved_delta_micros < 0) OR
    (event_type = 'release' AND balance_delta_micros = 0 AND reserved_delta_micros < 0)
);
DROP TABLE IF EXISTS billing_redemption_uses;
DROP TABLE IF EXISTS billing_redemption_codes;
DROP INDEX IF EXISTS idx_billing_limit_counters_user_period;
DROP TABLE IF EXISTS billing_limit_counters;
DROP TABLE IF EXISTS billing_customer_limits;
ALTER TABLE billing_reservations DROP CONSTRAINT IF EXISTS ck_billing_reservation_amount;
ALTER TABLE billing_reservations ADD CONSTRAINT ck_billing_reservation_amount CHECK (reserved_micros > 0);
ALTER TABLE billing_reservations DROP COLUMN IF EXISTS reserved_tokens;
