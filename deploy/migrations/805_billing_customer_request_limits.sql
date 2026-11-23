-- +goose Up
-- +goose StatementBegin
ALTER TABLE billing_customer_limits
    ADD COLUMN IF NOT EXISTS rpm_limit BIGINT NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS concurrency_limit BIGINT NOT NULL DEFAULT 0;

ALTER TABLE billing_customer_limits
    DROP CONSTRAINT IF EXISTS ck_billing_customer_limits_nonnegative;
ALTER TABLE billing_customer_limits
    ADD CONSTRAINT ck_billing_customer_limits_nonnegative CHECK (
        daily_amount_micros >= 0 AND monthly_amount_micros >= 0 AND
        daily_token_limit >= 0 AND monthly_token_limit >= 0 AND
        rpm_limit >= 0 AND concurrency_limit >= 0
    );

CREATE INDEX IF NOT EXISTS idx_billing_reservations_wallet_created
    ON billing_reservations(wallet_id, created_at DESC);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS idx_billing_reservations_wallet_created;

ALTER TABLE billing_customer_limits
    DROP CONSTRAINT IF EXISTS ck_billing_customer_limits_nonnegative;
ALTER TABLE billing_customer_limits
    DROP COLUMN IF EXISTS rpm_limit,
    DROP COLUMN IF EXISTS concurrency_limit;
ALTER TABLE billing_customer_limits
    ADD CONSTRAINT ck_billing_customer_limits_nonnegative CHECK (
        daily_amount_micros >= 0 AND monthly_amount_micros >= 0 AND
        daily_token_limit >= 0 AND monthly_token_limit >= 0
    );
-- +goose StatementEnd
