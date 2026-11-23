-- +goose Up
-- +goose StatementBegin
-- Monthly funding is real wallet money, separated from permanent credit/redemption.
CREATE TABLE IF NOT EXISTS billing_wallet_monthly_grants (
 id VARCHAR(64) PRIMARY KEY,
 tenant_id VARCHAR(64) NOT NULL,
 wallet_id VARCHAR(64) NOT NULL,
 user_id VARCHAR(64) NOT NULL,
 currency VARCHAR(8) NOT NULL,
 month_start TIMESTAMPTZ NOT NULL,
 month_end TIMESTAMPTZ NOT NULL,
 timezone VARCHAR(64) NOT NULL,
 amount_micros BIGINT NOT NULL CHECK(amount_micros > 0),
 remaining_micros BIGINT NOT NULL,
 reserved_micros BIGINT NOT NULL DEFAULT 0,
 expired_micros BIGINT NOT NULL DEFAULT 0,
 adjusted_micros BIGINT NOT NULL DEFAULT 0,
 expired_at TIMESTAMPTZ,
 created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
 updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
 CONSTRAINT fk_monthly_grant_wallet FOREIGN KEY(wallet_id,tenant_id) REFERENCES billing_wallets(id,tenant_id),
 CONSTRAINT fk_monthly_grant_user FOREIGN KEY(user_id,tenant_id) REFERENCES users(id,tenant_id),
 CONSTRAINT uq_monthly_grant_period UNIQUE(tenant_id,wallet_id,month_start),
 CONSTRAINT uq_monthly_grant_owner UNIQUE(id,tenant_id,wallet_id),
 CONSTRAINT ck_monthly_grant_period CHECK(month_end>month_start),
 CONSTRAINT ck_monthly_grant_money CHECK(reserved_micros>=0 AND remaining_micros>=reserved_micros AND expired_micros>=0 AND adjusted_micros>=0 AND remaining_micros+expired_micros+adjusted_micros<=amount_micros)
);
CREATE INDEX IF NOT EXISTS idx_monthly_grant_expiry ON billing_wallet_monthly_grants(month_end,wallet_id) WHERE remaining_micros>0;
CREATE TABLE IF NOT EXISTS billing_wallet_monthly_allocations (
 tenant_id VARCHAR(64) NOT NULL,
 wallet_id VARCHAR(64) NOT NULL,
 reservation_id VARCHAR(64) NOT NULL,
 grant_id VARCHAR(64) NOT NULL,
 amount_micros BIGINT NOT NULL CHECK(amount_micros>=0),
 created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
 PRIMARY KEY(tenant_id,reservation_id,grant_id),
 CONSTRAINT fk_monthly_allocation_reservation FOREIGN KEY(reservation_id,tenant_id,wallet_id) REFERENCES billing_reservations(id,tenant_id,wallet_id),
 CONSTRAINT fk_monthly_allocation_grant FOREIGN KEY(grant_id,tenant_id,wallet_id) REFERENCES billing_wallet_monthly_grants(id,tenant_id,wallet_id)
);
CREATE TABLE IF NOT EXISTS billing_wallet_monthly_worker_cursor (
 worker_name VARCHAR(64) PRIMARY KEY,
 cursor_tenant_id VARCHAR(64) NOT NULL DEFAULT '',
 cursor_user_id VARCHAR(64) NOT NULL DEFAULT '',
 updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
-- A token-only quote may have zero monetary preoccupation and nonzero actual
-- usage. Its legitimate final debit must remain visible in the append-only ledger.
ALTER TABLE billing_ledger_entries DROP CONSTRAINT IF EXISTS ck_billing_ledger_delta_shape;
ALTER TABLE billing_ledger_entries ADD CONSTRAINT ck_billing_ledger_delta_shape CHECK (
 (event_type IN ('credit','redemption','refund') AND balance_delta_micros>0 AND reserved_delta_micros=0) OR
 (event_type='adjustment' AND balance_delta_micros<>0 AND reserved_delta_micros=0) OR
 (event_type='reserve' AND balance_delta_micros=0 AND reserved_delta_micros>0) OR
 (event_type='settle' AND balance_delta_micros<=0 AND reserved_delta_micros<=0 AND (reserved_delta_micros<0 OR (balance_delta_micros<0 AND reservation_id IS NOT NULL AND request_id IS NOT NULL))) OR
 (event_type='release' AND balance_delta_micros=0 AND reserved_delta_micros<0)
);
COMMENT ON TABLE billing_wallet_monthly_grants IS 'Monthly non-carryover funding; remaining includes funds frozen for original in-flight requests';
COMMENT ON TABLE billing_wallet_monthly_allocations IS 'Immutable admission funding split; legacy reservations without rows use permanent wallet money';
-- +goose StatementEnd
-- +goose Down
-- Financial history is append-only. Rollback requires explicit reconciliation;
-- do not drop grants or allocations from a funded installation.
