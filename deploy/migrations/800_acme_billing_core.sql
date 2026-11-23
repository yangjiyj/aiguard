-- +goose Up
-- +goose StatementBegin
-- 800-849 is reserved for the Acme customer branch. This migration must
-- not be cherry-picked into main without an explicit productization review.

CREATE UNIQUE INDEX IF NOT EXISTS idx_users_id_tenant_unique
    ON users(id, tenant_id);

CREATE TABLE IF NOT EXISTS billing_wallets (
    id VARCHAR(64) PRIMARY KEY,
    tenant_id VARCHAR(64) NOT NULL REFERENCES tenants(id),
    user_id VARCHAR(64) NOT NULL,
    currency VARCHAR(8) NOT NULL DEFAULT 'CNY',
    balance_micros BIGINT NOT NULL DEFAULT 0,
    reserved_micros BIGINT NOT NULL DEFAULT 0,
    version BIGINT NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT fk_billing_wallet_user_tenant
        FOREIGN KEY (user_id, tenant_id) REFERENCES users(id, tenant_id),
    CONSTRAINT uq_billing_wallet_owner UNIQUE (tenant_id, user_id, currency),
    CONSTRAINT uq_billing_wallet_id_tenant UNIQUE (id, tenant_id),
    CONSTRAINT ck_billing_wallet_currency CHECK (currency ~ '^[A-Z]{3,8}$'),
    CONSTRAINT ck_billing_wallet_reserved_nonnegative CHECK (reserved_micros >= 0)
);

CREATE INDEX IF NOT EXISTS idx_billing_wallets_tenant_updated
    ON billing_wallets(tenant_id, updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_billing_wallets_user
    ON billing_wallets(tenant_id, user_id);

CREATE TABLE IF NOT EXISTS billing_reservations (
    id VARCHAR(64) PRIMARY KEY,
    tenant_id VARCHAR(64) NOT NULL,
    wallet_id VARCHAR(64) NOT NULL,
    request_id VARCHAR(128) NOT NULL,
    reserved_micros BIGINT NOT NULL,
    settled_micros BIGINT,
    status VARCHAR(16) NOT NULL DEFAULT 'reserved',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    finalized_at TIMESTAMPTZ,
    CONSTRAINT fk_billing_reservation_wallet
        FOREIGN KEY (wallet_id, tenant_id) REFERENCES billing_wallets(id, tenant_id),
    CONSTRAINT uq_billing_reservation_request UNIQUE (tenant_id, request_id),
    CONSTRAINT uq_billing_reservation_wallet_owner UNIQUE (id, tenant_id, wallet_id),
    CONSTRAINT ck_billing_reservation_amount CHECK (reserved_micros > 0),
    CONSTRAINT ck_billing_reservation_settled CHECK (settled_micros IS NULL OR settled_micros >= 0),
    CONSTRAINT ck_billing_reservation_status CHECK (status IN ('reserved', 'settled', 'released')),
    CONSTRAINT ck_billing_reservation_finalization CHECK (
        (status = 'reserved' AND settled_micros IS NULL AND finalized_at IS NULL) OR
        (status = 'released' AND settled_micros IS NULL AND finalized_at IS NOT NULL) OR
        (status = 'settled' AND settled_micros IS NOT NULL AND finalized_at IS NOT NULL)
    )
);

CREATE INDEX IF NOT EXISTS idx_billing_reservations_wallet_status
    ON billing_reservations(wallet_id, status, created_at DESC);

CREATE TABLE IF NOT EXISTS billing_ledger_entries (
    id VARCHAR(64) PRIMARY KEY,
    tenant_id VARCHAR(64) NOT NULL,
    wallet_id VARCHAR(64) NOT NULL,
    reservation_id VARCHAR(64),
    request_id VARCHAR(128),
    event_type VARCHAR(24) NOT NULL,
    balance_delta_micros BIGINT NOT NULL,
    reserved_delta_micros BIGINT NOT NULL,
    balance_after_micros BIGINT NOT NULL,
    reserved_after_micros BIGINT NOT NULL,
    idempotency_key VARCHAR(192) NOT NULL,
    actor_type VARCHAR(24) NOT NULL DEFAULT 'system',
    actor_id VARCHAR(64),
    metadata_json JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT fk_billing_ledger_wallet
        FOREIGN KEY (wallet_id, tenant_id) REFERENCES billing_wallets(id, tenant_id),
    CONSTRAINT fk_billing_ledger_reservation
        FOREIGN KEY (reservation_id, tenant_id, wallet_id)
        REFERENCES billing_reservations(id, tenant_id, wallet_id),
    CONSTRAINT uq_billing_ledger_idempotency UNIQUE (wallet_id, idempotency_key),
    CONSTRAINT ck_billing_ledger_event CHECK (
        event_type IN ('credit', 'adjustment', 'reserve', 'settle', 'release', 'refund')
    ),
    CONSTRAINT ck_billing_ledger_reserved_after CHECK (reserved_after_micros >= 0),
    CONSTRAINT ck_billing_ledger_delta_shape CHECK (
        (event_type IN ('credit', 'refund') AND balance_delta_micros > 0 AND reserved_delta_micros = 0) OR
        (event_type = 'adjustment' AND balance_delta_micros <> 0 AND reserved_delta_micros = 0) OR
        (event_type = 'reserve' AND balance_delta_micros = 0 AND reserved_delta_micros > 0) OR
        (event_type = 'settle' AND balance_delta_micros <= 0 AND reserved_delta_micros < 0) OR
        (event_type = 'release' AND balance_delta_micros = 0 AND reserved_delta_micros < 0)
    )
);

CREATE INDEX IF NOT EXISTS idx_billing_ledger_tenant_created
    ON billing_ledger_entries(tenant_id, created_at DESC, id DESC);
CREATE INDEX IF NOT EXISTS idx_billing_ledger_wallet_created
    ON billing_ledger_entries(wallet_id, created_at DESC, id DESC);
CREATE INDEX IF NOT EXISTS idx_billing_ledger_request
    ON billing_ledger_entries(tenant_id, request_id)
    WHERE request_id IS NOT NULL;

CREATE OR REPLACE FUNCTION reject_billing_audit_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'billing audit table % is append-only', TG_TABLE_NAME
        USING ERRCODE = '55000';
END;
$$;

DROP TRIGGER IF EXISTS trg_billing_ledger_append_only ON billing_ledger_entries;
CREATE TRIGGER trg_billing_ledger_append_only
    BEFORE UPDATE OR DELETE ON billing_ledger_entries
    FOR EACH ROW EXECUTE FUNCTION reject_billing_audit_mutation();

CREATE TABLE IF NOT EXISTS billing_model_prices (
    id VARCHAR(64) PRIMARY KEY,
    tenant_id VARCHAR(64) NOT NULL REFERENCES tenants(id),
    model_name VARCHAR(255) NOT NULL,
    customer_group VARCHAR(64) NOT NULL DEFAULT 'default',
    version INTEGER NOT NULL,
    pricing_mode VARCHAR(16) NOT NULL DEFAULT 'direct',
    currency VARCHAR(8) NOT NULL DEFAULT 'CNY',
    input_per_million_micros BIGINT,
    cached_input_per_million_micros BIGINT,
    cache_write_per_million_micros BIGINT,
    output_per_million_micros BIGINT,
    base_input_per_million_micros BIGINT,
    model_ratio_ppm BIGINT,
    completion_ratio_ppm BIGINT,
    group_ratio_ppm BIGINT,
    cached_input_ratio_ppm BIGINT,
    cache_write_ratio_ppm BIGINT,
    status VARCHAR(16) NOT NULL DEFAULT 'active',
    effective_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ,
    created_by VARCHAR(64),
    metadata_json JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_billing_model_price_version
        UNIQUE (tenant_id, model_name, customer_group, version),
    CONSTRAINT uq_billing_model_price_id_tenant UNIQUE (id, tenant_id),
    CONSTRAINT ck_billing_model_price_mode CHECK (pricing_mode IN ('direct', 'newapi_ratio')),
    CONSTRAINT ck_billing_model_price_status CHECK (status IN ('draft', 'active', 'retired')),
    CONSTRAINT ck_billing_model_price_currency CHECK (currency ~ '^[A-Z]{3,8}$'),
    CONSTRAINT ck_billing_model_price_window CHECK (expires_at IS NULL OR expires_at > effective_at),
    CONSTRAINT ck_billing_model_price_nonnegative CHECK (
        COALESCE(input_per_million_micros, 0) >= 0 AND
        COALESCE(cached_input_per_million_micros, 0) >= 0 AND
        COALESCE(cache_write_per_million_micros, 0) >= 0 AND
        COALESCE(output_per_million_micros, 0) >= 0 AND
        COALESCE(base_input_per_million_micros, 0) >= 0 AND
        COALESCE(model_ratio_ppm, 0) >= 0 AND
        COALESCE(completion_ratio_ppm, 0) >= 0 AND
        COALESCE(group_ratio_ppm, 0) >= 0 AND
        COALESCE(cached_input_ratio_ppm, 0) >= 0 AND
        COALESCE(cache_write_ratio_ppm, 0) >= 0
    ),
    CONSTRAINT ck_billing_model_price_fields CHECK (
        (pricing_mode = 'direct' AND input_per_million_micros IS NOT NULL AND output_per_million_micros IS NOT NULL)
        OR
        (pricing_mode = 'newapi_ratio' AND base_input_per_million_micros IS NOT NULL AND model_ratio_ppm IS NOT NULL)
    )
);

CREATE INDEX IF NOT EXISTS idx_billing_model_prices_lookup
    ON billing_model_prices(tenant_id, model_name, customer_group, effective_at DESC, version DESC)
    WHERE status = 'active';

CREATE TABLE IF NOT EXISTS billing_charge_records (
    id VARCHAR(64) PRIMARY KEY,
    tenant_id VARCHAR(64) NOT NULL,
    wallet_id VARCHAR(64) NOT NULL,
    reservation_id VARCHAR(64),
    price_id VARCHAR(64),
    request_id VARCHAR(128) NOT NULL,
    model_name VARCHAR(255) NOT NULL,
    prompt_tokens BIGINT NOT NULL DEFAULT 0,
    cached_input_tokens BIGINT NOT NULL DEFAULT 0,
    cache_write_input_tokens BIGINT NOT NULL DEFAULT 0,
    output_tokens BIGINT NOT NULL DEFAULT 0,
    reasoning_tokens BIGINT NOT NULL DEFAULT 0,
    input_per_million_micros BIGINT NOT NULL DEFAULT 0,
    cached_input_per_million_micros BIGINT NOT NULL DEFAULT 0,
    cache_write_per_million_micros BIGINT NOT NULL DEFAULT 0,
    output_per_million_micros BIGINT NOT NULL DEFAULT 0,
    amount_micros BIGINT NOT NULL DEFAULT 0,
    upstream_cost_micros BIGINT,
    pricing_mode VARCHAR(16) NOT NULL,
    currency VARCHAR(8) NOT NULL DEFAULT 'CNY',
    status VARCHAR(16) NOT NULL DEFAULT 'settled',
    raw_usage_json JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT fk_billing_charge_wallet
        FOREIGN KEY (wallet_id, tenant_id) REFERENCES billing_wallets(id, tenant_id),
    CONSTRAINT fk_billing_charge_reservation
        FOREIGN KEY (reservation_id, tenant_id, wallet_id)
        REFERENCES billing_reservations(id, tenant_id, wallet_id),
    CONSTRAINT fk_billing_charge_price
        FOREIGN KEY (price_id, tenant_id) REFERENCES billing_model_prices(id, tenant_id),
    CONSTRAINT uq_billing_charge_request UNIQUE (tenant_id, request_id),
    CONSTRAINT ck_billing_charge_usage CHECK (
        prompt_tokens >= 0 AND cached_input_tokens >= 0 AND cache_write_input_tokens >= 0 AND
        output_tokens >= 0 AND reasoning_tokens >= 0 AND
        cached_input_tokens + cache_write_input_tokens <= prompt_tokens AND
        reasoning_tokens <= output_tokens
    ),
    CONSTRAINT ck_billing_charge_amount CHECK (amount_micros >= 0),
    CONSTRAINT ck_billing_charge_status CHECK (status IN ('settled', 'released', 'unpriced', 'failed')),
    CONSTRAINT ck_billing_charge_price_snapshot CHECK (
        input_per_million_micros >= 0 AND cached_input_per_million_micros >= 0 AND
        cache_write_per_million_micros >= 0 AND output_per_million_micros >= 0 AND
        (upstream_cost_micros IS NULL OR upstream_cost_micros >= 0)
    ),
    CONSTRAINT ck_billing_charge_pricing_mode CHECK (pricing_mode IN ('direct', 'newapi_ratio')),
    CONSTRAINT ck_billing_charge_currency CHECK (currency ~ '^[A-Z]{3,8}$')
);

CREATE INDEX IF NOT EXISTS idx_billing_charges_wallet_created
    ON billing_charge_records(wallet_id, created_at DESC, id DESC);
CREATE INDEX IF NOT EXISTS idx_billing_charges_tenant_model_created
    ON billing_charge_records(tenant_id, model_name, created_at DESC);

DROP TRIGGER IF EXISTS trg_billing_charge_append_only ON billing_charge_records;
CREATE TRIGGER trg_billing_charge_append_only
    BEFORE UPDATE OR DELETE ON billing_charge_records
    FOR EACH ROW EXECUTE FUNCTION reject_billing_audit_mutation();

COMMENT ON TABLE billing_wallets IS 'Customer wallet; CNY amounts are integer micros and PostgreSQL is authoritative';
COMMENT ON TABLE billing_ledger_entries IS 'Immutable append-only balance and reservation audit ledger';
COMMENT ON TABLE billing_model_prices IS 'Versioned direct prices plus New API ratio compatibility inputs';
COMMENT ON TABLE billing_charge_records IS 'Per-request billable usage and immutable price snapshot';
COMMENT ON COLUMN billing_charge_records.upstream_cost_micros IS 'Optional upstream cost, distinct from customer billable amount';

-- +goose StatementEnd

-- +goose Down
-- Customer migration rollback is intentionally explicit and reverse-ordered.
DROP TABLE IF EXISTS billing_charge_records;
DROP TABLE IF EXISTS billing_model_prices;
DROP TRIGGER IF EXISTS trg_billing_ledger_append_only ON billing_ledger_entries;
DROP FUNCTION IF EXISTS reject_billing_audit_mutation();
DROP TABLE IF EXISTS billing_ledger_entries;
DROP TABLE IF EXISTS billing_reservations;
DROP TABLE IF EXISTS billing_wallets;
DROP INDEX IF EXISTS idx_users_id_tenant_unique;
