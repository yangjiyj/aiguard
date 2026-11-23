-- +goose Up
-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS billing_request_leases (
    tenant_id VARCHAR(64) NOT NULL,
    user_id VARCHAR(64) NOT NULL,
    request_id VARCHAR(128) NOT NULL,
    acquired_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    released_at TIMESTAMPTZ,
    PRIMARY KEY (tenant_id, request_id),
    CONSTRAINT fk_billing_request_lease_user
        FOREIGN KEY (user_id, tenant_id) REFERENCES users(id, tenant_id) ON DELETE CASCADE,
    CONSTRAINT ck_billing_request_lease_expiry CHECK (expires_at > acquired_at),
    CONSTRAINT ck_billing_request_lease_release CHECK (
        released_at IS NULL OR released_at >= acquired_at
    )
);

CREATE INDEX IF NOT EXISTS idx_billing_request_leases_user_acquired
    ON billing_request_leases(tenant_id, user_id, acquired_at DESC);
CREATE INDEX IF NOT EXISTS idx_billing_request_leases_user_active
    ON billing_request_leases(tenant_id, user_id, expires_at)
    WHERE released_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_billing_request_leases_expiry
    ON billing_request_leases(expires_at)
    WHERE released_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_billing_request_leases_released
    ON billing_request_leases(acquired_at)
    WHERE released_at IS NOT NULL;

-- Request rate limiting no longer scans financial reservations.
DROP INDEX IF EXISTS idx_billing_reservations_wallet_created;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS billing_request_leases;
CREATE INDEX IF NOT EXISTS idx_billing_reservations_wallet_created
    ON billing_reservations(wallet_id, created_at DESC);
-- +goose StatementEnd
