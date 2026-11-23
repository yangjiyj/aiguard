-- +goose Up
-- +goose StatementBegin
-- Productized customer groups for tenant-scoped billing. Group codes are
-- immutable business keys so historic price quotes remain explainable.
CREATE TABLE IF NOT EXISTS billing_customer_groups (
    id VARCHAR(64) PRIMARY KEY,
    tenant_id VARCHAR(64) NOT NULL REFERENCES tenants(id),
    code VARCHAR(64) NOT NULL,
    name VARCHAR(120) NOT NULL,
    description VARCHAR(255) NOT NULL DEFAULT '',
    status VARCHAR(16) NOT NULL DEFAULT 'active',
    is_default BOOLEAN NOT NULL DEFAULT FALSE,
    created_by VARCHAR(64),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_billing_customer_group_code UNIQUE (tenant_id, code),
    CONSTRAINT uq_billing_customer_group_id_tenant UNIQUE (id, tenant_id),
    CONSTRAINT ck_billing_customer_group_code CHECK (code <> '' AND length(code) <= 64),
    CONSTRAINT ck_billing_customer_group_status CHECK (status IN ('active', 'disabled'))
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_billing_customer_groups_one_default
    ON billing_customer_groups(tenant_id) WHERE is_default;
CREATE INDEX IF NOT EXISTS idx_billing_customer_groups_tenant_status
    ON billing_customer_groups(tenant_id, status, name, code);

-- Every existing tenant gets a stable fallback group. Preserve any historic
-- ad-hoc group strings already referenced by prices or reservations.
INSERT INTO billing_customer_groups (id, tenant_id, code, name, status, is_default)
SELECT 'group_' || md5(t.id || ':default'), t.id, 'default', 'Default customer group', 'active', TRUE
FROM tenants t
ON CONFLICT (tenant_id, code) DO UPDATE SET is_default = TRUE;

WITH historic_groups AS (
    SELECT tenant_id, customer_group AS code
    FROM billing_model_prices
    WHERE customer_group IS NOT NULL AND customer_group <> '' AND customer_group <> 'default'
    UNION
    SELECT tenant_id, customer_group AS code
    FROM billing_reservations
    WHERE customer_group IS NOT NULL AND customer_group <> '' AND customer_group <> 'default'
)
INSERT INTO billing_customer_groups (id, tenant_id, code, name, status, is_default)
SELECT 'group_' || md5(tenant_id || ':' || code), tenant_id, code, code, 'active', FALSE
FROM historic_groups
ON CONFLICT (tenant_id, code) DO NOTHING;

CREATE TABLE IF NOT EXISTS billing_customer_group_memberships (
    tenant_id VARCHAR(64) NOT NULL,
    user_id VARCHAR(64) NOT NULL,
    customer_group VARCHAR(64) NOT NULL,
    updated_by VARCHAR(64),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, user_id),
    CONSTRAINT fk_billing_customer_group_member_user
        FOREIGN KEY (user_id, tenant_id) REFERENCES users(id, tenant_id),
    CONSTRAINT fk_billing_customer_group_member_group
        FOREIGN KEY (tenant_id, customer_group)
        REFERENCES billing_customer_groups(tenant_id, code)
);

CREATE INDEX IF NOT EXISTS idx_billing_customer_group_memberships_group
    ON billing_customer_group_memberships(tenant_id, customer_group, updated_at DESC);

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conname = 'fk_billing_model_price_customer_group'
      AND conrelid = 'billing_model_prices'::regclass
  ) THEN
    ALTER TABLE billing_model_prices
      ADD CONSTRAINT fk_billing_model_price_customer_group
      FOREIGN KEY (tenant_id, customer_group)
      REFERENCES billing_customer_groups(tenant_id, code);
  END IF;
END $$;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conname = 'fk_billing_reservation_customer_group'
      AND conrelid = 'billing_reservations'::regclass
  ) THEN
    ALTER TABLE billing_reservations
      ADD CONSTRAINT fk_billing_reservation_customer_group
      FOREIGN KEY (tenant_id, customer_group)
      REFERENCES billing_customer_groups(tenant_id, code);
  END IF;
END $$;

ALTER TABLE billing_charge_records
    ADD COLUMN IF NOT EXISTS customer_group VARCHAR(64) NOT NULL DEFAULT 'default';

ALTER TABLE billing_charge_records DISABLE TRIGGER trg_billing_charge_append_only;
UPDATE billing_charge_records c
SET customer_group = r.customer_group
FROM billing_reservations r
WHERE r.tenant_id = c.tenant_id
  AND r.request_id = c.request_id
  AND r.customer_group IS NOT NULL
  AND r.customer_group <> ''
  AND c.customer_group IS DISTINCT FROM r.customer_group;
ALTER TABLE billing_charge_records ENABLE TRIGGER trg_billing_charge_append_only;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conname = 'fk_billing_charge_customer_group'
      AND conrelid = 'billing_charge_records'::regclass
  ) THEN
    ALTER TABLE billing_charge_records
      ADD CONSTRAINT fk_billing_charge_customer_group
      FOREIGN KEY (tenant_id, customer_group)
      REFERENCES billing_customer_groups(tenant_id, code);
  END IF;
END $$;

COMMENT ON TABLE billing_customer_groups IS 'Tenant-scoped billable customer groups; codes are immutable';
COMMENT ON TABLE billing_customer_group_memberships IS 'Current customer-to-billing-group assignment';
COMMENT ON COLUMN billing_charge_records.customer_group IS 'Actual customer group locked by the reservation quote';
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE billing_charge_records DROP CONSTRAINT IF EXISTS fk_billing_charge_customer_group;
ALTER TABLE billing_charge_records DROP COLUMN IF EXISTS customer_group;
ALTER TABLE billing_reservations DROP CONSTRAINT IF EXISTS fk_billing_reservation_customer_group;
ALTER TABLE billing_model_prices DROP CONSTRAINT IF EXISTS fk_billing_model_price_customer_group;
DROP INDEX IF EXISTS idx_billing_customer_group_memberships_group;
DROP TABLE IF EXISTS billing_customer_group_memberships;
DROP INDEX IF EXISTS idx_billing_customer_groups_tenant_status;
DROP INDEX IF EXISTS idx_billing_customer_groups_one_default;
DROP TABLE IF EXISTS billing_customer_groups;
-- +goose StatementEnd
