-- +goose Up
-- +goose StatementBegin
-- Customer-group pricing is a multiplier over one immutable model base price.
-- Snapshot the selected multiplier at admission so later group edits cannot
-- rewrite an in-flight request or its historic charge.
ALTER TABLE billing_customer_groups
    ADD COLUMN IF NOT EXISTS ratio_ppm BIGINT NOT NULL DEFAULT 1000000;
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conname = 'ck_billing_customer_group_ratio'
      AND conrelid = 'billing_customer_groups'::regclass
  ) THEN
    ALTER TABLE billing_customer_groups
      ADD CONSTRAINT ck_billing_customer_group_ratio
      CHECK (ratio_ppm > 0 AND ratio_ppm <= 1000000000);
  END IF;
END $$;

ALTER TABLE billing_reservations
    ADD COLUMN IF NOT EXISTS customer_group_ratio_ppm BIGINT NOT NULL DEFAULT 1000000;
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conname = 'ck_billing_reservation_group_ratio'
      AND conrelid = 'billing_reservations'::regclass
  ) THEN
    ALTER TABLE billing_reservations
      ADD CONSTRAINT ck_billing_reservation_group_ratio
      CHECK (customer_group_ratio_ppm > 0 AND customer_group_ratio_ppm <= 1000000000);
  END IF;
END $$;

ALTER TABLE billing_charge_records
    ADD COLUMN IF NOT EXISTS customer_group_ratio_ppm BIGINT NOT NULL DEFAULT 1000000;
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conname = 'ck_billing_charge_group_ratio'
      AND conrelid = 'billing_charge_records'::regclass
  ) THEN
    ALTER TABLE billing_charge_records
      ADD CONSTRAINT ck_billing_charge_group_ratio
      CHECK (customer_group_ratio_ppm > 0 AND customer_group_ratio_ppm <= 1000000000);
  END IF;
END $$;

COMMENT ON COLUMN billing_customer_groups.ratio_ppm IS 'Customer-wide billing multiplier in parts per million';
COMMENT ON COLUMN billing_reservations.customer_group_ratio_ppm IS 'Immutable customer-group multiplier selected at admission';
COMMENT ON COLUMN billing_charge_records.customer_group_ratio_ppm IS 'Customer-group multiplier snapshot used for this charge';
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE billing_charge_records DROP CONSTRAINT IF EXISTS ck_billing_charge_group_ratio;
ALTER TABLE billing_charge_records DROP COLUMN IF EXISTS customer_group_ratio_ppm;
ALTER TABLE billing_reservations DROP CONSTRAINT IF EXISTS ck_billing_reservation_group_ratio;
ALTER TABLE billing_reservations DROP COLUMN IF EXISTS customer_group_ratio_ppm;
ALTER TABLE billing_customer_groups DROP CONSTRAINT IF EXISTS ck_billing_customer_group_ratio;
ALTER TABLE billing_customer_groups DROP COLUMN IF EXISTS ratio_ppm;
-- +goose StatementEnd
