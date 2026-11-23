-- +goose Up
-- +goose StatementBegin
-- The quote is immutable once a reservation is created. Settlement must use
-- this price version rather than resolving the current price again.
ALTER TABLE billing_reservations
    ADD COLUMN IF NOT EXISTS price_id VARCHAR(64),
    ADD COLUMN IF NOT EXISTS model_name VARCHAR(255),
    ADD COLUMN IF NOT EXISTS customer_group VARCHAR(64);

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conname = 'fk_billing_reservation_price'
      AND conrelid = 'billing_reservations'::regclass
  ) THEN
    ALTER TABLE billing_reservations
      ADD CONSTRAINT fk_billing_reservation_price
      FOREIGN KEY (price_id, tenant_id) REFERENCES billing_model_prices(id, tenant_id);
  END IF;
END $$;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conname = 'ck_billing_reservation_quote'
      AND conrelid = 'billing_reservations'::regclass
  ) THEN
    ALTER TABLE billing_reservations
      ADD CONSTRAINT ck_billing_reservation_quote
      CHECK (
      (price_id IS NULL AND model_name IS NULL AND customer_group IS NULL) OR
      (price_id IS NOT NULL AND model_name IS NOT NULL AND customer_group IS NOT NULL)
      );
  END IF;
END $$;

CREATE INDEX IF NOT EXISTS idx_billing_reservations_price
    ON billing_reservations(tenant_id, price_id)
    WHERE price_id IS NOT NULL;
-- +goose StatementEnd

-- +goose Down
DROP INDEX IF EXISTS idx_billing_reservations_price;
ALTER TABLE billing_reservations DROP CONSTRAINT IF EXISTS ck_billing_reservation_quote;
ALTER TABLE billing_reservations DROP CONSTRAINT IF EXISTS fk_billing_reservation_price;
ALTER TABLE billing_reservations DROP COLUMN IF EXISTS customer_group;
ALTER TABLE billing_reservations DROP COLUMN IF EXISTS model_name;
ALTER TABLE billing_reservations DROP COLUMN IF EXISTS price_id;
