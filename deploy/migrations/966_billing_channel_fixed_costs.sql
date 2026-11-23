-- Offline-compatible overlap enforcement: no optional PostgreSQL extensions.
CREATE TABLE IF NOT EXISTS billing_channel_fixed_costs (
  id VARCHAR(64) PRIMARY KEY,
  tenant_id VARCHAR(64) NOT NULL REFERENCES tenants(id),
  provider_id VARCHAR(64) NOT NULL REFERENCES providers(id),
  currency VARCHAR(3) NOT NULL CHECK (currency IN ('CNY','USD')),
  amount_micros BIGINT NOT NULL CHECK (amount_micros >= 0),
  period VARCHAR(8) NOT NULL DEFAULT 'month' CHECK (period IN ('month','year')),
  effective_from DATE NOT NULL,
  effective_to DATE,
  note TEXT NOT NULL DEFAULT '',
  created_by VARCHAR(64) REFERENCES users(id),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CHECK (effective_to IS NULL OR effective_to > effective_from)
);
CREATE INDEX IF NOT EXISTS idx_billing_channel_fixed_costs_channel
  ON billing_channel_fixed_costs(tenant_id,provider_id,effective_from);
CREATE OR REPLACE FUNCTION check_billing_channel_fixed_cost_overlap() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  PERFORM pg_advisory_xact_lock(hashtextextended('channel-fixed-cost:' || NEW.tenant_id || ':' || NEW.provider_id,0));
  IF NOT EXISTS (SELECT 1 FROM providers WHERE id=NEW.provider_id AND tenant_id=NEW.tenant_id) THEN
    RAISE EXCEPTION 'fixed cost provider belongs to another tenant' USING ERRCODE='23514';
  END IF;
  IF EXISTS (SELECT 1 FROM billing_channel_fixed_costs c
    WHERE c.tenant_id=NEW.tenant_id AND c.provider_id=NEW.provider_id AND c.id<>NEW.id
    AND daterange(c.effective_from,c.effective_to,'[)') && daterange(NEW.effective_from,NEW.effective_to,'[)')) THEN
    RAISE EXCEPTION 'channel fixed cost effective periods overlap' USING ERRCODE='23P01';
  END IF;
  RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS billing_channel_fixed_cost_overlap ON billing_channel_fixed_costs;
CREATE TRIGGER billing_channel_fixed_cost_overlap BEFORE INSERT OR UPDATE ON billing_channel_fixed_costs
  FOR EACH ROW EXECUTE FUNCTION check_billing_channel_fixed_cost_overlap();
