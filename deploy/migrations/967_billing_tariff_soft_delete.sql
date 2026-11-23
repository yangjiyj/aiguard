ALTER TABLE billing_tariff_plans ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMPTZ;
CREATE INDEX IF NOT EXISTS idx_billing_tariff_plans_visible
  ON billing_tariff_plans(tenant_id,effective_at DESC) WHERE deleted_at IS NULL;
