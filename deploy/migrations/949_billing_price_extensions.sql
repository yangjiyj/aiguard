-- Preserve extended pricing and measured usage in the same immutable version
-- and settlement records as token pricing. Money remains in its source currency.
ALTER TABLE billing_model_prices ADD COLUMN IF NOT EXISTS pricing_extras JSONB NOT NULL DEFAULT '{}';
ALTER TABLE billing_charge_records ADD COLUMN IF NOT EXISTS pricing_extras JSONB NOT NULL DEFAULT '{}';
ALTER TABLE billing_charge_records ADD COLUMN IF NOT EXISTS usage_extras JSONB NOT NULL DEFAULT '{}';
ALTER TABLE billing_usage_facts ADD COLUMN IF NOT EXISTS usage_extras JSONB NOT NULL DEFAULT '{}';
