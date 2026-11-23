-- Monthly employee allowances are separate from prepaid wallet balances.
-- NULL default means disabled. Amounts remain in the configured currency;
-- no exchange-rate conversion or destructive monthly ledger reset occurs.
CREATE TABLE IF NOT EXISTS billing_employee_settings (
  tenant_id VARCHAR(64) PRIMARY KEY REFERENCES tenants(id),
  currency VARCHAR(3) NOT NULL DEFAULT 'CNY' CHECK (currency IN ('CNY','USD')),
  timezone VARCHAR(64) NOT NULL DEFAULT 'Asia/Shanghai',
  default_monthly_micros BIGINT CHECK (default_monthly_micros >= 0),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS billing_employee_allowances (
  tenant_id VARCHAR(64) NOT NULL REFERENCES tenants(id),
  user_id VARCHAR(64) NOT NULL REFERENCES users(id),
  monthly_micros BIGINT CHECK (monthly_micros >= 0),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (tenant_id,user_id)
);
CREATE TABLE IF NOT EXISTS billing_employee_reservations (
  tenant_id VARCHAR(64) NOT NULL REFERENCES tenants(id),
  request_id VARCHAR(128) NOT NULL,
  user_id VARCHAR(64) NOT NULL REFERENCES users(id),
  month_start TIMESTAMPTZ NOT NULL,
  month_end TIMESTAMPTZ NOT NULL,
  amount_micros BIGINT NOT NULL CHECK (amount_micros >= 0),
  currency VARCHAR(3) NOT NULL CHECK (currency IN ('CNY','USD')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (tenant_id,request_id)
);
CREATE INDEX IF NOT EXISTS idx_employee_reservations_month
  ON billing_employee_reservations(tenant_id,user_id,month_start);
CREATE TABLE IF NOT EXISTS billing_upstream_rates (
  tenant_id VARCHAR(64) NOT NULL REFERENCES tenants(id),
  provider_id VARCHAR(64) NOT NULL REFERENCES providers(id),
  model_name VARCHAR(255) NOT NULL,
  currency VARCHAR(3) NOT NULL CHECK (currency IN ('CNY','USD')),
  price_json JSONB NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY(tenant_id,provider_id,model_name)
);
