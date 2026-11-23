-- +goose Up
-- +goose StatementBegin
-- Billing analytics and time-of-use tariffs. 800-806 created the prepaid
-- ledger; this migration adds a mode-independent metering fact and immutable
-- tariff snapshots without changing historic ledger semantics.

CREATE TABLE IF NOT EXISTS billing_tariff_plans (
    id VARCHAR(64) PRIMARY KEY,
    tenant_id VARCHAR(64) NOT NULL REFERENCES tenants(id),
    name VARCHAR(120) NOT NULL,
    version INTEGER NOT NULL,
    status VARCHAR(16) NOT NULL DEFAULT 'draft',
    timezone VARCHAR(64) NOT NULL DEFAULT 'Asia/Shanghai',
    effective_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ,
    created_by VARCHAR(64),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_billing_tariff_plan_version UNIQUE (tenant_id, name, version),
    CONSTRAINT uq_billing_tariff_plan_id_tenant UNIQUE (id, tenant_id),
    CONSTRAINT ck_billing_tariff_plan_status CHECK (status IN ('draft', 'active', 'retired')),
    CONSTRAINT ck_billing_tariff_plan_timezone CHECK (timezone <> ''),
    CONSTRAINT ck_billing_tariff_plan_window CHECK (expires_at IS NULL OR expires_at > effective_at)
);

CREATE INDEX IF NOT EXISTS idx_billing_tariff_plans_lookup
    ON billing_tariff_plans(tenant_id, effective_at DESC, version DESC)
    WHERE status = 'active';

CREATE TABLE IF NOT EXISTS billing_tariff_rules (
    id VARCHAR(64) PRIMARY KEY,
    tenant_id VARCHAR(64) NOT NULL,
    plan_id VARCHAR(64) NOT NULL,
    code VARCHAR(64) NOT NULL,
    name VARCHAR(120) NOT NULL,
    band VARCHAR(16) NOT NULL DEFAULT 'flat',
    weekdays SMALLINT[] NOT NULL DEFAULT ARRAY[1,2,3,4,5,6,7]::SMALLINT[],
    special_date DATE,
    start_minute SMALLINT NOT NULL,
    end_minute SMALLINT NOT NULL,
    multiplier_ppm BIGINT NOT NULL DEFAULT 1000000,
    priority INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT fk_billing_tariff_rule_plan
        FOREIGN KEY (plan_id, tenant_id) REFERENCES billing_tariff_plans(id, tenant_id) ON DELETE CASCADE,
    CONSTRAINT uq_billing_tariff_rule_code UNIQUE (plan_id, code),
    CONSTRAINT ck_billing_tariff_rule_band CHECK (band IN ('peak', 'flat', 'valley', 'custom')),
    CONSTRAINT ck_billing_tariff_rule_weekdays CHECK (
        cardinality(weekdays) > 0 AND weekdays <@ ARRAY[1,2,3,4,5,6,7]::SMALLINT[]
    ),
    CONSTRAINT ck_billing_tariff_rule_minutes CHECK (
        start_minute >= 0 AND start_minute < 1440 AND end_minute > start_minute AND end_minute <= 1440
    ),
    CONSTRAINT ck_billing_tariff_rule_multiplier CHECK (multiplier_ppm > 0 AND multiplier_ppm <= 1000000000)
);

CREATE INDEX IF NOT EXISTS idx_billing_tariff_rules_match
    ON billing_tariff_rules(tenant_id, plan_id, special_date, start_minute, end_minute, priority DESC);

ALTER TABLE billing_reservations
    ADD COLUMN IF NOT EXISTS user_id VARCHAR(64),
    ADD COLUMN IF NOT EXISTS department_id VARCHAR(64),
    ADD COLUMN IF NOT EXISTS department_name VARCHAR(255) NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS tariff_plan_id VARCHAR(64),
    ADD COLUMN IF NOT EXISTS tariff_plan_version INTEGER,
    ADD COLUMN IF NOT EXISTS tariff_rule_id VARCHAR(64),
    ADD COLUMN IF NOT EXISTS tariff_band VARCHAR(16) NOT NULL DEFAULT 'flat',
    ADD COLUMN IF NOT EXISTS tariff_multiplier_ppm BIGINT NOT NULL DEFAULT 1000000,
    ADD COLUMN IF NOT EXISTS billing_timezone VARCHAR(64) NOT NULL DEFAULT 'Asia/Shanghai',
    ADD COLUMN IF NOT EXISTS admitted_at TIMESTAMPTZ NOT NULL DEFAULT NOW();

ALTER TABLE billing_reservations
    ADD CONSTRAINT ck_billing_reservation_tariff_band
        CHECK (tariff_band IN ('peak', 'flat', 'valley', 'custom')),
    ADD CONSTRAINT ck_billing_reservation_tariff_multiplier
        CHECK (tariff_multiplier_ppm > 0 AND tariff_multiplier_ppm <= 1000000000);

ALTER TABLE billing_charge_records
    ADD COLUMN IF NOT EXISTS user_id VARCHAR(64),
    ADD COLUMN IF NOT EXISTS department_id VARCHAR(64),
    ADD COLUMN IF NOT EXISTS department_name VARCHAR(255) NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS project_id VARCHAR(64),
    ADD COLUMN IF NOT EXISTS client_id VARCHAR(64),
    ADD COLUMN IF NOT EXISTS provider_id VARCHAR(64),
    ADD COLUMN IF NOT EXISTS provider_name VARCHAR(255) NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS provider_type VARCHAR(64) NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS model_id VARCHAR(64),
    ADD COLUMN IF NOT EXISTS tariff_plan_id VARCHAR(64),
    ADD COLUMN IF NOT EXISTS tariff_plan_version INTEGER,
    ADD COLUMN IF NOT EXISTS tariff_rule_id VARCHAR(64),
    ADD COLUMN IF NOT EXISTS tariff_band VARCHAR(16) NOT NULL DEFAULT 'flat',
    ADD COLUMN IF NOT EXISTS tariff_multiplier_ppm BIGINT NOT NULL DEFAULT 1000000,
    ADD COLUMN IF NOT EXISTS billing_timezone VARCHAR(64) NOT NULL DEFAULT 'Asia/Shanghai',
    ADD COLUMN IF NOT EXISTS admitted_at TIMESTAMPTZ;

ALTER TABLE billing_charge_records
    ADD CONSTRAINT ck_billing_charge_tariff_band
        CHECK (tariff_band IN ('peak', 'flat', 'valley', 'custom')),
    ADD CONSTRAINT ck_billing_charge_tariff_multiplier
        CHECK (tariff_multiplier_ppm > 0 AND tariff_multiplier_ppm <= 1000000000);

CREATE INDEX IF NOT EXISTS idx_billing_charges_department_created
    ON billing_charge_records(tenant_id, department_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_billing_charges_provider_created
    ON billing_charge_records(tenant_id, provider_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_billing_charges_tariff_created
    ON billing_charge_records(tenant_id, tariff_band, created_at DESC);

CREATE TABLE IF NOT EXISTS billing_usage_facts (
    id VARCHAR(64) PRIMARY KEY,
    tenant_id VARCHAR(64) NOT NULL REFERENCES tenants(id),
    request_id VARCHAR(128) NOT NULL,
    billing_mode VARCHAR(16) NOT NULL DEFAULT 'metering',
    user_id VARCHAR(64),
    user_name VARCHAR(255) NOT NULL DEFAULT '',
    department_id VARCHAR(64),
    department_name VARCHAR(255) NOT NULL DEFAULT '',
    project_id VARCHAR(64),
    project_name VARCHAR(255) NOT NULL DEFAULT '',
    client_id VARCHAR(64),
    provider_id VARCHAR(64),
    provider_name VARCHAR(255) NOT NULL DEFAULT '',
    provider_type VARCHAR(64) NOT NULL DEFAULT '',
    model_id VARCHAR(64),
    model_name VARCHAR(255) NOT NULL DEFAULT '',
    prompt_tokens BIGINT NOT NULL DEFAULT 0,
    cached_input_tokens BIGINT NOT NULL DEFAULT 0,
    cache_write_input_tokens BIGINT NOT NULL DEFAULT 0,
    output_tokens BIGINT NOT NULL DEFAULT 0,
    reasoning_tokens BIGINT NOT NULL DEFAULT 0,
    billable_amount_micros BIGINT,
    upstream_cost_micros BIGINT,
    currency VARCHAR(8) NOT NULL DEFAULT 'CNY',
    price_id VARCHAR(64),
    tariff_plan_id VARCHAR(64),
    tariff_plan_version INTEGER,
    tariff_rule_id VARCHAR(64),
    tariff_band VARCHAR(16) NOT NULL DEFAULT 'flat',
    tariff_multiplier_ppm BIGINT NOT NULL DEFAULT 1000000,
    billing_timezone VARCHAR(64) NOT NULL DEFAULT 'Asia/Shanghai',
    attribution_quality VARCHAR(16) NOT NULL DEFAULT 'exact',
    status VARCHAR(16) NOT NULL DEFAULT 'settled',
    occurred_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_billing_usage_fact_request UNIQUE (tenant_id, request_id),
    CONSTRAINT ck_billing_usage_fact_mode CHECK (billing_mode IN ('metering', 'prepaid')),
    CONSTRAINT ck_billing_usage_fact_usage CHECK (
        prompt_tokens >= 0 AND cached_input_tokens >= 0 AND cache_write_input_tokens >= 0 AND
        output_tokens >= 0 AND reasoning_tokens >= 0 AND
        cached_input_tokens + cache_write_input_tokens <= prompt_tokens AND reasoning_tokens <= output_tokens
    ),
    CONSTRAINT ck_billing_usage_fact_amounts CHECK (
        (billable_amount_micros IS NULL OR billable_amount_micros >= 0) AND
        (upstream_cost_micros IS NULL OR upstream_cost_micros >= 0)
    ),
    CONSTRAINT ck_billing_usage_fact_currency CHECK (currency ~ '^[A-Z]{3,8}$'),
    CONSTRAINT ck_billing_usage_fact_tariff_band CHECK (tariff_band IN ('peak', 'flat', 'valley', 'custom')),
    CONSTRAINT ck_billing_usage_fact_tariff_multiplier CHECK (tariff_multiplier_ppm > 0 AND tariff_multiplier_ppm <= 1000000000),
    CONSTRAINT ck_billing_usage_fact_quality CHECK (attribution_quality IN ('exact', 'inferred', 'unknown')),
    CONSTRAINT ck_billing_usage_fact_status CHECK (status IN ('settled', 'released', 'unpriced', 'failed'))
);

CREATE INDEX IF NOT EXISTS idx_billing_usage_facts_tenant_time
    ON billing_usage_facts(tenant_id, occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_billing_usage_facts_department_time
    ON billing_usage_facts(tenant_id, department_id, occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_billing_usage_facts_provider_time
    ON billing_usage_facts(tenant_id, provider_id, occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_billing_usage_facts_band_time
    ON billing_usage_facts(tenant_id, tariff_band, occurred_at DESC);

DROP TRIGGER IF EXISTS trg_billing_usage_facts_append_only ON billing_usage_facts;
CREATE TRIGGER trg_billing_usage_facts_append_only
    BEFORE UPDATE OR DELETE ON billing_usage_facts
    FOR EACH ROW EXECUTE FUNCTION reject_billing_audit_mutation();

COMMENT ON TABLE billing_usage_facts IS 'Immutable per-request metering fact for department, channel and time-band analytics';
COMMENT ON COLUMN billing_usage_facts.department_id IS 'Department snapshot at admission; never derived from current membership for new facts';
COMMENT ON COLUMN billing_usage_facts.provider_id IS 'Actual settled provider/channel, including fallback route';
COMMENT ON COLUMN billing_usage_facts.billable_amount_micros IS 'Internal/showback or prepaid charge amount; NULL means unpriced';
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TRIGGER IF EXISTS trg_billing_usage_facts_append_only ON billing_usage_facts;
DROP TABLE IF EXISTS billing_usage_facts;
DROP INDEX IF EXISTS idx_billing_charges_tariff_created;
DROP INDEX IF EXISTS idx_billing_charges_provider_created;
DROP INDEX IF EXISTS idx_billing_charges_department_created;
ALTER TABLE billing_charge_records
    DROP CONSTRAINT IF EXISTS ck_billing_charge_tariff_multiplier,
    DROP CONSTRAINT IF EXISTS ck_billing_charge_tariff_band,
    DROP COLUMN IF EXISTS admitted_at,
    DROP COLUMN IF EXISTS billing_timezone,
    DROP COLUMN IF EXISTS tariff_multiplier_ppm,
    DROP COLUMN IF EXISTS tariff_band,
    DROP COLUMN IF EXISTS tariff_rule_id,
    DROP COLUMN IF EXISTS tariff_plan_version,
    DROP COLUMN IF EXISTS tariff_plan_id,
    DROP COLUMN IF EXISTS model_id,
    DROP COLUMN IF EXISTS provider_type,
    DROP COLUMN IF EXISTS provider_name,
    DROP COLUMN IF EXISTS provider_id,
    DROP COLUMN IF EXISTS client_id,
    DROP COLUMN IF EXISTS project_id,
    DROP COLUMN IF EXISTS department_name,
    DROP COLUMN IF EXISTS department_id,
    DROP COLUMN IF EXISTS user_id;
ALTER TABLE billing_reservations
    DROP CONSTRAINT IF EXISTS ck_billing_reservation_tariff_multiplier,
    DROP CONSTRAINT IF EXISTS ck_billing_reservation_tariff_band,
    DROP COLUMN IF EXISTS admitted_at,
    DROP COLUMN IF EXISTS billing_timezone,
    DROP COLUMN IF EXISTS tariff_multiplier_ppm,
    DROP COLUMN IF EXISTS tariff_band,
    DROP COLUMN IF EXISTS tariff_rule_id,
    DROP COLUMN IF EXISTS tariff_plan_version,
    DROP COLUMN IF EXISTS tariff_plan_id,
    DROP COLUMN IF EXISTS department_name,
    DROP COLUMN IF EXISTS department_id,
    DROP COLUMN IF EXISTS user_id;
DROP TABLE IF EXISTS billing_tariff_rules;
DROP TABLE IF EXISTS billing_tariff_plans;
-- +goose StatementEnd
