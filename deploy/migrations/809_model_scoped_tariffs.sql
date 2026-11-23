-- +goose Up
-- +goose StatementBegin
-- Time-of-use rules are model-scoped. Existing tenant-wide rules are copied
-- to every currently active model once, preserving the old effective price
-- while making future changes explicit per model.

ALTER TABLE billing_tariff_rules
  ADD COLUMN IF NOT EXISTS model_name VARCHAR(255);

CREATE INDEX IF NOT EXISTS idx_billing_tariff_rules_model_match
  ON billing_tariff_rules(tenant_id, plan_id, model_name, special_date, start_minute, end_minute, priority DESC);

INSERT INTO billing_tariff_rules (
  id, tenant_id, plan_id, code, name, band, weekdays, special_date,
  start_minute, end_minute, multiplier_ppm, priority, model_name
)
SELECT
  LEFT(rule.id || '_' || SUBSTRING(md5(model.model_name) FROM 1 FOR 12), 64),
  rule.tenant_id, rule.plan_id,
  LEFT(rule.code || '-' || SUBSTRING(md5(model.model_name) FROM 1 FOR 8), 64),
  rule.name, rule.band, rule.weekdays, rule.special_date,
  rule.start_minute, rule.end_minute, rule.multiplier_ppm, rule.priority,
  model.model_name
FROM billing_tariff_rules rule
JOIN LATERAL (
  SELECT DISTINCT ON (p.tenant_id, m.model_name)
    p.tenant_id, m.model_name
  FROM models m
  JOIN providers p ON p.id = m.provider_id
  WHERE p.tenant_id = rule.tenant_id
    AND m.status = 'active'
    AND p.status = 'active'
    AND m.model_name <> ''
  ORDER BY p.tenant_id, m.model_name, m.id
) model ON TRUE
WHERE rule.model_name IS NULL
ON CONFLICT (id) DO NOTHING;

DELETE FROM billing_tariff_rules rule
WHERE rule.model_name IS NULL
  AND EXISTS (
    SELECT 1 FROM billing_tariff_rules scoped
    WHERE scoped.plan_id = rule.plan_id AND scoped.model_name IS NOT NULL
  );

COMMENT ON COLUMN billing_tariff_rules.model_name IS
  'Required for new plans; tariff schedule and multiplier apply only to this model name';
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS idx_billing_tariff_rules_model_match;
ALTER TABLE billing_tariff_rules DROP COLUMN IF EXISTS model_name;
-- +goose StatementEnd
