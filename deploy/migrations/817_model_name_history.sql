BEGIN;

CREATE TABLE IF NOT EXISTS model_name_history (
    tenant_id VARCHAR(64) NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    model_id VARCHAR(128) NOT NULL,
    provider_id VARCHAR(64) NOT NULL DEFAULT '',
    model_name VARCHAR(255) NOT NULL,
    model_label VARCHAR(255) NOT NULL DEFAULT '',
    first_seen_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    last_seen_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, model_id),
    CONSTRAINT ck_model_name_history_public_name
        CHECK (BTRIM(model_name) <> '')
);

COMMENT ON TABLE model_name_history IS
    'Tenant-scoped public model names retained after catalog rows are deleted.';

-- Billing facts already carry immutable model-name snapshots. Use the latest
-- snapshot per model while retaining the observed time range.
INSERT INTO model_name_history (
    tenant_id, model_id, provider_id, model_name, model_label, first_seen_at, last_seen_at
)
SELECT DISTINCT ON (tenant_id, model_id)
    tenant_id,
    model_id,
    COALESCE(provider_id, ''),
    BTRIM(model_name),
    BTRIM(model_name),
    MIN(COALESCE(occurred_at, created_at)) OVER (PARTITION BY tenant_id, model_id),
    MAX(COALESCE(occurred_at, created_at)) OVER (PARTITION BY tenant_id, model_id)
FROM billing_usage_facts
WHERE NULLIF(BTRIM(COALESCE(model_id, '')), '') IS NOT NULL
  AND NULLIF(BTRIM(COALESCE(model_name, '')), '') IS NOT NULL
ORDER BY tenant_id, model_id, COALESCE(occurred_at, created_at) DESC, created_at DESC
ON CONFLICT (tenant_id, model_id) DO UPDATE
SET provider_id = EXCLUDED.provider_id,
    model_name = EXCLUDED.model_name,
    model_label = EXCLUDED.model_label,
    first_seen_at = LEAST(model_name_history.first_seen_at, EXCLUDED.first_seen_at),
    last_seen_at = GREATEST(model_name_history.last_seen_at, EXCLUDED.last_seen_at);

INSERT INTO model_name_history (
    tenant_id, model_id, provider_id, model_name, model_label, first_seen_at, last_seen_at
)
SELECT DISTINCT ON (tenant_id, model_id)
    tenant_id,
    model_id,
    COALESCE(provider_id, ''),
    BTRIM(model_name),
    BTRIM(model_name),
    MIN(created_at) OVER (PARTITION BY tenant_id, model_id),
    MAX(created_at) OVER (PARTITION BY tenant_id, model_id)
FROM billing_charge_records
WHERE NULLIF(BTRIM(COALESCE(model_id, '')), '') IS NOT NULL
  AND NULLIF(BTRIM(COALESCE(model_name, '')), '') IS NOT NULL
ORDER BY tenant_id, model_id, created_at DESC
ON CONFLICT (tenant_id, model_id) DO UPDATE
SET provider_id = EXCLUDED.provider_id,
    model_name = EXCLUDED.model_name,
    model_label = EXCLUDED.model_label,
    first_seen_at = LEAST(model_name_history.first_seen_at, EXCLUDED.first_seen_at),
    last_seen_at = GREATEST(model_name_history.last_seen_at, EXCLUDED.last_seen_at)
WHERE EXCLUDED.last_seen_at >= model_name_history.last_seen_at;

-- The current catalog is authoritative over older billing snapshots.
INSERT INTO model_name_history (
    tenant_id, model_id, provider_id, model_name, model_label, first_seen_at, last_seen_at
)
SELECT
    p.tenant_id,
    m.id,
    m.provider_id,
    BTRIM(m.model_name),
    COALESCE(BTRIM(m.model_label), ''),
    COALESCE(m.created_at, NOW()),
    COALESCE(m.updated_at, m.created_at, NOW())
FROM models m
JOIN providers p ON p.id = m.provider_id
WHERE NULLIF(BTRIM(COALESCE(m.model_name, '')), '') IS NOT NULL
ON CONFLICT (tenant_id, model_id) DO UPDATE
SET provider_id = EXCLUDED.provider_id,
    model_name = EXCLUDED.model_name,
    model_label = EXCLUDED.model_label,
    first_seen_at = LEAST(model_name_history.first_seen_at, EXCLUDED.first_seen_at),
    last_seen_at = GREATEST(model_name_history.last_seen_at, EXCLUDED.last_seen_at);

CREATE OR REPLACE FUNCTION retain_model_name_history()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    source_tenant_id VARCHAR(64);
    source_model_id VARCHAR(128);
    source_provider_id VARCHAR(64);
    source_model_name VARCHAR(255);
    source_model_label VARCHAR(255);
BEGIN
    IF TG_OP = 'DELETE' THEN
        source_model_id := OLD.id;
        source_provider_id := OLD.provider_id;
        source_model_name := BTRIM(COALESCE(OLD.model_name, ''));
        source_model_label := BTRIM(COALESCE(OLD.model_label, ''));
    ELSE
        source_model_id := NEW.id;
        source_provider_id := NEW.provider_id;
        source_model_name := BTRIM(COALESCE(NEW.model_name, ''));
        source_model_label := BTRIM(COALESCE(NEW.model_label, ''));
    END IF;

    SELECT tenant_id
      INTO source_tenant_id
      FROM providers
     WHERE id = source_provider_id;

    IF source_tenant_id IS NOT NULL AND source_model_name <> '' THEN
        INSERT INTO model_name_history (
            tenant_id, model_id, provider_id, model_name, model_label, first_seen_at, last_seen_at
        )
        VALUES (
            source_tenant_id,
            source_model_id,
            source_provider_id,
            source_model_name,
            source_model_label,
            NOW(),
            NOW()
        )
        ON CONFLICT (tenant_id, model_id) DO UPDATE
        SET provider_id = EXCLUDED.provider_id,
            model_name = EXCLUDED.model_name,
            model_label = EXCLUDED.model_label,
            last_seen_at = EXCLUDED.last_seen_at;
    END IF;

    IF TG_OP = 'DELETE' THEN
        RETURN OLD;
    END IF;
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_models_retain_name_history_write ON models;
CREATE TRIGGER trg_models_retain_name_history_write
AFTER INSERT OR UPDATE OF provider_id, model_name, model_label
ON models
FOR EACH ROW
EXECUTE FUNCTION retain_model_name_history();

DROP TRIGGER IF EXISTS trg_models_retain_name_history_delete ON models;
CREATE TRIGGER trg_models_retain_name_history_delete
BEFORE DELETE
ON models
FOR EACH ROW
EXECUTE FUNCTION retain_model_name_history();

COMMIT;
