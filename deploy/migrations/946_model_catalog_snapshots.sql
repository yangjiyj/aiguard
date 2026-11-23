-- +goose Up
-- Inventory ownership is explicit. Legacy/manual rows are never guessed from
-- model names. Only recorded catalog-sync proof may establish legacy ownership.
CREATE TABLE IF NOT EXISTS model_catalog_sync_state (
 provider_id varchar(64) PRIMARY KEY REFERENCES providers(id),
 tenant_id varchar(64) NOT NULL REFERENCES tenants(id),
 interval_seconds integer NOT NULL DEFAULT 3600 CHECK(interval_seconds=0 OR interval_seconds BETWEEN 300 AND 86400),
 lease_token text, lease_expires_at timestamptz,
 last_started_at timestamptz, last_finished_at timestamptz,
 last_success_at timestamptz, next_sync_at timestamptz NOT NULL DEFAULT NOW(),
 last_status text NOT NULL DEFAULT 'never', last_error text NOT NULL DEFAULT '',
 last_result jsonb NOT NULL DEFAULT '{}'
);
CREATE TABLE IF NOT EXISTS model_catalog_entries (
 provider_id varchar(64) NOT NULL REFERENCES providers(id),
 upstream_model_id varchar(255) NOT NULL,
 model_id varchar(64) REFERENCES models(id) ON DELETE SET NULL,
 display_name text NOT NULL DEFAULT '', description text NOT NULL DEFAULT '',
 present boolean NOT NULL DEFAULT true,
 restore_status text NOT NULL DEFAULT 'pending',
 first_seen_at timestamptz NOT NULL DEFAULT NOW(), last_seen_at timestamptz NOT NULL DEFAULT NOW(),
 removed_at timestamptz,
 PRIMARY KEY(provider_id,upstream_model_id), UNIQUE(model_id)
);
CREATE TABLE IF NOT EXISTS model_catalog_sync_runs (
 id text PRIMARY KEY, tenant_id varchar(64) NOT NULL, provider_id varchar(64) NOT NULL,
 source text NOT NULL, started_at timestamptz NOT NULL, finished_at timestamptz NOT NULL DEFAULT NOW(),
 status text NOT NULL, error_code text NOT NULL DEFAULT '', result jsonb NOT NULL DEFAULT '{}'
);

-- Adopt only complete historical creation batches with matching cardinality
-- and no manual-creation audit. Protocol proof alone is not ownership proof.
WITH audits AS (
 SELECT a.id,a.action_detail->>'provider_id' AS provider_id,
 CASE WHEN a.action_detail->>'created' ~ '^[0-9]{1,7}$' THEN (a.action_detail->>'created')::int ELSE 0 END AS expected,
 a.created_at,lag(a.created_at) OVER(PARTITION BY a.action_detail->>'provider_id' ORDER BY a.created_at,a.id) AS previous
 FROM audit_operations a WHERE a.action_type='sync_models'
), members AS (
 SELECT a.id AS batch_id,a.expected,m.id AS model_id,m.provider_id,
 COALESCE(NULLIF(m.upstream_model_id,''),m.model_name) AS upstream_id,
 COALESCE(NULLIF(m.model_label,''),m.model_name) AS label,m.status,
 EXISTS(SELECT 1 FROM audit_operations manual WHERE manual.action_type='create_model' AND manual.target_id=m.id) AS manual
 FROM audits a JOIN providers p ON p.id=a.provider_id
 JOIN models m ON m.provider_id=a.provider_id AND m.created_at<=a.created_at AND m.created_at>COALESCE(a.previous,p.created_at)
 WHERE a.expected>0 AND COALESCE(p.auth_mode,'')<>'authorization_raw'
), confirmed AS (
 SELECT batch_id FROM members GROUP BY batch_id,expected HAVING count(*)=expected AND NOT bool_or(manual)
)
INSERT INTO model_catalog_entries(provider_id,upstream_model_id,model_id,display_name,restore_status)
SELECT m.provider_id,m.upstream_id,m.model_id,m.label,m.status
FROM members m JOIN confirmed c ON c.batch_id=m.batch_id
WHERE NOT EXISTS(SELECT 1 FROM models duplicate WHERE duplicate.provider_id=m.provider_id AND duplicate.id<>m.model_id
 AND COALESCE(NULLIF(duplicate.upstream_model_id,''),duplicate.model_name)=m.upstream_id)
ON CONFLICT DO NOTHING;
-- +goose Down
-- Preserve catalog ownership and sync audit on rollback; old binaries ignore it.
