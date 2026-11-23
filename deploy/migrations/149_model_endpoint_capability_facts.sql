-- Endpoint capability truth is separate from catalog hints and administrator
-- overrides. This is expand-only so the previous binary can keep reading
-- models.capabilities_json during rollback.
CREATE TABLE IF NOT EXISTS model_endpoint_capability_facts (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    provider_id TEXT NOT NULL REFERENCES providers(id) ON DELETE CASCADE,
    model_id TEXT NOT NULL REFERENCES models(id) ON DELETE CASCADE,
    endpoint_type TEXT NOT NULL CHECK (endpoint_type IN ('chat','responses','messages','images','embeddings','files')),
    state TEXT NOT NULL CHECK (state IN ('supported','unsupported','unknown')),
    source TEXT NOT NULL,
    source_version TEXT NOT NULL,
    provider_config_digest TEXT NOT NULL DEFAULT '',
    generation BIGINT NOT NULL DEFAULT 1 CHECK (generation > 0),
    verified_at TIMESTAMPTZ,
    expires_at TIMESTAMPTZ,
    evidence_summary_json JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (model_id, endpoint_type, source)
);

CREATE INDEX IF NOT EXISTS idx_model_endpoint_capability_facts_lookup
    ON model_endpoint_capability_facts (model_id, endpoint_type, generation DESC, updated_at DESC);

CREATE TABLE IF NOT EXISTS model_endpoint_capability_overrides (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    model_id TEXT NOT NULL REFERENCES models(id) ON DELETE CASCADE,
    endpoint_type TEXT NOT NULL CHECK (endpoint_type IN ('chat','responses','messages','images','embeddings','files')),
    state TEXT NOT NULL CHECK (state IN ('supported','unsupported')),
    reason TEXT NOT NULL CHECK (length(btrim(reason)) BETWEEN 1 AND 500),
    actor_user_id TEXT NOT NULL,
    config_version BIGINT NOT NULL DEFAULT 1 CHECK (config_version > 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (model_id, endpoint_type)
);

CREATE INDEX IF NOT EXISTS idx_model_endpoint_capability_overrides_tenant
    ON model_endpoint_capability_overrides (tenant_id, model_id);

-- Existing JSON is migrated as evidence, not silently promoted. Only rows
-- carrying the old verified marker retain a supported/unsupported fact;
-- everything else is explicitly unknown and therefore unavailable to the new
-- runtime until verified or overridden.
WITH endpoints(endpoint_type, protocol_key) AS (
    VALUES
        ('chat', 'chat_completions'),
        ('responses', 'responses_native'),
        ('messages', 'anthropic_messages'),
        ('images', 'images'),
        ('embeddings', 'embeddings'),
        ('files', 'files')
), recent_success AS (
    SELECT route_model.id AS model_id, rl.provider_id, rl.endpoint_type,
           MAX(rl.created_at) AS last_success_at
    FROM request_logs rl
    JOIN models requested_model ON requested_model.id = rl.model_id
    JOIN models route_model
      ON route_model.provider_id = rl.provider_id
     AND route_model.model_name = requested_model.model_name
     AND route_model.status = 'active'
    WHERE rl.request_status = 'success'
      AND rl.created_at >= NOW() - INTERVAL '30 days'
      AND rl.provider_id IS NOT NULL
      AND rl.endpoint_type IN ('chat','responses','messages','images','embeddings','files')
    GROUP BY route_model.id, rl.provider_id, rl.endpoint_type
)
INSERT INTO model_endpoint_capability_facts (
    id, tenant_id, provider_id, model_id, endpoint_type, state, source,
    source_version, provider_config_digest, generation, verified_at,
    expires_at, evidence_summary_json
)
SELECT
    'mecf_legacy_' || md5(m.id || ':' || e.endpoint_type),
    p.tenant_id,
    m.provider_id,
    m.id,
    e.endpoint_type,
    CASE
        WHEN COALESCE(m.capabilities_json->'protocols'->'metadata'->>'verified' = 'true', false)
             AND m.capabilities_json->'protocols' ? e.protocol_key
        THEN CASE WHEN COALESCE(m.capabilities_json->'protocols'->>e.protocol_key = 'true', false)
                  THEN 'supported' ELSE 'unsupported' END
        WHEN rs.last_success_at IS NOT NULL THEN 'supported'
        ELSE 'unknown'
    END,
    CASE
        WHEN COALESCE(m.capabilities_json->'protocols'->'metadata'->>'verified' = 'true', false)
             AND m.capabilities_json->'protocols' ? e.protocol_key THEN 'legacy_verified_migration'
        WHEN rs.last_success_at IS NOT NULL THEN 'observed_success_migration'
        ELSE 'legacy_migration'
    END,
    '149',
    'legacy-md5:' || md5(COALESCE(p.provider_type, '') || chr(31) || COALESCE(p.base_url, '') || chr(31) || COALESCE(p.auth_mode, '')),
    1,
    CASE WHEN COALESCE(m.capabilities_json->'protocols'->'metadata'->>'verified' = 'true', false)
         THEN COALESCE(m.updated_at, m.created_at)
         ELSE rs.last_success_at END,
    CASE WHEN COALESCE(m.capabilities_json->'protocols'->'metadata'->>'verified' = 'true', false)
         THEN COALESCE(m.updated_at, m.created_at) + INTERVAL '30 days'
         WHEN rs.last_success_at IS NOT NULL THEN rs.last_success_at + INTERVAL '30 days' END,
    jsonb_build_object('migrated', true, 'protocol_key', e.protocol_key,
                       'operational_success_observed', rs.last_success_at IS NOT NULL)
FROM models m
JOIN providers p ON p.id = m.provider_id
CROSS JOIN endpoints e
LEFT JOIN recent_success rs
  ON rs.model_id = m.id AND rs.provider_id = m.provider_id AND rs.endpoint_type = e.endpoint_type
ON CONFLICT (id) DO UPDATE
SET state = EXCLUDED.state,
    source = EXCLUDED.source,
    source_version = EXCLUDED.source_version,
    provider_config_digest = EXCLUDED.provider_config_digest,
    verified_at = EXCLUDED.verified_at,
    expires_at = EXCLUDED.expires_at,
    evidence_summary_json = EXCLUDED.evidence_summary_json,
    updated_at = NOW()
WHERE model_endpoint_capability_facts.state IS DISTINCT FROM EXCLUDED.state
   OR model_endpoint_capability_facts.source IS DISTINCT FROM EXCLUDED.source
   OR model_endpoint_capability_facts.provider_config_digest IS DISTINCT FROM EXCLUDED.provider_config_digest
   OR model_endpoint_capability_facts.verified_at IS DISTINCT FROM EXCLUDED.verified_at
   OR model_endpoint_capability_facts.expires_at IS DISTINCT FROM EXCLUDED.expires_at;

CREATE OR REPLACE VIEW model_endpoint_capability_effective AS
WITH endpoints(endpoint_type) AS (
    VALUES ('chat'), ('responses'), ('messages'), ('images'), ('embeddings'), ('files')
)
SELECT
    p.tenant_id,
    m.provider_id,
    m.id AS model_id,
    e.endpoint_type,
    COALESCE(o.state,
        CASE WHEN f.expires_at IS NOT NULL AND f.expires_at <= NOW() THEN 'expired' ELSE f.state END,
        'unknown') AS state,
    COALESCE(CASE WHEN o.id IS NOT NULL THEN 'administrator_override' END, f.source, 'none') AS source,
    COALESCE(CASE WHEN o.id IS NOT NULL THEN o.config_version::text END, f.source_version, '') AS source_version,
    COALESCE(f.provider_config_digest, '') AS provider_config_digest,
    f.verified_at,
    f.expires_at,
    (o.id IS NOT NULL) AS is_override,
    COALESCE(o.updated_at, f.updated_at, m.created_at) AS updated_at
FROM models m
JOIN providers p ON p.id = m.provider_id
CROSS JOIN endpoints e
LEFT JOIN LATERAL (
    SELECT fact.*
    FROM model_endpoint_capability_facts fact
    WHERE fact.model_id = m.id AND fact.endpoint_type = e.endpoint_type
    ORDER BY CASE fact.source
               WHEN 'verified_sync' THEN 100
               WHEN 'probe' THEN 90
               WHEN 'administrator_import' THEN 80
               WHEN 'observed_success_migration' THEN 50
               WHEN 'legacy_verified_migration' THEN 40
               ELSE 10
             END DESC,
             fact.updated_at DESC, fact.generation DESC, fact.id DESC
    LIMIT 1
) f ON TRUE
LEFT JOIN model_endpoint_capability_overrides o
    ON o.model_id = m.id AND o.endpoint_type = e.endpoint_type;
