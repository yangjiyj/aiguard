BEGIN;

-- Keep the legacy source stable across the full backfill transaction.
LOCK TABLE agent_endpoint_assets IN SHARE MODE;


DO $validate_agent_asset_source_identity$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM agent_endpoint_assets
        WHERE btrim(endpoint_id) = '' OR octet_length(endpoint_id) > 255
           OR position(chr(30) IN endpoint_id) > 0 OR position(chr(31) IN endpoint_id) > 0
           OR btrim(asset_type) = ''
           OR position(chr(30) IN asset_type) > 0 OR position(chr(31) IN asset_type) > 0
           OR btrim(name) = ''
           OR position(chr(30) IN name) > 0 OR position(chr(31) IN name) > 0
           OR octet_length(asset_type || chr(30) || name) > 512
    ) THEN
        RAISE EXCEPTION 'migration 860 cannot create unified identities from invalid legacy endpoint assets';
    END IF;
END
$validate_agent_asset_source_identity$;

CREATE TABLE IF NOT EXISTS agent_unified_assets (
    id text PRIMARY KEY,
    tenant_id varchar(64) NOT NULL,
    asset_type text NOT NULL,
    identity_key text NOT NULL,
    display_name text NOT NULL DEFAULT '',
    owner_user_id varchar(64),
    business_unit text NOT NULL DEFAULT '',
    business_service text NOT NULL DEFAULT '',
    catalog_status text NOT NULL DEFAULT 'unreviewed'
        CHECK (catalog_status IN ('unreviewed','approved','exception')),
    catalog_reason text NOT NULL DEFAULT '',
    catalog_expires_at timestamptz,
    catalog_updated_by text NOT NULL DEFAULT '',
    catalog_updated_at timestamptz,
    merged_into_id text,
    first_seen timestamptz NOT NULL DEFAULT now(),
    last_seen timestamptz NOT NULL DEFAULT now(),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, id),
    UNIQUE (tenant_id, asset_type, identity_key),
    FOREIGN KEY (tenant_id, owner_user_id)
        REFERENCES users (tenant_id, id),
    FOREIGN KEY (tenant_id, merged_into_id)
        REFERENCES agent_unified_assets (tenant_id, id),
    CHECK (
        catalog_status <> 'exception'
        OR (length(btrim(catalog_reason)) > 0 AND catalog_expires_at IS NOT NULL)
    )
);
CREATE INDEX IF NOT EXISTS idx_agent_unified_assets_tenant_seen
    ON agent_unified_assets (tenant_id, last_seen DESC, id);
CREATE INDEX IF NOT EXISTS idx_agent_unified_assets_tenant_catalog
    ON agent_unified_assets (tenant_id, catalog_status, catalog_expires_at);

CREATE TABLE IF NOT EXISTS agent_asset_source_refs (
    id text PRIMARY KEY,
    tenant_id varchar(64) NOT NULL,
    asset_id text NOT NULL,
    source_type text NOT NULL CHECK (source_type IN ('agent_endpoint','identity_event')),
    source_namespace text NOT NULL CHECK (length(btrim(source_namespace)) BETWEEN 1 AND 255),
    native_id text NOT NULL CHECK (length(btrim(native_id)) BETWEEN 1 AND 512),
    created_by text NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, id),
    UNIQUE (tenant_id, source_type, source_namespace, native_id),
    FOREIGN KEY (tenant_id, asset_id)
        REFERENCES agent_unified_assets (tenant_id, id)
);
CREATE INDEX IF NOT EXISTS idx_agent_asset_source_refs_asset
    ON agent_asset_source_refs (tenant_id, asset_id);

CREATE TABLE IF NOT EXISTS agent_unified_asset_instances (
    id text PRIMARY KEY,
    tenant_id varchar(64) NOT NULL,
    asset_id text NOT NULL,
    source_asset_id text NOT NULL,
    source_ref_id text NOT NULL,
    instance_key text NOT NULL,
    endpoint_id text,
    display_name text NOT NULL DEFAULT '',
    version text NOT NULL DEFAULT '',
    content_hash text NOT NULL DEFAULT '',
    present boolean NOT NULL DEFAULT true,
    scan_status text NOT NULL DEFAULT '',
    scan_decision text NOT NULL DEFAULT '',
    evidence jsonb NOT NULL DEFAULT '{}'::jsonb,
    first_seen timestamptz NOT NULL DEFAULT now(),
    last_observed_at timestamptz NOT NULL DEFAULT now(),
    last_received_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, id),
    UNIQUE (tenant_id, asset_id, source_ref_id, instance_key),
    FOREIGN KEY (tenant_id, asset_id)
        REFERENCES agent_unified_assets (tenant_id, id),
    FOREIGN KEY (tenant_id, source_asset_id)
        REFERENCES agent_unified_assets (tenant_id, id),
    FOREIGN KEY (tenant_id, source_ref_id)
        REFERENCES agent_asset_source_refs (tenant_id, id)
);
CREATE INDEX IF NOT EXISTS idx_agent_unified_asset_instances_asset
    ON agent_unified_asset_instances (tenant_id, asset_id, last_observed_at DESC);
CREATE INDEX IF NOT EXISTS idx_agent_unified_asset_instances_endpoint
    ON agent_unified_asset_instances (tenant_id, endpoint_id);

CREATE TABLE IF NOT EXISTS agent_unified_asset_observations (
    id text PRIMARY KEY,
    tenant_id varchar(64) NOT NULL,
    asset_id text NOT NULL,
    source_asset_id text NOT NULL,
    instance_id text NOT NULL,
    source_ref_id text NOT NULL,
    source_event_id text NOT NULL,
    provenance text NOT NULL DEFAULT 'authenticated_source',
    source_occurred_at timestamptz NOT NULL,
    received_at timestamptz NOT NULL DEFAULT now(),
    display_name text NOT NULL DEFAULT '',
    version text NOT NULL DEFAULT '',
    content_hash text NOT NULL DEFAULT '',
    present boolean NOT NULL DEFAULT true,
    scan_status text NOT NULL DEFAULT '',
    scan_decision text NOT NULL DEFAULT '',
    evidence jsonb NOT NULL DEFAULT '{}'::jsonb,
    UNIQUE (tenant_id, id),
    UNIQUE (tenant_id, source_ref_id, source_event_id),
    FOREIGN KEY (tenant_id, asset_id)
        REFERENCES agent_unified_assets (tenant_id, id),
    FOREIGN KEY (tenant_id, source_asset_id)
        REFERENCES agent_unified_assets (tenant_id, id),
    FOREIGN KEY (tenant_id, instance_id)
        REFERENCES agent_unified_asset_instances (tenant_id, id),
    FOREIGN KEY (tenant_id, source_ref_id)
        REFERENCES agent_asset_source_refs (tenant_id, id)
);
CREATE INDEX IF NOT EXISTS idx_agent_unified_asset_observations_history
    ON agent_unified_asset_observations (tenant_id, asset_id, received_at DESC, id);
CREATE INDEX IF NOT EXISTS idx_agent_unified_asset_observations_instance
    ON agent_unified_asset_observations (tenant_id, instance_id, received_at DESC);

-- Import the current endpoint inventory as a historical snapshot. The identity key
-- includes the authenticated endpoint namespace, so same-host Agent installs stay
-- separate. Hash/version changes remain in observation history under that identity.
WITH legacy_assets AS (
    SELECT tenant_id, endpoint_id, asset_type, name,
           asset_type || chr(30) || name AS native_id,
           MIN(first_seen) AS first_seen,
           MAX(last_seen) AS last_seen
    FROM agent_endpoint_assets
    GROUP BY tenant_id, endpoint_id, asset_type, name
), identities AS (
    SELECT tenant_id, endpoint_id, asset_type, name, native_id, first_seen, last_seen,
           'agent_endpoint' || chr(31) || endpoint_id || chr(31) || native_id AS identity_key,
           'uaa_' || md5(tenant_id || chr(31) || 'agent_endpoint' || chr(31) || endpoint_id || chr(31) || native_id) AS asset_id,
           'uasr_' || md5(tenant_id || chr(31) || 'agent_endpoint' || chr(31) || endpoint_id || chr(31) || native_id) AS source_ref_id
    FROM legacy_assets
)
INSERT INTO agent_unified_assets(id, tenant_id, asset_type, identity_key, display_name, first_seen, last_seen)
SELECT asset_id, tenant_id, asset_type, identity_key, name,
       LEAST(first_seen, now()), LEAST(last_seen, now())
FROM identities
ON CONFLICT (tenant_id, asset_type, identity_key) DO NOTHING;

WITH legacy_assets AS (
    SELECT DISTINCT tenant_id, endpoint_id, asset_type, name,
           asset_type || chr(30) || name AS native_id
    FROM agent_endpoint_assets
), identities AS (
    SELECT tenant_id, endpoint_id, asset_type, name, native_id,
           'uaa_' || md5(tenant_id || chr(31) || 'agent_endpoint' || chr(31) || endpoint_id || chr(31) || native_id) AS asset_id,
           'uasr_' || md5(tenant_id || chr(31) || 'agent_endpoint' || chr(31) || endpoint_id || chr(31) || native_id) AS source_ref_id
    FROM legacy_assets
)
INSERT INTO agent_asset_source_refs(id, tenant_id, asset_id, source_type, source_namespace, native_id)
SELECT source_ref_id, tenant_id, asset_id, 'agent_endpoint', endpoint_id, native_id
FROM identities
ON CONFLICT (tenant_id, source_type, source_namespace, native_id) DO NOTHING;

WITH legacy_rows AS (
    SELECT a.*,
           a.asset_type || chr(30) || a.name AS native_id,
           'uaa_' || md5(a.tenant_id || chr(31) || 'agent_endpoint' || chr(31) || a.endpoint_id || chr(31) || a.asset_type || chr(30) || a.name) AS asset_id,
           'uasr_' || md5(a.tenant_id || chr(31) || 'agent_endpoint' || chr(31) || a.endpoint_id || chr(31) || a.asset_type || chr(30) || a.name) AS source_ref_id,
           '__source_native_identity__' AS instance_key,
           MIN(a.first_seen) OVER (PARTITION BY a.tenant_id,a.endpoint_id,a.asset_type,a.name) AS instance_first_seen
    FROM agent_endpoint_assets a
), instances AS (
    SELECT DISTINCT ON (tenant_id, source_ref_id)
           tenant_id, endpoint_id, asset_type, name, hash, version, present, scan_status, scan_decision,
           evidence, native_id, asset_id, source_ref_id, instance_key, instance_first_seen, last_seen
    FROM legacy_rows
    ORDER BY tenant_id, source_ref_id, last_seen DESC, id
)
INSERT INTO agent_unified_asset_instances(
    id, tenant_id, asset_id, source_asset_id, source_ref_id, instance_key, endpoint_id,
    display_name, version, content_hash, present, scan_status, scan_decision, evidence,
    first_seen, last_observed_at, last_received_at
)
SELECT
    'uai_' || md5(i.tenant_id || chr(31) || i.source_ref_id || chr(31) || i.instance_key),
    i.tenant_id, i.asset_id, i.asset_id, i.source_ref_id, i.instance_key, i.endpoint_id,
    i.name, i.version, i.hash, i.present, i.scan_status, i.scan_decision, i.evidence,
    LEAST(i.instance_first_seen, now()), LEAST(i.last_seen, now()), now()
FROM instances i
ON CONFLICT (tenant_id, asset_id, source_ref_id, instance_key) DO NOTHING;

WITH legacy_rows AS (
    SELECT a.*,
           a.asset_type || chr(30) || a.name AS native_id,
           'uaa_' || md5(a.tenant_id || chr(31) || 'agent_endpoint' || chr(31) || a.endpoint_id || chr(31) || a.asset_type || chr(30) || a.name) AS asset_id,
           'uasr_' || md5(a.tenant_id || chr(31) || 'agent_endpoint' || chr(31) || a.endpoint_id || chr(31) || a.asset_type || chr(30) || a.name) AS source_ref_id,
           '__source_native_identity__' AS instance_key,
           'legacy:' || a.id AS source_event_id
    FROM agent_endpoint_assets a
), identities AS (
    SELECT l.*,
           'uai_' || md5(l.tenant_id || chr(31) || l.source_ref_id || chr(31) || l.instance_key) AS instance_id
    FROM legacy_rows l
)
INSERT INTO agent_unified_asset_observations(
    id, tenant_id, asset_id, source_asset_id, instance_id, source_ref_id, source_event_id,
    provenance, source_occurred_at, received_at, display_name, version, content_hash,
    present, scan_status, scan_decision, evidence
)
SELECT
    'uao_' || md5(i.tenant_id || chr(31) || i.source_ref_id || chr(31) || i.source_event_id),
    i.tenant_id, i.asset_id, i.asset_id, i.instance_id, i.source_ref_id, i.source_event_id,
    'legacy_snapshot', i.last_seen, now(), i.name, i.version, i.hash,
    i.present, i.scan_status, i.scan_decision, i.evidence
FROM identities i
ON CONFLICT (tenant_id, source_ref_id, source_event_id) DO NOTHING;

COMMIT;
