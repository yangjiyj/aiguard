BEGIN;

ALTER TABLE quota_policies
    ADD COLUMN IF NOT EXISTS key_id VARCHAR(64);

CREATE UNIQUE INDEX IF NOT EXISTS uq_internal_keys_tenant_id_id
    ON internal_keys(tenant_id, id);

DO $migration$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conname = 'fk_quota_policies_key_id'
          AND conrelid = 'quota_policies'::regclass
    ) THEN
        ALTER TABLE quota_policies
            ADD CONSTRAINT fk_quota_policies_key_id
            FOREIGN KEY (tenant_id, key_id)
            REFERENCES internal_keys(tenant_id, id) ON DELETE CASCADE;
    END IF;
END
$migration$;

-- A legacy prefix is safe to bind only when both sides are singular inside the
-- tenant. Ambiguous key prefixes and duplicate legacy policy rows stay NULL.
WITH unique_keys AS (
    SELECT tenant_id, key_prefix, MIN(id) AS key_id
    FROM internal_keys
    WHERE NULLIF(BTRIM(key_prefix), '') IS NOT NULL
    GROUP BY tenant_id, key_prefix
    HAVING COUNT(*) = 1
),
unique_legacy_policies AS (
    SELECT tenant_id, key_prefix, MIN(id) AS policy_id
    FROM quota_policies
    WHERE scope_type = 'key'
      AND key_id IS NULL
      AND NULLIF(BTRIM(key_prefix), '') IS NOT NULL
    GROUP BY tenant_id, key_prefix
    HAVING COUNT(*) = 1
)
UPDATE quota_policies policy
SET key_id = keys.key_id
FROM unique_keys keys
JOIN unique_legacy_policies legacy
  ON legacy.tenant_id = keys.tenant_id
 AND legacy.key_prefix = keys.key_prefix
WHERE policy.id = legacy.policy_id
  AND policy.tenant_id = legacy.tenant_id
  AND policy.key_id IS NULL;

CREATE INDEX IF NOT EXISTS idx_quota_policies_key_id
    ON quota_policies(key_id)
    WHERE key_id IS NOT NULL;

CREATE UNIQUE INDEX IF NOT EXISTS uq_quota_policies_tenant_key_id
    ON quota_policies(tenant_id, key_id)
    WHERE scope_type = 'key' AND key_id IS NOT NULL;

COMMENT ON COLUMN quota_policies.key_id IS
    'key scope 的稳定 internal_keys.id；key_prefix 仅用于迁移兼容，歧义旧数据保持 NULL';

COMMIT;
