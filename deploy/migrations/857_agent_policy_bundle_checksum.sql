BEGIN;
-- Bundle versions are immutable and monotonically increasing. The same semantic
-- checksum can recur after a rollback, so only (tenant_id, version) is unique.
ALTER TABLE agent_policy_bundles
    DROP CONSTRAINT IF EXISTS agent_policy_bundles_tenant_id_checksum_key;
CREATE INDEX IF NOT EXISTS idx_agent_policy_bundles_tenant_checksum
    ON agent_policy_bundles (tenant_id, checksum);
COMMIT;
