-- Global baseline and tenant override scopes for Agent destructive-operation policies.
-- NULL tenant_id is the platform-wide baseline; it is not a synthetic system tenant.

ALTER TABLE agent_destructive_policies
  ALTER COLUMN tenant_id DROP NOT NULL;

ALTER TABLE agent_destructive_policy_audits
  ALTER COLUMN tenant_id DROP NOT NULL;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1
    FROM pg_constraint
    WHERE conrelid = 'agent_destructive_policies'::regclass
      AND conname = 'agent_destructive_policies_global_application_check'
  ) THEN
    ALTER TABLE agent_destructive_policies
      ADD CONSTRAINT agent_destructive_policies_global_application_check
      CHECK (tenant_id IS NOT NULL OR scope_type <> 'application');
  END IF;

  IF NOT EXISTS (
    SELECT 1
    FROM pg_constraint
    WHERE conrelid = 'agent_destructive_policies'::regclass
      AND conname = 'agent_destructive_policies_global_channels_check'
  ) THEN
    ALTER TABLE agent_destructive_policies
      ADD CONSTRAINT agent_destructive_policies_global_channels_check
      CHECK (tenant_id IS NOT NULL OR notify_channel_ids_json = '[]'::jsonb);
  END IF;
END
$$;

DROP INDEX IF EXISTS uq_agent_destructive_policies_enabled_scope;

CREATE UNIQUE INDEX IF NOT EXISTS uq_agent_destructive_policies_enabled_tenant_scope
  ON agent_destructive_policies (tenant_id, scope_type, scope_ref)
  WHERE enabled AND tenant_id IS NOT NULL;

CREATE UNIQUE INDEX IF NOT EXISTS uq_agent_destructive_policies_enabled_global_scope
  ON agent_destructive_policies (scope_type, scope_ref)
  WHERE enabled AND tenant_id IS NULL;

COMMENT ON COLUMN agent_destructive_policies.tenant_id IS
  'Owning tenant; NULL means the platform-wide baseline.';

COMMENT ON COLUMN agent_destructive_policy_audits.tenant_id IS
  'Owning tenant; NULL records a platform-wide baseline change.';
