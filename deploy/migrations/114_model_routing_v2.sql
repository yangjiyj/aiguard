-- Existing routing policies remain schema version 1; this migration does not convert them.
ALTER TABLE routing_policies
  ADD COLUMN IF NOT EXISTS schema_version smallint NOT NULL DEFAULT 1,
  ADD COLUMN IF NOT EXISTS config_version bigint NOT NULL DEFAULT 1;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1
    FROM pg_constraint
    WHERE conname = 'chk_routing_v2_scope_shape'
      AND conrelid = 'routing_policies'::regclass
  ) THEN
    ALTER TABLE routing_policies
      ADD CONSTRAINT chk_routing_v2_scope_shape
      CHECK (
        schema_version <> 2
        OR (
          layer = 'provider'
          AND (
            (
              scope_type = 'tenant'
              AND scope_ref IS NOT NULL
              AND scope_ref = tenant_id
            )
            OR (
              scope_type = 'model'
              AND scope_ref IS NOT NULL
              AND btrim(scope_ref) <> ''
            )
          )
        )
      );
  END IF;
END
$$;

-- routing_policies is a small configuration table. Run this migration during a
-- maintenance window because these standard index builds take table locks.
-- v2 default policies use tenant scope and are unique per tenant.
CREATE UNIQUE INDEX IF NOT EXISTS uq_routing_v2_default
  ON routing_policies (tenant_id)
  WHERE schema_version = 2 AND scope_type = 'tenant' AND layer = 'provider';

-- v2 override policies use model scope and are unique per tenant and model.
CREATE UNIQUE INDEX IF NOT EXISTS uq_routing_v2_override
  ON routing_policies (tenant_id, scope_ref)
  WHERE schema_version = 2 AND scope_type = 'model' AND layer = 'provider';
