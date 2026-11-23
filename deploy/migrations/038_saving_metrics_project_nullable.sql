-- 038_saving_metrics_project_nullable.sql
-- Allow project_id to be NULL for tenant-level saving sources (circuit_breaker, key_mgmt_labor).
-- Previously project_id was NOT NULL with FK to projects, preventing tenant-level aggregation.

ALTER TABLE saving_metrics DROP CONSTRAINT IF EXISTS saving_metrics_project_id_fkey;
ALTER TABLE saving_metrics ALTER COLUMN project_id DROP NOT NULL;
ALTER TABLE saving_metrics ALTER COLUMN project_id DROP DEFAULT;

-- Also allow team_id and user_id to be NULL (currently they are stored as '' not NULL,
-- but for consistency allow NULL too).
-- The UNIQUE constraint uses '' for team_id/user_id per ON CONFLICT semantics note in calculator.go.
-- No change needed for those - keep '' convention for UNIQUE compatibility.

COMMENT ON COLUMN saving_metrics.project_id IS 'Project scope (NULL for tenant-level sources like circuit_breaker, key_mgmt_labor)';
COMMENT ON COLUMN saving_metrics.source IS 'cache_hit | model_downgraded | negotiated_price | circuit_breaker | key_mgmt_labor';
