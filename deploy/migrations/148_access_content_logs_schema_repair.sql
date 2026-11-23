-- Repair only the expandable schema shape. Historical values, NOT NULL
-- validation and support indexes are handled after migration 836 by resumable
-- backfill and migration 837. This file stays safe on partially upgraded large
-- databases.
BEGIN;

ALTER TABLE request_logs
    ADD COLUMN IF NOT EXISTS environment_scope VARCHAR(32);
ALTER TABLE access_content_logs
    ADD COLUMN IF NOT EXISTS environment_scope VARCHAR(32),
    ADD COLUMN IF NOT EXISTS section_id VARCHAR(128),
    ADD COLUMN IF NOT EXISTS conversation_id VARCHAR(128);
ALTER TABLE content_logs
    ADD COLUMN IF NOT EXISTS environment_scope VARCHAR(32);
ALTER TABLE retained_artifacts
    ADD COLUMN IF NOT EXISTS environment_scope VARCHAR(32);
ALTER TABLE access_content_artifact_links
    ADD COLUMN IF NOT EXISTS environment_scope VARCHAR(32);

ALTER TABLE request_logs
    ALTER COLUMN environment_scope SET DEFAULT 'legacy-unclassified';
ALTER TABLE access_content_logs
    ALTER COLUMN environment_scope SET DEFAULT 'legacy-unclassified';
ALTER TABLE content_logs
    ALTER COLUMN environment_scope SET DEFAULT 'legacy-unclassified';
ALTER TABLE retained_artifacts
    ALTER COLUMN environment_scope SET DEFAULT 'legacy-unclassified';
ALTER TABLE access_content_artifact_links
    ALTER COLUMN environment_scope SET DEFAULT 'legacy-unclassified';

DO $$
DECLARE
    item RECORD;
BEGIN
    FOR item IN SELECT * FROM (VALUES
        ('request_logs', 'request_logs_environment_scope_check'),
        ('access_content_logs', 'access_content_logs_environment_scope_check'),
        ('content_logs', 'content_logs_environment_scope_check'),
        ('retained_artifacts', 'retained_artifacts_environment_scope_check'),
        ('access_content_artifact_links', 'access_content_artifact_links_environment_scope_check')
    ) AS expected(table_name, constraint_name)
    LOOP
        IF NOT EXISTS (
            SELECT 1 FROM pg_constraint
            WHERE conname = item.constraint_name
              AND conrelid = to_regclass('public.' || item.table_name)
        ) THEN
            EXECUTE format(
                'ALTER TABLE %I ADD CONSTRAINT %I CHECK (environment_scope IN (''customer'', ''home'', ''claude'', ''codex'', ''legacy-unclassified'')) NOT VALID',
                item.table_name, item.constraint_name
            );
        END IF;
    END LOOP;
END $$;

COMMIT;
