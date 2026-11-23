BEGIN;

ALTER TABLE request_logs
    ADD COLUMN IF NOT EXISTS environment_scope VARCHAR(32) NOT NULL DEFAULT 'legacy-unclassified';

ALTER TABLE access_content_logs
    ADD COLUMN IF NOT EXISTS environment_scope VARCHAR(32) NOT NULL DEFAULT 'legacy-unclassified';

ALTER TABLE content_logs
    ADD COLUMN IF NOT EXISTS environment_scope VARCHAR(32) NOT NULL DEFAULT 'legacy-unclassified';

ALTER TABLE retained_artifacts
    ADD COLUMN IF NOT EXISTS environment_scope VARCHAR(32) NOT NULL DEFAULT 'legacy-unclassified';

ALTER TABLE access_content_artifact_links
    ADD COLUMN IF NOT EXISTS environment_scope VARCHAR(32) NOT NULL DEFAULT 'legacy-unclassified';

-- Historical propagation is activated as a resumable customer-only task by
-- the upgrade entry after migration 836. This expand migration never scans
-- the evidence tables.

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'request_logs_environment_scope_check'
    ) THEN
        ALTER TABLE request_logs ADD CONSTRAINT request_logs_environment_scope_check
            CHECK (environment_scope IN ('customer', 'home', 'claude', 'codex', 'legacy-unclassified')) NOT VALID;
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'access_content_logs_environment_scope_check'
    ) THEN
        ALTER TABLE access_content_logs ADD CONSTRAINT access_content_logs_environment_scope_check
            CHECK (environment_scope IN ('customer', 'home', 'claude', 'codex', 'legacy-unclassified')) NOT VALID;
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'content_logs_environment_scope_check'
    ) THEN
        ALTER TABLE content_logs ADD CONSTRAINT content_logs_environment_scope_check
            CHECK (environment_scope IN ('customer', 'home', 'claude', 'codex', 'legacy-unclassified')) NOT VALID;
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'retained_artifacts_environment_scope_check'
    ) THEN
        ALTER TABLE retained_artifacts ADD CONSTRAINT retained_artifacts_environment_scope_check
            CHECK (environment_scope IN ('customer', 'home', 'claude', 'codex', 'legacy-unclassified')) NOT VALID;
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'access_content_artifact_links_environment_scope_check'
    ) THEN
        ALTER TABLE access_content_artifact_links ADD CONSTRAINT access_content_artifact_links_environment_scope_check
            CHECK (environment_scope IN ('customer', 'home', 'claude', 'codex', 'legacy-unclassified')) NOT VALID;
    END IF;
END $$;

COMMIT;
