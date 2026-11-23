BEGIN;

-- New request logs must be evaluated by the current customer-content boundary.
-- Historical rows are repaired by migration_backfill_tasks after migration
-- 834. Keep this synchronous expand step independent of table size.
ALTER TABLE request_logs
    ALTER COLUMN customer_content_rule_version SET DEFAULT 1;

COMMIT;
