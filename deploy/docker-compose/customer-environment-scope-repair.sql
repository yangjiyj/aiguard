BEGIN;

-- The customer upgrade entry activates the task after all schema migrations
-- commit. The worker performs the historical repair in bounded transactions
-- after service startup.
UPDATE migration_backfill_tasks
SET state = CASE WHEN state IN ('paused', 'failed') THEN 'pending' ELSE state END,
    pause_requested = FALSE,
    cancel_requested = FALSE,
    retry_count = CASE WHEN state = 'failed' THEN 0 ELSE retry_count END,
    error_summary = CASE WHEN state = 'failed' THEN '' ELSE error_summary END,
    updated_at = NOW()
WHERE task_name = 'customer_environment_scope_v1'
  AND task_version = 1
  AND state NOT IN ('completed', 'cancelled');

INSERT INTO migration_backfill_events(
    task_name, task_version, event_type, state, summary
)
SELECT task_name, task_version, 'activated', state,
       'Customer deployment activated environment-scope background repair'
FROM migration_backfill_tasks
WHERE task_name = 'customer_environment_scope_v1'
  AND task_version = 1;

COMMIT;
