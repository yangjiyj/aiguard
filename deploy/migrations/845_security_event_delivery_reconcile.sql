BEGIN;

INSERT INTO migration_backfill_tasks (
    task_name, task_version, state, checkpoint, scan_upper_bound,
    batch_size, rate_limit_rows_per_second, lock_timeout_ms,
    statement_timeout_ms, max_retries, priority
)
SELECT
    'security_event_delivery_v1', 2, 'pending', '{}'::jsonb, '{}'::jsonb,
    1000, 5000, 1000, 30000, 20, 15
WHERE EXISTS (
    SELECT 1 FROM migration_backfill_tasks
    WHERE task_name='security_event_delivery_v1'
      AND task_version=1 AND state='completed'
)
ON CONFLICT (task_name, task_version) DO NOTHING;

INSERT INTO migration_backfill_events(task_name, task_version, event_type, state, summary)
SELECT 'security_event_delivery_v1', 2, 'registered', 'pending',
       'Reconcile rows written after the version-1 scan upper bound'
WHERE EXISTS (
    SELECT 1 FROM migration_backfill_tasks
    WHERE task_name='security_event_delivery_v1'
      AND task_version=2
)
AND NOT EXISTS (
    SELECT 1 FROM migration_backfill_events
    WHERE task_name='security_event_delivery_v1'
      AND task_version=2 AND event_type='registered'
);

COMMIT;
