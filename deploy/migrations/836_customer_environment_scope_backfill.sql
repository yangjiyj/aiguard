BEGIN;

INSERT INTO migration_backfill_tasks (
    task_name, task_version, state, checkpoint, scan_upper_bound,
    batch_size, rate_limit_rows_per_second, lock_timeout_ms,
    statement_timeout_ms, max_retries, priority, pause_requested
)
VALUES (
    'customer_environment_scope_v1', 1, 'paused', '{}'::jsonb, '{}'::jsonb,
    1000, 5000, 1000, 30000, 20, 5, TRUE
)
ON CONFLICT (task_name, task_version) DO NOTHING;

INSERT INTO migration_backfill_events(task_name, task_version, event_type, state, summary)
SELECT 'customer_environment_scope_v1', 1, 'registered', 'paused',
       'Customer-only environment-scope repair awaits activation by the installer'
WHERE NOT EXISTS (
    SELECT 1 FROM migration_backfill_events
    WHERE task_name='customer_environment_scope_v1'
      AND task_version=1 AND event_type='registered'
);

COMMIT;

