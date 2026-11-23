BEGIN;

INSERT INTO migration_backfill_tasks (
    task_name, task_version, state, checkpoint, scan_upper_bound,
    batch_size, rate_limit_rows_per_second, lock_timeout_ms,
    statement_timeout_ms, max_retries, priority
)
VALUES (
    'request_log_compatibility_v1', 1, 'pending', '{}'::jsonb, '{}'::jsonb,
    1000, 5000, 1000, 30000, 20, 20
)
ON CONFLICT (task_name, task_version) DO NOTHING;

INSERT INTO migration_backfill_events(task_name, task_version, event_type, state, summary)
SELECT 'request_log_compatibility_v1', 1, 'registered', 'pending',
       'Historical proxy mode, retention lifecycle, and concrete Codex User-Agent repair scheduled'
WHERE NOT EXISTS (
    SELECT 1 FROM migration_backfill_events
    WHERE task_name='request_log_compatibility_v1'
      AND task_version=1 AND event_type='registered'
);

COMMIT;
