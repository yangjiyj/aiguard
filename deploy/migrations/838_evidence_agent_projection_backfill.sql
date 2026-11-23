BEGIN;

INSERT INTO migration_backfill_tasks (
    task_name, task_version, state, checkpoint, scan_upper_bound,
    batch_size, rate_limit_rows_per_second, lock_timeout_ms,
    statement_timeout_ms, max_retries, priority
)
VALUES (
    'evidence_agent_projection_v1', 1, 'pending', '{}'::jsonb, '{}'::jsonb,
    100, 1000, 1000, 30000, 20, 30
)
ON CONFLICT (task_name, task_version) DO NOTHING;

INSERT INTO migration_backfill_events(task_name, task_version, event_type, state, summary)
SELECT 'evidence_agent_projection_v1', 1, 'registered', 'pending',
       'Sticky Codex evidence projection repair scheduled in bounded batches'
WHERE NOT EXISTS (
    SELECT 1 FROM migration_backfill_events
    WHERE task_name='evidence_agent_projection_v1'
      AND task_version=1 AND event_type='registered'
);

COMMIT;
