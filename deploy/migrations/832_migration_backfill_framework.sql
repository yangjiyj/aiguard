BEGIN;

CREATE TABLE IF NOT EXISTS migration_backfill_tasks (
    task_name TEXT NOT NULL,
    task_version INTEGER NOT NULL,
    state TEXT NOT NULL DEFAULT 'pending'
        CHECK (state IN ('pending','running','paused','failed','completed','cancelled')),
    checkpoint JSONB NOT NULL DEFAULT '{}'::jsonb,
    scan_upper_bound JSONB NOT NULL DEFAULT '{}'::jsonb,
    batch_size INTEGER NOT NULL DEFAULT 500 CHECK (batch_size BETWEEN 1 AND 10000),
    rate_limit_rows_per_second INTEGER NOT NULL DEFAULT 2000
        CHECK (rate_limit_rows_per_second BETWEEN 1 AND 100000),
    lock_timeout_ms INTEGER NOT NULL DEFAULT 1000 CHECK (lock_timeout_ms BETWEEN 1 AND 60000),
    statement_timeout_ms INTEGER NOT NULL DEFAULT 30000
        CHECK (statement_timeout_ms BETWEEN 1000 AND 900000),
    max_retries INTEGER NOT NULL DEFAULT 20 CHECK (max_retries BETWEEN 0 AND 1000),
    retry_count INTEGER NOT NULL DEFAULT 0,
    error_summary TEXT NOT NULL DEFAULT '',
    scanned BIGINT NOT NULL DEFAULT 0,
    updated BIGINT NOT NULL DEFAULT 0,
    skipped BIGINT NOT NULL DEFAULT 0,
    failed BIGINT NOT NULL DEFAULT 0,
    current_rate DOUBLE PRECISION NOT NULL DEFAULT 0,
    estimated_rows BIGINT NOT NULL DEFAULT 0,
    eta_seconds BIGINT,
    lease_owner TEXT,
    lease_expires_at TIMESTAMPTZ,
    heartbeat_at TIMESTAMPTZ,
    pause_requested BOOLEAN NOT NULL DEFAULT FALSE,
    cancel_requested BOOLEAN NOT NULL DEFAULT FALSE,
    validation_status TEXT NOT NULL DEFAULT 'pending'
        CHECK (validation_status IN ('pending','running','passed','failed')),
    priority INTEGER NOT NULL DEFAULT 100,
    started_at TIMESTAMPTZ,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at TIMESTAMPTZ,
    PRIMARY KEY (task_name, task_version)
);

CREATE TABLE IF NOT EXISTS migration_backfill_retry_rows (
    task_name TEXT NOT NULL,
    task_version INTEGER NOT NULL,
    row_id VARCHAR(64) NOT NULL,
    row_created_at TIMESTAMPTZ NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    next_retry_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_error TEXT NOT NULL DEFAULT '',
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (task_name, task_version, row_id),
    FOREIGN KEY (task_name, task_version)
        REFERENCES migration_backfill_tasks(task_name, task_version)
        ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS migration_backfill_events (
    id BIGSERIAL PRIMARY KEY,
    task_name TEXT NOT NULL,
    task_version INTEGER NOT NULL,
    event_type TEXT NOT NULL,
    state TEXT NOT NULL,
    summary TEXT NOT NULL DEFAULT '',
    metrics JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_migration_backfill_tasks_claim
    ON migration_backfill_tasks(priority, updated_at)
    WHERE state IN ('pending','running');
CREATE INDEX IF NOT EXISTS idx_migration_backfill_retry_ready
    ON migration_backfill_retry_rows(task_name, task_version, next_retry_at, row_created_at, row_id);
CREATE INDEX IF NOT EXISTS idx_migration_backfill_events_task
    ON migration_backfill_events(task_name, task_version, created_at DESC);

COMMENT ON TABLE migration_backfill_tasks IS
    'Persistent, resumable expand-contract backfills. Customer content is never stored in task metadata or events.';

COMMIT;
