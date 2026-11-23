-- +goose NO TRANSACTION
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_security_events_delivery_backfill
    ON security_events (
        COALESCE(created_at, '0001-01-01 00:00:00+00'::timestamptz),
        id
    )
    WHERE alerted_at IS NOT NULL
      AND (processed_at IS NULL OR delivery IS NULL);
