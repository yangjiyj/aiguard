-- Migration: 063_security_events_alerted_at
-- Purpose: Add alerted_at column for security event → alert inbox deduplication
-- Part of: P0-2 告警闭环 (Task 1.1)

ALTER TABLE security_events ADD COLUMN IF NOT EXISTS alerted_at TIMESTAMP WITH TIME ZONE DEFAULT NULL;

-- Index for efficient unalerted high/critical query
CREATE INDEX IF NOT EXISTS idx_security_events_unalerted_severity
    ON security_events (created_at, severity)
    WHERE alerted_at IS NULL AND severity IN ('high', 'critical');

COMMENT ON COLUMN security_events.alerted_at IS 'Timestamp when this event was pushed to alert_inbox; NULL = not yet alerted';