-- Migration 112: Remove hard_floor concept entirely
-- Drops hard_floor columns, their CHECK constraints, and rebuilds affected indexes.
-- Hard-floor enforcement is removed system-wide (decision layer, findings, UI).

BEGIN;

-- 1. Drop CHECK constraints that pin hard_floor = false
ALTER TABLE IF EXISTS agentguard_exceptions
    DROP CONSTRAINT IF EXISTS agentguard_exceptions_hard_floor_check;
ALTER TABLE IF EXISTS content_audit_exceptions
    DROP CONSTRAINT IF EXISTS content_audit_exceptions_hard_floor_check;

-- 2. Rebuild idx_alert_groups_ttl without the NOT hard_floor predicate
DROP INDEX IF EXISTS idx_alert_groups_ttl;
CREATE INDEX idx_alert_groups_ttl
    ON alert_groups (tenant_id, last_seen_at)
    WHERE (status IN ('open', 'acknowledged') AND NOT is_canary);

-- 3. Drop hard_floor columns from all tables
ALTER TABLE IF EXISTS tool_call_logs        DROP COLUMN IF EXISTS hard_floor;
ALTER TABLE IF EXISTS agentguard_exceptions DROP COLUMN IF EXISTS hard_floor;
ALTER TABLE IF EXISTS content_audit_exceptions DROP COLUMN IF EXISTS hard_floor;
ALTER TABLE IF EXISTS alert_groups          DROP COLUMN IF EXISTS hard_floor;

COMMIT;
