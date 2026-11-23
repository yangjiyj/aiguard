ALTER TABLE request_logs
    ADD COLUMN IF NOT EXISTS upstream_outcome TEXT NOT NULL DEFAULT 'unknown',
    ADD COLUMN IF NOT EXISTS delivery_outcome TEXT NOT NULL DEFAULT 'unknown',
    ADD COLUMN IF NOT EXISTS billing_outcome TEXT NOT NULL DEFAULT 'unknown',
    ADD COLUMN IF NOT EXISTS cancel_outcome TEXT NOT NULL DEFAULT 'none',
    ADD COLUMN IF NOT EXISTS audit_outcome TEXT NOT NULL DEFAULT 'pending',
    ADD COLUMN IF NOT EXISTS outcome_schema_version SMALLINT NOT NULL DEFAULT 1;

CREATE INDEX IF NOT EXISTS idx_request_logs_outcome_reconcile
    ON request_logs (audit_outcome, billing_outcome, created_at)
    WHERE audit_outcome='pending' OR billing_outcome='pending';

COMMENT ON COLUMN request_logs.request_status IS
    'Compatibility summary; authoritative forwarding states are the outcome dimension columns.';
