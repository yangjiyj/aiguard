-- Migration: 070_alert_groups
-- Purpose: materialized alert groups for customer-facing triage workflows.

CREATE TABLE IF NOT EXISTS alert_groups (
    id VARCHAR(64) PRIMARY KEY,
    tenant_id VARCHAR(64) NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    project_id VARCHAR(64),
    group_key VARCHAR(128) NOT NULL,
    status VARCHAR(32) NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'acknowledged', 'resolved', 'false_positive')),
    severity VARCHAR(16) NOT NULL CHECK (severity IN ('info', 'warning', 'high', 'critical')),
    alert_type VARCHAR(64) NOT NULL,
    title VARCHAR(256) NOT NULL,
    representative_event_id VARCHAR(64),
    request_id VARCHAR(64),
    occurrence_count INTEGER NOT NULL DEFAULT 1 CHECK (occurrence_count >= 1),
    body_json JSONB NOT NULL DEFAULT '{}'::jsonb,
    first_seen_at TIMESTAMP WITH TIME ZONE NOT NULL,
    last_seen_at TIMESTAMP WITH TIME ZONE NOT NULL,
    acknowledged_at TIMESTAMP WITH TIME ZONE,
    resolved_at TIMESTAMP WITH TIME ZONE,
    false_positive_at TIMESTAMP WITH TIME ZONE,
    closed_at TIMESTAMP WITH TIME ZONE,
    reopened_at TIMESTAMP WITH TIME ZONE,
    disposition_by VARCHAR(64),
    disposition_note TEXT,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_alert_groups_open_unique
    ON alert_groups(tenant_id, group_key)
    WHERE status IN ('open', 'acknowledged');

CREATE INDEX IF NOT EXISTS idx_alert_groups_tenant_status_last_seen
    ON alert_groups(tenant_id, status, last_seen_at DESC);

CREATE INDEX IF NOT EXISTS idx_alert_groups_tenant_severity_last_seen
    ON alert_groups(tenant_id, severity, last_seen_at DESC);

CREATE INDEX IF NOT EXISTS idx_alert_groups_representative_event
    ON alert_groups(representative_event_id)
    WHERE representative_event_id IS NOT NULL;

COMMENT ON TABLE alert_groups IS 'Customer-facing alert groups derived from raw security_events.';
COMMENT ON COLUMN alert_groups.group_key IS 'Stable dedup key scoped by tenant; open/acknowledged groups are unique per tenant.';
COMMENT ON COLUMN alert_groups.status IS 'open | acknowledged | resolved | false_positive';
