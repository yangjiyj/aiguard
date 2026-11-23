-- Migration: 072_outbox_events
-- Purpose: durable event outbox for decoupling gateway hot-path evidence writes from workers.

CREATE TABLE IF NOT EXISTS outbox_events (
    id VARCHAR(96) PRIMARY KEY,
    tenant_id VARCHAR(64) NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    event_type VARCHAR(128) NOT NULL,
    schema_version VARCHAR(16) NOT NULL DEFAULT 'v1',
    request_id VARCHAR(64),
    trace_id VARCHAR(128),
    payload_json JSONB NOT NULL DEFAULT '{}'::jsonb,
    status VARCHAR(16) NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'processing', 'processed', 'failed', 'dead')),
    attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    available_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    locked_at TIMESTAMP WITH TIME ZONE,
    locked_by VARCHAR(128),
    last_error TEXT,
    processed_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_outbox_events_pending
    ON outbox_events (available_at ASC, created_at ASC)
    WHERE status IN ('pending', 'failed');

CREATE INDEX IF NOT EXISTS idx_outbox_events_tenant_created
    ON outbox_events (tenant_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_outbox_events_request
    ON outbox_events (request_id)
    WHERE request_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_outbox_events_type_status
    ON outbox_events (event_type, status, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_outbox_events_processing_stale
    ON outbox_events (locked_at ASC)
    WHERE status = 'processing';

COMMENT ON TABLE outbox_events IS 'Durable outbox for async gateway evidence writes and worker fan-out.';
COMMENT ON COLUMN outbox_events.status IS 'pending | processing | processed | failed | dead';
COMMENT ON COLUMN outbox_events.available_at IS 'Next time the event may be claimed by a worker.';
COMMENT ON COLUMN outbox_events.locked_by IS 'Worker consumer name that currently owns a processing event.';
COMMENT ON COLUMN outbox_events.payload_json IS 'Versioned event payload; large binary evidence must live in retention/object storage, not here.';
