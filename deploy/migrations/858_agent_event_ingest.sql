BEGIN;

ALTER TABLE agent_endpoints
    ADD COLUMN IF NOT EXISTS event_count bigint NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS tool_call_count bigint NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS blocked_count bigint NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS would_block_count bigint NOT NULL DEFAULT 0;

CREATE TABLE IF NOT EXISTS agent_alerts (
    id text PRIMARY KEY,
    tenant_id text NOT NULL,
    endpoint_id text NOT NULL,
    session_id text NOT NULL DEFAULT '',
    event_id text NOT NULL,
    severity text NOT NULL CHECK (severity IN ('high', 'critical')),
    alert_type text NOT NULL DEFAULT 'agent_endpoint_risk',
    decision text NOT NULL DEFAULT '',
    payload_summary jsonb NOT NULL DEFAULT '{}'::jsonb,
    occurred_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, event_id)
);

CREATE INDEX IF NOT EXISTS idx_agent_alerts_tenant_session_time
    ON agent_alerts (tenant_id, session_id, occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_agent_alerts_tenant_endpoint_time
    ON agent_alerts (tenant_id, endpoint_id, occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_agent_events_retention
    ON agent_events (occurred_at);
CREATE INDEX IF NOT EXISTS idx_agent_turns_retention
    ON agent_turns (tenant_id, session_id, ended_at, started_at);
CREATE INDEX IF NOT EXISTS idx_agent_assets_retention
    ON agent_endpoint_assets (last_seen) WHERE present = false;
CREATE INDEX IF NOT EXISTS idx_agent_sessions_retention
    ON agent_sessions (status, ended_at, last_request_at) WHERE status <> 'active';

COMMIT;
