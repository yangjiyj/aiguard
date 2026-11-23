-- T16 approved task ledger. Task IDs are locators; authority is re-resolved
-- from the authenticated endpoint/principal and the live T13 grants per call.
BEGIN;

CREATE TABLE IF NOT EXISTS agent_intent_tasks (
    id UUID PRIMARY KEY,
    tenant_id VARCHAR(64) NOT NULL,
    endpoint_id TEXT NOT NULL,
    product VARCHAR(32) NOT NULL CHECK (product IN ('claude-code','openclaw','opencode')),
    principal_id UUID NOT NULL,
    state VARCHAR(16) NOT NULL DEFAULT 'approved'
        CHECK (state IN ('approved','revoked','completed')),
    purpose TEXT NOT NULL CHECK (length(purpose) BETWEEN 1 AND 2048),
    purpose_sha256 CHAR(64) NOT NULL CHECK (purpose_sha256 ~ '^[0-9a-f]{64}$'),
    source_scope JSONB NOT NULL CHECK (jsonb_typeof(source_scope) = 'object'),
    source_scope_sha256 CHAR(64) NOT NULL CHECK (source_scope_sha256 ~ '^[0-9a-f]{64}$'),
    scope_sha256 CHAR(64) NOT NULL CHECK (scope_sha256 ~ '^[0-9a-f]{64}$'),
    approved_by VARCHAR(128) NOT NULL,
    approved_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_by VARCHAR(128),
    revoked_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    CHECK (expires_at > approved_at),
    CHECK ((state = 'revoked') = (revoked_at IS NOT NULL)),
    UNIQUE (tenant_id, id)
);

-- Deliberately no foreign key to T13 principal/grant rows: their expiry,
-- revocation, or retention deletion must make a task unresolved without
-- preventing existing T13 retention. The resolver rechecks each live row.
CREATE INDEX IF NOT EXISTS idx_agent_intent_tasks_active_endpoint
    ON agent_intent_tasks (tenant_id, endpoint_id, principal_id, expires_at)
    WHERE state = 'approved';
CREATE INDEX IF NOT EXISTS idx_agent_intent_tasks_expiry_cleanup
    ON agent_intent_tasks (expires_at) WHERE state <> 'revoked';

CREATE OR REPLACE FUNCTION agent_intent_task_snapshot_immutable()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
       OR NEW.endpoint_id IS DISTINCT FROM OLD.endpoint_id
       OR NEW.product IS DISTINCT FROM OLD.product
       OR NEW.principal_id IS DISTINCT FROM OLD.principal_id
       OR NEW.purpose IS DISTINCT FROM OLD.purpose
       OR NEW.purpose_sha256 IS DISTINCT FROM OLD.purpose_sha256
       OR NEW.source_scope IS DISTINCT FROM OLD.source_scope
       OR NEW.source_scope_sha256 IS DISTINCT FROM OLD.source_scope_sha256
       OR NEW.scope_sha256 IS DISTINCT FROM OLD.scope_sha256
       OR NEW.approved_by IS DISTINCT FROM OLD.approved_by
       OR NEW.approved_at IS DISTINCT FROM OLD.approved_at
       OR NEW.expires_at IS DISTINCT FROM OLD.expires_at THEN
        RAISE EXCEPTION 'approved intent task snapshot is immutable';
    END IF;
    RETURN NEW;
END;
$$;
DROP TRIGGER IF EXISTS trg_agent_intent_task_snapshot_immutable ON agent_intent_tasks;
CREATE TRIGGER trg_agent_intent_task_snapshot_immutable
    BEFORE UPDATE ON agent_intent_tasks
    FOR EACH ROW EXECUTE FUNCTION agent_intent_task_snapshot_immutable();

CREATE TABLE IF NOT EXISTS agent_intent_task_grants (
    tenant_id VARCHAR(64) NOT NULL,
    task_id UUID NOT NULL,
    grant_id UUID NOT NULL,
    action VARCHAR(64) NOT NULL,
    resource_type VARCHAR(64) NOT NULL,
    resource_ref_hash CHAR(64) NOT NULL CHECK (resource_ref_hash ~ '^[0-9a-f]{64}$'),
    grant_expires_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id, task_id, grant_id),
    UNIQUE (tenant_id, task_id, action, resource_type, resource_ref_hash),
    FOREIGN KEY (tenant_id, task_id)
        REFERENCES agent_intent_tasks (tenant_id, id) ON DELETE CASCADE
);

CREATE OR REPLACE FUNCTION agent_intent_task_grant_snapshot_immutable()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'approved intent task grant snapshot is immutable';
END;
$$;
DROP TRIGGER IF EXISTS trg_agent_intent_task_grant_snapshot_immutable ON agent_intent_task_grants;
CREATE TRIGGER trg_agent_intent_task_grant_snapshot_immutable
    BEFORE UPDATE ON agent_intent_task_grants
    FOR EACH ROW EXECUTE FUNCTION agent_intent_task_grant_snapshot_immutable();

CREATE TABLE IF NOT EXISTS agent_intent_task_steps (
    id UUID PRIMARY KEY,
    tenant_id VARCHAR(64) NOT NULL,
    task_id UUID NOT NULL,
    server_sequence BIGINT NOT NULL CHECK (server_sequence > 0),
    endpoint_id TEXT NOT NULL,
    product VARCHAR(32) NOT NULL,
    session_ref_hash CHAR(64) NOT NULL CHECK (session_ref_hash ~ '^[0-9a-f]{64}$'),
    prompt_ref_hash CHAR(64) NOT NULL CHECK (prompt_ref_hash ~ '^[0-9a-f]{64}$'),
    tool_use_ref_hash CHAR(64) NOT NULL CHECK (tool_use_ref_hash ~ '^[0-9a-f]{64}$'),
    tool_call_log_id TEXT NOT NULL,
    arguments_hash VARCHAR(71) NOT NULL CHECK (arguments_hash ~ '^sha256:[0-9a-f]{64}$'),
    tool_name VARCHAR(255) NOT NULL,
    tool_type VARCHAR(32) NOT NULL DEFAULT 'other',
    action VARCHAR(64) NOT NULL DEFAULT '',
    resource_type VARCHAR(64) NOT NULL DEFAULT '',
    resource_ref_hash CHAR(64) NOT NULL DEFAULT repeat('0',64)
        CHECK (resource_ref_hash ~ '^[0-9a-f]{64}$'),
    authorization_state VARCHAR(24) NOT NULL,
    authorization_bindings_hash CHAR(64) NOT NULL CHECK (authorization_bindings_hash ~ '^[0-9a-f]{64}$'),
    principal_ref_hash CHAR(64) NOT NULL CHECK (principal_ref_hash ~ '^[0-9a-f]{64}$'),
    grant_ref_hash CHAR(64) NOT NULL CHECK (grant_ref_hash ~ '^[0-9a-f]{64}$'),
    source_refs JSONB NOT NULL DEFAULT '[]'::JSONB CHECK (jsonb_typeof(source_refs) = 'array'),
    terminal_event_id TEXT,
    terminal_event_ref_hash CHAR(64),
    terminal_outcome VARCHAR(24) NOT NULL DEFAULT 'pending'
        CHECK (terminal_outcome IN ('pending','succeeded','failed','denied','uncertain')),
    result_hash CHAR(64),
    result_length BIGINT CHECK (result_length IS NULL OR result_length >= 0),
    lineage_state VARCHAR(24) NOT NULL DEFAULT 'uncertain'
        CHECK (lineage_state IN ('server_task_record','partial','uncertain')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    UNIQUE (tenant_id, task_id, server_sequence),
    UNIQUE (tenant_id, tool_call_log_id),
    FOREIGN KEY (tenant_id, task_id)
        REFERENCES agent_intent_tasks (tenant_id, id) ON DELETE CASCADE
);

-- tool_call_log_id and terminal_event_id are intentionally non-FK references.
-- T07 log/event retention must not be blocked by task history; a missing
-- referenced row is surfaced as incomplete/uncertain on read.
CREATE INDEX IF NOT EXISTS idx_agent_intent_task_steps_order
    ON agent_intent_task_steps (tenant_id, task_id, server_sequence);
CREATE INDEX IF NOT EXISTS idx_agent_intent_task_steps_log
    ON agent_intent_task_steps (tenant_id, tool_call_log_id);

COMMIT;
