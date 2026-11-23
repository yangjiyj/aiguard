-- Migration 901 (W5 5.2 + 5.3): AgentGuard confirmation single-use retry and
-- approver separation.
--
-- 5.2: a non-MCP confirmation approved by an admin promised "the client may
-- retry", but the gateway never looked the approval up. The gateway now asks
-- the control plane to consume an approved, not-yet-used confirmation that is
-- bound to the same tenant, requester (user + API key), tool name and
-- canonical arguments hash. Consumption flips replay_status to 'executed'
-- exactly once (row lock + status predicate).
--
-- 5.3: approvals must come from someone other than the requester, and an
-- optional second approver can be required. requester_* are recorded at
-- creation; first_approved_* hold the first of two approvals.
--
-- Legacy rows keep NULL requester/arguments_hash: they can still be resolved
-- (the requester is unknown, so self-approval cannot be detected) but can never
-- be consumed by a retry because the hash does not match.
-- Idempotent: every statement is IF NOT EXISTS.
BEGIN;

ALTER TABLE agentguard_confirmations
    ADD COLUMN IF NOT EXISTS requester_user_id   VARCHAR(64),
    ADD COLUMN IF NOT EXISTS requester_client_id VARCHAR(64),
    ADD COLUMN IF NOT EXISTS arguments_hash      VARCHAR(64),
    ADD COLUMN IF NOT EXISTS first_approved_by   VARCHAR(64),
    ADD COLUMN IF NOT EXISTS first_approved_at   TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS consumed_request_id VARCHAR(128);

CREATE INDEX IF NOT EXISTS idx_agentguard_confirmations_consume
    ON agentguard_confirmations (tenant_id, tool_name, arguments_hash)
    WHERE status IN ('pending', 'approved') AND COALESCE(source, '') = '';

COMMIT;
