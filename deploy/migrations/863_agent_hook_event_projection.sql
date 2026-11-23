-- Complete the hookd events.v1 identity projection without rewriting historical claims.
BEGIN;
ALTER TABLE agent_sessions ALTER COLUMN session_id TYPE text;
ALTER TABLE tool_events ALTER COLUMN session_id TYPE text;
ALTER TABLE tool_call_logs ALTER COLUMN session_id TYPE text;
ALTER TABLE tool_call_logs ALTER COLUMN tool_name TYPE text;
ALTER TABLE tool_call_logs ADD COLUMN IF NOT EXISTS endpoint_id text;

COMMIT;
