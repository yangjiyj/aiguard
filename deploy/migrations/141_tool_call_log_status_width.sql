-- Migration 141: widen tool_call_logs.status for Agent destructive confirmation states.
-- Existing destructive-operation lifecycle writes status='waiting_confirmation',
-- which is longer than the original VARCHAR(16) tool audit status column.

ALTER TABLE tool_call_logs
  ALTER COLUMN status TYPE VARCHAR(32);

COMMENT ON COLUMN tool_call_logs.status IS
  'Execution status: success, failed, blocked, waiting_confirmation';
