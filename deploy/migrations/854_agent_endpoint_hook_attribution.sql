BEGIN;
ALTER TABLE tool_call_logs DROP CONSTRAINT IF EXISTS tool_call_logs_attribution_mode_check;
ALTER TABLE tool_call_logs ADD CONSTRAINT tool_call_logs_attribution_mode_check
  CHECK (attribution_mode IN ('explicit', 'linked', 'inferred', 'none', 'endpoint_hook')) NOT VALID;
COMMIT;
