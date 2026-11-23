BEGIN;
ALTER TABLE tool_call_logs DROP CONSTRAINT IF EXISTS tool_call_logs_execution_fact_check;
ALTER TABLE tool_call_logs ADD CONSTRAINT tool_call_logs_execution_fact_check
  CHECK (
    attribution_mode = 'endpoint_hook'
    OR (
      (event_kind IS NULL AND execution_observed IS NULL AND result_observed IS NULL)
      OR (
        event_kind IS NOT NULL
        AND execution_observed IS NOT NULL
        AND result_observed IS NOT NULL
        AND (event_kind = 'execution_forwarded') = execution_observed
      )
    )
  ) NOT VALID;
COMMIT;
