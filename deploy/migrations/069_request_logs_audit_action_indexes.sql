-- Migration: 069_request_logs_audit_action_indexes
-- Purpose: 避免对整段 input/output_audit_result jsonb 建 btree 索引。
--          长 findings/evidence 会超过 btree 单行上限，导致 request_logs 写入失败。

DROP INDEX IF EXISTS idx_request_logs_input_audit;
DROP INDEX IF EXISTS idx_request_logs_output_audit;

CREATE INDEX IF NOT EXISTS idx_request_logs_input_audit
    ON request_logs ((input_audit_result->>'action_taken'))
    WHERE input_audit_result IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_request_logs_output_audit
    ON request_logs ((output_audit_result->>'action_taken'))
    WHERE output_audit_result IS NOT NULL;
