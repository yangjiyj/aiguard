-- Migration 007: Audit Enhancement
-- Add input/output audit result fields to request_logs

-- 1. Add audit result fields
ALTER TABLE request_logs ADD COLUMN IF NOT EXISTS
    input_audit_result JSONB DEFAULT '{}';

ALTER TABLE request_logs ADD COLUMN IF NOT EXISTS
    output_audit_result JSONB DEFAULT '{}';

ALTER TABLE request_logs ADD COLUMN IF NOT EXISTS
    proxy_mode VARCHAR(16) DEFAULT 'reverse';

-- 2. Add indexes for audit result queries
CREATE INDEX IF NOT EXISTS idx_request_logs_input_audit
    ON request_logs((input_audit_result->>'action_taken'))
    WHERE input_audit_result != '{}';

CREATE INDEX IF NOT EXISTS idx_request_logs_output_audit
    ON request_logs((output_audit_result->>'action_taken'))
    WHERE output_audit_result != '{}';

-- 3. Comments
COMMENT ON COLUMN request_logs.input_audit_result IS '输入安全检测结果: {findings, action_taken, check_time}';
COMMENT ON COLUMN request_logs.output_audit_result IS '输出安全检测结果: {findings, action_taken, check_time}';
COMMENT ON COLUMN request_logs.proxy_mode IS '代理模式: reverse(反向代理) / forward(正向代理)';