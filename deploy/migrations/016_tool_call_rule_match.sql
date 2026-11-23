-- Migration 016: Tool Call Matched Policy Snapshot
-- Persists which tool policy matched at the time of audit.

ALTER TABLE IF EXISTS tool_call_logs
  ADD COLUMN IF NOT EXISTS matched_policy_id VARCHAR(64),
  ADD COLUMN IF NOT EXISTS matched_policy_name VARCHAR(255),
  ADD COLUMN IF NOT EXISTS matched_action VARCHAR(32),
  ADD COLUMN IF NOT EXISTS match_reason TEXT;

CREATE INDEX IF NOT EXISTS idx_tool_call_logs_matched_policy ON tool_call_logs(matched_policy_id);

COMMENT ON COLUMN tool_call_logs.matched_policy_id IS '命中的工具调用策略 ID 快照';
COMMENT ON COLUMN tool_call_logs.matched_policy_name IS '命中的工具调用策略名称快照';
COMMENT ON COLUMN tool_call_logs.matched_action IS '命中策略当时的处置动作快照';
COMMENT ON COLUMN tool_call_logs.match_reason IS '工具调用命中策略或动态风险检测的原因摘要';
