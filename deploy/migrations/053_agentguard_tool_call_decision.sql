-- Migration 053: AgentGuard Tool Call Decision Fields
-- Persists raw/effective AgentGuard decisions for replayable tool-call audit.

ALTER TABLE IF EXISTS tool_call_logs
  ADD COLUMN IF NOT EXISTS raw_decision VARCHAR(16),
  ADD COLUMN IF NOT EXISTS effective_decision VARCHAR(16),
  ADD COLUMN IF NOT EXISTS mode VARCHAR(16),
  ADD COLUMN IF NOT EXISTS effective_reason TEXT,
  ADD COLUMN IF NOT EXISTS policy_version VARCHAR(64),
  ADD COLUMN IF NOT EXISTS trace_id VARCHAR(128),
  ADD COLUMN IF NOT EXISTS confidence DOUBLE PRECISION,
  ADD COLUMN IF NOT EXISTS evidence_json JSONB NOT NULL DEFAULT '[]'::jsonb,
  ADD COLUMN IF NOT EXISTS normalized_target TEXT,
  ADD COLUMN IF NOT EXISTS provenance VARCHAR(16),
  ADD COLUMN IF NOT EXISTS tainted_arguments JSONB NOT NULL DEFAULT '[]'::jsonb,
  ADD COLUMN IF NOT EXISTS hard_floor BOOLEAN NOT NULL DEFAULT FALSE;

CREATE INDEX IF NOT EXISTS idx_tool_call_logs_effective_decision
  ON tool_call_logs(effective_decision);

CREATE INDEX IF NOT EXISTS idx_tool_call_logs_trace_id
  ON tool_call_logs(trace_id);

CREATE INDEX IF NOT EXISTS idx_tool_call_logs_policy_version
  ON tool_call_logs(policy_version);

COMMENT ON COLUMN tool_call_logs.raw_decision IS 'AgentGuard 原始判定：allow/audit/confirm/block';
COMMENT ON COLUMN tool_call_logs.effective_decision IS 'AgentGuard 按模式和策略折算后的实际动作';
COMMENT ON COLUMN tool_call_logs.mode IS 'AgentGuard 生效模式：observe/audit/strict';
COMMENT ON COLUMN tool_call_logs.effective_reason IS 'raw 到 effective 的折算原因';
COMMENT ON COLUMN tool_call_logs.policy_version IS '生成本次判定的策略版本';
COMMENT ON COLUMN tool_call_logs.trace_id IS '贯穿 pre/post 与审计的追踪 ID';
COMMENT ON COLUMN tool_call_logs.confidence IS 'AgentGuard 判定置信度';
COMMENT ON COLUMN tool_call_logs.evidence_json IS '已脱敏/哈希的证据 JSON，禁止存储原始密钥';
COMMENT ON COLUMN tool_call_logs.normalized_target IS '归一化后的目标 URL、IP 或路径';
COMMENT ON COLUMN tool_call_logs.provenance IS '参数级来源：trusted/untrusted/mixed/tainted';
COMMENT ON COLUMN tool_call_logs.tainted_arguments IS '命中不可信来源的参数名列表';
COMMENT ON COLUMN tool_call_logs.hard_floor IS '是否命中不可被例外绕过的硬底线';
