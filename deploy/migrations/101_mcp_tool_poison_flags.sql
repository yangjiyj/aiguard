-- 101_mcp_tool_poison_flags.sql
-- MCP 二期：描述投毒检测（observe-only）。
-- 在 mcp_tools 上加 poison_flags 列，存 sync 时对每个工具 description 送 security-engine
-- 描述投毒扫描（agent_guard.scan_mcp_description）命中的标签数组（如 ["mcp_description_poison"]）。
-- 空数组 / NULL = 干净。observe-only：只标记不阻断，不影响任何决策/落库成败。
-- 幂等（ADD COLUMN IF NOT EXISTS），可安全重跑。

ALTER TABLE mcp_tools ADD COLUMN IF NOT EXISTS poison_flags JSONB;

COMMENT ON COLUMN mcp_tools.poison_flags IS '描述投毒命中标签数组（observe-only）：sync 时送 security-engine 扫 description，命中的 rule/category（如 mcp_description_poison）；空数组/NULL=干净';
