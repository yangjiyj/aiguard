-- 100_mcp_confirmation_source.sql
-- 给 agentguard_confirmations 增加 source 列，用于审批列表按来源区分 MCP 单。
-- 背景：MCP 网关的 confirm 处置复用 agentguard_confirmations 通道（099 决策）。
--   MCP 审批页需要只看 MCP 来源的确认单，此前只能靠 tool_name 含 '__' 的脆弱启发式
--   （server.Name + '__' + toolName 的拼接约定），一旦工具名本身含 '__' 就误判。
--   本列给建单侧一个可靠判据：gateway MCP 侧建单写 source='mcp'，AgentGuard 侧留空。
-- 影响面：加法改动。source 默认空串，AgentGuard 现有行为完全不变（不传/空=旧口径）。
-- 幂等：ADD COLUMN IF NOT EXISTS，可安全重跑；走 package-offline-bundle 的 acceptance-gate。

ALTER TABLE agentguard_confirmations
  ADD COLUMN IF NOT EXISTS source VARCHAR(32) NOT NULL DEFAULT '';

COMMENT ON COLUMN agentguard_confirmations.source IS '确认单来源：''''=AgentGuard（默认）；''mcp''=MCP 安全网关。用于审批列表按来源过滤，替代 tool_name 含 ''__'' 的脆弱启发式';
