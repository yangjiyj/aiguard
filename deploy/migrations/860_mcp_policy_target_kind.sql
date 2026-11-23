-- W1 1.2：MCP 策略目标类别。tools/call 之外的方法（resources/read、prompts/get、其他方法）
-- 也进入策略判定。既有策略全部落 'tool'，只对 tools/call 生效，行为不变；
-- 管理员显式建 resource/prompt/method 策略后才会影响对应方法（配了 block 才拦）。
ALTER TABLE mcp_policies ADD COLUMN IF NOT EXISTS target_kind TEXT NOT NULL DEFAULT 'tool';

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'mcp_policies_target_kind_check'
  ) THEN
    ALTER TABLE mcp_policies
      ADD CONSTRAINT mcp_policies_target_kind_check
      CHECK (target_kind IN ('tool','resource','prompt','method'));
  END IF;
END
$$;

COMMENT ON COLUMN mcp_policies.target_kind IS
  '策略目标类别：tool=tools/call 按工具名；resource=resources/read 按 uri；prompt=prompts/get 按提示名；method=其他方法按方法名（区分大小写，不做别名归一）。tool_pattern 对所有类别都表示目标名匹配模式';
