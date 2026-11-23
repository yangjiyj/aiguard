BEGIN;
-- 智能体受限文件模式：租户级"禁止交给模型的文件类型"配置。
-- 挂在智能体操作策略表上，与 discardable_paths 同表同链路，默认关闭（空数组）。
-- ADD COLUMN IF NOT EXISTS 保证对现网既有行安全：默认 '[]' + 'block'，行为不变。

ALTER TABLE agent_destructive_policies
  ADD COLUMN IF NOT EXISTS restricted_file_patterns_json jsonb NOT NULL DEFAULT '[]'::jsonb,
  ADD COLUMN IF NOT EXISTS restricted_file_action varchar(16) NOT NULL DEFAULT 'block';

-- 模式列表：复用 140 的字符串数组校验函数 + 条数上限。
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'agent_destructive_policies_restricted_file_patterns_check'
  ) THEN
    ALTER TABLE agent_destructive_policies
      ADD CONSTRAINT agent_destructive_policies_restricted_file_patterns_check
      CHECK (
        agent_destructive_json_string_array_valid(restricted_file_patterns_json)
        AND jsonb_array_length(restricted_file_patterns_json) <= 64
      );
  END IF;
END $$;

-- 动作词：沿用策略中心动作，不支持 confirm。
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'agent_destructive_policies_restricted_file_action_check'
  ) THEN
    ALTER TABLE agent_destructive_policies
      ADD CONSTRAINT agent_destructive_policies_restricted_file_action_check
      CHECK (restricted_file_action IN ('record', 'alert_allow', 'block'));
  END IF;
END $$;

COMMIT;
