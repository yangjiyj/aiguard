-- 065 AgentGuard HITL 确认重放：持久化原始工具调用上下文 + 重放状态
-- Task 2.3 (P0-6, 支柱⑦)。批准后 control-plane 需取出原始调用并真正重放，
-- 而非只翻状态位；故在确认表上补齐 tool_call_id / 原始参数 / choice 序号
-- 及重放状态字段。全部幂等（IF NOT EXISTS），可重复执行。

ALTER TABLE agentguard_confirmations
    ADD COLUMN IF NOT EXISTS tool_call_id        VARCHAR(64),
    ADD COLUMN IF NOT EXISTS tool_call_arguments TEXT,
    ADD COLUMN IF NOT EXISTS choice_index        INTEGER NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS replay_status       VARCHAR(16) NOT NULL DEFAULT 'pending',
    ADD COLUMN IF NOT EXISTS replayed_at         TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS replay_tool_log_id  VARCHAR(64);

-- 重放状态取值约束（幂等添加）
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'agentguard_confirmations_replay_status_check'
    ) THEN
        ALTER TABLE agentguard_confirmations
            ADD CONSTRAINT agentguard_confirmations_replay_status_check
            CHECK (replay_status IN ('pending','executed','skipped','failed'));
    END IF;
END$$;
