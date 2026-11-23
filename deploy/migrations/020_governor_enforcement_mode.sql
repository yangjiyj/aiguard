-- 020_governor_enforcement_mode.sql
-- 加 governor 执行模式字段与日预算字段。一期 quota_policies.overage_action 已存在，
-- 本迁移加 enforcement_mode 决定是否真实执行 overage_action。

ALTER TABLE quota_policies
    ADD COLUMN IF NOT EXISTS enforcement_mode VARCHAR(16) NOT NULL DEFAULT 'soft';
ALTER TABLE quota_policies
    ADD COLUMN IF NOT EXISTS daily_budget_limit DECIMAL(18,2) DEFAULT 0;

COMMENT ON COLUMN quota_policies.enforcement_mode IS
    'governor 执行模式：soft 仅告警，enforce 真实硬触发，bypass 完全跳过';
COMMENT ON COLUMN quota_policies.daily_budget_limit IS
    '日预算上限（CNY），补充月预算字段';
