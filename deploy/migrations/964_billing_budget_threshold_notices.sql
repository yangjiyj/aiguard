-- 964_billing_budget_threshold_notices: 预算 80% / 100% 预警外发去重（P2 任务 4）。
--
-- 员工月额度、部门预算、组织预算在每个预算周期内用到 80% 和 100% 时各通知一次。
-- 一行 = 某作用域在某周期某阈值已经通知过；主键冲突即表示已发过，重启或多实例也不会重复外发。
-- 只保存作用域标识与周期，不保存金额等业务内容。

CREATE TABLE IF NOT EXISTS billing_budget_threshold_notices (
    tenant_id    VARCHAR(64) NOT NULL,
    scope_type   VARCHAR(16) NOT NULL,
    scope_id     VARCHAR(128) NOT NULL,
    period_start TIMESTAMPTZ NOT NULL,
    threshold    SMALLINT NOT NULL,
    notified_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, scope_type, scope_id, period_start, threshold),
    CONSTRAINT ck_budget_threshold_scope CHECK (scope_type IN ('employee', 'department', 'organization')),
    CONSTRAINT ck_budget_threshold_value CHECK (threshold IN (80, 100))
);

CREATE INDEX IF NOT EXISTS idx_billing_budget_threshold_notices_notified
    ON billing_budget_threshold_notices (notified_at);
