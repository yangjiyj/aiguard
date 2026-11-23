-- +goose NO TRANSACTION
-- 963_p2_billing_ops_alerts: 计费类告警进告警组（P2 任务 9）。
--
-- billing_ops_alert_marks 记录“已经转成告警的计费事件”，让控制面扫描任务可以带回看窗口重复扫描
-- （长流式请求的结算结果晚于建行时间），重启后也不会重复计数。只保存来源标识，不保存业务内容；
-- 由控制面定期清理 3 天前的标记。
--
-- 部分索引只覆盖被预算拒绝/结算失败的少量请求行，用 CONCURRENTLY 在线创建，不阻塞 request_logs 写入。

CREATE TABLE IF NOT EXISTS billing_ops_alert_marks (
    tenant_id   VARCHAR(64) NOT NULL,
    source_kind VARCHAR(32) NOT NULL,
    source_id   VARCHAR(128) NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, source_kind, source_id)
);

CREATE INDEX IF NOT EXISTS idx_billing_ops_alert_marks_created
    ON billing_ops_alert_marks (created_at);

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_request_logs_billing_ops_alert
    ON request_logs (created_at)
    WHERE billing_outcome IN ('budget_exhausted', 'budget_unpriced', 'budget_unavailable', 'failed');

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_billing_ledger_overdraft_created
    ON billing_ledger_entries (created_at)
    WHERE (metadata_json->>'overdraft') = 'true';
