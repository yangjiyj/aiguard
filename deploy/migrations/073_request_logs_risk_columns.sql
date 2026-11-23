-- Migration: 073_request_logs_risk_columns
-- Purpose: 预计算并索引 risk_state / has_retained_content，把安全告警/内容留存两页
--          的过滤从「全表实时 jsonb 计算」改为「索引列查」。列由 control-plane
--          维护 goroutine 填充（启动全量回填 + 周期增量），热路径不参与。

ALTER TABLE request_logs ADD COLUMN IF NOT EXISTS risk_state VARCHAR(16);
ALTER TABLE request_logs ADD COLUMN IF NOT EXISTS has_retained_content BOOLEAN;

-- 风险/阻断行很少，partial 索引体积极小，支撑安全告警页 risk_state=risk/blocked 过滤
CREATE INDEX IF NOT EXISTS idx_request_logs_tenant_risk_created
    ON request_logs (tenant_id, risk_state, created_at DESC)
    WHERE risk_state IN ('risk', 'blocked');

-- 内容留存行同理，支撑内容与数据安全页 content_only 过滤与计数
CREATE INDEX IF NOT EXISTS idx_request_logs_tenant_content_created
    ON request_logs (tenant_id, created_at DESC)
    WHERE has_retained_content;
