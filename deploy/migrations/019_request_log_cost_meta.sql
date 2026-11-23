ALTER TABLE request_logs
    ADD COLUMN IF NOT EXISTS cost_meta_json JSONB DEFAULT NULL;

CREATE INDEX IF NOT EXISTS idx_request_logs_tenant_cost_created
    ON request_logs(tenant_id, created_at)
    WHERE total_cost IS NOT NULL;

COMMENT ON COLUMN request_logs.total_cost IS '模型调用成本，USD 基准金额；未定价模型为 NULL';
COMMENT ON COLUMN request_logs.cost_meta_json IS '成本计算元数据：currency、pricing_unit、input_price、output_price、calculated_at';
