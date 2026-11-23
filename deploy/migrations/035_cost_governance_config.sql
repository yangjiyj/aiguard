-- 035_cost_governance_config.sql
CREATE TABLE IF NOT EXISTS cost_governance_config (
    tenant_id VARCHAR(64) PRIMARY KEY,
    self_research_saving_monthly DECIMAL(18,2) DEFAULT 0,
    labor_hourly_rate DECIMAL(10,2) DEFAULT 250,
    labor_hours_per_op DECIMAL(6,2) DEFAULT 0.5,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
COMMENT ON COLUMN cost_governance_config.self_research_saving_monthly IS '自研平台月节省（客户自填配置项，非算法计算）';
COMMENT ON COLUMN cost_governance_config.labor_hourly_rate IS '运维人力时薪（默认 250，可调）';
