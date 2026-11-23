-- 022_saving_metrics.sql
-- 节省金额多维日聚合表。维度：tenant / team / project / user / source / date
-- 由 saving_calculator 每 5 分钟 UPSERT。

CREATE TABLE IF NOT EXISTS saving_metrics (
    id BIGSERIAL PRIMARY KEY,
    tenant_id VARCHAR(64) NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    team_id VARCHAR(64),
    project_id VARCHAR(64) NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    user_id VARCHAR(64),
    date DATE NOT NULL,
    source VARCHAR(32) NOT NULL,
    saving_usd DECIMAL(18,6) NOT NULL DEFAULT 0,
    saving_cny DECIMAL(18,6) NOT NULL DEFAULT 0,
    request_count BIGINT NOT NULL DEFAULT 0,
    UNIQUE (tenant_id, team_id, project_id, user_id, date, source)
);

CREATE INDEX IF NOT EXISTS idx_saving_metrics_tenant_date
    ON saving_metrics(tenant_id, date DESC);
CREATE INDEX IF NOT EXISTS idx_saving_metrics_team_date
    ON saving_metrics(team_id, date DESC) WHERE team_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_saving_metrics_project_date
    ON saving_metrics(project_id, date DESC);

COMMENT ON TABLE saving_metrics IS '节省金额多维日聚合：cache_hit / model_downgraded 两个 source';
COMMENT ON COLUMN saving_metrics.source IS 'cache_hit | model_downgraded';
