-- 047_team_models.sql
-- Department model whitelist: zero-trust default (no models if not configured)
CREATE TABLE IF NOT EXISTS team_models (
    team_id VARCHAR(64) NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
    model_id VARCHAR(64) NOT NULL REFERENCES models(id) ON DELETE CASCADE,
    allowed BOOLEAN NOT NULL DEFAULT TRUE,
    daily_token_limit BIGINT,
    granted_by VARCHAR(64),
    granted_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    PRIMARY KEY (team_id, model_id)
);
CREATE INDEX IF NOT EXISTS idx_team_models_team ON team_models(team_id);
COMMENT ON TABLE team_models IS '部门模型白名单：未配则部门成员看不到任何模型（零信任默认）';
