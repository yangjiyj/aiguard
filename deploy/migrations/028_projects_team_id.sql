-- 028_projects_team_id.sql
-- projects 加 team_id（可空，过渡期兼容；金融客户可在控制台配 require_team_assignment）

ALTER TABLE projects
    ADD COLUMN IF NOT EXISTS team_id VARCHAR(64) REFERENCES teams(id) ON DELETE SET NULL;
CREATE INDEX IF NOT EXISTS idx_projects_team ON projects(team_id);

COMMENT ON COLUMN projects.team_id IS '所属部门；NULL 表示未分配（过渡期兼容）';
