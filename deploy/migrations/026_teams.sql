-- 026_teams.sql
-- 部门 / 业务组，支持父子层级（最深 5 层，应用层校验）
-- path 字符串 /root/child/grandchild 便于 LIKE 'X/%' 子树查询
-- 不引入 ltree 扩展（信创 PG 国产化兼容性优先，见 ADR #13）

CREATE TABLE IF NOT EXISTS teams (
    id VARCHAR(64) PRIMARY KEY,
    tenant_id VARCHAR(64) NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name VARCHAR(128) NOT NULL,
    parent_team_id VARCHAR(64) REFERENCES teams(id) ON DELETE SET NULL,
    path VARCHAR(512) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    UNIQUE (tenant_id, name),
    CHECK (parent_team_id IS NULL OR parent_team_id != id)
);

CREATE INDEX IF NOT EXISTS idx_teams_tenant ON teams(tenant_id);
CREATE INDEX IF NOT EXISTS idx_teams_path ON teams(path varchar_pattern_ops);
CREATE INDEX IF NOT EXISTS idx_teams_parent ON teams(parent_team_id);

COMMENT ON COLUMN teams.path IS '形如 /root_id/child_id/grandchild_id，便于子树查询';
