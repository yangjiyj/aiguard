-- 108_group_mapping_rules.sql
-- 门户 GroupMappingRule 迁入网关库：部门(SSO department claim) → 分组/网关项目/团队 映射规则。
-- 原在 portal-proxy SQLite，现网关为权威、控制台管理，portal-proxy 改读网关（带 SQLite 兜底）。
-- 幂等，可安全重跑。
-- 仅建表结构；具体映射规则由各部署在控制台「分组映射规则」页维护，不随迁移下发——
-- 避免把某一部署的部门/项目数据带进他人库并触发外键失败（fresh install 无对应 project）。
CREATE TABLE IF NOT EXISTS group_mapping_rules (
    id                 varchar(64)  PRIMARY KEY,
    tenant_id          varchar(64)  NOT NULL REFERENCES tenants(id),
    match_type         varchar(32)  NOT NULL DEFAULT 'department',
    match_value        varchar(255) NOT NULL,
    mapped_group       varchar(255) NOT NULL,
    gateway_project_id varchar(64)  NOT NULL REFERENCES projects(id),
    gateway_team_id    varchar(64)  REFERENCES teams(id) ON DELETE SET NULL,
    priority           integer      NOT NULL DEFAULT 100,
    enabled            boolean      NOT NULL DEFAULT true,
    created_at         timestamptz  NOT NULL DEFAULT now(),
    updated_at         timestamptz  NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_gmr_tenant_match ON group_mapping_rules(tenant_id, match_type, match_value);
CREATE INDEX IF NOT EXISTS idx_gmr_project ON group_mapping_rules(gateway_project_id);
