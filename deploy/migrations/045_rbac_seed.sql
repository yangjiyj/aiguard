-- 045_rbac_seed.sql
-- RBAC base tables must exist before builtin role seeding. Clean offline installs
-- reach this migration before the Go runtime can self-heal RBAC metadata.
CREATE TABLE IF NOT EXISTS system_roles (
    id VARCHAR(50) PRIMARY KEY,
    name VARCHAR(50) NOT NULL,
    code VARCHAR(50) NOT NULL,
    description TEXT,
    permissions JSONB NOT NULL DEFAULT '[]'::jsonb,
    is_default BOOLEAN NOT NULL DEFAULT FALSE,
    is_system BOOLEAN NOT NULL DEFAULT FALSE,
    level VARCHAR(2) NOT NULL DEFAULT 'U1',
    member_count INTEGER NOT NULL DEFAULT 0,
    created_by VARCHAR(64),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at TIMESTAMPTZ,
    is_builtin BOOLEAN NOT NULL DEFAULT FALSE
);

ALTER TABLE system_roles ADD COLUMN IF NOT EXISTS code VARCHAR(50);
ALTER TABLE system_roles ADD COLUMN IF NOT EXISTS description TEXT;
ALTER TABLE system_roles ADD COLUMN IF NOT EXISTS permissions JSONB NOT NULL DEFAULT '[]'::jsonb;
ALTER TABLE system_roles ADD COLUMN IF NOT EXISTS is_default BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE system_roles ADD COLUMN IF NOT EXISTS is_system BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE system_roles ADD COLUMN IF NOT EXISTS level VARCHAR(2) NOT NULL DEFAULT 'U1';
ALTER TABLE system_roles ADD COLUMN IF NOT EXISTS member_count INTEGER NOT NULL DEFAULT 0;
ALTER TABLE system_roles ADD COLUMN IF NOT EXISTS created_by VARCHAR(64);
ALTER TABLE system_roles ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ NOT NULL DEFAULT NOW();
ALTER TABLE system_roles ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW();
ALTER TABLE system_roles ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMPTZ;
CREATE UNIQUE INDEX IF NOT EXISTS system_roles_name_key ON system_roles(name);
CREATE UNIQUE INDEX IF NOT EXISTS system_roles_code_key ON system_roles(code);

CREATE TABLE IF NOT EXISTS system_permissions (
    id VARCHAR(50) PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    code VARCHAR(100) NOT NULL,
    description TEXT,
    category VARCHAR(50),
    parent_code VARCHAR(100),
    level VARCHAR(2),
    is_system BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    role_name VARCHAR(64),
    resource VARCHAR(64),
    action VARCHAR(32)
);

ALTER TABLE system_permissions ADD COLUMN IF NOT EXISTS name VARCHAR(100);
ALTER TABLE system_permissions ADD COLUMN IF NOT EXISTS code VARCHAR(100);
ALTER TABLE system_permissions ADD COLUMN IF NOT EXISTS description TEXT;
ALTER TABLE system_permissions ADD COLUMN IF NOT EXISTS category VARCHAR(50);
ALTER TABLE system_permissions ADD COLUMN IF NOT EXISTS parent_code VARCHAR(100);
ALTER TABLE system_permissions ADD COLUMN IF NOT EXISTS level VARCHAR(2);
ALTER TABLE system_permissions ADD COLUMN IF NOT EXISTS is_system BOOLEAN NOT NULL DEFAULT TRUE;
ALTER TABLE system_permissions ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ NOT NULL DEFAULT NOW();
ALTER TABLE system_permissions ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW();
CREATE UNIQUE INDEX IF NOT EXISTS system_permissions_code_key ON system_permissions(code);

-- system_roles: add is_builtin column (description already exists)
ALTER TABLE system_roles ADD COLUMN IF NOT EXISTS is_builtin BOOLEAN NOT NULL DEFAULT FALSE;

-- Upsert 8 builtin roles (name is unique)
INSERT INTO system_roles (id, name, code, description, is_builtin, is_system) VALUES
    ('role_platform_admin',    'platform_admin',    'platform_admin',    '平台超级管理员',       TRUE, TRUE),
    ('role_tenant_owner',      'tenant_owner',      'tenant_owner',      '租户管理员',           TRUE, TRUE),
    ('role_auditor',           'auditor',           'auditor',           '审计员（只读+导出）',   TRUE, TRUE),
    ('role_team_owner',        'team_owner',        'team_owner',        '部门管理员',           TRUE, TRUE),
    ('role_team_member',       'team_member',       'team_member',       '部门成员',             TRUE, TRUE),
    ('role_project_owner',     'project_owner',     'project_owner',     '应用管理员',           TRUE, TRUE),
    ('role_project_developer', 'project_developer', 'project_developer', '应用开发者',           TRUE, TRUE),
    ('role_project_viewer',    'project_viewer',    'project_viewer',    '应用观察者',           TRUE, TRUE)
ON CONFLICT (name) DO UPDATE SET
    description = EXCLUDED.description,
    is_builtin = TRUE,
    is_system = TRUE;

-- system_permissions: add role_name, resource, action columns for RBAC matrix
ALTER TABLE system_permissions ADD COLUMN IF NOT EXISTS role_name VARCHAR(64);
ALTER TABLE system_permissions ADD COLUMN IF NOT EXISTS resource VARCHAR(64);
ALTER TABLE system_permissions ADD COLUMN IF NOT EXISTS action VARCHAR(32);

-- unique index on (role_name, resource, action) for RBAC entries
CREATE UNIQUE INDEX IF NOT EXISTS uq_perm_role_res_act
    ON system_permissions(role_name, resource, action)
    WHERE role_name IS NOT NULL AND resource IS NOT NULL AND action IS NOT NULL;
