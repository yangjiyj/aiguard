-- +goose Up
-- +goose StatementBegin

-- 身份源配置（OIDC）。每租户至多一条生效配置，草稿和历史版本用 status 区分。
-- client_secret_enc 使用 enc:v1: 前缀密文（packages/shared-go/secrets AES-256-GCM）。
CREATE TABLE IF NOT EXISTS identity_sources (
    id                  varchar(64)   PRIMARY KEY,
    tenant_id           varchar(64)   NOT NULL REFERENCES tenants(id),
    display_name        varchar(128)  NOT NULL,
    protocol            varchar(16)   NOT NULL DEFAULT 'oidc' CHECK (protocol = 'oidc'),
    issuer_url          varchar(512)  NOT NULL,
    client_id           varchar(128)  NOT NULL,
    client_secret_enc   text          NOT NULL,
    scopes              varchar(256)  NOT NULL DEFAULT 'openid profile email',
    subject_claim       varchar(64)   NOT NULL DEFAULT 'sub',
    username_claim      varchar(64)   NOT NULL DEFAULT 'preferred_username',
    name_claim          varchar(64)   NOT NULL DEFAULT 'name',
    email_claim         varchar(64)   NOT NULL DEFAULT 'email',
    phone_claim         varchar(64)   NOT NULL DEFAULT 'phone_number',
    dept_code_claim     varchar(64)   NOT NULL DEFAULT 'department_code',
    dept_name_claim     varchar(64)   NOT NULL DEFAULT 'department_name',
    groups_claim        varchar(64)   NOT NULL DEFAULT 'groups',
    status              varchar(24)   NOT NULL DEFAULT 'draft' CHECK (status IN ('draft', 'tested', 'active', 'disabled')),
    is_default          boolean       NOT NULL DEFAULT false,
    version             integer       NOT NULL DEFAULT 1,
    published_by        varchar(64),
    published_at        timestamptz,
    last_tested_at      timestamptz,
    last_test_result    jsonb,
    created_at          timestamptz   NOT NULL DEFAULT now(),
    updated_at          timestamptz   NOT NULL DEFAULT now(),
    CONSTRAINT uq_identity_sources_tenant_id UNIQUE (tenant_id, id)
);
CREATE INDEX IF NOT EXISTS idx_identity_sources_tenant ON identity_sources(tenant_id, status);
CREATE UNIQUE INDEX IF NOT EXISTS uq_identity_sources_active_per_tenant ON identity_sources(tenant_id) WHERE status='active';
CREATE UNIQUE INDEX IF NOT EXISTS uq_identity_sources_pending_per_tenant ON identity_sources(tenant_id) WHERE status IN ('draft', 'tested');

-- 部门属性映射：外部属性值 → JJDGuard 部门（team）+ 默认应用（project）
CREATE TABLE IF NOT EXISTS identity_dept_mappings (
    id                  varchar(64)   PRIMARY KEY,
    tenant_id           varchar(64)   NOT NULL REFERENCES tenants(id),
    identity_source_id  varchar(64)   NOT NULL,
    match_value         varchar(255)  NOT NULL,
    mapped_team_id      varchar(64)   REFERENCES teams(id) ON DELETE SET NULL,
    mapped_project_id   varchar(64)   REFERENCES projects(id) ON DELETE SET NULL,
    priority            integer       NOT NULL DEFAULT 100,
    enabled             boolean       NOT NULL DEFAULT true,
    created_at          timestamptz   NOT NULL DEFAULT now(),
    updated_at          timestamptz   NOT NULL DEFAULT now(),
    CONSTRAINT fk_idm_source_tenant FOREIGN KEY (tenant_id, identity_source_id)
        REFERENCES identity_sources(tenant_id, id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_idm_tenant_source ON identity_dept_mappings(tenant_id, identity_source_id);
CREATE UNIQUE INDEX IF NOT EXISTS uq_idm_tenant_source_match ON identity_dept_mappings(tenant_id, identity_source_id, match_value);

-- +goose StatementEnd
-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS identity_dept_mappings;
DROP TABLE IF EXISTS identity_sources;
-- +goose StatementEnd
