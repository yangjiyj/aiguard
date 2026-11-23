-- +goose Up
-- +goose StatementBegin

-- 租户表
CREATE TABLE IF NOT EXISTS tenants (
    id VARCHAR(64) PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    edition VARCHAR(32) NOT NULL DEFAULT 'cloud',
    status VARCHAR(32) NOT NULL DEFAULT 'active',
    config_json JSONB DEFAULT '{}',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX idx_tenants_created_at ON tenants(created_at);

-- 用户表
CREATE TABLE IF NOT EXISTS users (
    id VARCHAR(64) PRIMARY KEY,
    tenant_id VARCHAR(64) NOT NULL REFERENCES tenants(id),
    username VARCHAR(255) NOT NULL,
    email VARCHAR(255),
    password_hash VARCHAR(255),
    role VARCHAR(64) NOT NULL DEFAULT 'developer',
    status VARCHAR(32) NOT NULL DEFAULT 'active',
    external_subject VARCHAR(255),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    UNIQUE(tenant_id, username)
);

CREATE INDEX idx_users_tenant_id ON users(tenant_id);
CREATE INDEX idx_users_created_at ON users(created_at);

-- 项目表
CREATE TABLE IF NOT EXISTS projects (
    id VARCHAR(64) PRIMARY KEY,
    tenant_id VARCHAR(64) NOT NULL REFERENCES tenants(id),
    name VARCHAR(255) NOT NULL,
    code VARCHAR(64),
    environment VARCHAR(32) DEFAULT 'production',
    owner_user_id VARCHAR(64) REFERENCES users(id),
    status VARCHAR(32) NOT NULL DEFAULT 'active',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX idx_projects_tenant_id ON projects(tenant_id);
CREATE INDEX idx_projects_created_at ON projects(created_at);

-- API客户端表
CREATE TABLE IF NOT EXISTS api_clients (
    id VARCHAR(64) PRIMARY KEY,
    tenant_id VARCHAR(64) NOT NULL REFERENCES tenants(id),
    project_id VARCHAR(64) NOT NULL REFERENCES projects(id),
    client_name VARCHAR(255),
    client_type VARCHAR(64),
    status VARCHAR(32) NOT NULL DEFAULT 'active',
    metadata_json JSONB DEFAULT '{}',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX idx_api_clients_project_id ON api_clients(project_id);

-- 内部密钥表
CREATE TABLE IF NOT EXISTS internal_keys (
    id VARCHAR(64) PRIMARY KEY,
    tenant_id VARCHAR(64) NOT NULL REFERENCES tenants(id),
    project_id VARCHAR(64) NOT NULL REFERENCES projects(id),
    user_id VARCHAR(64) REFERENCES users(id),
    key_hash VARCHAR(128) NOT NULL,
    key_prefix VARCHAR(16) NOT NULL,
    scopes_json JSONB DEFAULT '[]',
    expires_at TIMESTAMP WITH TIME ZONE,
    last_used_at TIMESTAMP WITH TIME ZONE,
    status VARCHAR(32) NOT NULL DEFAULT 'active',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX idx_internal_keys_key_hash ON internal_keys(key_hash);
CREATE INDEX idx_internal_keys_project_id ON internal_keys(project_id);
CREATE INDEX idx_internal_keys_status ON internal_keys(status);

-- 提供商表
CREATE TABLE IF NOT EXISTS providers (
    id VARCHAR(64) PRIMARY KEY,
    tenant_id VARCHAR(64) NOT NULL REFERENCES tenants(id),
    name VARCHAR(255) NOT NULL,
    provider_type VARCHAR(64) NOT NULL,
    base_url VARCHAR(512),
    auth_mode VARCHAR(64) DEFAULT 'api_key',
    is_default BOOLEAN DEFAULT FALSE,
    status VARCHAR(32) NOT NULL DEFAULT 'active',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX idx_providers_tenant_id ON providers(tenant_id);
CREATE INDEX idx_providers_type ON providers(provider_type);

-- 提供商凭证表
CREATE TABLE IF NOT EXISTS provider_credentials (
    id VARCHAR(64) PRIMARY KEY,
    provider_id VARCHAR(64) NOT NULL REFERENCES providers(id),
    credential_name VARCHAR(255),
    secret_ciphertext TEXT,
    kms_key_ref VARCHAR(255),
    status VARCHAR(32) NOT NULL DEFAULT 'active',
    rotated_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX idx_provider_credentials_provider_id ON provider_credentials(provider_id);

-- 模型表
CREATE TABLE IF NOT EXISTS models (
    id VARCHAR(64) PRIMARY KEY,
    provider_id VARCHAR(64) NOT NULL REFERENCES providers(id),
    model_name VARCHAR(255) NOT NULL,
    model_label VARCHAR(255),
    capabilities_json JSONB DEFAULT '{}',
    pricing_json JSONB DEFAULT '{}',
    context_window INTEGER,
    status VARCHAR(32) NOT NULL DEFAULT 'active',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX idx_models_provider_id ON models(provider_id);
CREATE INDEX idx_models_name ON models(model_name);

-- 模型策略表
CREATE TABLE IF NOT EXISTS model_policies (
    id VARCHAR(64) PRIMARY KEY,
    tenant_id VARCHAR(64) NOT NULL REFERENCES tenants(id),
    project_id VARCHAR(64) REFERENCES projects(id),
    scope_type VARCHAR(32) NOT NULL,
    scope_ref VARCHAR(64),
    allow_models_json JSONB DEFAULT '[]',
    deny_models_json JSONB DEFAULT '[]',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX idx_model_policies_tenant_id ON model_policies(tenant_id);
CREATE INDEX idx_model_policies_project_id ON model_policies(project_id);

-- 配额策略表
CREATE TABLE IF NOT EXISTS quota_policies (
    id VARCHAR(64) PRIMARY KEY,
    tenant_id VARCHAR(64) NOT NULL REFERENCES tenants(id),
    project_id VARCHAR(64) REFERENCES projects(id),
    scope_type VARCHAR(32) NOT NULL,
    scope_ref VARCHAR(64),
    daily_token_limit BIGINT DEFAULT 0,
    monthly_token_limit BIGINT DEFAULT 0,
    monthly_budget_limit DECIMAL(18,2) DEFAULT 0,
    rpm_limit INTEGER DEFAULT 0,
    concurrency_limit INTEGER DEFAULT 0,
    overage_action VARCHAR(32) NOT NULL DEFAULT 'notify',
    status VARCHAR(32) NOT NULL DEFAULT 'active',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX idx_quota_policies_tenant_id ON quota_policies(tenant_id);
CREATE INDEX idx_quota_policies_project_id ON quota_policies(project_id);

-- 规则集表
CREATE TABLE IF NOT EXISTS rule_sets (
    id VARCHAR(64) PRIMARY KEY,
    tenant_id VARCHAR(64) NOT NULL REFERENCES tenants(id),
    name VARCHAR(255) NOT NULL,
    version VARCHAR(32) NOT NULL DEFAULT '1.0',
    source_type VARCHAR(32),
    published BOOLEAN DEFAULT FALSE,
    created_by VARCHAR(64),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX idx_rule_sets_tenant_id ON rule_sets(tenant_id);
CREATE INDEX idx_rule_sets_published ON rule_sets(published);

-- 规则表
CREATE TABLE IF NOT EXISTS rules (
    id VARCHAR(64) PRIMARY KEY,
    rule_set_id VARCHAR(64) NOT NULL REFERENCES rule_sets(id),
    rule_type VARCHAR(64) NOT NULL,
    name VARCHAR(255) NOT NULL,
    priority INTEGER DEFAULT 0,
    severity VARCHAR(32) DEFAULT 'medium',
    scope_json JSONB DEFAULT '{}',
    match_config_json JSONB DEFAULT '{}',
    action VARCHAR(32) NOT NULL DEFAULT 'audit',
    enabled BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX idx_rules_rule_set_id ON rules(rule_set_id);
CREATE INDEX idx_rules_type ON rules(rule_type);
CREATE INDEX idx_rules_enabled ON rules(enabled);

-- 请求日志表
CREATE TABLE IF NOT EXISTS request_logs (
    id VARCHAR(64) PRIMARY KEY,
    request_id VARCHAR(64) NOT NULL UNIQUE,
    tenant_id VARCHAR(64) NOT NULL REFERENCES tenants(id),
    project_id VARCHAR(64) NOT NULL REFERENCES projects(id),
    user_id VARCHAR(64) REFERENCES users(id),
    client_id VARCHAR(64),
    provider_id VARCHAR(64) REFERENCES providers(id),
    model_id VARCHAR(64) REFERENCES models(id),
    session_id VARCHAR(64),
    agent_type VARCHAR(64),
    endpoint_type VARCHAR(32),
    request_status VARCHAR(32),
    upstream_status_code INTEGER,
    latency_ms INTEGER,
    input_tokens INTEGER,
    output_tokens INTEGER,
    total_cost DECIMAL(18,6),
    raw_retained BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX idx_request_logs_tenant_created ON request_logs(tenant_id, created_at);
CREATE INDEX idx_request_logs_project_created ON request_logs(project_id, created_at);
CREATE INDEX idx_request_logs_user_created ON request_logs(user_id, created_at);
CREATE INDEX idx_request_logs_request_id ON request_logs(request_id);
CREATE INDEX idx_request_logs_session_id ON request_logs(session_id);
CREATE INDEX idx_request_logs_model_created ON request_logs(model_id, created_at);

-- 安全事件表
CREATE TABLE IF NOT EXISTS security_events (
    id VARCHAR(64) PRIMARY KEY,
    request_id VARCHAR(64) NOT NULL REFERENCES request_logs(request_id),
    tenant_id VARCHAR(64) NOT NULL REFERENCES tenants(id),
    project_id VARCHAR(64) NOT NULL REFERENCES projects(id),
    user_id VARCHAR(64) REFERENCES users(id),
    event_type VARCHAR(64) NOT NULL,
    severity VARCHAR(32) NOT NULL,
    rule_id VARCHAR(64) REFERENCES rules(id),
    action_taken VARCHAR(32) NOT NULL,
    matched_summary JSONB DEFAULT '{}',
    evidence_ref VARCHAR(255),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX idx_security_events_tenant_created ON security_events(tenant_id, created_at);
CREATE INDEX idx_security_events_project_created ON security_events(project_id, created_at);
CREATE INDEX idx_security_events_type_created ON security_events(event_type, created_at);
CREATE INDEX idx_security_events_severity_created ON security_events(severity, created_at);
CREATE INDEX idx_security_events_request_id ON security_events(request_id);

-- 日使用量汇总表
CREATE TABLE IF NOT EXISTS usage_daily (
    id VARCHAR(64) PRIMARY KEY,
    tenant_id VARCHAR(64) NOT NULL REFERENCES tenants(id),
    project_id VARCHAR(64) NOT NULL REFERENCES projects(id),
    user_id VARCHAR(64) REFERENCES users(id),
    day DATE NOT NULL,
    request_count INTEGER DEFAULT 0,
    input_tokens BIGINT DEFAULT 0,
    output_tokens BIGINT DEFAULT 0,
    total_cost DECIMAL(18,6) DEFAULT 0,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    UNIQUE(tenant_id, project_id, user_id, day)
);

CREATE INDEX idx_usage_daily_tenant_day ON usage_daily(tenant_id, day);
CREATE INDEX idx_usage_daily_project_day ON usage_daily(project_id, day);

-- 告警表
CREATE TABLE IF NOT EXISTS alerts (
    id VARCHAR(64) PRIMARY KEY,
    tenant_id VARCHAR(64) NOT NULL REFERENCES tenants(id),
    project_id VARCHAR(64) REFERENCES projects(id),
    event_id VARCHAR(64),
    channel VARCHAR(64),
    delivery_status VARCHAR(32),
    payload_summary JSONB DEFAULT '{}',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX idx_alerts_tenant_created ON alerts(tenant_id, created_at);

-- Agent会话表 (Phase 5 预留)
CREATE TABLE IF NOT EXISTS agent_sessions (
    id VARCHAR(64) PRIMARY KEY,
    tenant_id VARCHAR(64) NOT NULL REFERENCES tenants(id),
    project_id VARCHAR(64) NOT NULL REFERENCES projects(id),
    user_id VARCHAR(64) REFERENCES users(id),
    session_id VARCHAR(64) NOT NULL UNIQUE,
    agent_type VARCHAR(64),
    workspace_id VARCHAR(64),
    client_name VARCHAR(255),
    client_version VARCHAR(64),
    first_request_at TIMESTAMP WITH TIME ZONE,
    last_request_at TIMESTAMP WITH TIME ZONE,
    request_count INTEGER DEFAULT 0,
    risk_score INTEGER DEFAULT 0,
    status VARCHAR(32) NOT NULL DEFAULT 'active',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX idx_agent_sessions_tenant_id ON agent_sessions(tenant_id);
CREATE INDEX idx_agent_sessions_session_id ON agent_sessions(session_id);
CREATE INDEX idx_agent_sessions_project_id ON agent_sessions(project_id);

-- MCP服务器表 (P2 预留)
CREATE TABLE IF NOT EXISTS mcp_servers (
    id VARCHAR(64) PRIMARY KEY,
    tenant_id VARCHAR(64) NOT NULL REFERENCES tenants(id),
    name VARCHAR(255) NOT NULL,
    server_url VARCHAR(512),
    owner VARCHAR(64),
    trust_level VARCHAR(32) DEFAULT 'low',
    capabilities_json JSONB DEFAULT '{}',
    status VARCHAR(32) NOT NULL DEFAULT 'active',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX idx_mcp_servers_tenant_id ON mcp_servers(tenant_id);

-- 工具事件表 (P2 预留)
CREATE TABLE IF NOT EXISTS tool_events (
    id VARCHAR(64) PRIMARY KEY,
    tenant_id VARCHAR(64) NOT NULL REFERENCES tenants(id),
    project_id VARCHAR(64) NOT NULL REFERENCES projects(id),
    session_id VARCHAR(64) REFERENCES agent_sessions(session_id),
    request_id VARCHAR(64) REFERENCES request_logs(request_id),
    tool_name VARCHAR(255),
    tool_category VARCHAR(64),
    tool_args_summary JSONB DEFAULT '{}',
    target_summary JSONB DEFAULT '{}',
    risk_level VARCHAR(32),
    action_taken VARCHAR(32),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX idx_tool_events_session_id ON tool_events(session_id);
CREATE INDEX idx_tool_events_created_at ON tool_events(created_at);

-- +goose StatementEnd

