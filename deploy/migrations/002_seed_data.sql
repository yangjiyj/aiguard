-- +goose Up
-- +goose StatementBegin

-- 创建 demo 租户
INSERT INTO tenants (id, name, edition, status) VALUES
('tenant_demo', 'Demo Tenant', 'cloud', 'active');

-- 创建 demo 用户
-- bcrypt hash for password "admin123" (generated with bcrypt rounds=10)
INSERT INTO users (id, tenant_id, username, email, password_hash, role, status) VALUES
('user_admin', 'tenant_demo', 'admin', 'admin@demo.local', ('$2b$10$' || 'hyMP/JkdSNIIYctdZPsu2.c./RwQ/YsIPvuj0bYrPZYwhpd5gUGVu'), 'platform_admin', 'active'),
('user_default', 'tenant_demo', 'developer', 'developer@demo.local', ('$2b$10$' || 'hyMP/JkdSNIIYctdZPsu2.c./RwQ/YsIPvuj0bYrPZYwhpd5gUGVu'), 'developer', 'active');

-- 创建 demo 项目
INSERT INTO projects (id, tenant_id, name, code, environment, owner_user_id, status) VALUES
('project_default', 'tenant_demo', 'Default Project', 'default', 'production', 'user_admin', 'active'),
('project_test', 'tenant_demo', 'Test Project', 'test', 'testing', 'user_default', 'active');

-- 创建提供商
INSERT INTO providers (id, tenant_id, name, provider_type, base_url, auth_mode, is_default, status) VALUES
('provider_openai', 'tenant_demo', 'OpenAI', 'openai', 'https://api.openai.com', 'api_key', TRUE, 'active'),
('provider_anthropic', 'tenant_demo', 'Anthropic', 'anthropic', 'https://api.anthropic.com', 'api_key', FALSE, 'active');

-- 创建模型
INSERT INTO models (id, provider_id, model_name, model_label, capabilities_json, pricing_json, context_window, status) VALUES
('model_gpt4', 'provider_openai', 'gpt-4', 'GPT-4', '{"chat": true, "streaming": true}', '{"input": 0.03, "output": 0.06}', 8192, 'active'),
('model_gpt35', 'provider_openai', 'gpt-3.5-turbo', 'GPT-3.5 Turbo', '{"chat": true, "streaming": true}', '{"input": 0.0015, "output": 0.002}', 4096, 'active'),
('model_claude3_sonnet', 'provider_anthropic', 'claude-3-sonnet-20240229', 'Claude 3 Sonnet', '{"chat": true, "streaming": true}', '{"input": 0.003, "output": 0.015}', 200000, 'active'),
('model_claude3_opus', 'provider_anthropic', 'claude-3-opus-20240229', 'Claude 3 Opus', '{"chat": true, "streaming": true}', '{"input": 0.015, "output": 0.075}', 200000, 'active');

-- 创建默认模型策略
INSERT INTO model_policies (id, tenant_id, project_id, scope_type, scope_ref, allow_models_json, deny_models_json) VALUES
('policy_model_default', 'tenant_demo', 'project_default', 'project', 'project_default', '["gpt-4", "gpt-3.5-turbo", "claude-3-sonnet-20240229"]', '[]');

-- 创建默认配额策略
INSERT INTO quota_policies (id, tenant_id, project_id, scope_type, scope_ref, daily_token_limit, monthly_token_limit, rpm_limit, concurrency_limit) VALUES
('policy_quota_default', 'tenant_demo', 'project_default', 'project', 'project_default', 1000000, 10000000, 100, 10);

-- 创建默认规则集
INSERT INTO rule_sets (id, tenant_id, name, version, source_type, published, created_by) VALUES
('ruleset_default', 'tenant_demo', 'Default Security Rules', '1.0', 'builtin', TRUE, 'user_admin');

-- 创建默认规则
INSERT INTO rules (id, rule_set_id, rule_type, name, priority, severity, scope_json, match_config_json, action, enabled) VALUES
('rule_pii_phone', 'ruleset_default', 'pii', 'Phone Number Detection', 10, 'medium', '{}', '{"patterns": ["phone"]}', 'mask', TRUE),
('rule_pii_id_card', 'ruleset_default', 'pii', 'ID Card Detection', 20, 'high', '{}', '{"patterns": ["id_card"]}', 'mask', TRUE),
('rule_secret_aws', 'ruleset_default', 'secret', 'AWS Key Detection', 30, 'critical', '{}', '{"patterns": ["aws_access_key", "aws_secret_key"]}', 'block', TRUE),
('rule_secret_api', 'ruleset_default', 'secret', 'Generic API Key', 40, 'high', '{}', '{"patterns": ["generic_api_key"]}', 'block', TRUE),
('rule_config_env', 'ruleset_default', 'code_config', 'Environment File Pattern', 50, 'medium', '{}', '{"patterns": ["env_file"]}', 'audit', TRUE);

-- +goose StatementEnd

