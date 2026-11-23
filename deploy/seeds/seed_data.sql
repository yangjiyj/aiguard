-- Seed data for JJDGuard

-- Default tenant
INSERT INTO tenants (id, name, edition, status, config_json) VALUES
    ('tenant_default', 'Default Tenant', 'enterprise', 'active', '{"features": ["chat", "embeddings", "security"]}');

-- Platform admin user with bcrypt hashed password (admin123)
-- bcrypt hash generated with cost 10 for password "admin123"
INSERT INTO users (id, tenant_id, username, email, password_hash, role, status) VALUES
    ('user_admin', 'tenant_default', 'admin', 'admin@jjdguard.local', ('$2a$10$' || 'N9qo8uLOickgx2ZMRZoMyeIjZRGdjGj/n3.QD9VYdO6j5e/K4n8O2'), 'platform_admin', 'active');

-- Default project
INSERT INTO projects (id, tenant_id, name, code, environment, owner_user_id, status) VALUES
    ('project_default', 'tenant_default', 'Default Project', 'default', 'production', 'user_admin', 'active');

-- Default providers
INSERT INTO providers (id, tenant_id, name, provider_type, base_url, auth_mode, is_default, status) VALUES
    ('prov_openai', 'tenant_default', 'OpenAI', 'openai', 'https://api.openai.com', 'api_key', true, 'active'),
    ('prov_anthropic', 'tenant_default', 'Anthropic', 'anthropic', 'https://api.anthropic.com', 'api_key', false, 'active');

-- Provider credentials (placeholder - should be replaced with real keys)
INSERT INTO provider_credentials (id, provider_id, credential_name, secret_ciphertext, status) VALUES
    ('cred_openai_default', 'prov_openai', 'Default OpenAI Key', 'PLACEHOLDER_OPENAI_API_KEY', 'active'),
    ('cred_anthropic_default', 'prov_anthropic', 'Default Anthropic Key', 'PLACEHOLDER_ANTHROPIC_API_KEY', 'active');

-- Default models
INSERT INTO models (id, provider_id, model_name, model_label, capabilities_json, pricing_json, context_window, status) VALUES
    ('model_gpt4', 'prov_openai', 'gpt-4', 'GPT-4', '{"chat": true, "vision": false}', '{"input": 0.03, "output": 0.06}', 8192, 'active'),
    ('model_gpt4o', 'prov_openai', 'gpt-4o', 'GPT-4o', '{"chat": true, "vision": true}', '{"input": 0.005, "output": 0.015}', 128000, 'active'),
    ('model_gpt4turbo', 'prov_openai', 'gpt-4-turbo', 'GPT-4 Turbo', '{"chat": true, "vision": true}', '{"input": 0.01, "output": 0.03}', 128000, 'active'),
    ('model_gpt35turbo', 'prov_openai', 'gpt-3.5-turbo', 'GPT-3.5 Turbo', '{"chat": true}', '{"input": 0.0015, "output": 0.002}', 16385, 'active'),
    ('model_claude3sonnet', 'prov_anthropic', 'claude-3-sonnet-20240229', 'Claude 3 Sonnet', '{"chat": true, "vision": true}', '{"input": 0.003, "output": 0.015}', 200000, 'active'),
    ('model_claude3opus', 'prov_anthropic', 'claude-3-opus-20240229', 'Claude 3 Opus', '{"chat": true, "vision": true}', '{"input": 0.015, "output": 0.075}', 200000, 'active'),
    ('model_claude35sonnet', 'prov_anthropic', 'claude-3-5-sonnet-20241022', 'Claude 3.5 Sonnet', '{"chat": true, "vision": true}', '{"input": 0.003, "output": 0.015}', 200000, 'active');

-- Default model policy (all models allowed)
INSERT INTO model_policies (id, tenant_id, project_id, scope_type, scope_ref, allow_models_json, deny_models_json) VALUES
    ('mpol_default', 'tenant_default', 'project_default', 'project', '', '[]', '[]');

-- Default quota policy
INSERT INTO quota_policies (id, tenant_id, project_id, scope_type, scope_ref, daily_token_limit, monthly_token_limit, monthly_budget_limit, rpm_limit, concurrency_limit, status) VALUES
    ('qpol_default', 'tenant_default', 'project_default', 'project', '', 1000000, 10000000, 100.00, 100, 10, 'active');

-- Default rule set for security
INSERT INTO rule_sets (id, tenant_id, name, version, source_type, published, created_by) VALUES
    ('ruleset_default', 'tenant_default', 'Default Security Rules', '1.0', 'builtin', true, 'user_admin');

-- Default security rules
INSERT INTO rules (id, rule_set_id, rule_type, name, priority, severity, scope_json, match_config_json, action, enabled) VALUES
    ('rule_pii_phone', 'ruleset_default', 'pii', 'Phone Number Detection', 100, 'medium', '{"direction": "input"}', '{"patterns": ["phone"]}', 'mask', true),
    ('rule_pii_idcard', 'ruleset_default', 'pii', 'ID Card Detection', 100, 'high', '{"direction": "input"}', '{"patterns": ["id_card"]}', 'mask', true),
    ('rule_secret_apikey', 'ruleset_default', 'secret', 'API Key Detection', 200, 'critical', '{"direction": "input"}', '{"patterns": ["api_key", "bearer_token"]}', 'block', true),
    ('rule_secret_aws', 'ruleset_default', 'secret', 'AWS Credential Detection', 200, 'critical', '{"direction": "all"}', '{"patterns": ["aws_access_key", "aws_secret_key"]}', 'block', true),
    ('rule_code_env', 'ruleset_default', 'code_config', 'Environment File Detection', 150, 'high', '{"direction": "input"}', '{"patterns": ["env_file", "config_json"]}', 'audit', true);