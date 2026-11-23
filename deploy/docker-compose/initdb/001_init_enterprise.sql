\set ON_ERROR_STOP on

-- Production/private deployment bootstrap.
-- This init sequence intentionally excludes deploy/migrations/002_seed_data.sql
-- so customer environments do not inherit demo tenant/users/providers/models.

\i /migrations/001_init_schema.sql

-- Bootstrap the default tenant/admin/project required by private deployment mode.
INSERT INTO tenants (id, name, edition, status, config_json)
VALUES ('tenant_default', '默认单位', 'enterprise', 'active', '{}')
ON CONFLICT (id) DO NOTHING;

-- Placeholder bootstrap password hash.
-- control-plane rotates this account to BOOTSTRAP_ADMIN_* on startup before formal use.
INSERT INTO users (id, tenant_id, username, email, password_hash, role, status)
VALUES (
  'user_admin',
  'tenant_default',
  'admin',
  'admin@local',
  ('$2b$10$' || 'hyMP/JkdSNIIYctdZPsu2.c./RwQ/YsIPvuj0bYrPZYwhpd5gUGVu'),
  'platform_admin',
  'active'
)
ON CONFLICT (tenant_id, username) DO NOTHING;

INSERT INTO projects (id, tenant_id, name, code, environment, owner_user_id, status)
VALUES ('project_default', 'tenant_default', '默认应用', 'private', 'production', 'user_admin', 'active')
ON CONFLICT (id) DO NOTHING;

\i /migrations/003_private_deployment.sql
\i /migrations/004_app_management.sql
\i /migrations/004_rule_description.sql
\i /migrations/005_content_audit.sql
\i /migrations/006_tool_call_audit.sql
\i /migrations/007_fix_request_logs_audit_fields.sql
\i /migrations/008_password_change_required.sql
\i /migrations/009_tool_risk_config.sql
\i /migrations/010_default_security_ruleset.sql
\i /migrations/011_proxy_models.sql
\i /migrations/012_proxy_usage_logs.sql
\i /migrations/013_reverse_proxy_routes.sql
\i /migrations/014_ca_certificates.sql
\i /migrations/015_models_updated_at.sql
\i /migrations/016_tool_call_rule_match.sql
\i /migrations/017_audit_dispositions.sql

UPDATE users
SET must_change_password = TRUE
WHERE id = 'user_admin';

INSERT INTO project_users (id, project_id, user_id)
VALUES ('pu_default_admin', 'project_default', 'user_admin')
ON CONFLICT DO NOTHING;
