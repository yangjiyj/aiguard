BEGIN;
-- P0-2 agent endpoint ledger. agent_sessions.project_id is intentionally nullable:
-- endpoint_hook sessions do not have a gateway project yet; existing gateway writes remain non-null.
CREATE TABLE IF NOT EXISTS agent_enrollment_tokens (
 id text PRIMARY KEY, tenant_id text NOT NULL, name text NOT NULL DEFAULT '', token_hash text NOT NULL UNIQUE,
 token_prefix text NOT NULL DEFAULT '', default_mode text NOT NULL DEFAULT 'monitor' CHECK (default_mode IN ('monitor','would_block','block')),
 allowed_products jsonb NOT NULL DEFAULT '[]'::jsonb, max_endpoints integer NOT NULL DEFAULT 0,
 enabled boolean NOT NULL DEFAULT true, expires_at timestamptz, revoked_at timestamptz,
 last_used_at timestamptz, created_by text NOT NULL DEFAULT '', created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS agent_enrollment_tokens_tenant ON agent_enrollment_tokens(tenant_id);
CREATE TABLE IF NOT EXISTS agent_endpoints (
 id text PRIMARY KEY, tenant_id text NOT NULL, machine_id text NOT NULL, hostname text NOT NULL,
 os text NOT NULL, os_version text NOT NULL DEFAULT '', arch text NOT NULL, os_user text NOT NULL DEFAULT '',
 agent_product text NOT NULL, agent_version text NOT NULL DEFAULT '', install_path_hash text NOT NULL DEFAULT '',
 adapter_name text NOT NULL DEFAULT '', adapter_version text NOT NULL DEFAULT '', hookd_version text NOT NULL DEFAULT '',
 capabilities jsonb NOT NULL DEFAULT '[]'::jsonb, token_hash text NOT NULL UNIQUE, token_prefix text NOT NULL DEFAULT '',
 token_rotated_at timestamptz, mode_override text CHECK (mode_override IS NULL OR mode_override IN ('monitor','would_block','block')),
 capture_level text NOT NULL DEFAULT 'metadata' CHECK (capture_level IN ('metadata','summary','full')),
 status text NOT NULL DEFAULT 'active' CHECK (status IN ('active','stale','revoked','disabled')),
 last_heartbeat_at timestamptz, last_event_at timestamptz, last_policy_version bigint NOT NULL DEFAULT 0,
 last_config_version bigint NOT NULL DEFAULT 0, enrollment_token_id text, probe_host_id text, probe_asset_id text,
 user_id text, department_id text, health jsonb NOT NULL DEFAULT '{}'::jsonb,
 created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now(),
 UNIQUE (tenant_id,machine_id,hostname,os_user,agent_product)
);
CREATE INDEX IF NOT EXISTS agent_endpoints_tenant_status_hb ON agent_endpoints(tenant_id,status,last_heartbeat_at);
CREATE TABLE IF NOT EXISTS agent_turns (
 id text PRIMARY KEY, tenant_id text NOT NULL, session_id text NOT NULL, prompt_id text NOT NULL DEFAULT '', seq integer NOT NULL DEFAULT 0,
 started_at timestamptz, ended_at timestamptz, stop_reason text NOT NULL DEFAULT '', prompt_hash text NOT NULL DEFAULT '', prompt_preview text NOT NULL DEFAULT '',
 assistant_preview text NOT NULL DEFAULT '', tool_call_count integer NOT NULL DEFAULT 0, blocked_count integer NOT NULL DEFAULT 0,
 UNIQUE(session_id,prompt_id)
);
CREATE INDEX IF NOT EXISTS agent_turns_session_seq ON agent_turns(session_id,seq);
CREATE TABLE IF NOT EXISTS agent_events (
 id text NOT NULL, tenant_id text NOT NULL, endpoint_id text NOT NULL, session_id text NOT NULL DEFAULT '', prompt_id text NOT NULL DEFAULT '', tool_use_id text NOT NULL DEFAULT '',
 event_type text NOT NULL, occurred_at timestamptz NOT NULL, received_at timestamptz NOT NULL DEFAULT now(), tool_name text NOT NULL DEFAULT '', tool_type text NOT NULL DEFAULT '', mcp_server text NOT NULL DEFAULT '',
 payload jsonb NOT NULL DEFAULT '{}'::jsonb, local_decision jsonb NOT NULL DEFAULT '{}'::jsonb, server_decision jsonb NOT NULL DEFAULT '{}',
 tool_call_log_id text, severity text NOT NULL DEFAULT 'low', security_event_id text, PRIMARY KEY(tenant_id,id)
);
CREATE INDEX IF NOT EXISTS agent_events_tenant_session_time ON agent_events(tenant_id,session_id,occurred_at);
CREATE INDEX IF NOT EXISTS agent_events_tenant_endpoint_received ON agent_events(tenant_id,endpoint_id,received_at);
CREATE TABLE IF NOT EXISTS agent_endpoint_assets (
 id text PRIMARY KEY, tenant_id text NOT NULL, endpoint_id text NOT NULL, asset_type text NOT NULL, name text NOT NULL, version text NOT NULL DEFAULT '', source text NOT NULL DEFAULT '', hash text NOT NULL DEFAULT '',
 evidence jsonb NOT NULL DEFAULT '{}', first_seen timestamptz NOT NULL DEFAULT now(), last_seen timestamptz NOT NULL DEFAULT now(), present boolean NOT NULL DEFAULT true,
 scan_status text NOT NULL DEFAULT '', scan_decision text NOT NULL DEFAULT '', UNIQUE(endpoint_id,asset_type,name,hash)
);
CREATE TABLE IF NOT EXISTS agent_policy_bundles (
 id text PRIMARY KEY, tenant_id text NOT NULL, version bigint NOT NULL, checksum text NOT NULL, bundle jsonb NOT NULL,
 derived_from jsonb NOT NULL DEFAULT '{}', created_at timestamptz NOT NULL DEFAULT now(), created_by text NOT NULL DEFAULT '', UNIQUE(tenant_id,version), UNIQUE(tenant_id,checksum)
);
ALTER TABLE agent_sessions ALTER COLUMN project_id DROP NOT NULL;
ALTER TABLE agent_sessions ADD COLUMN IF NOT EXISTS endpoint_id text;
ALTER TABLE agent_sessions ADD COLUMN IF NOT EXISTS source text NOT NULL DEFAULT 'gateway';
ALTER TABLE agent_sessions ADD COLUMN IF NOT EXISTS parent_session_id text;
ALTER TABLE agent_sessions ADD COLUMN IF NOT EXISTS agent_id text;
ALTER TABLE agent_sessions ADD COLUMN IF NOT EXISTS agent_role text;
ALTER TABLE agent_sessions ADD COLUMN IF NOT EXISTS product text;
ALTER TABLE agent_sessions ADD COLUMN IF NOT EXISTS model text;
ALTER TABLE agent_sessions ADD COLUMN IF NOT EXISTS cwd_hash text;
ALTER TABLE agent_sessions ADD COLUMN IF NOT EXISTS project_label text;
ALTER TABLE agent_sessions ADD COLUMN IF NOT EXISTS permission_mode text;
ALTER TABLE agent_sessions ADD COLUMN IF NOT EXISTS started_at timestamptz;
ALTER TABLE agent_sessions ADD COLUMN IF NOT EXISTS ended_at timestamptz;
ALTER TABLE agent_sessions ADD COLUMN IF NOT EXISTS end_reason text;
ALTER TABLE agent_sessions ADD COLUMN IF NOT EXISTS start_source text;
ALTER TABLE agent_sessions ADD COLUMN IF NOT EXISTS turn_count integer NOT NULL DEFAULT 0;
ALTER TABLE agent_sessions ADD COLUMN IF NOT EXISTS event_count integer NOT NULL DEFAULT 0;
ALTER TABLE agent_sessions ADD COLUMN IF NOT EXISTS tool_call_count integer NOT NULL DEFAULT 0;
ALTER TABLE agent_sessions ADD COLUMN IF NOT EXISTS blocked_count integer NOT NULL DEFAULT 0;
ALTER TABLE agent_sessions ADD COLUMN IF NOT EXISTS would_block_count integer NOT NULL DEFAULT 0;
ALTER TABLE agent_sessions ADD COLUMN IF NOT EXISTS gateway_request_count integer NOT NULL DEFAULT 0;
CREATE INDEX IF NOT EXISTS agent_sessions_endpoint ON agent_sessions(tenant_id,endpoint_id);
INSERT INTO system_settings(key,value,updated_at) VALUES ('agent_endpoint_default_mode','monitor',NOW()),('agent_endpoint_capture_level','metadata',NOW()),('agent_endpoint_heartbeat_interval_sec','300',NOW()),('agent_endpoint_decide_timeout_ms','300',NOW()),('agent_endpoint_decide_fail_mode','open',NOW()) ON CONFLICT(key) DO NOTHING;
COMMIT;
