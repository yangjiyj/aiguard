CREATE TABLE IF NOT EXISTS integration_agent_policies (
 id varchar(128) PRIMARY KEY,
 tenant_id varchar(64) NOT NULL REFERENCES tenants(id),
 agent_instance_id varchar(128) NOT NULL,
 action varchar(32) NOT NULL CHECK(action IN ('block_model_egress','disable_mcp')),
 enabled boolean NOT NULL DEFAULT true,
 mode varchar(16) NOT NULL CHECK(mode IN ('record','protect')),
 mcp_server_id varchar(128) NOT NULL DEFAULT '',
 version bigint NOT NULL DEFAULT 1 CHECK(version>0),
 updated_at timestamptz NOT NULL DEFAULT now(),
 UNIQUE(tenant_id,agent_instance_id,action,mcp_server_id)
);
CREATE TABLE IF NOT EXISTS integration_gateway_instances (
 instance_id varchar(128) PRIMARY KEY,
 boot_id varchar(128) NOT NULL,
 mode varchar(16) NOT NULL CHECK(mode IN ('record','protect')),
 last_seen_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS integration_gateway_receipts (
 instance_id varchar(128) NOT NULL REFERENCES integration_gateway_instances(instance_id),
 policy_id varchar(128) NOT NULL REFERENCES integration_agent_policies(id) ON DELETE CASCADE,
 boot_id varchar(128) NOT NULL,
 loaded_version bigint NOT NULL,
 loaded_at timestamptz NOT NULL DEFAULT now(),
 hit_count bigint NOT NULL DEFAULT 0,
 blocked_count bigint NOT NULL DEFAULT 0,
 PRIMARY KEY(instance_id,policy_id)
);
