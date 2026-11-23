-- 099_mcp_gateway.sql
-- MCP 安全网关 v1（能力识别 + 权限管控）数据模型。
-- 影响面：
--   1) mcp_servers（001 已建，P2 预留表）——只 ALTER 加列，绝不重建；
--      新增传输方式/能力清单指纹/鉴权凭据密文/内网放行开关/同步时间戳。
--   2) 新建 mcp_tools：能力识别产物（sync 时整批 upsert；manifest 中消失的工具标 removed 不物理删）。
--   3) 新建 mcp_policies：MCP 工具调用权限策略（scope_type+scope_ref 通配回退，语义仿 agentguard_policies）。
-- MCP 调用审计复用 tool_call_logs（006 的 tool_type 枚举已含 'mcp'，053 双决策列齐备），不新建审计表。
-- 开关：数据面代理由 gateway-core 的 MCP_GATEWAY_ENABLED（默认 false）门控；本迁移只加数据模型，无行为变化。
-- 全部语句幂等（ADD COLUMN IF NOT EXISTS / CREATE TABLE IF NOT EXISTS），可安全重跑。

-- ============ 1. mcp_servers 加列（001:311 已存在，只 ALTER） ============

ALTER TABLE mcp_servers
  ADD COLUMN IF NOT EXISTS transport TEXT NOT NULL DEFAULT 'streamable_http',
  ADD COLUMN IF NOT EXISTS manifest_hash TEXT NOT NULL DEFAULT '',
  ADD COLUMN IF NOT EXISTS auth_ciphertext TEXT NOT NULL DEFAULT '',
  ADD COLUMN IF NOT EXISTS auth_key_ref TEXT NOT NULL DEFAULT '',
  ADD COLUMN IF NOT EXISTS allow_private_egress BOOLEAN NOT NULL DEFAULT FALSE,
  ADD COLUMN IF NOT EXISTS last_synced_at TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS last_manifest_changed_at TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT now();

COMMENT ON COLUMN mcp_servers.transport IS 'MCP 传输方式：streamable_http | sse';
COMMENT ON COLUMN mcp_servers.manifest_hash IS '能力清单指纹：对 tools 规范化 JSON 的 sha256，变更即 rug-pull 信号';
COMMENT ON COLUMN mcp_servers.auth_ciphertext IS '鉴权凭据密文（secrets.EncryptProviderSecret，enc:v1: 前缀），禁存明文';
COMMENT ON COLUMN mcp_servers.auth_key_ref IS '加密密钥引用（如 env:JJD_MASTER_KEY）';
COMMENT ON COLUMN mcp_servers.allow_private_egress IS '内网 MCP 显式授权：网关转发默认封禁私网目标，登记时显式打开才放行';
COMMENT ON COLUMN mcp_servers.last_synced_at IS '最近一次能力同步（initialize+tools/list）时间';
COMMENT ON COLUMN mcp_servers.last_manifest_changed_at IS '能力清单最近一次变更时间（rug-pull 标记）';

-- ============ 2. mcp_tools：能力识别产物 ============

CREATE TABLE IF NOT EXISTS mcp_tools (
  id TEXT PRIMARY KEY,                          -- 'mcpt_'+uuid[:8]
  server_id TEXT NOT NULL REFERENCES mcp_servers(id) ON DELETE CASCADE,
  tenant_id TEXT NOT NULL,
  tool_name TEXT NOT NULL,
  description TEXT NOT NULL DEFAULT '',
  input_schema JSONB,
  risk_tags JSONB,                              -- 自动标注: destructive/network_egress/data_export/cred_access/file_write
  schema_hash TEXT NOT NULL DEFAULT '',         -- 单工具指纹（description+schema），偏离检测
  first_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  removed BOOLEAN NOT NULL DEFAULT FALSE,       -- manifest 中消失的工具标 removed 不物理删
  UNIQUE(server_id, tool_name)
);
CREATE INDEX IF NOT EXISTS idx_mcp_tools_tenant ON mcp_tools(tenant_id, server_id);

COMMENT ON TABLE mcp_tools IS 'MCP 工具清单（能力识别产物）：sync 时整批 upsert，消失的工具标 removed 保留审计线索';
COMMENT ON COLUMN mcp_tools.risk_tags IS '关键词启发式风险标签数组：destructive/network_egress/data_export/cred_access/file_write';
COMMENT ON COLUMN mcp_tools.schema_hash IS '单工具指纹：sha256(description+input_schema)，用于工具定义偏离检测';

-- ============ 3. mcp_policies：MCP 工具调用权限策略 ============

CREATE TABLE IF NOT EXISTS mcp_policies (
  id TEXT PRIMARY KEY,                          -- 'mcppol_'+uuid[:8]
  tenant_id TEXT NOT NULL,
  scope_type TEXT NOT NULL DEFAULT 'tenant'
    CHECK (scope_type IN ('tenant','project','user','key','agent','session')),
  scope_ref TEXT NOT NULL DEFAULT '',           -- ''=该档位通配
  server_id TEXT NOT NULL DEFAULT '',           -- ''=全部 server
  tool_pattern TEXT NOT NULL DEFAULT '',        -- ''=全部 tool；精确名；'ns.*' 前缀 glob
  mode TEXT NOT NULL DEFAULT 'audit' CHECK (mode IN ('observe','audit','strict')),
  default_action TEXT NOT NULL DEFAULT 'audit'
    CHECK (default_action IN ('allow','audit','confirm','block')),
  priority INTEGER NOT NULL DEFAULT 0,
  enabled BOOLEAN NOT NULL DEFAULT TRUE,
  note TEXT NOT NULL DEFAULT '',
  created_by TEXT NOT NULL DEFAULT '',
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_mcp_policies_tenant ON mcp_policies(tenant_id, enabled);

COMMENT ON TABLE mcp_policies IS 'MCP 工具调用权限策略：作用域通配回退（session>key>agent>user>project>tenant）×server×tool 三维匹配；mode 原样下发、audit_only 钳制只在 gateway-core 决策器';
COMMENT ON COLUMN mcp_policies.scope_ref IS '作用域引用：空串=该 scope_type 档位下通配（如 scope_type=key + scope_ref 空 = 全部密钥）';
COMMENT ON COLUMN mcp_policies.tool_pattern IS '工具匹配模式：空串=全部；精确名；ns.* 前缀 glob';
COMMENT ON COLUMN mcp_policies.mode IS '执行模式：observe/audit/strict。策略层原样存取，SECURITY_AUDIT_ONLY 钳制在网关决策器，不在此层';
COMMENT ON COLUMN mcp_policies.default_action IS '命中后的默认处置：allow/audit/confirm/block（audit_only 下 block/confirm 只留痕不执行）';
