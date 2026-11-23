-- 2.9.22：去掉内置安全底线，全部防护项改为控制台可配置。
-- 只建结构、改约束，不写任何数据行：缺行时取代码注册表的默认值。
-- 全部语句幂等，可重跑。

CREATE TABLE IF NOT EXISTS protection_settings (
    tenant_id   VARCHAR(64) NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    item_key    VARCHAR(96) NOT NULL,
    action      VARCHAR(16) NOT NULL,
    params_json JSONB       NOT NULL DEFAULT '{}'::jsonb,
    updated_by  VARCHAR(64) NOT NULL DEFAULT '',
    updated_at  TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, item_key),
    CHECK (action IN ('record','alert_allow','confirm','block')),
    CHECK (jsonb_typeof(params_json) = 'object')
);
COMMENT ON TABLE protection_settings IS
  '2.9.22：租户级防护项动作与参数。键和默认值以 packages/shared-go/protection 注册表为准，缺行取默认（告警放行）';

-- MCP 红线：动作加“关闭”“仅记录”两档。
ALTER TABLE mcp_redline_settings DROP CONSTRAINT IF EXISTS mcp_redline_settings_action_check;
ALTER TABLE mcp_redline_settings
  ADD CONSTRAINT mcp_redline_settings_action_check CHECK (action IN ('off','record','alert','block'));

-- 对象级出站放行（防跳板，缺省全拒绝）。
ALTER TABLE reverse_proxy_routes ADD COLUMN IF NOT EXISTS egress_overrides JSONB NOT NULL DEFAULT '{}'::jsonb;
ALTER TABLE mcp_servers          ADD COLUMN IF NOT EXISTS egress_overrides JSONB NOT NULL DEFAULT '{}'::jsonb;

-- 已批准的 MCP 工具记下批准时的投毒标记，Schema 没变时下次同步不再打回。
ALTER TABLE mcp_tools ADD COLUMN IF NOT EXISTS approved_poison_flags JSONB;

-- 受限文件作用范围：工具调用、用户消息提及、正向代理模型输出，默认三项全选（等于现状）。
ALTER TABLE agent_destructive_policies
  ADD COLUMN IF NOT EXISTS restricted_file_scopes_json JSONB NOT NULL
  DEFAULT '["tool_call","user_mention","proxy_output"]'::jsonb;

-- 012 的旧注释与代码不符。
COMMENT ON TABLE proxy_whitelist IS '正向代理白名单：未登记目标的处置见 system_settings.forward_proxy_unlisted_action';

-- 删除与破坏选“确认”不再限定 MCP 与应用/智能体范围（批次 2B）：删掉 140 的 confirm_capability_check。
-- protocol 的取值（空 = 所有协议，或 mcp）仍由 140 的 protocol_check 管，不再重建一条被它隐含的约束。
-- 非 MCP 协议有确认通道时走普通确认票据，没有时按防护项 agent.confirm_without_channel。可重复执行。
ALTER TABLE agent_destructive_policies DROP CONSTRAINT IF EXISTS agent_destructive_policies_confirm_capability_check;

-- MCP 准入（批次 3）：数据库触发器不再自动隔离。路由、清单、Schema 变化只更新观测值，
-- 已批准的值不动；网关按解析出的 route/schema_binding_mismatch 走 mcp.drift 防护项处置
-- （默认告警放行）。mcp.drift 设为阻断时由控制面同步照旧隔离（见 mcp_supply_chain_sync.go）。
-- 管理员手动隔离、撤销不受影响。修订号递增规则与 982 相同。
-- 对象级出站放行（egress_overrides）纳入路由指纹，与 allow_private_egress 一致：打开任一项后
-- 已批准的服务要重新批准。缺省（全 false、无自定义 CA）摘要为空串，存量指纹不变。
-- 用 plpgsql：创建时不校验引用的 982 函数，迁移测试的最小库里也能建。
CREATE OR REPLACE FUNCTION mcp_egress_override_digest(p JSONB) RETURNS TEXT AS $$
DECLARE
  normalized JSONB;
BEGIN
  IF p IS NULL OR jsonb_typeof(p) <> 'object' THEN
    RETURN '';
  END IF;
  normalized := jsonb_build_object(
    'allow_loopback',           COALESCE(p->>'allow_loopback','false') = 'true',
    'allow_link_local',         COALESCE(p->>'allow_link_local','false') = 'true',
    'allow_metadata',           COALESCE(p->>'allow_metadata','false') = 'true',
    'allow_internal_hostnames', COALESCE(p->>'allow_internal_hostnames','false') = 'true',
    'insecure_skip_verify',     COALESCE(p->>'insecure_skip_verify','false') = 'true',
    'allow_same_host_redirect', COALESCE(p->>'allow_same_host_redirect','false') = 'true',
    'trusted_ca_pem',           btrim(COALESCE(p->>'trusted_ca_pem','')));
  IF normalized = jsonb_build_object(
    'allow_loopback', false, 'allow_link_local', false, 'allow_metadata', false,
    'allow_internal_hostnames', false, 'insecure_skip_verify', false,
    'allow_same_host_redirect', false, 'trusted_ca_pem', '') THEN
    RETURN '';
  END IF;
  RETURN encode(sha256(convert_to(normalized::text, 'UTF8')), 'hex');
END; $$ LANGUAGE plpgsql IMMUTABLE;

CREATE OR REPLACE FUNCTION compute_mcp_route_hash(
  p_server_url TEXT, p_transport TEXT, p_allow_private BOOLEAN,
  p_auth_key_ref TEXT, p_auth_ciphertext TEXT, p_capabilities JSONB, p_egress JSONB
) RETURNS TEXT AS $$
DECLARE
  base TEXT := compute_mcp_route_hash(p_server_url, p_transport, p_allow_private, p_auth_key_ref, p_auth_ciphertext, p_capabilities);
  egress TEXT := mcp_egress_override_digest(p_egress);
BEGIN
  IF egress = '' THEN
    RETURN base;
  END IF;
  RETURN encode(sha256(convert_to(base || chr(31) || 'egress' || chr(31) || egress, 'UTF8')), 'hex');
END; $$ LANGUAGE plpgsql IMMUTABLE;

CREATE OR REPLACE FUNCTION set_mcp_server_route_hash() RETURNS TRIGGER AS $$
BEGIN
  NEW.observed_route_hash:=compute_mcp_route_hash(NEW.server_url,NEW.transport,NEW.allow_private_egress,NEW.auth_key_ref,NEW.auth_ciphertext,NEW.capabilities_json,NEW.egress_overrides);
  RETURN NEW;
END; $$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION enforce_mcp_server_admission_transition() RETURNS TRIGGER AS $$
BEGIN
  NEW.observed_route_hash:=compute_mcp_route_hash(NEW.server_url,NEW.transport,NEW.allow_private_egress,NEW.auth_key_ref,NEW.auth_ciphertext,NEW.capabilities_json,NEW.egress_overrides);
  IF ROW(NEW.admission_status,NEW.approved_manifest_hash,NEW.approved_manifest_snapshot,NEW.approved_route_hash,NEW.quarantine_reason,NEW.quarantined_at,NEW.admission_reviewed_by,NEW.admission_reviewed_at)
     IS DISTINCT FROM ROW(OLD.admission_status,OLD.approved_manifest_hash,OLD.approved_manifest_snapshot,OLD.approved_route_hash,OLD.quarantine_reason,OLD.quarantined_at,OLD.admission_reviewed_by,OLD.admission_reviewed_at)
  THEN NEW.admission_revision:=OLD.admission_revision+1; ELSE NEW.admission_revision:=OLD.admission_revision; END IF;
  RETURN NEW;
END; $$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION enforce_mcp_tool_admission_transition() RETURNS TRIGGER AS $$
BEGIN
  IF ROW(NEW.admission_status,NEW.approved_schema_hash,NEW.approved_schema_snapshot,NEW.quarantine_reason,NEW.quarantined_at,NEW.admission_reviewed_by,NEW.admission_reviewed_at)
     IS DISTINCT FROM ROW(OLD.admission_status,OLD.approved_schema_hash,OLD.approved_schema_snapshot,OLD.quarantine_reason,OLD.quarantined_at,OLD.admission_reviewed_by,OLD.admission_reviewed_at)
  THEN NEW.admission_revision:=OLD.admission_revision+1; ELSE NEW.admission_revision:=OLD.admission_revision; END IF;
  RETURN NEW;
END; $$ LANGUAGE plpgsql;
