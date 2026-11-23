-- deploy/migrations/rollback/999_protection_settings.sql
-- 回滚迁移 999（2.9.22 防护项全部可配置）。
-- 按段落组织，其他批次的段落合流时追加。每段自带事务，可重复执行。
-- 先回退应用版本，再执行本文件。
-- 本文件不删除 schema_migrations 里 999 的记录：回滚后直接再升级，迁移运行器会认为 999 已执行而跳过。
-- 回滚后如需再升级，先手工执行
--   DELETE FROM schema_migrations WHERE version = '999_protection_settings.sql';
-- 再运行升级（999 全部语句幂等，可重跑）。
--
-- 回滚须知：
-- 1. 打开过对象级出站放行（egress_overrides 有任一项）的已批准 MCP 服务，回滚后要由管理员重新批准。
--    回滚后路由指纹不再包含 egress_overrides：这类服务下一次被更新（包括定时重新同步）时 observed_route_hash
--    按 982 的公式重算，与批准时记下的 approved_route_hash 不一致，2.9.21 按路由绑定不一致拦下它的全部
--    调用，直到重新批准。执行本文件之前（本文件会删掉 mcp_egress_override_digest）先列出受影响的服务：
--      SELECT tenant_id, id, name FROM mcp_servers
--       WHERE admission_status = 'approved' AND mcp_egress_override_digest(egress_overrides) <> '';
-- 2. 2.9.22 下“保持批准但记了发现”的 MCP 工具（批准状态、quarantine_reason 非空，如同名不一致
--    shadow_schema_diverges），回滚后 2.9.21 把它们当普通已批准工具放行，不再自动打回。回滚前列出，
--    需要时由管理员手动隔离：
--      SELECT tenant_id, server_id, id, tool_name, quarantine_reason FROM mcp_tools
--       WHERE admission_status = 'approved' AND COALESCE(quarantine_reason, '') <> '';
-- 3. 删除与破坏选“确认”的租户范围或所有协议行（2.9.22 起允许）在回滚后保留，2.9.21 的有效策略 SQL 跳过
--    它们，退到更低一级策略；确认约束以 NOT VALID 恢复，只拦新写入。回滚前列出：
--      SELECT tenant_id, id, scope_type, scope_ref, protocol FROM agent_destructive_policies
--       WHERE action = 'confirm' AND NOT (scope_type IN ('application','agent') AND protocol = 'mcp');
-- 4. MCP 红线选了“关闭”“仅记录”的，回滚后改为“告警”（2.9.21 的缺省，只有告警、阻断两档）。
-- 5. 防护项表 protection_settings 和 999 新增的列（egress_overrides、approved_poison_flags、
--    restricted_file_scopes_json）保留：2.9.21 不读它们，再升级时管理员的配置还在。

-- ---------------------------------------------------------------------------
-- 批次 3：MCP 准入恢复触发器自动隔离，路由指纹去掉 egress_overrides。
-- 三个触发器函数恢复为 982（服务端，set_mcp_server_route_hash 用 982 的 6 参数指纹）与
-- 117（工具端）的函数体：已批准服务改路由、上游连接配置或清单，已批准工具改 Schema，重新自动隔离。
-- 先换掉引用 7 参数指纹的触发器函数，再删 999 新增的两个函数。
-- 打开过对象级出站放行（egress_overrides）后批准的服务，下一次更新按 982 公式重算 observed_route_hash，
-- 与批准值不一致，需要重新批准。egress_overrides 列本身保留。
BEGIN;

CREATE OR REPLACE FUNCTION set_mcp_server_route_hash() RETURNS TRIGGER AS $$
BEGIN
  NEW.observed_route_hash:=compute_mcp_route_hash(NEW.server_url,NEW.transport,NEW.allow_private_egress,NEW.auth_key_ref,NEW.auth_ciphertext,NEW.capabilities_json);
  RETURN NEW;
END; $$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION enforce_mcp_server_admission_transition() RETURNS TRIGGER AS $$
BEGIN
  NEW.observed_route_hash:=compute_mcp_route_hash(NEW.server_url,NEW.transport,NEW.allow_private_egress,NEW.auth_key_ref,NEW.auth_ciphertext,NEW.capabilities_json);
  IF OLD.admission_status='approved' AND (
       ROW(NEW.server_url,NEW.transport,NEW.allow_private_egress,NEW.auth_key_ref,NEW.auth_ciphertext)
         IS DISTINCT FROM ROW(OLD.server_url,OLD.transport,OLD.allow_private_egress,OLD.auth_key_ref,OLD.auth_ciphertext)
       OR mcp_route_config_digest(NEW.capabilities_json) IS DISTINCT FROM mcp_route_config_digest(OLD.capabilities_json)
     ) THEN
    NEW.admission_status:='quarantined'; NEW.quarantine_reason:='route_binding_changed';
    NEW.quarantined_at:=now(); NEW.admission_reviewed_by:='system'; NEW.admission_reviewed_at:=now();
  ELSIF OLD.admission_status='approved' AND OLD.manifest_hash<>'' AND NEW.manifest_hash IS DISTINCT FROM OLD.manifest_hash THEN
    NEW.admission_status:='quarantined'; NEW.quarantine_reason:='rug_pull_manifest_changed';
    NEW.quarantined_at:=now(); NEW.admission_reviewed_by:='system'; NEW.admission_reviewed_at:=now();
  END IF;
  IF ROW(NEW.admission_status,NEW.approved_manifest_hash,NEW.approved_manifest_snapshot,NEW.approved_route_hash,NEW.quarantine_reason,NEW.quarantined_at,NEW.admission_reviewed_by,NEW.admission_reviewed_at)
     IS DISTINCT FROM ROW(OLD.admission_status,OLD.approved_manifest_hash,OLD.approved_manifest_snapshot,OLD.approved_route_hash,OLD.quarantine_reason,OLD.quarantined_at,OLD.admission_reviewed_by,OLD.admission_reviewed_at)
  THEN NEW.admission_revision:=OLD.admission_revision+1; ELSE NEW.admission_revision:=OLD.admission_revision; END IF;
  RETURN NEW;
END; $$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION enforce_mcp_tool_admission_transition() RETURNS TRIGGER AS $$
BEGIN
  IF OLD.admission_status='approved' AND OLD.schema_hash<>'' AND NEW.schema_hash IS DISTINCT FROM OLD.schema_hash THEN
    NEW.admission_status:='quarantined'; NEW.quarantine_reason:='rug_pull_schema_changed';
    NEW.quarantined_at:=now(); NEW.admission_reviewed_by:='system'; NEW.admission_reviewed_at:=now();
  END IF;
  IF ROW(NEW.admission_status,NEW.approved_schema_hash,NEW.approved_schema_snapshot,NEW.quarantine_reason,NEW.quarantined_at,NEW.admission_reviewed_by,NEW.admission_reviewed_at)
     IS DISTINCT FROM ROW(OLD.admission_status,OLD.approved_schema_hash,OLD.approved_schema_snapshot,OLD.quarantine_reason,OLD.quarantined_at,OLD.admission_reviewed_by,OLD.admission_reviewed_at)
  THEN NEW.admission_revision:=OLD.admission_revision+1; ELSE NEW.admission_revision:=OLD.admission_revision; END IF;
  RETURN NEW;
END; $$ LANGUAGE plpgsql;

DROP FUNCTION IF EXISTS compute_mcp_route_hash(TEXT,TEXT,BOOLEAN,TEXT,TEXT,JSONB,JSONB);
DROP FUNCTION IF EXISTS mcp_egress_override_digest(JSONB);

COMMIT;

-- ---------------------------------------------------------------------------
-- 批次 2B：删除与破坏的确认约束恢复为 140 的定义（只允许应用/智能体范围、MCP 协议选确认）。
-- 以 NOT VALID 加回：2.9.22 存下的租户范围、所有协议的确认行不动（2.9.21 的有效策略 SQL 跳过它们），
-- 之后的新写入照 2.9.21 拦。可重复执行。
BEGIN;

ALTER TABLE agent_destructive_policies DROP CONSTRAINT IF EXISTS agent_destructive_policies_confirm_capability_check;
ALTER TABLE agent_destructive_policies
  ADD CONSTRAINT agent_destructive_policies_confirm_capability_check
  CHECK (action <> 'confirm' OR (scope_type IN ('application', 'agent') AND protocol = 'mcp')) NOT VALID;

COMMIT;

-- ---------------------------------------------------------------------------
-- 批次 1：MCP 红线动作回到 862 的两档（告警、阻断），“关闭”“仅记录”的存量行改为告警（2.9.21 缺省）。
-- protection_settings 表与新增列保留（2.9.21 不读，见回滚须知第 5 条）。可重复执行。
BEGIN;

UPDATE mcp_redline_settings SET action = 'alert' WHERE action IN ('off', 'record');
ALTER TABLE mcp_redline_settings DROP CONSTRAINT IF EXISTS mcp_redline_settings_action_check;
ALTER TABLE mcp_redline_settings
  ADD CONSTRAINT mcp_redline_settings_action_check CHECK (action IN ('alert', 'block'));

COMMIT;
