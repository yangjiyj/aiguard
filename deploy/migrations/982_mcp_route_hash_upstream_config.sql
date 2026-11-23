-- 982: MCP 路由指纹覆盖上游连接配置（capabilities_json 里的鉴权位置/头名/参数名/值模板/额外请求头）。
--
-- 背景：117 的路由指纹只绑定 server_url、transport、allow_private_egress、auth_key_ref、auth_ciphertext。
-- 控制面新增“上游连接配置”后，这些配置决定密钥被放在哪里、以什么格式发往上游，属于路由的一部分：
-- 已批准服务若只改这些配置（地址与密钥不变），必须像改地址一样被自动隔离并等待复核。
--
-- 设计约束：
--   1) 没配置任何新字段的存量行，新指纹必须与旧公式逐字节相同——否则迁移瞬间所有已批准服务
--      （含现网 streamable_http 服务）会因指纹变化被自动隔离。做法：配置摘要为空串时不向输入追加任何内容。
--   2) 只纳入本次新增的“密钥被发往哪里 / 怎么注入”的键：
--        upstream_auth_location、upstream_auth_query_param、upstream_auth_template、upstream_extra_headers。
--      刻意不纳入：
--        - 存量键 auth_header_name：现网已批准且自定义了头名的服务，若把它并入摘要，迁移后的下一次
--          任意 UPDATE 就会让指纹与已批准指纹失配，被网关当作“路由未批准”硬阻断，等于强制所有存量
--          服务重新审批。代价：已批准服务仅改头名不会被触发器自动隔离；该风险由控制面保存校验兜底
--          （改头名/位置/模板必须同时重新提交密钥，见 UpdateMCPServer），且不引入对存量的破坏。
--        - detected_transport、protocol_version、protocol_version_raw、protocol_version_forward_compat：
--          它们由控制面同步写入，纳入会导致每次同步后服务自我隔离。
--      网关转发时以 transport + 鉴权配置为准，不依赖 detected_transport 的取值稳定。
--
--   关于“为什么不纳入存量键 auth_header_name”，以及由谁兜底（供复审与后续维护者查阅）：
--      a) 不纳入的原因是兼容：117 的旧指纹公式里没有它。现网凡是自定义了鉴权头名的已批准服务，
--         若新公式把它并入摘要，迁移后的下一次任意 UPDATE（哪怕只是改负责人）就会让 observed_route_hash
--         与 approved_route_hash 失配，网关会把它当作“路由未批准”硬阻断——等于强制所有这类存量服务重新审批。
--      b) 代价是：已批准服务只改 auth_header_name（地址与密钥都不变）时，触发器不会自动隔离它。
--      c) 兜底在控制面 UpdateMCPServer：任何导致鉴权形态变化（鉴权位置、头名、参数名、值模板）或上游地址
--         变化的保存，都必须同时重新提交 auth_token，否则返回 400；因此旧密钥不可能被悄悄带去新的注入方式。
--         该规则有回归测试（TestAdvReviewC_*、TestFollowupL3_*）。
--      d) 同步写入的 detected_transport / protocol_version* 不会触发隔离，有回归测试
--         （TestFollowupM2_SyncWrittenCapabilitiesDoNotSelfQuarantineApprovedServer）。
--   3) 幂等：全部使用 CREATE OR REPLACE / DROP TRIGGER IF EXISTS；重复执行结果不变。
--      不重写存量行：存量行 observed_route_hash 本来就等于旧公式，空配置下新公式与之相同；
--      只有下一次 UPDATE 经触发器重算时才会按新公式取值。

CREATE OR REPLACE FUNCTION mcp_route_config_digest(p_capabilities JSONB) RETURNS TEXT AS $$
  -- jsonb 的文本形态按键排序、与书写顺序无关，天然规范化。无任何路由相关键时返回空串。
  SELECT CASE
    WHEN p_capabilities IS NULL THEN ''
    WHEN NOT (p_capabilities ?| ARRAY['upstream_auth_location','upstream_auth_query_param',
                                       'upstream_auth_template','upstream_extra_headers']) THEN ''
    -- 仅取路由相关键，组成新的 jsonb 对象（jsonb 文本按键排序，与书写顺序无关）。
    ELSE encode(sha256(convert_to(
      jsonb_strip_nulls(jsonb_build_object(
        'upstream_auth_location',    p_capabilities -> 'upstream_auth_location',
        'upstream_auth_query_param', p_capabilities -> 'upstream_auth_query_param',
        'upstream_auth_template',    p_capabilities -> 'upstream_auth_template',
        'upstream_extra_headers',    p_capabilities -> 'upstream_extra_headers'
      ))::text, 'UTF8')), 'hex')
  END
$$ LANGUAGE SQL IMMUTABLE;

-- 旧签名（5 参数）保持不动，兼容仍在调用它的代码与测试；新增 6 参数重载承载配置摘要。
CREATE OR REPLACE FUNCTION compute_mcp_route_hash(
  p_server_url TEXT, p_transport TEXT, p_allow_private BOOLEAN,
  p_auth_key_ref TEXT, p_auth_ciphertext TEXT, p_capabilities JSONB
) RETURNS TEXT AS $$
  SELECT encode(sha256(convert_to(
    COALESCE(p_server_url,'') || chr(31) ||
    COALESCE(p_transport,'streamable_http') || chr(31) ||
    COALESCE(p_allow_private,FALSE)::text || chr(31) ||
    COALESCE(p_auth_key_ref,'') || chr(31) ||
    encode(sha256(convert_to(COALESCE(p_auth_ciphertext,''),'UTF8')),'hex') ||
    CASE WHEN mcp_route_config_digest(p_capabilities) = '' THEN ''
         ELSE chr(31) || mcp_route_config_digest(p_capabilities) END,
    'UTF8'
  )),'hex')
$$ LANGUAGE SQL IMMUTABLE;

CREATE OR REPLACE FUNCTION set_mcp_server_route_hash() RETURNS TRIGGER AS $$
BEGIN
  NEW.observed_route_hash:=compute_mcp_route_hash(NEW.server_url,NEW.transport,NEW.allow_private_egress,NEW.auth_key_ref,NEW.auth_ciphertext,NEW.capabilities_json);
  RETURN NEW;
END; $$ LANGUAGE plpgsql;

-- 与 117 相同的准入状态机，仅把“路由是否变化”的判断扩展到上游连接配置摘要。
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

DROP TRIGGER IF EXISTS trg_mcp_server_route_hash_insert ON mcp_servers;
CREATE TRIGGER trg_mcp_server_route_hash_insert BEFORE INSERT ON mcp_servers
FOR EACH ROW EXECUTE FUNCTION set_mcp_server_route_hash();
DROP TRIGGER IF EXISTS trg_mcp_server_admission_transition ON mcp_servers;
CREATE TRIGGER trg_mcp_server_admission_transition BEFORE UPDATE ON mcp_servers
FOR EACH ROW EXECUTE FUNCTION enforce_mcp_server_admission_transition();

COMMENT ON FUNCTION mcp_route_config_digest(JSONB) IS
  '上游连接配置摘要：仅覆盖新增的鉴权位置/参数名/值模板/额外请求头（不含存量 auth_header_name）；不含 detected_transport 等同步写入字段；无配置返回空串以保持存量指纹不变';
COMMENT ON COLUMN mcp_servers.observed_route_hash IS
  'SHA-256 binding of URL, transport, private-egress flag, auth key ref, inner SHA-256 of ciphertext, and, when configured, a digest of upstream connection capabilities; never exposes credentials';
