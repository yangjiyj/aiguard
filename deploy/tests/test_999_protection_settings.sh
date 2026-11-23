#!/usr/bin/env bash
# deploy/tests/test_999_protection_settings.sh
# 仅供显式指定的可丢弃测试库使用。只在专用 schema（prot999_test）里建迁移引用到的最小表，
# 不对 public 下任何表做 DROP；结束时删掉这个 schema。
# 用法：PROTECTION_TEST_DATABASE_URL=postgres://... bash deploy/tests/test_999_protection_settings.sh
set -euo pipefail
: "${PROTECTION_TEST_DATABASE_URL:?请指定可丢弃测试库连接串}"
repo_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
migration="$repo_root/deploy/migrations/999_protection_settings.sql"
schema=prot999_test
psql_admin() { psql -X "$PROTECTION_TEST_DATABASE_URL" -v ON_ERROR_STOP=1 "$@"; }
psql_test() { PGOPTIONS="-c search_path=$schema" psql -X "$PROTECTION_TEST_DATABASE_URL" -v ON_ERROR_STOP=1 "$@"; }
created_schema=0
cleanup() { if [ "$created_schema" = 1 ]; then psql_admin -q -c "DROP SCHEMA IF EXISTS $schema CASCADE" >/dev/null 2>&1 || true; fi; }
trap cleanup EXIT

# ---- 静态检查：只建结构、改约束，不写任何数据行（缺行取注册表默认值） ----
code=$(grep -v '^[[:space:]]*--' "$migration" | sed -E 's/ON[[:space:]]+DELETE[[:space:]]+CASCADE//Ig')
! grep -Eiq '\b(INSERT|UPDATE|DELETE|TRUNCATE|MERGE)\b' <<<"$code" || { echo "999 不应写数据行"; exit 1; }
! grep -Eiq '\bDROP[[:space:]]+(TABLE|COLUMN)\b' <<<"$code" || { echo "999 不应删表或删列"; exit 1; }

if [ "$(psql_admin -At -c "SELECT count(*) FROM pg_namespace WHERE nspname = '$schema'")" != 0 ]; then
  echo "测试库里已经存在 schema $schema，脚本不会删除它，请确认后手工 DROP SCHEMA $schema CASCADE 再重跑。" >&2
  exit 1
fi
psql_admin -q -c "CREATE SCHEMA $schema" >/dev/null
created_schema=1
[ "$(psql_test -At -c 'SELECT current_schema()')" = "$schema" ] || { echo "search_path 没有生效，终止"; exit 1; }

psql_test -q <<'SQL'
CREATE TABLE tenants (id VARCHAR(64) PRIMARY KEY);
INSERT INTO tenants VALUES ('t1');
CREATE TABLE mcp_redline_settings (
  tenant_id VARCHAR(64) NOT NULL, rule_name VARCHAR(64) NOT NULL, action VARCHAR(16) NOT NULL DEFAULT 'alert',
  PRIMARY KEY (tenant_id, rule_name),
  CONSTRAINT mcp_redline_settings_action_check CHECK (action IN ('alert','block')));
CREATE TABLE reverse_proxy_routes (id VARCHAR(64) PRIMARY KEY);
CREATE TABLE mcp_servers (id VARCHAR(64) PRIMARY KEY);
CREATE TABLE mcp_tools (id VARCHAR(64) PRIMARY KEY);
-- 140 里与 999 相关的列和约束（confirm_capability_check 由 999 删掉）。
CREATE TABLE agent_destructive_policies (
  id VARCHAR(64) PRIMARY KEY,
  scope_type varchar(32) NOT NULL DEFAULT 'tenant', scope_ref varchar(256) NOT NULL DEFAULT '',
  action varchar(32) NOT NULL DEFAULT 'record', protocol varchar(32) NOT NULL DEFAULT '',
  CONSTRAINT agent_destructive_policies_protocol_check CHECK (protocol IN ('', 'mcp')),
  CONSTRAINT agent_destructive_policies_confirm_capability_check
    CHECK (action <> 'confirm' OR (scope_type IN ('application', 'agent') AND protocol = 'mcp')));
CREATE TABLE proxy_whitelist (id VARCHAR(32) PRIMARY KEY);
INSERT INTO reverse_proxy_routes VALUES ('r1');
INSERT INTO mcp_servers VALUES ('s1');
INSERT INTO agent_destructive_policies VALUES ('d1');
SQL

# ---- 跑两遍，第二遍不得报错 ----
psql_test -q -f "$migration" >/dev/null
psql_test -q -f "$migration" >/dev/null

expect_fail() { if psql_test -q -c "$1" >/dev/null 2>&1; then echo "应失败却成功：$1"; exit 1; fi; }
expect_ok() { psql_test -q -c "$1" >/dev/null || { echo "应成功却失败：$1"; exit 1; }; }

expect_ok   "INSERT INTO protection_settings (tenant_id,item_key,action) VALUES ('t1','agent.ssh_private_key','block')"
expect_fail "INSERT INTO protection_settings (tenant_id,item_key,action) VALUES ('t1','agent.env_file','nonsense')"
expect_fail "INSERT INTO protection_settings (tenant_id,item_key,action,params_json) VALUES ('t1','agent.burst','alert_allow','[]'::jsonb)"
expect_fail "INSERT INTO protection_settings (tenant_id,item_key,action) VALUES ('missing','agent.burst','record')"
for a in off record alert block; do expect_ok "INSERT INTO mcp_redline_settings VALUES ('t1','r_$a','$a')"; done
expect_fail "INSERT INTO mcp_redline_settings VALUES ('t1','r_bad','bogus')"

[ "$(psql_test -At -c "SELECT egress_overrides::text FROM reverse_proxy_routes WHERE id='r1'")" = '{}' ] || { echo "反向代理 egress_overrides 缺省不是 {}"; exit 1; }
[ "$(psql_test -At -c "SELECT egress_overrides::text FROM mcp_servers WHERE id='s1'")" = '{}' ] || { echo "MCP 服务 egress_overrides 缺省不是 {}"; exit 1; }
[ "$(psql_test -At -c "SELECT count(*) FROM information_schema.columns WHERE table_schema='$schema' AND table_name='mcp_tools' AND column_name='approved_poison_flags' AND is_nullable='YES'")" = 1 ] || { echo "mcp_tools.approved_poison_flags 缺失或不可空"; exit 1; }
[ "$(psql_test -At -c "SELECT restricted_file_scopes_json = '[\"tool_call\",\"user_mention\",\"proxy_output\"]'::jsonb FROM agent_destructive_policies WHERE id='d1'")" = t ] || { echo "受限文件作用范围缺省不是三项全选"; exit 1; }

# 删除与破坏的“确认”：租户范围、所有协议都能选；协议取值只由 protocol_check 管（空或 mcp），
# 140 的 confirm_capability_check 由 999 删掉，不再重建一条被 protocol_check 隐含的约束。
[ "$(psql_test -At -c "SELECT count(*) FROM pg_constraint WHERE conrelid = 'agent_destructive_policies'::regclass AND conname = 'agent_destructive_policies_confirm_capability_check'")" = 0 ] || { echo "confirm_capability_check 应已删除"; exit 1; }
[ "$(psql_test -At -c "SELECT count(*) FROM pg_constraint WHERE conrelid = 'agent_destructive_policies'::regclass AND conname = 'agent_destructive_policies_protocol_check'")" = 1 ] || { echo "protocol_check 不应被动"; exit 1; }
expect_ok   "INSERT INTO agent_destructive_policies (id,scope_type,scope_ref,action,protocol) VALUES ('c_tenant','tenant','','confirm','')"
expect_ok   "INSERT INTO agent_destructive_policies (id,scope_type,scope_ref,action,protocol) VALUES ('c_app','application','app-a','confirm','')"
expect_ok   "INSERT INTO agent_destructive_policies (id,scope_type,scope_ref,action,protocol) VALUES ('c_mcp','agent','codex','confirm','mcp')"
expect_fail "INSERT INTO agent_destructive_policies (id,scope_type,scope_ref,action,protocol) VALUES ('c_chat','tenant','','confirm','chat')"
expect_fail "INSERT INTO agent_destructive_policies (id,scope_type,scope_ref,action,protocol) VALUES ('b_chat','tenant','','block','chat')"
# MCP 出站放行纳入路由指纹：缺省（全 false）摘要为空，存量指纹不变；打开任一项摘要非空。
[ "$(psql_test -At -c "SELECT mcp_egress_override_digest('{}'::jsonb)")" = '' ] || { echo "缺省出站放行的摘要不是空串"; exit 1; }
[ "$(psql_test -At -c "SELECT mcp_egress_override_digest('{\"allow_loopback\":false,\"trusted_ca_pem\":\"\"}'::jsonb)")" = '' ] || { echo "全 false 的摘要不是空串"; exit 1; }
[ -n "$(psql_test -At -c "SELECT mcp_egress_override_digest('{\"allow_loopback\":true}'::jsonb)")" ] || { echo "打开回环后摘要为空"; exit 1; }
[ "$(psql_test -At -c "SELECT mcp_egress_override_digest('{\"allow_loopback\":true}'::jsonb) <> mcp_egress_override_digest('{\"allow_metadata\":true}'::jsonb)")" = t ] || { echo "不同放行项摘要相同"; exit 1; }

# ---- 回滚（rollback/999，按段落）：跑两遍不报错；只回退 2.9.21 依赖的约束，表和列保留 ----
rollback="$repo_root/deploy/migrations/rollback/999_protection_settings.sql"
psql_test -q -f "$rollback" >/dev/null
psql_test -q -f "$rollback" >/dev/null
# 批次 1：红线回到两档，off/record 的存量行折成 alert（2.9.21 的缺省）；防护项表与新增列保留。
[ "$(psql_test -At -c "SELECT string_agg(rule_name || '=' || action, ',' ORDER BY rule_name) FROM mcp_redline_settings")" = 'r_alert=alert,r_block=block,r_off=alert,r_record=alert' ] || { echo "回滚后红线存量行不对"; exit 1; }
expect_fail "INSERT INTO mcp_redline_settings VALUES ('t1','r_off2','off')"
[ "$(psql_test -At -c "SELECT count(*) FROM protection_settings")" -ge 1 ] || { echo "回滚不应删防护项表"; exit 1; }
[ "$(psql_test -At -c "SELECT count(*) FROM information_schema.columns WHERE table_schema='$schema' AND column_name IN ('egress_overrides','approved_poison_flags','restricted_file_scopes_json')")" = 4 ] || { echo "回滚不应删新增列"; exit 1; }
# 2B：确认约束以 NOT VALID 恢复，存量的租户范围/所有协议确认行不动（2.9.21 的有效策略 SQL 跳过它们），新写入照 2.9.21 拦。
[ "$(psql_test -At -c "SELECT convalidated FROM pg_constraint WHERE conrelid = 'agent_destructive_policies'::regclass AND conname = 'agent_destructive_policies_confirm_capability_check'")" = f ] || { echo "回滚后确认约束应以 NOT VALID 恢复"; exit 1; }
[ "$(psql_test -At -c "SELECT count(*) FROM agent_destructive_policies WHERE id IN ('c_tenant','c_app')")" = 2 ] || { echo "回滚不应删存量确认行"; exit 1; }
expect_fail "INSERT INTO agent_destructive_policies (id,scope_type,scope_ref,action,protocol) VALUES ('c_tenant2','tenant','','confirm','')"
expect_ok   "INSERT INTO agent_destructive_policies (id,scope_type,scope_ref,action,protocol) VALUES ('c_mcp2','agent','codex','confirm','mcp')"
# 回滚后再升级（999 幂等）。
psql_test -q -f "$migration" >/dev/null
[ "$(psql_test -At -c "SELECT count(*) FROM pg_constraint WHERE conrelid = 'agent_destructive_policies'::regclass AND conname = 'agent_destructive_policies_confirm_capability_check'")" = 0 ] || { echo "再升级后确认约束应再次删除"; exit 1; }

echo "test_999_protection_settings: ok"
