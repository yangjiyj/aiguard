#!/usr/bin/env bash
# deploy/tests/test_1002_1003_alert_case_store.sh
# 告警案件物化（1002 建表、1003 变更登记触发器、1004 口径版本表）的迁移测试。
# 仅供显式指定的、已按正式流程迁移到最新的可丢弃测试库使用；只写一个专用测试租户的行，结束时删掉。
# 测试会重跑 1002–1004；1006 改过 1003 建的同名触发器和函数，重跑 1003 会把它们降回旧定义，所以紧接着重跑
# 1006 恢复，退出时（含失败）再恢复一次，最后核对触发器定义摘要与 1008 记下的一致，不让目标库停在旧定义上。
# 用法：ALERT_CASE_STORE_TEST_DATABASE_URL=postgres://... bash deploy/tests/test_1002_1003_alert_case_store.sh
set -euo pipefail
: "${ALERT_CASE_STORE_TEST_DATABASE_URL:?请指定可丢弃测试库连接串}"
repo_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
store="$repo_root/deploy/migrations/1002_alert_case_store.sql"
triggers="$repo_root/deploy/migrations/1003_alert_case_dirty_triggers.sql"
version="$repo_root/deploy/migrations/1004_alert_case_store_version.sql"
restore="$repo_root/deploy/migrations/1006_alert_retention_dirty_triggers.sql"
digest_migration="$repo_root/deploy/migrations/1008_alert_case_trigger_digest.sql"
rollback_1003="$repo_root/deploy/migrations/rollback/1003_alert_case_dirty_triggers.sql"
psql_db() { psql -X "$ALERT_CASE_STORE_TEST_DATABASE_URL" -v ON_ERROR_STOP=1 -q "$@"; }
tenant="acs_mig_test_$$"
# 1008 的摘要函数与控制面完整性检查是同一段 SQL（Go 测试核对）。
grep -q "jjd_alert_case_trigger_digest" "$digest_migration" || { echo "1008 缺摘要函数"; exit 1; }
digest_ok() { psql_db -At -c "SELECT COALESCE((SELECT digest FROM alert_case_trigger_expected) = jjd_alert_case_trigger_digest(), FALSE)"; }
[ "$(digest_ok)" = t ] || { echo "测试库的登记触发器与 1008 记下的不一致：先按正式流程迁移到最新"; exit 1; }

# ---- 回滚说明：1006 改了 1003 的同名触发器，回滚 1003 必须连同 1006 一起，并写明顺序 ----
grep -q "rollback/1006" "$rollback_1003" || { echo "1003 回滚说明没写先执行 rollback/1006"; exit 1; }
grep -q "DELETE FROM schema_migrations WHERE version IN ('1003_alert_case_dirty_triggers.sql', '1006_alert_retention_dirty_triggers.sql')" "$rollback_1003" \
  || { echo "1003 回滚说明没写同时删 1003、1006 的迁移记录"; exit 1; }

cleanup() {
  psql_db -f "$restore" >/dev/null 2>&1 || true
  psql_db >/dev/null 2>&1 <<SQL || true
DELETE FROM audit_dispositions WHERE tenant_id='$tenant';
DELETE FROM security_events WHERE tenant_id='$tenant';
DELETE FROM alert_groups WHERE tenant_id='$tenant';
DELETE FROM access_content_logs WHERE tenant_id='$tenant';
DELETE FROM request_logs WHERE tenant_id='$tenant';
DELETE FROM internal_keys WHERE tenant_id='$tenant';
DELETE FROM projects WHERE tenant_id='$tenant';
DELETE FROM alert_case_dirty WHERE tenant_id='$tenant';
DELETE FROM alert_case_backfill WHERE tenant_id='$tenant';
DELETE FROM tenants WHERE id='$tenant';
SQL
}
trap cleanup EXIT

# ---- 静态检查：1002 只建新表和索引，1003 只建函数和触发器，都不改写现有表的数据 ----
grep -Eiq '^[[:space:]]*(UPDATE[[:space:]]|DELETE[[:space:]]+FROM|ALTER[[:space:]]+TABLE)' "$store" && { echo "1002 不应改动现有表"; exit 1; }
grep -Eiq '^[[:space:]]*(UPDATE[[:space:]]|DELETE[[:space:]]+FROM|ALTER[[:space:]]+TABLE|CREATE[[:space:]]+(UNIQUE[[:space:]]+)?INDEX)' "$triggers" && { echo "1003 不应改表或建索引"; exit 1; }

# ---- 重跑两遍不报错；之后重跑 1006 恢复到最新定义，下面的登记检查按升级后的实际定义做 ----
for _ in 1 2; do psql_db -f "$store" >/dev/null; psql_db -f "$triggers" >/dev/null; psql_db -f "$version" >/dev/null; done
[ "$(digest_ok)" = f ] || { echo "只重跑 1003 时摘要应与 1008 记下的不一致（控制面据此改走实时查询）"; exit 1; }
psql_db -f "$restore" >/dev/null
[ "$(digest_ok)" = t ] || { echo "重跑 1006 后摘要应恢复一致"; exit 1; }

count() { psql_db -At -c "SELECT count(*) FROM alert_case_dirty WHERE tenant_id='$tenant' AND kind='$1' AND ref='$2'"; }
reset() { psql_db -c "DELETE FROM alert_case_dirty WHERE tenant_id='$tenant'"; }
expect() { [ "$(count "$1" "$2")" -ge 1 ] || { echo "缺少待重算条目：$3"; exit 1; }; }
expect_none() { [ "$(psql_db -At -c "SELECT count(*) FROM alert_case_dirty WHERE tenant_id='$tenant'")" = 0 ] || { echo "不该登记却登记了：$1"; exit 1; }; }

psql_db <<SQL
INSERT INTO tenants(id,name,edition,status,is_test) VALUES('$tenant','$tenant','enterprise','active',TRUE);
INSERT INTO projects(id,tenant_id,name) VALUES('${tenant}_p','$tenant','应用');
INSERT INTO internal_keys(id,tenant_id,project_id,key_hash,key_prefix,name) VALUES('${tenant}_k','$tenant','${tenant}_p',md5('$tenant'),'sk','凭据');
INSERT INTO request_logs(id,request_id,tenant_id,project_id,session_id,environment_scope,created_at) VALUES('${tenant}_r','${tenant}_r','$tenant','${tenant}_p','s1','customer',now());
INSERT INTO alert_groups(id,tenant_id,group_key,status,severity,alert_type,title,first_seen_at,last_seen_at) VALUES('${tenant}_g','$tenant','${tenant}_g','open','high','content','组',now(),now());
SQL
expect key "${tenant}_k" "新增凭据"
expect group "${tenant}_g" "新增告警组"
reset

psql_db -c "INSERT INTO security_events(id,request_id,tenant_id,project_id,event_type,severity,action_taken,matched_summary) VALUES('${tenant}_e','${tenant}_r','$tenant','${tenant}_p','security_check','high','flag','{\"findings\":[{\"type\":\"pii\",\"category\":\"email\"}]}')"
expect event "${tenant}_e" "新增安全事件"
reset

psql_db -c "UPDATE security_events SET processed_at=now(), delivery='delivered' WHERE id='${tenant}_e'"
expect_none "安全事件的投递状态变化"
psql_db -c "UPDATE security_events SET alert_group_id='${tenant}_g' WHERE id='${tenant}_e'"
expect event "${tenant}_e" "安全事件换告警组"
reset

psql_db -c "UPDATE request_logs SET risk_state='risk', request_status='success' WHERE id='${tenant}_r'"
expect_none "请求记录的预算列与状态变化"
psql_db -c "UPDATE request_logs SET session_id='s2' WHERE id='${tenant}_r'"
expect request "${tenant}_r" "请求会话变化"
reset

psql_db -c "INSERT INTO access_content_logs(request_id,tenant_id,conversation_id,environment_scope) VALUES('${tenant}_r','$tenant','c1','customer')"
expect request "${tenant}_r" "已有告警的请求新增留存会话"
reset

psql_db -c "UPDATE alert_groups SET occurrence_count=occurrence_count+1, last_seen_at=now() WHERE id='${tenant}_g'"
expect_none "告警组计数变化"
psql_db -c "UPDATE alert_groups SET status='false_positive' WHERE id='${tenant}_g'"
expect group "${tenant}_g" "告警组状态变化"
reset

psql_db -c "UPDATE internal_keys SET name='改名' WHERE id='${tenant}_k'"
expect_none "凭据改名"
psql_db -c "UPDATE internal_keys SET traffic_class='evaluation' WHERE id='${tenant}_k'"
expect key "${tenant}_k" "凭据流量标记变化"
reset

psql_db <<SQL
INSERT INTO audit_dispositions(tenant_id,subject_type,subject_id,status) VALUES
 ('$tenant','security_event','${tenant}_e','resolved'),('$tenant','request','${tenant}_r','resolved'),
 ('$tenant','alert_case','ac1_00000000000000000000000000000000','resolved'),('$tenant','tool_call','x','resolved');
SQL
expect event "${tenant}_e" "事件处置"
expect request "${tenant}_r" "请求处置"
expect case "ac1_00000000000000000000000000000000" "案件处置"
[ "$(psql_db -At -c "SELECT count(*) FROM alert_case_dirty WHERE tenant_id='$tenant' AND ref='x'")" = 0 ] || { echo "工具调用处置不该登记"; exit 1; }
reset

psql_db -c "DELETE FROM security_events WHERE id='${tenant}_e'"
expect event "${tenant}_e" "删除安全事件"
expect group "${tenant}_g" "删除安全事件时登记原告警组"

[ "$(digest_ok)" = t ] || { echo "测完登记触发器不是最新定义"; exit 1; }
echo "test_1002_1003_alert_case_store: ok"
