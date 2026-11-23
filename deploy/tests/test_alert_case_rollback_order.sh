#!/usr/bin/env bash
# deploy/tests/test_alert_case_rollback_order.sh
# 2.9.22 批次 7 迁移（1001–1006）的回滚顺序：依赖还在时回滚脚本必须拒绝执行，按说明的顺序则能执行完、
# 执行完安全事件照样写得进库。全部在一个事务里做、最后 ROLLBACK，不改动目标库。
# 用法：ALERT_CASE_STORE_TEST_DATABASE_URL=postgres://... bash deploy/tests/test_alert_case_rollback_order.sh
# （目标库须按正式流程迁移到最新）
set -euo pipefail
: "${ALERT_CASE_STORE_TEST_DATABASE_URL:?请指定已迁移到最新的测试库连接串}"
repo_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
rollback_dir="$repo_root/deploy/migrations/rollback"
body() { sed -e '/^BEGIN;$/d' -e '/^COMMIT;$/d' "$rollback_dir/$1"; }
run_in_rolled_back_tx() { { echo "BEGIN;"; cat; echo "ROLLBACK;"; } | psql -X "$ALERT_CASE_STORE_TEST_DATABASE_URL" -v ON_ERROR_STOP=1 -q 2>&1; }

expect_refused() {
  local name=$1 need=$2 out
  if out=$(body "$name" | run_in_rolled_back_tx); then
    echo "$name 在依赖还在时不应执行成功"; exit 1
  fi
  grep -q "$need" <<<"$out" || { echo "$name 拒绝时应提示先执行 $need：$out"; exit 1; }
}

# 依赖还在：单独回滚 1001（1006 的触发器还引用这些列）、1003（1006 还在）、1002（1003 的触发器还在往队列表写）都要拒绝。
expect_refused 1001_request_logs_retention_summary_columns.sql rollback/1006
expect_refused 1003_alert_case_dirty_triggers.sql rollback/1006
expect_refused 1002_alert_case_store.sql rollback/1003

# 运维常见用法是不带 ON_ERROR_STOP 的 psql -f：检查报错之后，后面的 DROP COLUMN 也不能执行，三列都要还在。
url=$ALERT_CASE_STORE_TEST_DATABASE_URL
budget_columns() { psql -X "$url" -At -c "SELECT count(*) FROM information_schema.columns WHERE table_schema=current_schema() AND table_name='request_logs' AND column_name IN ('risk_reasons','request_body_exists','response_body_exists')"; }
[ "$(budget_columns)" = 3 ] || { echo "测试库 request_logs 缺 1001 的预算列：先按正式流程迁移到最新"; exit 1; }
psql -X "$url" -q -f "$rollback_dir/1001_request_logs_retention_summary_columns.sql" >/dev/null 2>&1 || true
if [ "$(budget_columns)" != 3 ]; then
  # 恢复测试库（1001 只加可空列），再报错。
  psql -X "$url" -v ON_ERROR_STOP=1 -q -f "$repo_root/deploy/migrations/1001_request_logs_retention_summary_columns.sql" >/dev/null
  echo "不带 ON_ERROR_STOP 执行 rollback/1001 时，检查报错后仍删了预算列：回滚脚本要包在一个事务里"; exit 1
fi

# 按说明的顺序（1006 → 1003 → 1002 → 1001）能执行完，执行完安全事件照样写得进库。
tenant="rollback_order_test_$$"
{
  body 1006_alert_retention_dirty_triggers.sql
  body 1003_alert_case_dirty_triggers.sql
  body 1002_alert_case_store.sql
  body 1001_request_logs_retention_summary_columns.sql
  cat <<SQL
INSERT INTO tenants(id,name,edition,status,is_test) VALUES('$tenant','$tenant','enterprise','active',TRUE);
INSERT INTO projects(id,tenant_id,name) VALUES('${tenant}_p','$tenant','应用');
INSERT INTO request_logs(id,request_id,tenant_id,project_id,environment_scope,created_at) VALUES('${tenant}_r','${tenant}_r','$tenant','${tenant}_p','customer',now());
INSERT INTO security_events(id,request_id,tenant_id,project_id,event_type,severity,action_taken,matched_summary)
  VALUES('${tenant}_e','${tenant}_r','$tenant','${tenant}_p','security_check','high','flag','{"findings":[]}');
UPDATE security_events SET matched_summary='{"findings":[{"type":"pii"}]}' WHERE id='${tenant}_e';
SQL
} | run_in_rolled_back_tx >/dev/null || { echo "按顺序回滚后写入失败"; exit 1; }

echo "test_alert_case_rollback_order: ok"
