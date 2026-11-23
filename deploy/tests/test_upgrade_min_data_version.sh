#!/usr/bin/env bash
# 单测最低数据版本闸门。fail() 桩必须与真实实现一致（exit 1），
# 因此每个用例放到子 shell 里跑。
set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../docker-compose" && pwd)"
FAILED=0

run_case() {
  local stub=$1
  (
    set -Eeuo pipefail
    fail() { echo "[error] $*" >&2; exit 1; }
    log()  { echo "$*"; }
    find_project_service_containers() { echo stub-postgres; }
    assert_container_matches_readonly_scope() { return 0; }
    source "$SCRIPT_DIR/../lib/migration-version.sh"
    CURRENT_STUB="$stub"
    docker() { printf '%s\n' "$CURRENT_STUB"; }
    eval "$(sed -n '/^validate_minimum_data_version() {/,/^}/p' $SCRIPT_DIR/upgrade-bundle.sh)"
    validate_minimum_data_version
  ) 2>&1
}

t() {
  local name="$1" stub="$2" want="$3" out rc
  out="$(run_case "$stub")"; rc=$?
  if [[ "$want" == pass && $rc -eq 0 ]]; then
    echo "ok   $name"
  elif [[ "$want" == fail && $rc -ne 0 ]]; then
    echo "ok   $name -> $(echo "$out" | head -1)"
  else
    echo "BAD  $name want=$want rc=$rc"; echo "     out=$out"; FAILED=1
  fi
}

test_non_default_database_credentials_are_loaded_before_probe() {
  local fixture output status
  fixture="$(mktemp -d)"
  cp "$SCRIPT_DIR/upgrade-bundle.sh" "$fixture/upgrade-bundle.sh"
  cp "$SCRIPT_DIR/upgrade-min-data-version" "$fixture/upgrade-min-data-version"
  cp "$SCRIPT_DIR/upgrade-bridge-target-version" "$fixture/upgrade-bridge-target-version"
  cp "$SCRIPT_DIR/tier1-topology.sh" "$fixture/tier1-topology.sh"
  printf 'POSTGRES_USER=newapi\nPOSTGRES_DB=newapi\n' >"$fixture/.env"
  set +e
  output="$(
    set -Eeuo pipefail
    cd "$fixture"
    source ./upgrade-bundle.sh
    log() { :; }
    find_project_service_containers() { printf '%s\n' stub-postgres; }
    assert_container_matches_readonly_scope() { return 0; }
    docker() {
      local args="$*"
      [[ "$args" == *'-U newapi'* && "$args" == *'-d newapi'* ]] || {
        printf 'wrong database identity: %s\n' "$args" >&2
        return 91
      }
      printf '%s\n' '831_workbuddy_product_identity_tasks.sql'
    }
    load_inherited_env
    validate_minimum_data_version
  )" 2>&1
  status=$?
  set -e
  rm -rf "$fixture"
  if [[ "$status" -ne 0 ]]; then
    echo "BAD  非默认数据库身份未传入版本闸门 rc=$status"
    echo "     out=$output"
    FAILED=1
  else
    echo 'ok   非默认数据库身份(newapi)传入版本闸门'
  fi
}

test_main_loads_database_env_before_version_gate() {
  local main_body load_line min_line
  main_body="$(sed -n '/^main() {/,/^}/p' "$SCRIPT_DIR/upgrade-bundle.sh")"
  load_line="$(printf '%s\n' "$main_body" | grep -n -E '^[[:space:]]*load_inherited_env[[:space:]]*$' | head -1 | cut -d: -f1)"
  min_line="$(printf '%s\n' "$main_body" | grep -n -E '^[[:space:]]*validate_minimum_data_version[[:space:]]*$' | head -1 | cut -d: -f1)"
  if [[ -z "$load_line" || -z "$min_line" || "$load_line" -ge "$min_line" ]]; then
    echo 'BAD  main 必须先加载继承配置再执行最低数据版本闸门'
    FAILED=1
  else
    echo 'ok   main 先加载继承配置再执行最低数据版本闸门'
  fi
}

t '低于桥接入口(076)必须拒绝'    '076_console_query_indexes.sql'           fail
t '恰好等于桥接入口(077)放行'    '077_request_logs_proxy_access_type_resolved.sql' pass
t '桥接范围(136)放行'            '136_something.sql'                       pass
t '恰好等于桥接目标(137)放行'    '137_enterprise_identity_department.sql'  pass
t '较新(145)放行'               '145_evidence_runs.sql'                   pass
t '生产实际水位(804)放行'        '804_billing_customer_group_ratio.sql'   pass
t '空水位必须拒绝'              ''                                        fail
t '早期环境(006)必须拒绝'        '006_tool_call_audit.sql'                fail
t '垃圾值必须拒绝'              'not-a-migration'                         fail
t '四位迁移水位(1000)放行'       '1000_future_contract.sql'                pass
test_non_default_database_credentials_are_loaded_before_probe
test_main_loads_database_env_before_version_gate
exit $FAILED
