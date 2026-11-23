#!/usr/bin/env bash
# #4 migration 失败测试：迁移 SQL 执行失败或 checksum 不匹配时，
# migration-runner.sh 必须非零退出并拒绝继续（不留半迁移状态）。
# 不依赖真实 Postgres：用 fake psql_cmd 模拟。
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
RUNNER="$ROOT/deploy/lib/migration-runner.sh"

fail() { echo "[fail] $*" >&2; exit 1; }
[[ -f "$RUNNER" ]] || fail "missing runner: $RUNNER"
bash -n "$RUNNER" || fail "runner 语法错误"

WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT
MIGR="$WORK/migrations"; mkdir -p "$MIGR"

# 一个正常 SQL 迁移 + 一个会失败的 SQL 迁移
printf 'CREATE TABLE t1(id int);\n' >"$MIGR/001_ok.sql"
printf 'THIS IS BROKEN SQL;\n' >"$MIGR/002_bad.sql"

# fake psql：记录调用，对含 "BROKEN" 的输入返回失败
export PSQL_LOG="$WORK/psql.log"
serve_lock_holder() {
  local argument line lock_holder=0
  for argument in "$@"; do
    if [[ "$argument" == "MIGRATION_RUNNER_LOCK_HOLDER=1" ]]; then
      lock_holder=1
      break
    fi
  done
  [[ "$lock_holder" -eq 1 ]] || return 1
  while IFS= read -r line; do
    case "$line" in
      *pg_try_advisory_lock*) printf '%s\n' '__MIGRATION_RUNNER_LOCK_ACQUIRED__' ;;
      '\q') return 0 ;;
    esac
  done
  return 0
}

psql_cmd() {
  local argument input="" expect_sql=0
  if serve_lock_holder "$@"; then return 0; fi
  for argument in "$@"; do
    if [[ "$expect_sql" -eq 1 ]]; then
      input="$argument"
      break
    fi
    case "$argument" in -c|-tAc|-Atc|-tc|-Ac) expect_sql=1 ;; esac
  done
  if [[ -z "$input" ]]; then
    input="$(cat)"
  fi
  printf '%s\n' "$input" >>"$PSQL_LOG"
  if printf '%s' "$input" | grep -q 'BROKEN'; then
    echo "psql: ERROR: syntax error" >&2
    return 1
  fi
  return 0
}
export -f psql_cmd serve_lock_holder

# schema_migrations 探测会调 psql_cmd -tAc "SELECT to_regclass(...)"——fake 需对探测返回空（表不存在）
# 上面 psql_cmd 对探测语句返回 0 但无输出 → schema_migrations_exists 判否 → ensure 建表（CREATE 返回0）
# 然后 apply 001 成功，apply 002 (BROKEN) 返回 1 → runner 报 "migration failed at 002_bad.sql" 非零退出

set +e
timeout 10 bash "$RUNNER" --migrations-dir "$MIGR" >/tmp/mig.log 2>&1
rc=$?
set -e

[[ $rc -ne 0 ]] || fail "迁移含失败 SQL 时 runner 应非零退出，实际 rc=$rc"
grep -q "migration failed at 002_bad.sql" /tmp/mig.log || fail "未报 002 失败: $(cat /tmp/mig.log)"
[[ $rc -ne 124 ]] || fail "SQL failure test timed out in migration lock holder"
grep -q "THIS IS BROKEN SQL" "$PSQL_LOG" || fail "broken SQL did not reach fake psql"
echo '[ok] #4: SQL 执行失败时 runner 非零退出并定位失败文件'

# ===== checksum 不匹配 → exit 2 =====
# 模拟：001 已应用且记录了 checksum=X，但文件内容变了 → checksum mismatch
psql_cmd2() {
  # 同时处理参数形式（-tAc "SQL" 探测）和 stdin（apply 管道）
  local arg_sql="" input expect_sql=0
  if serve_lock_holder "$@"; then return 0; fi
  # 从参数里取最后一个看起来像 SQL 的串
  local a
  for a in "$@"; do
    if [[ "$expect_sql" -eq 1 ]]; then
      arg_sql="$a"
      break
    fi
    case "$a" in -c|-tAc|-Atc|-tc|-Ac) expect_sql=1 ;; esac
  done
  input=""
  if [[ -z "$arg_sql" ]]; then
    input="$(cat 2>/dev/null || true)"
  fi
  local combined="$arg_sql
$input"
  printf '%s\n' "$combined" >>"$PSQL_LOG"
  if printf '%s' "$combined" | grep -q "to_regclass('public.schema_migrations')"; then printf 'schema_migrations\n'; return 0; fi
  if printf '%s' "$combined" | grep -q "column_name = 'checksum'"; then printf '1\n'; return 0; fi
  if printf '%s' "$combined" | grep -q "FROM schema_migrations WHERE version = '001_ok.sql'"; then
    printf 'deadbeef0000000000000000000000000000000000000000000000000000bad\n'; return 0
  fi
  if printf '%s' "$combined" | grep -q "EXISTS (SELECT 1 FROM schema_migrations)"; then printf '0\n'; return 0; fi
  return 0
}
psql_cmd() { psql_cmd2 "$@"; }
export -f psql_cmd psql_cmd2 serve_lock_holder

set +e
timeout 10 bash "$RUNNER" --migrations-dir "$MIGR" >/tmp/mig2.log 2>&1
rc2=$?
set -e
[[ $rc2 -eq 2 ]] || fail "checksum 不匹配应 exit 2，实际 rc=$rc2"
grep -q "checksum mismatch" /tmp/mig2.log || fail "未报 checksum mismatch: $(cat /tmp/mig2.log)"
echo '[ok] #4: checksum 不匹配时 runner exit 2 拒绝继续'
[[ $rc2 -ne 124 ]] || fail "checksum mismatch test timed out in migration lock holder"
grep -q "FROM schema_migrations WHERE version = '001_ok.sql'" "$PSQL_LOG" || fail "checksum query did not reach fake psql"

echo '[ok] #4 migration 失败测试通过'
