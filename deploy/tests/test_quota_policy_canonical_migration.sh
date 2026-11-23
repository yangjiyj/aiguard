#!/usr/bin/env bash
set -euo pipefail
# 临时容器：打测试标签、先回收被杀掉的测试进程留下的孤儿容器，清理用 docker rm -f -v（见该库说明）。
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib/test-containers.sh"
jjd_test_reap_orphan_containers
jjd_test_container_labels quota-policy-canonical-migration

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
MIGRATION="$ROOT/deploy/migrations/827_quota_policy_money_micros.sql"
container="jjdguard-quota-827-$RANDOM-$$"
schema="quota_827_$RANDOM"_$$
partial_schema="quota_827_partial_$RANDOM"_$$

fail() {
  echo "FAIL: $*" >&2
  exit 1
}

cleanup() {
  docker rm -f -v "$container" >/dev/null 2>&1 || true
}
trap cleanup EXIT

command -v docker >/dev/null 2>&1 || fail "docker is required"
docker image inspect postgres:16-alpine >/dev/null 2>&1 || fail "postgres:16-alpine must already exist"
docker run "${JJD_TEST_CONTAINER_LABELS[@]}" --pull=never --rm -d --name "$container" -e POSTGRES_PASSWORD=test -e POSTGRES_DB=test postgres:16-alpine >/dev/null

for _ in $(seq 1 300); do
  if docker logs "$container" 2>&1 | grep -Fq "PostgreSQL init process complete"; then
    break
  fi
  sleep 0.1
done
for _ in $(seq 1 300); do
  if docker exec "$container" psql -X -U postgres -d test -tAc "SELECT 1" 2>/dev/null | grep -qx 1; then
    break
  fi
  sleep 0.1
done
docker exec "$container" psql -X -U postgres -d test -tAc "SELECT 1" 2>/dev/null | grep -qx 1 || fail "PostgreSQL did not become ready"

psql_base() {
  docker exec -i "$container" psql -X -v ON_ERROR_STOP=1 -U postgres -d test "$@"
}

psql_schema() {
  docker exec -e PGOPTIONS="-c search_path=$schema" -i "$container" psql -X -v ON_ERROR_STOP=1 -U postgres -d test "$@"
}

create_legacy_table() {
  psql_schema -q >/dev/null <<'SQL'
CREATE TABLE quota_policies (
  id VARCHAR(64) PRIMARY KEY,
  daily_budget_limit NUMERIC,
  monthly_budget_limit NUMERIC,
  daily_token_limit BIGINT,
  monthly_token_limit BIGINT,
  rpm_limit INTEGER,
  concurrency_limit INTEGER
);
SQL
}

expect_migration_failure() {
  local message="$1"
  local log
  log="$(mktemp)"
  if psql_schema -q <"$MIGRATION" >"$log" 2>&1; then
    rm -f "$log"
    fail "migration unexpectedly accepted unsafe legacy values"
  fi
  grep -Fq "$message" "$log" || {
    sed -n '1,120p' "$log" >&2
    rm -f "$log"
    fail "migration error did not identify $message"
  }
  rm -f "$log"
}

psql_base -q -c "CREATE SCHEMA $schema" >/dev/null
create_legacy_table
psql_schema -q >/dev/null <<'SQL'
INSERT INTO quota_policies
  (id, daily_budget_limit, monthly_budget_limit, daily_token_limit,
   monthly_token_limit, rpm_limit, concurrency_limit)
VALUES
  ('nulls', NULL, NULL, NULL, NULL, NULL, NULL),
  ('zero', 0, 0, 0, 0, 0, 0),
  ('positive', 12.345678, 98.765432, 123, 456, 60, 7),
  ('negative', -1, -2, -3, -4, -5, -6),
  ('not-a-number', 'NaN', '-Infinity', 1, 1, 1, 1),
  ('finite-overflow', 9007199254.740992, 1, 1, 1, 1, 1),
  ('infinity', 'Infinity', 1, 1, 1, 1, 1),
  ('monthly-overflow', 1, 9007199254.740992, 1, 1, 1, 1),
  ('daily-token-overflow', 1, 1, 9007199254740992, 1, 1, 1),
  ('monthly-token-overflow', 1, 1, 1, 9007199254740992, 1, 1);
SQL

expect_migration_failure "daily_budget_limit"
rolled_back_columns="$(psql_schema -tAc "SELECT COUNT(*) FROM information_schema.columns WHERE table_schema=current_schema() AND table_name='quota_policies' AND column_name='daily_budget_micros'")"
[[ "$rolled_back_columns" == "0" ]] || fail "failed migration did not roll back DDL"

psql_schema -q -c "UPDATE quota_policies SET daily_budget_limit=9007199254.740991 WHERE id='finite-overflow'" >/dev/null
expect_migration_failure "daily_budget_limit"
psql_schema -q -c "UPDATE quota_policies SET daily_budget_limit=0 WHERE id='infinity'" >/dev/null
expect_migration_failure "monthly_budget_limit"
psql_schema -q -c "UPDATE quota_policies SET monthly_budget_limit=9007199254.740991 WHERE id='monthly-overflow'" >/dev/null
expect_migration_failure "daily_token_limit"
psql_schema -q -c "UPDATE quota_policies SET daily_token_limit=9007199254740991 WHERE id='daily-token-overflow'" >/dev/null
expect_migration_failure "monthly_token_limit"
psql_schema -q -c "UPDATE quota_policies SET monthly_token_limit=9007199254740991 WHERE id='monthly-token-overflow'" >/dev/null

psql_schema -q <"$MIGRATION" >/dev/null

columns="$(psql_schema -tAc "
  SELECT COUNT(*)
  FROM information_schema.columns
  WHERE table_schema = current_schema()
    AND table_name = 'quota_policies'
    AND column_name IN (
      'daily_budget_micros','monthly_budget_micros',
      'daily_budget_blocked','monthly_budget_blocked',
      'daily_token_limit_canonical','monthly_token_limit_canonical',
      'daily_token_blocked','monthly_token_blocked',
      'rpm_limit_canonical','rpm_blocked',
      'concurrency_limit_canonical','concurrency_blocked',
      'quota_timezone'
    )
")"
[[ "$columns" == "13" ]] || fail "canonical column count=$columns"

actual="$(psql_schema -tAc "
  SELECT id || '=' ||
    COALESCE(daily_budget_micros::text, 'NULL') || ',' || daily_budget_blocked || '|' ||
    COALESCE(monthly_budget_micros::text, 'NULL') || ',' || monthly_budget_blocked || '|' ||
    COALESCE(daily_token_limit_canonical::text, 'NULL') || ',' || daily_token_blocked || '|' ||
    COALESCE(monthly_token_limit_canonical::text, 'NULL') || ',' || monthly_token_blocked || '|' ||
    COALESCE(rpm_limit_canonical::text, 'NULL') || ',' || rpm_blocked || '|' ||
    COALESCE(concurrency_limit_canonical::text, 'NULL') || ',' || concurrency_blocked || '|' ||
    quota_timezone
  FROM quota_policies
  ORDER BY id
")"

while IFS= read -r expected; do
  grep -Fqx "$expected" <<<"$actual" || fail "missing backfill row: $expected"
done <<'EXPECTED_ROWS'
finite-overflow=9007199254740991,false|1000000,false|1,false|1,false|1,false|1,false|Asia/Shanghai
negative=0,false|0,false|0,false|0,false|0,false|0,false|Asia/Shanghai
not-a-number=0,false|0,false|1,false|1,false|1,false|1,false|Asia/Shanghai
nulls=NULL,false|NULL,false|NULL,false|NULL,false|NULL,false|NULL,false|Asia/Shanghai
positive=12345678,false|98765432,false|123,false|456,false|60,false|7,false|Asia/Shanghai
zero=0,false|0,false|0,false|0,false|0,false|0,false|Asia/Shanghai
EXPECTED_ROWS

validated="$(psql_schema -tAc "
  SELECT COUNT(*)
  FROM pg_constraint
  WHERE conrelid='quota_policies'::regclass
    AND conname IN (
      'chk_quota_daily_budget_micros','chk_quota_monthly_budget_micros',
      'chk_quota_daily_token_canonical','chk_quota_monthly_token_canonical',
      'chk_quota_rpm_canonical','chk_quota_concurrency_canonical',
      'chk_quota_timezone_nonempty'
    )
    AND convalidated
")"
[[ "$validated" == "7" ]] || fail "validated constraint count=$validated"

psql_schema -q -c "
  UPDATE quota_policies
  SET daily_budget_micros=NULL, monthly_budget_micros=NULL,
      daily_token_limit_canonical=NULL, monthly_token_limit_canonical=NULL,
      rpm_limit_canonical=NULL, concurrency_limit_canonical=NULL,
      quota_timezone='UTC'
  WHERE id='positive'
" >/dev/null
psql_schema -q <"$MIGRATION" >/dev/null

second_run="$(psql_schema -tAc "
  SELECT COALESCE(daily_budget_micros::text,'NULL') || '|' ||
         COALESCE(monthly_budget_micros::text,'NULL') || '|' ||
         COALESCE(daily_token_limit_canonical::text,'NULL') || '|' ||
         COALESCE(monthly_token_limit_canonical::text,'NULL') || '|' ||
         COALESCE(rpm_limit_canonical::text,'NULL') || '|' ||
         COALESCE(concurrency_limit_canonical::text,'NULL') || '|' ||
         quota_timezone
  FROM quota_policies WHERE id='positive'
")"
[[ "$second_run" == "NULL|NULL|NULL|NULL|NULL|NULL|UTC" ]] || fail "second run overwrote explicit inheritance: $second_run"

expect_rejected() {
  local sql="$1"
  if psql_schema -q -c "$sql" >/dev/null 2>&1; then
    fail "constraint accepted invalid write: $sql"
  fi
}

expect_rejected "UPDATE quota_policies SET daily_budget_blocked=true,daily_budget_micros=0 WHERE id='zero'"
expect_rejected "UPDATE quota_policies SET monthly_budget_micros=-1 WHERE id='zero'"
expect_rejected "UPDATE quota_policies SET daily_token_blocked=true,daily_token_limit_canonical=0 WHERE id='zero'"
expect_rejected "UPDATE quota_policies SET monthly_token_limit_canonical=9007199254740992 WHERE id='zero'"
expect_rejected "UPDATE quota_policies SET rpm_limit_canonical=-1 WHERE id='zero'"
expect_rejected "UPDATE quota_policies SET concurrency_blocked=true,concurrency_limit_canonical=0 WHERE id='zero'"
expect_rejected "UPDATE quota_policies SET quota_timezone='' WHERE id='zero'"

schema="$partial_schema"
psql_base -q -c "CREATE SCHEMA $schema" >/dev/null
create_legacy_table
psql_schema -q >/dev/null <<'SQL'
ALTER TABLE quota_policies
  ADD COLUMN daily_budget_micros BIGINT,
  ADD COLUMN daily_token_limit_canonical BIGINT,
  ADD COLUMN rpm_limit_canonical INTEGER,
  ADD COLUMN quota_timezone VARCHAR(64) NOT NULL DEFAULT 'Asia/Shanghai';
INSERT INTO quota_policies
  (id, daily_budget_limit, monthly_budget_limit, daily_token_limit,
   monthly_token_limit, rpm_limit, concurrency_limit, quota_timezone)
VALUES ('partial', 7, 8, 10, 20, 30, 4, 'UTC');
SQL
psql_schema -q <"$MIGRATION" >/dev/null
partial="$(psql_schema -tAc "
  SELECT COALESCE(daily_budget_micros::text,'NULL') || '|' ||
         monthly_budget_micros || '|' ||
         COALESCE(daily_token_limit_canonical::text,'NULL') || '|' ||
         monthly_token_limit_canonical || '|' ||
         COALESCE(rpm_limit_canonical::text,'NULL') || '|' ||
         concurrency_limit_canonical || '|' || quota_timezone
  FROM quota_policies WHERE id='partial'
")"
[[ "$partial" == "NULL|8000000|NULL|20|NULL|4|UTC" ]] || fail "partial-column migration overwrote canonical state: $partial"

echo "PASS: quota policy canonical migration rejects unsafe overflow, preserves inheritance, and validates constraints"
