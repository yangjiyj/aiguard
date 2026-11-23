#!/usr/bin/env bash
set -euo pipefail
# 临时容器：打测试标签、先回收被杀掉的测试进程留下的孤儿容器，清理用 docker rm -f -v（见该库说明）。
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib/test-containers.sh"
jjd_test_reap_orphan_containers
jjd_test_container_labels migration-runner

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
RUNNER="$ROOT_DIR/deploy/lib/migration-runner.sh"

assert_contains() {
  local haystack="$1"
  local needle="$2"
  if [[ "$haystack" != *"$needle"* ]]; then
    echo "expected output to contain: $needle" >&2
    echo "actual output:" >&2
    echo "$haystack" >&2
    exit 1
  fi
}

assert_not_contains() {
  local haystack="$1"
  local needle="$2"
  if [[ "$haystack" == *"$needle"* ]]; then
    echo "expected output not to contain: $needle" >&2
    echo "actual output:" >&2
    echo "$haystack" >&2
    exit 1
  fi
}

assert_equals() {
  local actual="$1"
  local expected="$2"
  if [[ "$actual" != "$expected" ]]; then
    echo "expected: $expected" >&2
    echo "actual:   $actual" >&2
    exit 1
  fi
}

assert_file_contains_normalized() {
  local file="$1"
  local needle="$2"
  local contents
  if [[ ! -f "$file" ]]; then
    echo "expected file to exist: $file" >&2
    exit 1
  fi
  contents="$(tr '\n' ' ' <"$file" | tr -s '[:space:]' ' ')"
  if [[ "$contents" != *"$needle"* ]]; then
    echo "expected $file to contain: $needle" >&2
    exit 1
  fi
}

assert_file_not_matches() {
  local file="$1"
  local pattern="$2"
  if [[ ! -f "$file" ]]; then
    echo "expected file to exist: $file" >&2
    exit 1
  fi
  if grep -Eiq "$pattern" "$file"; then
    echo "expected $file not to match: $pattern" >&2
    exit 1
  fi
}

make_fixture() {
  local dir="$1"
  mkdir -p "$dir/migrations" "$dir/bin" "$dir/db"

  cat >"$dir/migrations/001_init_schema.sql" <<'SQL'
CREATE TABLE IF NOT EXISTS tenants(id text PRIMARY KEY);
SQL
  cat >"$dir/migrations/002_seed_data.sql" <<'SQL'
INSERT INTO tenants(id) VALUES ('seed');
SQL
  cat >"$dir/migrations/003_private_deployment.sql" <<'SQL'
CREATE TABLE IF NOT EXISTS projects(id text PRIMARY KEY);
SQL
  cat >"$dir/migrations/070_alert_groups.sql" <<'SQL'
CREATE TABLE IF NOT EXISTS alert_groups(id text PRIMARY KEY);
SQL
  cat >"$dir/migrations/071_rollup_read_models.sql" <<'SQL'
CREATE TABLE IF NOT EXISTS rollup_read_models(id text PRIMARY KEY);
SQL
  cat >"$dir/migrations/072_outbox_events.sql" <<'SQL'
CREATE TABLE IF NOT EXISTS outbox_events(id text PRIMARY KEY);
SQL
  cat >"$dir/migrations/076_console_query_indexes.sql" <<'SQL'
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_projects_id ON projects(id);
SQL
  cat >"$dir/migrations/077_request_logs_proxy_access_type_resolved_verify.sql" <<'SQL'
SELECT 'verify only';
SQL
  cat >"$dir/migrations/080_self_transaction.sql" <<'SQL'
BEGIN;
CREATE TABLE IF NOT EXISTS self_transaction(id text PRIMARY KEY);
COMMIT;
SQL
  cat >"$dir/migrations/090_failure.sql" <<'SQL'
SELECT fail_migration();
SQL
  cp "$ROOT_DIR/deploy/migrations/114_model_routing_v2.sql" "$dir/migrations/114_model_routing_v2.sql"
  cp "$ROOT_DIR/deploy/migrations/115_request_logs_ttft.sql" "$dir/migrations/115_request_logs_ttft.sql"
  cp "$ROOT_DIR/deploy/migrations/116_explicit_model_routing.sql" "$dir/migrations/116_explicit_model_routing.sql"
  cp "$ROOT_DIR/deploy/migrations/120_identity_sources.sql" "$dir/migrations/120_identity_sources.sql"
  cp "$ROOT_DIR/deploy/migrations/121_identity_runtime_publications.sql" "$dir/migrations/121_identity_runtime_publications.sql"

  cat >"$dir/bin/fake-psql" <<'BASH'
#!/usr/bin/env bash
set -euo pipefail

DB_DIR="${FAKE_DB_DIR:?}"
STATE="$DB_DIR/schema_migrations.tsv"
LOG="$DB_DIR/psql.log"
mkdir -p "$DB_DIR"
  touch "$LOG"

sql=""
lock_holder=0
on_error_stop=0
args=()
while (($#)); do
  case "$1" in
    -c)
      shift
      sql="${1:-}"
      ;;
    -tAc|-Atc|-tc|-Ac)
      shift
      sql="${1:-}"
      ;;
    -v)
      shift
      if [[ "${1:-}" == "MIGRATION_RUNNER_LOCK_HOLDER=1" ]]; then
        lock_holder=1
      fi
      if [[ "${1:-}" == "ON_ERROR_STOP=1" ]]; then
        on_error_stop=1
      fi
      ;;
    -f)
      shift
      if [[ "${FAKE_PSQL_REJECT_FILE:-0}" == "1" ]]; then
        echo "ERROR: container psql cannot read host file ${1:-}" >&2
        exit 127
      fi
      sql="$(cat "${1:-}")"
      ;;
    *)
      args+=("$1")
      ;;
  esac
  shift || true
done

if [[ "$lock_holder" -eq 1 ]]; then
  lock_holder_pid_file="$DB_DIR/lock-holder.pid"
  printf '%s\n' "$$" >"$lock_holder_pid_file"
  trap 'rm -f "$lock_holder_pid_file"' EXIT
  while IFS= read -r line; do
    case "$line" in
      *pg_try_advisory_lock*)
        if [[ "${FAKE_PSQL_LOCK_ERROR:-0}" == "1" ]]; then
          echo "ERROR: intentional advisory lock query failure" >&2
          if [[ "$on_error_stop" -eq 1 ]]; then
            exit 7
          fi
        else
          printf '%s\n' "__MIGRATION_RUNNER_LOCK_ACQUIRED__"
        fi
        ;;
      '\q')
        exit 0
        ;;
    esac
  done
  exit 0
fi

if [[ -z "$sql" ]]; then
  sql="$(cat)"
fi

printf '%s\n---\n' "$sql" >>"$LOG"

if [[ "$sql" == *"fail_migration()"* ]]; then
  echo "ERROR: intentional migration failure" >&2
  exit 3
fi

has_schema_table() {
  [[ -f "$DB_DIR/schema_migrations.exists" || -f "$STATE" ]]
}

has_checksum_column() {
  [[ -f "$DB_DIR/schema_migrations.has_checksum" ]]
}

if [[ "$sql" == *"to_regclass('public.schema_migrations')"* ]]; then
  if has_schema_table; then
    printf '%s\n' "schema_migrations"
  fi
  exit 0
fi

if [[ "$sql" == *"information_schema.columns"* && "$sql" == *"table_name = 'schema_migrations'"* && "$sql" == *"column_name = 'checksum'"* ]]; then
  if has_checksum_column; then
    printf '%s\n' "1"
  fi
  exit 0
fi

if [[ "$sql" == *"to_regclass('public.tenants')"* && "$sql" == *"to_regclass('public.users')"* && "$sql" == *"to_regclass('public.projects')"* && "$sql" == *"to_regclass('public.request_logs')"* && "$sql" == *"to_regclass('public.audit_dispositions')"* && "$sql" == *"to_regclass('public.proxy_usage_logs')"* && "$sql" == *"to_regclass('public.ca_certificates')"* ]]; then
  if [[ -f "$DB_DIR/initdb_schema.exists" ]]; then
    printf '%s\n' "1"
  else
    printf '%s\n' "0"
  fi
  exit 0
fi

if [[ "$sql" == *"CREATE TABLE IF NOT EXISTS schema_migrations"* ]]; then
  touch "$DB_DIR/schema_migrations.exists" "$DB_DIR/schema_migrations.has_checksum" "$STATE"
fi

if [[ "$sql" == *"ALTER TABLE schema_migrations"* && "$sql" == *"ADD COLUMN IF NOT EXISTS checksum"* ]]; then
  if ! has_schema_table; then
    echo "ERROR: relation \"schema_migrations\" does not exist" >&2
    exit 1
  fi
  touch "$DB_DIR/schema_migrations.has_checksum" "$STATE"
fi

if [[ "$sql" == *"EXISTS (SELECT 1 FROM schema_migrations)"* ]]; then
  if ! has_schema_table; then
    echo "ERROR: relation \"schema_migrations\" does not exist" >&2
    exit 1
  fi
  if [[ -s "$STATE" ]]; then
    printf '%s\n' "0"
  else
    printf '%s\n' "1"
  fi
  exit 0
fi

if [[ "$sql" == *"SELECT 1 FROM schema_migrations WHERE version ="* ]]; then
  if ! has_schema_table; then
    echo "ERROR: relation \"schema_migrations\" does not exist" >&2
    exit 1
  fi
  version="$(printf '%s' "$sql" | sed -n "s/.*version = '\([^']*\)'.*/\1/p")"
  if [[ -f "$STATE" ]] && grep -Fq "${version}"$'\t' "$STATE"; then
    printf '%s\n' "1"
  fi
  exit 0
fi

if [[ "$sql" == *"FROM schema_migrations WHERE version ="* ]]; then
  if ! has_schema_table; then
    echo "ERROR: relation \"schema_migrations\" does not exist" >&2
    exit 1
  fi
  if [[ "$sql" == *"checksum"* ]] && ! has_checksum_column; then
    echo "ERROR: column \"checksum\" does not exist" >&2
    exit 1
  fi
  version="$(printf '%s' "$sql" | sed -n "s/.*version = '\([^']*\)'.*/\1/p")"
  if [[ -f "$STATE" ]] && grep -Fq "${version}"$'\t' "$STATE"; then
    checksum="$(grep -F "${version}"$'\t' "$STATE" | tail -1 | awk -F '\t' '{print $2}')"
    if [[ -n "$checksum" ]]; then
      printf '%s\n' "$checksum"
    else
      printf '%s\n' "__EMPTY_CHECKSUM__"
    fi
  fi
  exit 0
fi

if [[ "$sql" == *"SELECT version FROM schema_migrations"* ]]; then
  if ! has_schema_table; then
    echo "ERROR: relation \"schema_migrations\" does not exist" >&2
    exit 1
  fi
  if [[ -f "$STATE" ]]; then
    cut -f1 "$STATE"
  fi
  exit 0
fi

if [[ "$sql" == *"UPDATE schema_migrations SET checksum ="* ]]; then
  if ! has_schema_table; then
    echo "ERROR: relation \"schema_migrations\" does not exist" >&2
    exit 1
  fi
  if ! has_checksum_column; then
    echo "ERROR: column \"checksum\" does not exist" >&2
    exit 1
  fi
  version="$(printf '%s' "$sql" | sed -n "s/.*WHERE version = '\([^']*\)'.*/\1/p")"
  checksum="$(printf '%s' "$sql" | sed -n "s/.*SET checksum = '\([^']*\)'.*/\1/p")"
  tmp="$(mktemp)"
  awk -F '\t' -v version="$version" -v checksum="$checksum" 'BEGIN { OFS = FS } $1 == version { $2 = checksum } { print }' "$STATE" >"$tmp"
  mv "$tmp" "$STATE"
fi

if [[ "$sql" == *"INSERT INTO schema_migrations"* ]]; then
  if ! has_schema_table; then
    echo "ERROR: relation \"schema_migrations\" does not exist" >&2
    exit 1
  fi
  if [[ "$sql" == *"checksum"* ]] && ! has_checksum_column; then
    echo "ERROR: column \"checksum\" does not exist" >&2
    exit 1
  fi
  touch "$STATE"
  version="$(printf '%s' "$sql" | sed -n "s/.*VALUES ('\([^']*\)', '\([^']*\)'.*/\1/p")"
  checksum="$(printf '%s' "$sql" | sed -n "s/.*VALUES ('\([^']*\)', '\([^']*\)'.*/\2/p")"
  if [[ -n "$version" && -n "$checksum" ]] && ! grep -Fq "${version}"$'\t' "$STATE"; then
    printf '%s\t%s\n' "$version" "$checksum" >>"$STATE"
  fi
fi

BASH
  chmod +x "$dir/bin/fake-psql"
}

run_runner() {
  local fixture="$1"
  shift
  FAKE_DB_DIR="$fixture/db" \
    MIGRATION_PSQL="$fixture/bin/fake-psql" \
    bash "$RUNNER" --migrations-dir "$fixture/migrations" "$@"
}

run_runner_composelike() {
  local fixture="$1"
  shift
  FAKE_PSQL_REJECT_FILE=1 run_runner "$fixture" "$@"
}

applied_versions() {
  local fixture="$1"
  if [[ -f "$fixture/db/schema_migrations.tsv" ]]; then
    cut -f1 "$fixture/db/schema_migrations.tsv" | paste -sd ',' -
  fi
}

test_model_routing_v2_migration_contract() {
  local migration="$ROOT_DIR/deploy/migrations/114_model_routing_v2.sql"

  assert_file_contains_normalized "$migration" "ALTER TABLE routing_policies ADD COLUMN IF NOT EXISTS schema_version smallint NOT NULL DEFAULT 1, ADD COLUMN IF NOT EXISTS config_version bigint NOT NULL DEFAULT 1;"
  assert_file_contains_normalized "$migration" "CREATE UNIQUE INDEX IF NOT EXISTS uq_routing_v2_default ON routing_policies (tenant_id) WHERE schema_version = 2 AND scope_type = 'tenant' AND layer = 'provider';"
  assert_file_contains_normalized "$migration" "CREATE UNIQUE INDEX IF NOT EXISTS uq_routing_v2_override ON routing_policies (tenant_id, scope_ref) WHERE schema_version = 2 AND scope_type = 'model' AND layer = 'provider';"
  assert_file_contains_normalized "$migration" "DO \$\$ BEGIN IF NOT EXISTS ( SELECT 1 FROM pg_constraint WHERE conname = 'chk_routing_v2_scope_shape' AND conrelid = 'routing_policies'::regclass ) THEN ALTER TABLE routing_policies ADD CONSTRAINT chk_routing_v2_scope_shape CHECK ( schema_version <> 2 OR ( layer = 'provider' AND ( ( scope_type = 'tenant' AND scope_ref IS NOT NULL AND scope_ref = tenant_id ) OR ( scope_type = 'model' AND scope_ref IS NOT NULL AND btrim(scope_ref) <> '' ) ) ) ); END IF; END \$\$;"
  assert_file_not_matches "$migration" '(^|[[:space:]])UPDATE[[:space:]]'
}

test_explicit_model_routing_migration_contract() {
  local migration="$ROOT_DIR/deploy/migrations/116_explicit_model_routing.sql"

  assert_file_contains_normalized "$migration" "CREATE UNIQUE INDEX uq_providers_tenant_provider ON providers (tenant_id, id);"
  assert_file_contains_normalized "$migration" "RAISE EXCEPTION 'incompatible definition for index uq_providers_tenant_provider: %', pg_get_indexdef(index_oid);"
  assert_file_contains_normalized "$migration" "CONSTRAINT fk_model_route_baseline_provider FOREIGN KEY (tenant_id, provider_id) REFERENCES providers(tenant_id, id)"
  assert_file_contains_normalized "$migration" "PRIMARY KEY (tenant_id, model_name)"
  assert_file_contains_normalized "$migration" "CONSTRAINT chk_routing_v3_explicit_model CHECK ( schema_version <> 3 OR ( scope_type = 'model' AND scope_ref IS NOT NULL AND btrim(scope_ref) <> '' AND layer = 'provider' ) )"
  assert_file_contains_normalized "$migration" "CREATE UNIQUE INDEX uq_routing_v3_model ON routing_policies (tenant_id, scope_ref) WHERE schema_version = 3 AND scope_type = 'model' AND layer = 'provider';"
  assert_file_contains_normalized "$migration" "RAISE EXCEPTION 'incompatible definition for index uq_routing_v3_model: %', pg_get_indexdef(index_oid);"
  assert_file_contains_normalized "$migration" "pg_get_expr(i.indpred, i.indrelid)"
  assert_file_contains_normalized "$migration" "non-concurrent indexes run under the transactional migration runner"
  assert_file_not_matches "$migration" '(^|[[:space:]])(UPDATE|DELETE)[[:space:]]'
}

test_request_logs_ttft_migration_contract() {
  local migration="$ROOT_DIR/deploy/migrations/115_request_logs_ttft.sql"
  assert_file_contains_normalized "$migration" "ALTER TABLE request_logs ADD COLUMN IF NOT EXISTS upstream_ttft_ms bigint;"
  assert_file_contains_normalized "$migration" "CHECK (upstream_ttft_ms IS NULL OR upstream_ttft_ms >= 0) NOT VALID"
  assert_file_contains_normalized "$migration" "VALIDATE CONSTRAINT chk_request_logs_upstream_ttft_nonnegative"
  assert_file_contains_normalized "$migration" "CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_request_logs_route_metrics ON request_logs (tenant_id, created_at DESC, model_id, provider_id);"
}

test_reverse_proxy_private_egress_migration_contract() {
  local migration="$ROOT_DIR/deploy/migrations/119_reverse_proxy_private_egress.sql"

  assert_file_contains_normalized "$migration" "ALTER TABLE reverse_proxy_routes ADD COLUMN IF NOT EXISTS allow_private_egress BOOLEAN NOT NULL DEFAULT FALSE, ADD COLUMN IF NOT EXISTS private_egress_cidrs TEXT[] NOT NULL DEFAULT '{}'::TEXT[];"
  assert_file_contains_normalized "$migration" "CHECK (NOT allow_private_egress OR cardinality(private_egress_cidrs) > 0)"
  assert_file_contains_normalized "$migration" "COMMENT ON COLUMN reverse_proxy_routes.allow_private_egress IS"
  assert_file_contains_normalized "$migration" "COMMENT ON COLUMN reverse_proxy_routes.private_egress_cidrs IS"
}

test_reverse_proxy_private_egress_migration_with_postgresql() (
  local migration="$ROOT_DIR/deploy/migrations/119_reverse_proxy_private_egress.sql"
  local container ready legacy_value columns
  if ! command -v docker >/dev/null 2>&1 || ! docker info >/dev/null 2>&1 || ! docker image inspect postgres:16-alpine >/dev/null 2>&1; then
    echo "SKIP: reverse proxy private egress PostgreSQL integration test"
    return 0
  fi
  container="jjdguard-private-egress-$$-$RANDOM"
  trap 'docker rm -f -v "$container" >/dev/null 2>&1 || true' EXIT INT TERM
  docker run "${JJD_TEST_CONTAINER_LABELS[@]}" --rm -d --name "$container" -e POSTGRES_PASSWORD=test -e POSTGRES_DB=test postgres:16-alpine >/dev/null
  ready=0
  for _ in {1..60}; do
    if [[ "$(docker exec "$container" psql -U postgres -d test -tAc 'SELECT 1' 2>/dev/null)" == "1" ]]; then ready=1; break; fi
    sleep 1
  done
  assert_equals "$ready" "1"
  docker exec "$container" psql -v ON_ERROR_STOP=1 -U postgres -d test -c \
    "CREATE TABLE reverse_proxy_routes (id text PRIMARY KEY); INSERT INTO reverse_proxy_routes VALUES ('legacy');" >/dev/null
  docker exec -i "$container" psql -v ON_ERROR_STOP=1 -U postgres -d test <"$migration" >/dev/null
  docker exec -i "$container" psql -v ON_ERROR_STOP=1 -U postgres -d test <"$migration" >/dev/null
  legacy_value="$(docker exec "$container" psql -U postgres -d test -tAc "SELECT allow_private_egress::text || '|' || cardinality(private_egress_cidrs) FROM reverse_proxy_routes WHERE id='legacy'")"
  columns="$(docker exec "$container" psql -U postgres -d test -tAc "SELECT count(*) FROM information_schema.columns WHERE table_name='reverse_proxy_routes' AND column_name IN ('allow_private_egress','private_egress_cidrs')")"
  assert_equals "$legacy_value" "false|0"
  assert_equals "$columns" "2"
  if docker exec "$container" psql -v ON_ERROR_STOP=1 -U postgres -d test -c \
    "UPDATE reverse_proxy_routes SET allow_private_egress=TRUE, private_egress_cidrs='{}'::text[] WHERE id='legacy';" >/dev/null 2>&1; then
    echo "expected empty private egress CIDRs to be rejected" >&2
    exit 1
  fi
  docker exec "$container" psql -v ON_ERROR_STOP=1 -U postgres -d test -c \
    "UPDATE reverse_proxy_routes SET allow_private_egress=TRUE, private_egress_cidrs=ARRAY['172.16.20.17/32'] WHERE id='legacy';" >/dev/null
)

test_reverse_proxy_private_egress_is_discovered_and_recorded() {
  local fixture first second
  fixture="$(mktemp -d)"
  make_fixture "$fixture"
  cp "$ROOT_DIR/deploy/migrations/119_reverse_proxy_private_egress.sql" "$fixture/migrations/119_reverse_proxy_private_egress.sql"
  local -a exclusions=(
    --exclude 001_init_schema.sql --exclude 003_private_deployment.sql
    --exclude 070_alert_groups.sql --exclude 071_rollup_read_models.sql --exclude 072_outbox_events.sql
    --exclude 076_console_query_indexes.sql --exclude 080_self_transaction.sql --exclude 090_failure.sql
    --exclude 114_model_routing_v2.sql --exclude 115_request_logs_ttft.sql --exclude 116_explicit_model_routing.sql --exclude 120_identity_sources.sql --exclude 121_identity_runtime_publications.sql
  )
  first="$(run_runner "$fixture" "${exclusions[@]}" 2>&1)"
  second="$(run_runner "$fixture" "${exclusions[@]}" 2>&1)"
  assert_contains "$first" "[apply] 119_reverse_proxy_private_egress.sql"
  assert_contains "$second" "[skip] 119_reverse_proxy_private_egress.sql (already applied)"
  assert_equals "$(applied_versions "$fixture")" "119_reverse_proxy_private_egress.sql"
}

test_request_logs_ttft_migration_with_postgresql() (
  local migration="$ROOT_DIR/deploy/migrations/115_request_logs_ttft.sql"
  local container ready value validated index_valid
  if ! command -v docker >/dev/null 2>&1 || ! docker info >/dev/null 2>&1 || ! docker image inspect postgres:16-alpine >/dev/null 2>&1; then
    echo "SKIP: request_logs TTFT PostgreSQL integration test"
    return 0
  fi
  container="jjdguard-ttft-$$-$RANDOM"
  trap 'docker rm -f -v "$container" >/dev/null 2>&1 || true' EXIT INT TERM
  docker run "${JJD_TEST_CONTAINER_LABELS[@]}" --rm -d --name "$container" -e POSTGRES_PASSWORD=test -e POSTGRES_DB=test postgres:16-alpine >/dev/null
  ready=0
  for _ in {1..60}; do
    if [[ "$(docker exec "$container" psql -U postgres -d test -tAc 'SELECT 1' 2>/dev/null)" == "1" ]]; then ready=1; break; fi
    sleep 1
  done
  assert_equals "$ready" "1"
  docker exec "$container" psql -v ON_ERROR_STOP=1 -U postgres -d test -c "CREATE TABLE request_logs (id text PRIMARY KEY, tenant_id text NOT NULL, created_at timestamptz NOT NULL, model_id text, provider_id text);" >/dev/null
  docker exec -i "$container" psql -v ON_ERROR_STOP=1 -U postgres -d test <"$migration" >/dev/null
  docker exec -i "$container" psql -v ON_ERROR_STOP=1 -U postgres -d test <"$migration" >/dev/null
  docker exec "$container" psql -v ON_ERROR_STOP=1 -U postgres -d test -c "INSERT INTO request_logs VALUES ('ok','t',NOW(),'m','p',123);" >/dev/null
  value="$(docker exec "$container" psql -U postgres -d test -tAc "SELECT upstream_ttft_ms FROM request_logs WHERE id='ok'")"
  assert_equals "$value" "123"
  validated="$(docker exec "$container" psql -U postgres -d test -tAc "SELECT convalidated FROM pg_constraint WHERE conname='chk_request_logs_upstream_ttft_nonnegative'")"
  index_valid="$(docker exec "$container" psql -U postgres -d test -tAc "SELECT i.indisvalid AND i.indisready FROM pg_index i JOIN pg_class c ON c.oid=i.indexrelid WHERE c.relname='idx_request_logs_route_metrics'")"
  assert_equals "$validated" "t"
  assert_equals "$index_valid" "t"
  if docker exec "$container" psql -v ON_ERROR_STOP=1 -U postgres -d test -c "INSERT INTO request_logs VALUES ('bad','t',NOW(),'m','p',-1);" >/dev/null 2>&1; then
    echo "expected negative upstream_ttft_ms to be rejected" >&2; exit 1
  fi
)

test_request_logs_ttft_runs_without_outer_transaction() {
	local fixture output log
	fixture="$(mktemp -d)"; make_fixture "$fixture"
	output="$(run_runner "$fixture" --exclude 001_init_schema.sql --exclude 003_private_deployment.sql --exclude 070_alert_groups.sql --exclude 071_rollup_read_models.sql --exclude 072_outbox_events.sql --exclude 076_console_query_indexes.sql --exclude 080_self_transaction.sql --exclude 090_failure.sql --exclude 114_model_routing_v2.sql --exclude 116_explicit_model_routing.sql --exclude 120_identity_sources.sql --exclude 121_identity_runtime_publications.sql 2>&1)"
	assert_contains "$output" "[apply] 115_request_logs_ttft.sql"
	log="$(cat "$fixture/db/psql.log")"
	assert_contains "$log" "CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_request_logs_route_metrics"
	assert_not_contains "$log" "BEGIN;"
}

test_unique_concurrent_index_runs_without_outer_transaction() {
  local fixture output log
  fixture="$(mktemp -d)"
  make_fixture "$fixture"
  rm -f "$fixture/migrations/"*.sql
  cat >"$fixture/migrations/078_unique_concurrent.sql" <<'SQL'
CREATE UNIQUE INDEX CONCURRENTLY uq_projects_id ON projects(id);
SQL

  output="$(run_runner "$fixture" 2>&1)"
  assert_contains "$output" "[apply] 078_unique_concurrent.sql"
  assert_contains "$output" "[ok] applied=1 skipped=0"
  log="$(cat "$fixture/db/psql.log")"
  assert_contains "$log" "CREATE UNIQUE INDEX CONCURRENTLY uq_projects_id"
  assert_not_contains "$log" "BEGIN;"
}

test_no_transaction_directive_runs_outside_outer_transaction() {
  local fixture output log
  fixture="$(mktemp -d)"
  make_fixture "$fixture"
  rm -f "$fixture/migrations/"*.sql
  cat >"$fixture/migrations/150_marked_no_transaction.sql" <<'SQL'
-- +goose Up
-- +goose NO TRANSACTION
CREATE TABLE marked_no_transaction(id text PRIMARY KEY);
SQL

  output="$(run_runner "$fixture" 2>&1)"
  assert_contains "$output" "[apply] 150_marked_no_transaction.sql"
  assert_contains "$output" "[ok] applied=1 skipped=0"
  assert_equals "$(applied_versions "$fixture")" "150_marked_no_transaction.sql"
  log="$(cat "$fixture/db/psql.log")"
  assert_contains "$log" "CREATE TABLE marked_no_transaction"
  assert_not_contains "$log" "BEGIN;"
}

test_no_transaction_failure_is_not_recorded() {
  local fixture output status log
  fixture="$(mktemp -d)"
  make_fixture "$fixture"
  rm -f "$fixture/migrations/"*.sql
  cat >"$fixture/migrations/150_marked_no_transaction_failure.sql" <<'SQL'
-- +goose Up
-- +goose NO TRANSACTION
CREATE TABLE marked_no_transaction_failure(id text PRIMARY KEY);
SELECT fail_migration();
SQL

  set +e
  output="$(run_runner "$fixture" 2>&1)"
  status=$?
  set -e

  assert_equals "$status" "3"
  assert_contains "$output" "[error] migration failed at 150_marked_no_transaction_failure.sql"
  assert_equals "$(applied_versions "$fixture")" ""
  log="$(cat "$fixture/db/psql.log")"
  assert_not_contains "$log" "INSERT INTO schema_migrations"
}

test_no_transaction_directive_is_statement_atomic_with_postgresql() (
  local fixture container ready output status table_exists rows recorded
  if ! command -v docker >/dev/null 2>&1 \
    || ! docker info >/dev/null 2>&1 \
    || ! docker image inspect postgres:16-alpine >/dev/null 2>&1; then
    echo "SKIP: no-transaction PostgreSQL integration test"
    return 0
  fi

  fixture="$(mktemp -d)"
  mkdir -p "$fixture/bin" "$fixture/migrations"
  cat >"$fixture/migrations/150_no_transaction_atomic.sql" <<'SQL'
-- +goose Up
-- +goose NO TRANSACTION
CREATE TABLE no_transaction_steps(id integer PRIMARY KEY);
INSERT INTO no_transaction_steps(id) VALUES (1);
SELECT 1 / 0;
SQL

  container="jjdguard-no-transaction-$$-$RANDOM"
  trap 'docker rm -f -v "$container" >/dev/null 2>&1 || true' EXIT INT TERM
  docker run "${JJD_TEST_CONTAINER_LABELS[@]}" --rm -d --name "$container" \
    -e POSTGRES_PASSWORD=test \
    -e POSTGRES_DB=test \
    postgres:16-alpine >/dev/null

  ready=0
  for _ in {1..60}; do
    if [[ "$(docker exec "$container" psql -U postgres -d test -tAc 'SELECT 1' 2>/dev/null)" == "1" ]]; then
      ready=1
      break
    fi
    sleep 0.25
  done
  assert_equals "$ready" "1"

  cat >"$fixture/bin/psql" <<BASH
#!/usr/bin/env bash
set -euo pipefail
exec docker exec -i "$container" psql -U postgres -d test "\$@"
BASH
  chmod +x "$fixture/bin/psql"

  set +e
  output="$(MIGRATION_PSQL="$fixture/bin/psql" bash "$RUNNER" --migrations-dir "$fixture/migrations" 2>&1)"
  status=$?
  set -e

  assert_equals "$status" "3"
  assert_contains "$output" "[error] migration failed at 150_no_transaction_atomic.sql"
  table_exists="$(docker exec "$container" psql -U postgres -d test -tAc "SELECT CASE WHEN to_regclass('public.no_transaction_steps') IS NULL THEN 'f' ELSE 't' END")"
  rows="$(docker exec "$container" psql -U postgres -d test -tAc "SELECT count(*) FROM no_transaction_steps")"
  recorded="$(docker exec "$container" psql -U postgres -d test -tAc "SELECT count(*) FROM schema_migrations WHERE version = '150_no_transaction_atomic.sql'")"
  assert_equals "$table_exists" "t"
  assert_equals "$rows" "1"
  assert_equals "$recorded" "0"
)

test_unmarked_migration_remains_transactional() {
  local fixture output log
  fixture="$(mktemp -d)"
  make_fixture "$fixture"
  rm -f "$fixture/migrations/"*.sql
  cat >"$fixture/migrations/149_transactional.sql" <<'SQL'
CREATE TABLE transactional_migration(id text PRIMARY KEY);
SQL

  output="$(run_runner "$fixture" 2>&1)"
  assert_contains "$output" "[apply] 149_transactional.sql"
  assert_equals "$(applied_versions "$fixture")" "149_transactional.sql"
  log="$(cat "$fixture/db/psql.log")"
  assert_contains "$log" "BEGIN;"
  assert_contains "$log" "INSERT INTO schema_migrations"
  assert_contains "$log" "COMMIT;"
}

test_lock_query_error_fails_bounded_and_releases_holder() {
  local fixture output status retry_output retry_status
  fixture="$(mktemp -d)"
  make_fixture "$fixture"

  set +e
  output="$(timeout 3 env \
    FAKE_PSQL_LOCK_ERROR=1 \
    FAKE_DB_DIR="$fixture/db" \
    MIGRATION_PSQL="$fixture/bin/fake-psql" \
    bash "$RUNNER" --migrations-dir "$fixture/migrations" --exclude 090_failure.sql 2>&1)"
  status=$?
  set -e

  [[ "$status" -ne 0 && "$status" -ne 124 ]] || {
    echo "advisory lock query error did not fail in bounded time: status=$status output=$output" >&2
    exit 1
  }
  assert_contains "$output" "intentional advisory lock query failure"
  [[ ! -e "$fixture/db/lock-holder.pid" ]] || {
    echo "advisory lock holder remained after query failure" >&2
    exit 1
  }

  set +e
  # 这里验证的是“锁释放后重试能成功”，不是速度；慢一些的构建机上整套夹具迁移要 6 秒左右。
  retry_output="$(timeout 30 env FAKE_DB_DIR="$fixture/db" MIGRATION_PSQL="$fixture/bin/fake-psql" \
    bash "$RUNNER" --migrations-dir "$fixture/migrations" --exclude 090_failure.sql 2>&1)"
  retry_status=$?
  set -e
  assert_equals "$retry_status" "0"
  assert_contains "$retry_output" "[ok]"
}

test_model_routing_v2_migration_with_postgresql() (
  local migration="$ROOT_DIR/deploy/migrations/114_model_routing_v2.sql"
  local container old_schema_version ready v2_count

  if ! command -v docker >/dev/null 2>&1 \
    || ! docker info >/dev/null 2>&1 \
    || ! docker image inspect postgres:16-alpine >/dev/null 2>&1; then
    echo "SKIP: PostgreSQL integration test (docker daemon or local postgres:16-alpine image unavailable)"
    return 0
  fi

  container="jjdguard-routing-v2-$$-$RANDOM"
  cleanup_postgresql() {
    docker rm -f -v "$container" >/dev/null 2>&1 || true
  }
  trap cleanup_postgresql EXIT INT TERM

  docker run "${JJD_TEST_CONTAINER_LABELS[@]}" --rm -d --name "$container" \
    -e POSTGRES_PASSWORD=test \
    -e POSTGRES_DB=test \
    postgres:16-alpine >/dev/null

  ready=0
  for _ in {1..60}; do
    if docker logs "$container" 2>&1 | grep -Fq 'PostgreSQL init process complete; ready for start up.' \
      && [[ "$(docker exec "$container" psql -v ON_ERROR_STOP=1 -U postgres -d test -tAc 'SELECT 1' 2>/dev/null)" == "1" ]]; then
      ready=1
      break
    fi
    sleep 1
  done
  assert_equals "$ready" "1"

  docker exec "$container" psql -v ON_ERROR_STOP=1 -U postgres -d test -c \
    "CREATE TABLE routing_policies (id bigserial PRIMARY KEY, tenant_id text NOT NULL, scope_type text NOT NULL, scope_ref text, layer text NOT NULL); INSERT INTO routing_policies (tenant_id, scope_type, scope_ref, layer) VALUES ('legacy-tenant', 'tenant', NULL, 'provider');" \
    >/dev/null

  docker exec -i "$container" psql -v ON_ERROR_STOP=1 -U postgres -d test <"$migration" >/dev/null
  docker exec -i "$container" psql -v ON_ERROR_STOP=1 -U postgres -d test <"$migration" >/dev/null

  old_schema_version="$(docker exec "$container" psql -v ON_ERROR_STOP=1 -U postgres -d test -tAc "SELECT schema_version FROM routing_policies WHERE tenant_id = 'legacy-tenant'")"
  assert_equals "$old_schema_version" "1"

  assert_pg_rejects() {
    local sql="$1"
    if docker exec "$container" psql -v ON_ERROR_STOP=1 -U postgres -d test -c "$sql" >/dev/null 2>&1; then
      echo "expected PostgreSQL to reject: $sql" >&2
      exit 1
    fi
  }

  assert_pg_constraint_rejects() {
    local sql="$1"
    local output
    if output="$(docker exec "$container" psql -v ON_ERROR_STOP=1 -U postgres -d test -c "$sql" 2>&1)"; then
      echo "expected PostgreSQL constraint rejection: $sql" >&2
      exit 1
    fi
    assert_contains "$output" 'chk_routing_v2_scope_shape'
  }

  docker exec "$container" psql -v ON_ERROR_STOP=1 -U postgres -d test -c \
    "INSERT INTO routing_policies (tenant_id, scope_type, scope_ref, layer, schema_version) VALUES ('tenant-a', 'tenant', 'tenant-a', 'provider', 2);" \
    >/dev/null
  assert_pg_rejects "INSERT INTO routing_policies (tenant_id, scope_type, scope_ref, layer, schema_version) VALUES ('tenant-a', 'tenant', 'tenant-a', 'provider', 2);"
  assert_pg_constraint_rejects "INSERT INTO routing_policies (tenant_id, scope_type, scope_ref, layer, schema_version) VALUES ('tenant-wrong-ref', 'tenant', 'different-tenant', 'provider', 2);"
  assert_pg_constraint_rejects "INSERT INTO routing_policies (tenant_id, scope_type, scope_ref, layer, schema_version) VALUES ('tenant-null-ref', 'tenant', NULL, 'provider', 2);"
  assert_pg_constraint_rejects "INSERT INTO routing_policies (tenant_id, scope_type, scope_ref, layer, schema_version) VALUES ('model-null-ref', 'model', NULL, 'provider', 2);"
  assert_pg_constraint_rejects "INSERT INTO routing_policies (tenant_id, scope_type, scope_ref, layer, schema_version) VALUES ('model-empty-ref', 'model', '   ', 'provider', 2);"

  docker exec "$container" psql -v ON_ERROR_STOP=1 -U postgres -d test -c \
    "INSERT INTO routing_policies (tenant_id, scope_type, scope_ref, layer, schema_version) VALUES ('tenant-a', 'model', 'model-a', 'provider', 2), ('tenant-a', 'model', 'model-b', 'provider', 2);" \
    >/dev/null
  assert_pg_rejects "INSERT INTO routing_policies (tenant_id, scope_type, scope_ref, layer, schema_version) VALUES ('tenant-a', 'model', 'model-a', 'provider', 2);"

  v2_count="$(docker exec "$container" psql -v ON_ERROR_STOP=1 -U postgres -d test -tAc "SELECT count(*) FROM routing_policies WHERE schema_version = 2")"
  assert_equals "$v2_count" "3"
)

test_empty_database_applies_all_discovered_migrations() {
  local fixture
  fixture="$(mktemp -d)"
  make_fixture "$fixture"

  output="$(run_runner "$fixture" --exclude 090_failure.sql 2>&1)"

  assert_contains "$output" "[apply] 001_init_schema.sql"
  assert_contains "$output" "[apply] 070_alert_groups.sql"
  assert_contains "$output" "[apply] 071_rollup_read_models.sql"
  assert_contains "$output" "[apply] 072_outbox_events.sql"
  assert_contains "$output" "[apply] 076_console_query_indexes.sql"
  assert_contains "$output" "[apply] 114_model_routing_v2.sql"
  assert_contains "$output" "[apply] 115_request_logs_ttft.sql"
  assert_contains "$output" "[apply] 116_explicit_model_routing.sql"
  assert_contains "$output" "[apply] 120_identity_sources.sql"
  assert_contains "$output" "[apply] 121_identity_runtime_publications.sql"
  assert_contains "$output" "[ok] applied=12 skipped=0"
  assert_not_contains "$output" "002_seed_data.sql"
  assert_not_contains "$output" "077_request_logs_proxy_access_type_resolved_verify.sql"
  assert_equals "$(applied_versions "$fixture")" "001_init_schema.sql,003_private_deployment.sql,070_alert_groups.sql,071_rollup_read_models.sql,072_outbox_events.sql,076_console_query_indexes.sql,080_self_transaction.sql,114_model_routing_v2.sql,115_request_logs_ttft.sql,116_explicit_model_routing.sql,120_identity_sources.sql,121_identity_runtime_publications.sql"
}

test_latest_database_rerun_is_noop() {
  local fixture first second
  fixture="$(mktemp -d)"
  make_fixture "$fixture"

  first="$(run_runner "$fixture" --exclude 090_failure.sql 2>&1)"
  second="$(run_runner "$fixture" --exclude 090_failure.sql 2>&1)"

  assert_contains "$first" "[apply] 114_model_routing_v2.sql"
  assert_contains "$first" "[ok] applied=12 skipped=0"
  assert_contains "$second" "[ok] applied=0 skipped=12"
  assert_contains "$second" "[skip] 070_alert_groups.sql (already applied)"
  assert_contains "$second" "[skip] 114_model_routing_v2.sql (already applied)"
  assert_contains "$second" "[skip] 115_request_logs_ttft.sql (already applied)"
  assert_contains "$second" "[skip] 116_explicit_model_routing.sql (already applied)"
  assert_contains "$second" "[skip] 120_identity_sources.sql (already applied)"
  assert_contains "$second" "[skip] 121_identity_runtime_publications.sql (already applied)"
  assert_equals "$(applied_versions "$fixture")" "001_init_schema.sql,003_private_deployment.sql,070_alert_groups.sql,071_rollup_read_models.sql,072_outbox_events.sql,076_console_query_indexes.sql,080_self_transaction.sql,114_model_routing_v2.sql,115_request_logs_ttft.sql,116_explicit_model_routing.sql,120_identity_sources.sql,121_identity_runtime_publications.sql"
}

test_middle_database_only_applies_missing_rollup_migrations() {
  local fixture output
  fixture="$(mktemp -d)"
  make_fixture "$fixture"

  touch "$fixture/db/schema_migrations.exists" "$fixture/db/schema_migrations.has_checksum"
  printf '%s\t%s\n' \
    "001_init_schema.sql" "$(sha256sum "$fixture/migrations/001_init_schema.sql" | awk '{print $1}')" \
    "003_private_deployment.sql" "$(sha256sum "$fixture/migrations/003_private_deployment.sql" | awk '{print $1}')" \
    >"$fixture/db/schema_migrations.tsv"

  output="$(run_runner "$fixture" --exclude 076_console_query_indexes.sql --exclude 080_self_transaction.sql --exclude 090_failure.sql 2>&1)"

  assert_contains "$output" "[skip] 001_init_schema.sql (already applied)"
  assert_contains "$output" "[apply] 070_alert_groups.sql"
  assert_contains "$output" "[apply] 071_rollup_read_models.sql"
  assert_contains "$output" "[apply] 072_outbox_events.sql"
  assert_contains "$output" "[apply] 114_model_routing_v2.sql"
  assert_contains "$output" "[ok] applied=8 skipped=2"
  assert_equals "$(applied_versions "$fixture")" "001_init_schema.sql,003_private_deployment.sql,070_alert_groups.sql,071_rollup_read_models.sql,072_outbox_events.sql,114_model_routing_v2.sql,115_request_logs_ttft.sql,116_explicit_model_routing.sql,120_identity_sources.sql,121_identity_runtime_publications.sql"
}

test_legacy_version_row_backfills_checksum_without_rerun() {
  local fixture output expected_checksum actual_checksum
  fixture="$(mktemp -d)"
  make_fixture "$fixture"
  touch "$fixture/db/schema_migrations.exists" "$fixture/db/schema_migrations.has_checksum"
  printf '%s\t\n' "070_alert_groups.sql" >"$fixture/db/schema_migrations.tsv"

  output="$(run_runner "$fixture" --exclude 001_init_schema.sql --exclude 003_private_deployment.sql --exclude 071_rollup_read_models.sql --exclude 072_outbox_events.sql --exclude 076_console_query_indexes.sql --exclude 080_self_transaction.sql --exclude 090_failure.sql --exclude 114_model_routing_v2.sql --exclude 115_request_logs_ttft.sql --exclude 116_explicit_model_routing.sql --exclude 120_identity_sources.sql --exclude 121_identity_runtime_publications.sql 2>&1)"

  expected_checksum="$(sha256sum "$fixture/migrations/070_alert_groups.sql" | awk '{print $1}')"
  actual_checksum="$(awk -F '\t' '$1 == "070_alert_groups.sql" { print $2 }' "$fixture/db/schema_migrations.tsv")"
  assert_contains "$output" "[skip] 070_alert_groups.sql (legacy checksum recorded)"
  assert_contains "$output" "[ok] applied=0 skipped=1"
  assert_equals "$actual_checksum" "$expected_checksum"
}

test_checksum_mismatch_refuses_to_run() {
  local fixture output status
  fixture="$(mktemp -d)"
  make_fixture "$fixture"
  run_runner "$fixture" --exclude 090_failure.sql >/dev/null
  printf '\n-- tampered\n' >>"$fixture/migrations/070_alert_groups.sql"

  set +e
  output="$(run_runner "$fixture" --exclude 090_failure.sql 2>&1)"
  status=$?
  set -e

  assert_equals "$status" "2"
  assert_contains "$output" "[error] checksum mismatch for 070_alert_groups.sql"
  assert_not_contains "$output" "[apply] 071_rollup_read_models.sql"
}

test_failure_stops_at_failed_migration_and_keeps_previous_records() {
  local fixture output status
  fixture="$(mktemp -d)"
  make_fixture "$fixture"

  set +e
  output="$(run_runner "$fixture" --exclude 076_console_query_indexes.sql --exclude 080_self_transaction.sql 2>&1)"
  status=$?
  set -e

  assert_equals "$status" "3"
  assert_contains "$output" "[error] migration failed at 090_failure.sql"
  assert_equals "$(applied_versions "$fixture")" "001_init_schema.sql,003_private_deployment.sql,070_alert_groups.sql,071_rollup_read_models.sql,072_outbox_events.sql"
}

test_dry_run_prints_plan_without_db_changes() {
  local fixture output
  fixture="$(mktemp -d)"
  make_fixture "$fixture"

  output="$(run_runner "$fixture" --dry-run --exclude 090_failure.sql 2>&1)"

  assert_contains "$output" "[dry-run] 001_init_schema.sql"
  assert_contains "$output" "[dry-run] 072_outbox_events.sql"
  assert_contains "$output" "[dry-run] 114_model_routing_v2.sql"
  assert_contains "$output" "[dry-run] 115_request_logs_ttft.sql"
  assert_contains "$output" "[dry-run] 116_explicit_model_routing.sql"
  assert_contains "$output" "[dry-run] 120_identity_sources.sql"
  assert_contains "$output" "[dry-run] 121_identity_runtime_publications.sql"
  assert_contains "$output" "[ok] dry-run pending=12"
  assert_equals "$(applied_versions "$fixture")" ""
  [[ ! -f "$fixture/db/schema_migrations.exists" ]] || {
    echo "dry-run created schema_migrations state" >&2
    exit 1
  }
}

test_dry_run_handles_legacy_version_table_without_writes() {
  local fixture output before after
  fixture="$(mktemp -d)"
  make_fixture "$fixture"
  touch "$fixture/db/schema_migrations.exists"
  printf '%s\t\n' "070_alert_groups.sql" >"$fixture/db/schema_migrations.tsv"
  before="$(cat "$fixture/db/schema_migrations.tsv")"

  output="$(run_runner "$fixture" --dry-run --exclude 001_init_schema.sql --exclude 003_private_deployment.sql --exclude 071_rollup_read_models.sql --exclude 072_outbox_events.sql --exclude 076_console_query_indexes.sql --exclude 080_self_transaction.sql --exclude 090_failure.sql --exclude 114_model_routing_v2.sql --exclude 115_request_logs_ttft.sql --exclude 116_explicit_model_routing.sql --exclude 120_identity_sources.sql --exclude 121_identity_runtime_publications.sql 2>&1)"
  after="$(cat "$fixture/db/schema_migrations.tsv")"

  assert_contains "$output" "[skip] 070_alert_groups.sql (legacy checksum would backfill)"
  assert_contains "$output" "[ok] dry-run pending=0"
  assert_equals "$after" "$before"
}

test_legacy_version_table_backfills_checksum_column_without_rerun() {
  local fixture output expected_checksum actual_checksum
  fixture="$(mktemp -d)"
  make_fixture "$fixture"
  touch "$fixture/db/schema_migrations.exists"
  printf '%s\t\n' "070_alert_groups.sql" >"$fixture/db/schema_migrations.tsv"

  output="$(run_runner "$fixture" --exclude 001_init_schema.sql --exclude 003_private_deployment.sql --exclude 071_rollup_read_models.sql --exclude 072_outbox_events.sql --exclude 076_console_query_indexes.sql --exclude 080_self_transaction.sql --exclude 090_failure.sql --exclude 114_model_routing_v2.sql --exclude 115_request_logs_ttft.sql --exclude 116_explicit_model_routing.sql --exclude 120_identity_sources.sql --exclude 121_identity_runtime_publications.sql 2>&1)"

  expected_checksum="$(sha256sum "$fixture/migrations/070_alert_groups.sql" | awk '{print $1}')"
  actual_checksum="$(awk -F '\t' '$1 == "070_alert_groups.sql" { print $2 }' "$fixture/db/schema_migrations.tsv")"
  [[ -f "$fixture/db/schema_migrations.has_checksum" ]] || {
    echo "expected checksum column marker to be created" >&2
    exit 1
  }
  assert_contains "$output" "[skip] 070_alert_groups.sql (legacy checksum recorded)"
  assert_equals "$actual_checksum" "$expected_checksum"
}

test_initdb_bootstrap_without_version_table_is_baselined() {
  local fixture output
  fixture="$(mktemp -d)"
  make_fixture "$fixture"
  touch "$fixture/db/initdb_schema.exists"

  output="$(run_runner "$fixture" --exclude 090_failure.sql 2>&1)"

  assert_not_contains "$output" "[apply] 001_init_schema.sql"
  assert_contains "$output" "[baseline] recorded initdb migrations through 017_audit_dispositions.sql"
  assert_contains "$output" "[apply] 070_alert_groups.sql"
  assert_contains "$output" "[ok] applied=10 skipped=2"
  assert_equals "$(applied_versions "$fixture")" "001_init_schema.sql,003_private_deployment.sql,070_alert_groups.sql,071_rollup_read_models.sql,072_outbox_events.sql,076_console_query_indexes.sql,080_self_transaction.sql,114_model_routing_v2.sql,115_request_logs_ttft.sql,116_explicit_model_routing.sql,120_identity_sources.sql,121_identity_runtime_publications.sql"
}

test_partial_base_schema_without_version_table_is_not_baselined() {
  local fixture output
  fixture="$(mktemp -d)"
  make_fixture "$fixture"

  output="$(run_runner "$fixture" --exclude 090_failure.sql 2>&1)"

  assert_not_contains "$output" "[baseline]"
  assert_contains "$output" "[apply] 001_init_schema.sql"
  assert_contains "$output" "[ok] applied=12 skipped=0"
}

test_transactional_migrations_are_sent_over_stdin_for_compose_entrypoint() {
  local fixture output
  fixture="$(mktemp -d)"
  make_fixture "$fixture"

  output="$(run_runner_composelike "$fixture" --exclude 076_console_query_indexes.sql --exclude 080_self_transaction.sql --exclude 090_failure.sql 2>&1)"

  assert_contains "$output" "[apply] 001_init_schema.sql"
  assert_contains "$output" "[apply] 072_outbox_events.sql"
  assert_contains "$output" "[ok] applied=10 skipped=0"
  assert_equals "$(applied_versions "$fixture")" "001_init_schema.sql,003_private_deployment.sql,070_alert_groups.sql,071_rollup_read_models.sql,072_outbox_events.sql,114_model_routing_v2.sql,115_request_logs_ttft.sql,116_explicit_model_routing.sql,120_identity_sources.sql,121_identity_runtime_publications.sql"
}


test_identity_runtime_publication_migration_contract() {
  local migration="$ROOT_DIR/deploy/migrations/121_identity_runtime_publications.sql"

  assert_file_contains_normalized "$migration" "ADD COLUMN IF NOT EXISTS runtime_alias varchar(64)"
  assert_file_contains_normalized "$migration" "ADD COLUMN IF NOT EXISTS config_digest varchar(128)"
  assert_file_contains_normalized "$migration" "ADD COLUMN IF NOT EXISTS applied_version integer"
  assert_file_contains_normalized "$migration" "publish_status IN ('not_published', 'publishing', 'active', 'error', 'drifted', 'disabled')"
  assert_file_contains_normalized "$migration" "ADD CONSTRAINT uq_identity_sources_tenant_id UNIQUE (tenant_id, id)"
  assert_file_contains_normalized "$migration" "ADD CONSTRAINT fk_idm_source_tenant FOREIGN KEY (tenant_id, identity_source_id) REFERENCES identity_sources(tenant_id, id) ON DELETE CASCADE"
  assert_file_contains_normalized "$migration" "CREATE TABLE IF NOT EXISTS identity_publication_events"
  assert_file_contains_normalized "$migration" "FOREIGN KEY (tenant_id, identity_source_id) REFERENCES identity_sources(tenant_id, id) ON DELETE CASCADE"
  assert_file_not_matches "$migration" 'client[_-]?secret|password_hash'
}

test_same_number_different_filenames_are_independent() {
  local fixture output
  fixture="$(mktemp -d)"
  make_fixture "$fixture"
  printf '%s\n' 'CREATE TABLE IF NOT EXISTS agent_binding_fixture(id text PRIMARY KEY);' >"$fixture/migrations/070_agent_binding_fixture.sql"
  output="$(run_runner "$fixture" --exclude 076_console_query_indexes.sql --exclude 080_self_transaction.sql --exclude 090_failure.sql 2>&1)"
  assert_contains "$output" '[apply] 070_alert_groups.sql'
  assert_contains "$output" '[apply] 070_agent_binding_fixture.sql'
  assert_contains "$output" '[ok] applied=11 skipped=0'
  assert_contains "$(applied_versions "$fixture")" '070_alert_groups.sql'
  assert_contains "$(applied_versions "$fixture")" '070_agent_binding_fixture.sql'
  output="$(run_runner "$fixture" --exclude 076_console_query_indexes.sql --exclude 080_self_transaction.sql --exclude 090_failure.sql 2>&1)"
  assert_contains "$output" '[skip] 070_alert_groups.sql'
  assert_contains "$output" '[skip] 070_agent_binding_fixture.sql'
  assert_contains "$output" '[ok] applied=0 skipped=11'
}

main() {
  test_same_number_different_filenames_are_independent
  test_model_routing_v2_migration_contract
  test_identity_runtime_publication_migration_contract
  bash "$ROOT_DIR/deploy/tests/test_identity_legacy_upgrade.sh"
  test_explicit_model_routing_migration_contract
  test_model_routing_v2_migration_with_postgresql
  test_request_logs_ttft_migration_contract
  test_request_logs_ttft_migration_with_postgresql
  test_reverse_proxy_private_egress_migration_contract
  test_reverse_proxy_private_egress_migration_with_postgresql
  test_reverse_proxy_private_egress_is_discovered_and_recorded
  test_request_logs_ttft_runs_without_outer_transaction
  test_unique_concurrent_index_runs_without_outer_transaction
  test_no_transaction_directive_runs_outside_outer_transaction
  test_no_transaction_failure_is_not_recorded
  test_no_transaction_directive_is_statement_atomic_with_postgresql
  test_unmarked_migration_remains_transactional
  test_lock_query_error_fails_bounded_and_releases_holder
  test_empty_database_applies_all_discovered_migrations
  test_latest_database_rerun_is_noop
  test_middle_database_only_applies_missing_rollup_migrations
  test_legacy_version_row_backfills_checksum_without_rerun
  test_checksum_mismatch_refuses_to_run
  test_failure_stops_at_failed_migration_and_keeps_previous_records
  test_dry_run_prints_plan_without_db_changes
  test_dry_run_handles_legacy_version_table_without_writes
  test_legacy_version_table_backfills_checksum_column_without_rerun
  test_initdb_bootstrap_without_version_table_is_baselined
  test_partial_base_schema_without_version_table_is_not_baselined
  test_transactional_migrations_are_sent_over_stdin_for_compose_entrypoint
  echo "migration runner tests passed"
}

main "$@"
