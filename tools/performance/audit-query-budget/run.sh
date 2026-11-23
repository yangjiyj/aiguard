#!/usr/bin/env bash
set -euo pipefail
# 临时容器：打测试标签、先回收被杀掉的进程留下的孤儿容器，清理用 docker rm -f -v（见该库说明）。
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/../../../deploy/tests/lib/test-containers.sh"
jjd_test_reap_orphan_containers
# JJD_QUERY_BENCHMARK_KEEP=1 保留容器排查时不带 owner_pid，回收不会碰。
if [[ "${JJD_QUERY_BENCHMARK_KEEP:-0}" == "1" ]]; then jjd_test_container_labels_kept audit-query-budget; else jjd_test_container_labels audit-query-budget; fi

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
ROWS="${1:-100000}"
OUTPUT_DIR="${2:-$ROOT/work/audit-query-budget-$ROWS}"
CASE_FILTER="${3:-}"
CONTAINER="jjdguard-query-budget-$ROWS-$$"
DATABASE="jjdguard_query_bench_$ROWS"
PASSWORD="bench"
TMPDIR_BENCH="$(mktemp -d)"

case "$ROWS" in
  100000|1000000) ;;
  *)
    echo "rows must be 100000 or 1000000" >&2
    exit 64
    ;;
esac

resolved_output="$(realpath -m "$OUTPUT_DIR")"
case "$resolved_output" in
  "$ROOT"/*) ;;
  *)
    echo "output directory must stay under repository root: $resolved_output" >&2
    exit 64
    ;;
esac
mkdir -p "$resolved_output"
chmod 700 "$resolved_output"

cleanup() {
  rm -rf "$TMPDIR_BENCH"
  if [[ "${JJD_QUERY_BENCHMARK_KEEP:-0}" != "1" ]]; then
    docker rm -f -v "$CONTAINER" >/dev/null 2>&1 || true
  else
    echo "[keep] container=$CONTAINER"
  fi
}
trap cleanup EXIT INT TERM

required_kb=$((ROWS == 1000000 ? 25000000 : 5000000))
available_kb="$(df -Pk "$resolved_output" | awk 'NR==2 {print $4}')"
if [[ -z "$available_kb" || "$available_kb" -lt "$required_kb" ]]; then
  echo "insufficient disk: available_kb=${available_kb:-unknown} required_kb=$required_kb" >&2
  exit 1
fi

for command in docker psql go sha256sum; do
  command -v "$command" >/dev/null || {
    echo "required command unavailable: $command" >&2
    exit 1
  }
done
docker image inspect postgres:16-alpine >/dev/null

echo "[start] rows=$ROWS container=$CONTAINER output=$resolved_output"
docker_args=(
  run --pull=never -d
  "${JJD_TEST_CONTAINER_LABELS[@]}"
  --name "$CONTAINER"
  --cpus=2
  --memory=2g
  --memory-swap=2g
  --shm-size=256m
  -p 127.0.0.1::5432
  -e "POSTGRES_PASSWORD=$PASSWORD"
  -e "POSTGRES_DB=$DATABASE"
  postgres:16-alpine
  postgres
  -c shared_buffers=256MB
  -c effective_cache_size=1GB
  -c work_mem=16MB
  -c maintenance_work_mem=128MB
  -c random_page_cost=1.1
  -c jit=off
  -c max_connections=40
  -c log_min_duration_statement=-1
)
docker "${docker_args[@]}" >/dev/null

for _ in $(seq 1 60); do
  if docker exec "$CONTAINER" pg_isready -U postgres -d "$DATABASE" >/dev/null 2>&1; then
    break
  fi
  sleep 1
done
docker exec "$CONTAINER" pg_isready -U postgres -d "$DATABASE" >/dev/null
PORT="$(docker port "$CONTAINER" 5432/tcp | sed 's/.*://')"
PSQL=(psql -X -h 127.0.0.1 -p "$PORT" -U postgres -d "$DATABASE" -v ON_ERROR_STOP=1)
export PGPASSWORD="$PASSWORD"
wait_postgres() {
  for _ in $(seq 1 60); do
    if "${PSQL[@]}" -Atc 'SELECT 1' >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  echo "PostgreSQL host connection did not become ready" >&2
  return 1
}
wait_postgres

refresh_connection() {
  PORT="$(docker port "$CONTAINER" 5432/tcp | sed 's/.*://')"
  PSQL=(psql -X -h 127.0.0.1 -p "$PORT" -U postgres -d "$DATABASE" -v ON_ERROR_STOP=1)
  DSN="postgres://postgres:$PASSWORD@127.0.0.1:$PORT/$DATABASE?sslmode=disable"
  export JJD_QUERY_BENCHMARK_DSN="$DSN"
}

mkdir -p "$TMPDIR_BENCH/first-migration"
cp "$ROOT/deploy/migrations/001_init_schema.sql" "$TMPDIR_BENCH/first-migration/001_init_schema.sql"
cat >"$TMPDIR_BENCH/psql" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
exec psql -X -h "$MIGRATION_HOST" -p "$MIGRATION_PORT" -U "$MIGRATION_USER" -d "$MIGRATION_DB" "$@"
EOF
chmod 700 "$TMPDIR_BENCH/psql"

echo "[migrate] applying schema"
env MIGRATION_HOST=127.0.0.1 MIGRATION_PORT="$PORT" MIGRATION_USER=postgres MIGRATION_DB="$DATABASE" MIGRATION_PSQL="$TMPDIR_BENCH/psql" bash "$ROOT/deploy/lib/migration-runner.sh" --migrations-dir "$TMPDIR_BENCH/first-migration" >"$resolved_output/migrations.log" 2>&1
"${PSQL[@]}" -c "INSERT INTO tenants(id,name,edition,status) VALUES ('tenant_default','默认单位','enterprise','active') ON CONFLICT DO NOTHING" -c "INSERT INTO users(id,tenant_id,username,role,status) VALUES ('user_admin','tenant_default','admin','platform_admin','active') ON CONFLICT DO NOTHING" >>"$resolved_output/migrations.log" 2>&1
PGPASSWORD="$PASSWORD" bash "$ROOT/deploy/migrate-private.sh" 127.0.0.1 "$PORT" "$DATABASE" postgres >>"$resolved_output/migrations.log" 2>&1

echo "[seed] generating target tenant=$ROWS plus 10% cross-tenant noise"
"${PSQL[@]}" -v "rows=$ROWS" -f "$ROOT/tools/performance/audit-query-budget/seed.sql" >"$resolved_output/seed.log" 2>&1

echo "[build] compiling benchmark harness"
(
  cd "$ROOT/apps/control-plane"
  PATH="/usr/local/go/bin:$PATH" GOWORK=off go test -c -o "$TMPDIR_BENCH/audit-query-bench.test" ./internal/handler
)

refresh_connection
export JJD_QUERY_BENCHMARK_ROWS="$ROWS"

cat >"$resolved_output/environment.txt" <<EOF
revision=$(git -C "$ROOT" rev-parse HEAD)
container_image=$(docker inspect -f '{{.Config.Image}}' "$CONTAINER")
container_cpus=2
container_memory=2g
container_shm=256m
host_kernel=$(uname -srmo)
host_cpu=$(LC_ALL=C lscpu | awk -F: '/Model name/ {gsub(/^ +/, "", $2); print $2; exit}')
host_memory_kb=$(awk '/^MemTotal:/ {print $2; exit}' /proc/meminfo)
host_logical_cpus=$(getconf _NPROCESSORS_ONLN)
rows_target_tenant=$ROWS
rows_noise_tenant=$((ROWS / 10))
seed_sha256=$(sha256sum "$ROOT/tools/performance/audit-query-budget/seed.sql" | awk '{print $1}')
pg_restart_cache_note=PostgreSQL_shared_buffers_cleared_host_page_cache_not_cleared
measurement_layer=Go_HTTP_handler_plus_PostgreSQL_response_body_only
selected_cases=${CASE_FILTER:-all}
EOF

run_phase() {
  local phase="$1"
  local output="$resolved_output/$phase.jsonl"
  rm -f "$output"
  if [[ -z "$CASE_FILTER" ]]; then
    env JJD_QUERY_BENCHMARK_PHASE="$phase" JJD_QUERY_BENCHMARK_OUTPUT="$output" "$TMPDIR_BENCH/audit-query-bench.test" -test.run '^TestAuditQueryBudgetBenchmark$' -test.v
    return
  fi
  local benchmark_case
  IFS=',' read -r -a selected_cases <<<"$CASE_FILTER"
  for benchmark_case in "${selected_cases[@]}"; do
    env JJD_QUERY_BENCHMARK_PHASE="$phase" JJD_QUERY_BENCHMARK_CASE="$benchmark_case" JJD_QUERY_BENCHMARK_OUTPUT="$output" "$TMPDIR_BENCH/audit-query-bench.test" -test.run '^TestAuditQueryBudgetBenchmark$' -test.v
  done
}

cold_cases=(
  content_main content_user content_keyword_zh2 content_keyword_acl_only content_keyword_content_only content_keyword_old_tail content_deep_1001 content_users
  access_records access_records_exact_count access_deep_1001 access_deep_1001_exact_count access_keyword_zh2 access_keyword_acl_only access_keyword_content_only access_keyword_old_tail access_runs access_runs_exact_count access_counts access_summary
  alert_detail alert_events alert_events_deep_1001
  tool_audit_exact_count tool_audit_101 tool_audit_1001 tool_audit_keyword_zh2
)
rm -f "$resolved_output/pg-restart-cold.jsonl"
selected_cold_cases=("${cold_cases[@]}")
if [[ -n "$CASE_FILTER" ]]; then
  IFS=',' read -r -a selected_cold_cases <<<"$CASE_FILTER"
fi
for benchmark_case in "${selected_cold_cases[@]}"; do
  echo "[pg-restart-cold] $benchmark_case"
  docker restart "$CONTAINER" >/dev/null
  refresh_connection
  wait_postgres
  env JJD_QUERY_BENCHMARK_PHASE=pg_restart_cold JJD_QUERY_BENCHMARK_CASE="$benchmark_case" JJD_QUERY_BENCHMARK_OUTPUT="$resolved_output/pg-restart-cold.jsonl" "$TMPDIR_BENCH/audit-query-bench.test" -test.run '^TestAuditQueryBudgetBenchmark$' -test.v
done

echo "[hot] five sequential samples per endpoint"
run_phase hot
echo "[concurrent] ten simultaneous requests per endpoint"
run_phase concurrent

echo "[plans] auto_explain analyze+buffers for exact handler SQL"
plan_since="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
rm -f "$resolved_output/explain.jsonl" "$resolved_output/auto-explain.log"
env JJD_QUERY_BENCHMARK_PHASE=explain JJD_QUERY_BENCHMARK_EXPLAIN=1 JJD_QUERY_BENCHMARK_OUTPUT="$resolved_output/explain.jsonl" "$TMPDIR_BENCH/audit-query-bench.test" -test.run '^TestAuditQueryBudgetBenchmark$' -test.v
docker logs --since "$plan_since" "$CONTAINER" >"$resolved_output/auto-explain.log" 2>&1

"${PSQL[@]}" -At >"$resolved_output/table-counts.tsv" <<'SQL'
SELECT 'request_logs', tenant_id, count(*) FROM request_logs GROUP BY tenant_id ORDER BY 1,2;
SELECT 'content_logs', tenant_id, count(*) FROM content_logs GROUP BY tenant_id ORDER BY 1,2;
SELECT 'access_content_logs', tenant_id, count(*) FROM access_content_logs GROUP BY tenant_id ORDER BY 1,2;
SELECT 'security_events', tenant_id, count(*) FROM security_events GROUP BY tenant_id ORDER BY 1,2;
SELECT 'alert_groups', tenant_id, count(*) FROM alert_groups GROUP BY tenant_id ORDER BY 1,2;
SELECT 'tool_call_logs', tenant_id, count(*) FROM tool_call_logs GROUP BY tenant_id ORDER BY 1,2;
SELECT 'audit_dispositions', tenant_id, count(*) FROM audit_dispositions GROUP BY tenant_id ORDER BY 1,2;
SELECT 'evidence_run_request_index', tenant_id, count(*) FROM evidence_run_request_index GROUP BY tenant_id ORDER BY 1,2;
SQL

echo "[ok] benchmark evidence: $resolved_output"
