#!/usr/bin/env bash
# Regression: upgrade-preflight must report every migration file that has no
# schema_migrations row, including files numbered below the applied waterline
# (the runner applies those; see deploy/lib/migration-runner.sh apply_migration).
# Uses a throwaway postgres:16-alpine container with --network none.
set -Eeuo pipefail
# 临时容器：打测试标签、先回收被杀掉的测试进程留下的孤儿容器，清理用 docker rm -f -v（见该库说明）。
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib/test-containers.sh"
jjd_test_reap_orphan_containers
jjd_test_container_labels upgrade-preflight-pending

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
command -v docker >/dev/null 2>&1 || { echo 'SKIP: docker is unavailable'; exit 0; }
docker info >/dev/null 2>&1 || { echo 'SKIP: docker engine is unavailable'; exit 0; }
docker image inspect postgres:16-alpine >/dev/null 2>&1 || { echo 'SKIP: postgres:16-alpine is unavailable'; exit 0; }

fixture="$(mktemp -d)"
container="jjdguard_preflight_pending_${RANDOM}_$$"
cleanup() {
  docker rm -f -v "$container" >/dev/null 2>&1 || true
  rm -rf "$fixture"
}
trap cleanup EXIT INT TERM
fail() { echo "[fail] $*" >&2; exit 1; }

# Isolated tree: real preflight + version lib, synthetic migration set.
mkdir -p "$fixture/deploy/docker-compose" "$fixture/deploy/lib" "$fixture/deploy/migrations"
cp "$ROOT/deploy/docker-compose/upgrade-preflight.sh" \
   "$ROOT/deploy/docker-compose/upgrade-min-data-version" \
   "$ROOT/deploy/docker-compose/upgrade-bridge-target-version" "$fixture/deploy/docker-compose/"
cp "$ROOT/deploy/lib/migration-version.sh" "$fixture/deploy/lib/"
for name in 001_init.sql 002_seed_data.sql 137_enterprise_identity_department.sql \
            865_applied.sql 866_below_waterline.sql 869_waterline.sql 870_new.sql 871_check_verify.sql; do
  printf 'SELECT 1;\n' >"$fixture/deploy/migrations/$name"
done

docker run "${JJD_TEST_CONTAINER_LABELS[@]}" -d --name "$container" --network none -e POSTGRES_HOST_AUTH_METHOD=trust \
  -e POSTGRES_DB=preflight postgres:16-alpine >/dev/null
# The image entrypoint restarts postgres after init; wait for the final server.
ready=0
for _ in $(seq 1 90); do
  if docker logs "$container" 2>&1 | grep -q 'PostgreSQL init process complete' &&
     docker exec "$container" pg_isready -U postgres -d preflight >/dev/null 2>&1; then
    ready=1; break
  fi
  sleep 1
done
(( ready == 1 )) || fail 'postgres did not become ready'

docker exec "$container" psql -X -v ON_ERROR_STOP=1 -U postgres -d preflight -qc "
CREATE TABLE schema_migrations (version TEXT PRIMARY KEY, checksum TEXT, applied_at TIMESTAMPTZ DEFAULT NOW());
INSERT INTO schema_migrations(version) VALUES
 ('001_init.sql'),('137_enterprise_identity_department.sql'),('865_applied.sql'),('869_waterline.sql');"

run_preflight() {
  local rc=0
  UPGRADE_PREFLIGHT_POSTGRES_CONTAINER="$container" POSTGRES_USER=postgres POSTGRES_DB=preflight \
    UPGRADE_FROM_VERSION=fixture-old UPGRADE_TO_VERSION=fixture-new UPGRADE_BACKUP_ROOT="$fixture" \
    bash "$fixture/deploy/docker-compose/upgrade-preflight.sh" --output "$fixture/preflight.json" \
    >"$fixture/preflight.stdout" 2>"$fixture/preflight.stderr" || rc=$?
  # 20 = BLOCKED by host capacity/activity; the pending list is still computed.
  [[ $rc -eq 0 || $rc -eq 20 ]] || { cat "$fixture/preflight.stderr" >&2; fail "preflight rc=$rc"; }
}
pending() {
  python3 -c 'import json,sys; print(",".join(json.load(open(sys.argv[1]))["pending_migrations"]))' "$fixture/preflight.json"
}
field() {
  python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))[sys.argv[2]])' "$fixture/preflight.json" "$1"
}

run_preflight
[[ "$(field current_data_version)" == 869_waterline.sql ]] || fail "waterline=$(field current_data_version)"
got="$(pending)"
[[ "$got" == "866_below_waterline.sql,870_new.sql" ]] || fail "pending=[$got], want [866_below_waterline.sql,870_new.sql]"
[[ "$(field risk)" != SAFE_ONLINE ]] || fail "risk must reflect pending migrations"
echo "[ok] waterline 869 + unapplied 866 and 870: pending=[$got]"

docker exec "$container" psql -X -v ON_ERROR_STOP=1 -U postgres -d preflight -qc \
  "INSERT INTO schema_migrations(version) VALUES ('866_below_waterline.sql'),('870_new.sql');"
run_preflight
got="$(pending)"
[[ -z "$got" ]] || fail "pending=[$got] after all applied, want []"
echo '[ok] all applied: pending=[] (excluded seed/verify files never reported)'
echo '[ok] upgrade-preflight pending test passed'
