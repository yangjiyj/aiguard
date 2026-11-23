#!/usr/bin/env bash
# Exercise the automatic failure handler against an isolated real PostgreSQL.
set -Eeuo pipefail
# 临时容器：打测试标签、先回收被杀掉的测试进程留下的孤儿容器，清理用 docker rm -f -v（见该库说明）。
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib/test-containers.sh"
jjd_test_reap_orphan_containers
jjd_test_container_labels upgrade-preserves-live-database
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
fixture="$(mktemp -d)"
pg=""
cleanup() {
  [[ -z "$pg" ]] || docker rm -f -v "$pg" >/dev/null 2>&1 || true
  rm -rf -- "$fixture"
}
trap cleanup EXIT
pg="$(docker run "${JJD_TEST_CONTAINER_LABELS[@]}" -d --memory 512m --network none -e POSTGRES_HOST_AUTH_METHOD=trust postgres:16-alpine)"
for attempt in $(seq 1 60); do
  docker exec "$pg" pg_isready -U postgres >/dev/null 2>&1 && break
  sleep 1
done
docker exec "$pg" createdb -U postgres jjdguard
docker exec "$pg" psql -U postgres -d jjdguard -v ON_ERROR_STOP=1 -c \
  "CREATE TABLE upgrade_preservation_probe(id integer PRIMARY KEY); INSERT INTO upgrade_preservation_probe VALUES (1);" >/dev/null
docker exec "$pg" pg_dump -U postgres -d jjdguard -Fc > "$fixture/postgres.dump"
docker exec "$pg" psql -U postgres -d jjdguard -v ON_ERROR_STOP=1 -c \
  "INSERT INTO upgrade_preservation_probe VALUES (2);" >/dev/null
set +e
(
  source "$ROOT/deploy/docker-compose/upgrade-bundle.sh"
  BACKUP_DIR="$fixture"
  IMAGE_SWITCH_STARTED=1
  DATABASE_MUTATION_STARTED=1
  SERVICES_QUIESCED=1
  UPGRADE_FAILURE_HANDLED=0
  OLD_RUNNING_SERVICES=(gateway-core postgres)
  NEW_COMPOSE_ARGS=(true)
  project_container() { printf '%s\n' "$pg"; }
  database_identity() { printf 'postgres|jjdguard\n'; }
  rollback_old_services() { printf 'application rollback attempted\n'; }
  upgrade_failure 42
) > "$fixture/handler.log" 2>&1
status=$?
set -e
[[ "$status" == 42 ]] || { cat "$fixture/handler.log"; exit 1; }
actual="$(docker exec "$pg" psql -U postgres -d jjdguard -Atc 'SELECT string_agg(id::text,chr(44) ORDER BY id) FROM upgrade_preservation_probe')"
[[ "$actual" == 1,2 ]] || { echo "post-backup writes lost: $actual" >&2; exit 1; }
grep -q 'application rollback attempted' "$fixture/handler.log"
echo '[ok] real PostgreSQL retains both pre-backup and post-backup writes after automatic upgrade failure'
