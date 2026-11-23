#!/usr/bin/env bash
set -Eeuo pipefail
# 临时容器：打测试标签、先回收被杀掉的测试进程留下的孤儿容器，清理用 docker rm -f -v（见该库说明）。
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib/test-containers.sh"
jjd_test_reap_orphan_containers
jjd_test_container_labels identity-legacy-upgrade

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
migration="$ROOT_DIR/deploy/migrations/121_identity_runtime_publications.sql"

if ! command -v docker >/dev/null 2>&1 \
  || ! docker info >/dev/null 2>&1 \
  || ! docker image inspect postgres:16-alpine >/dev/null 2>&1; then
  echo "SKIP: identity legacy upgrade PostgreSQL test"
  exit 0
fi

container="jjdguard-identity-legacy-$$-$RANDOM"
cleanup() {
  docker rm -f -v "$container" >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

docker run "${JJD_TEST_CONTAINER_LABELS[@]}" --rm -d --name "$container" \
  -e POSTGRES_PASSWORD=test \
  -e POSTGRES_DB=test \
  postgres:16-alpine >/dev/null

ready=0
for _ in {1..90}; do
  if [[ "$(docker exec "$container" psql -U postgres -d test -tAc 'SELECT 1' 2>/dev/null)" == 1 ]]; then
    ready=1
    break
  fi
  sleep 1
done
[[ "$ready" == 1 ]] || { echo "PostgreSQL readiness timeout" >&2; exit 1; }

docker exec "$container" psql -v ON_ERROR_STOP=1 -U postgres -d test -c "
  CREATE TABLE tenants (id varchar(64) PRIMARY KEY);
  CREATE TABLE identity_sources (
    id varchar(64) PRIMARY KEY,
    tenant_id varchar(64) NOT NULL REFERENCES tenants(id)
  );
  CREATE TABLE identity_dept_mappings (
    id varchar(64) PRIMARY KEY,
    tenant_id varchar(64) NOT NULL REFERENCES tenants(id),
    identity_source_id varchar(64) NOT NULL REFERENCES identity_sources(id)
  );
  INSERT INTO tenants(id) VALUES ('tenant-a'), ('tenant-b');
  INSERT INTO identity_sources(id, tenant_id) VALUES ('source-a', 'tenant-a');
" >/dev/null

apply_up() {
  sed '/^-- +goose Down/,$d' "$migration" |
    docker exec -i "$container" psql -v ON_ERROR_STOP=1 -U postgres -d test >/dev/null
}

apply_up
apply_up

unique_constraint="$(docker exec "$container" psql -U postgres -d test -tAc \
  "SELECT count(*) FROM pg_constraint WHERE conrelid='identity_sources'::regclass AND conname='uq_identity_sources_tenant_id' AND contype='u'")"
mapping_constraint="$(docker exec "$container" psql -U postgres -d test -tAc \
  "SELECT count(*) FROM pg_constraint WHERE conrelid='identity_dept_mappings'::regclass AND conname='fk_idm_source_tenant' AND contype='f'")"
publication_constraint="$(docker exec "$container" psql -U postgres -d test -tAc \
  "SELECT count(*) FROM pg_constraint WHERE conrelid='identity_publication_events'::regclass AND conname='fk_identity_publication_source' AND contype='f'")"
[[ "$unique_constraint" == 1 ]]
[[ "$mapping_constraint" == 1 ]]
[[ "$publication_constraint" == 1 ]]

if docker exec "$container" psql -v ON_ERROR_STOP=1 -U postgres -d test -c \
  "INSERT INTO identity_dept_mappings(id, tenant_id, identity_source_id) VALUES ('bad-map', 'tenant-b', 'source-a')" >/dev/null 2>&1; then
  echo "cross-tenant identity mapping was accepted" >&2
  exit 1
fi

if docker exec "$container" psql -v ON_ERROR_STOP=1 -U postgres -d test -c \
  "INSERT INTO identity_publication_events(tenant_id, identity_source_id, source_version, action, result) VALUES ('tenant-b', 'source-a', 1, 'publish', 'started')" >/dev/null 2>&1; then
  echo "cross-tenant identity publication was accepted" >&2
  exit 1
fi

docker exec "$container" psql -v ON_ERROR_STOP=1 -U postgres -d test -c \
  "INSERT INTO identity_dept_mappings(id, tenant_id, identity_source_id) VALUES ('good-map', 'tenant-a', 'source-a');
   INSERT INTO identity_publication_events(tenant_id, identity_source_id, source_version, action, result) VALUES ('tenant-a', 'source-a', 1, 'publish', 'started');" >/dev/null

echo "identity legacy upgrade PostgreSQL test passed"
