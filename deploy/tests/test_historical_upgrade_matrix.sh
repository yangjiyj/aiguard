#!/usr/bin/env bash
set -Eeuo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
RUNNER="$ROOT/deploy/lib/migration-runner.sh"
LEGACY="$ROOT/deploy/lib/legacy-migration-checksums.tsv"
cases=(
  "1.4.0:9bbb35ed"
  "1.7.0:34ce8c56"
  "2.0:863f2f30"
  "2.6.3:dc98a525"
  "2.6.7:11a36157"
)
start_at="${JJD_HISTORY_START_AT:-}"
started=0
executed=0
command -v docker >/dev/null
docker info >/dev/null
docker compose version >/dev/null
docker image inspect postgres:16-alpine >/dev/null

for item in "${cases[@]}"; do
  version="${item%%:*}"
  revision="${item#*:}"
  if [[ -n "$start_at" && "$started" -eq 0 ]]; then
    [[ "$version" == "$start_at" ]] || continue
    started=1
  fi
  executed=$((executed + 1))
  fixture="$(mktemp -d)"
  project="jjdguard_history_${version//./_}_${RANDOM}_$$"
  cleanup_case() {
    docker compose -p "$project" -f "$fixture/compose.yml" down -v --remove-orphans >/dev/null 2>&1 || true
    rm -rf "$fixture"
  }
  trap cleanup_case EXIT INT TERM
  mkdir -p "$fixture/source"
  git -C "$ROOT" archive "$revision" deploy/migrations deploy/docker-compose/initdb/001_init_enterprise.sql |
    tar -x -C "$fixture/source"
  cat >"$fixture/compose.yml" <<'YAML'
services:
  postgres:
    image: postgres:16-alpine
    environment:
      POSTGRES_PASSWORD: history
      POSTGRES_USER: jjdguard
      POSTGRES_DB: jjdguard
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U jjdguard -d jjdguard"]
      interval: 1s
      timeout: 2s
      retries: 60
    volumes: [history-db:/var/lib/postgresql/data]
volumes:
  history-db: {}
YAML
  docker compose -p "$project" -f "$fixture/compose.yml" up -d --wait --wait-timeout 90
  container="$(docker compose -p "$project" -f "$fixture/compose.yml" ps -q postgres)"
  docker cp "$fixture/source/deploy/migrations/." "$container:/migrations"
  docker exec -i "$container" psql -X -v ON_ERROR_STOP=1 -U jjdguard -d jjdguard \
    <"$fixture/source/deploy/docker-compose/initdb/001_init_enterprise.sql" >/dev/null
  cat >"$fixture/psql" <<EOF
#!/bin/sh
exec docker exec -i $container psql -X -U jjdguard -d jjdguard "\$@"
EOF
  chmod +x "$fixture/psql"

  MIGRATION_PSQL="$fixture/psql" MIGRATION_HEARTBEAT_INTERVAL=30 \
    bash "$RUNNER" --migrations-dir "$fixture/source/deploy/migrations" >/dev/null
  before="$(docker exec "$container" psql -X -U jjdguard -d jjdguard -qAt -c "
SELECT version FROM schema_migrations ORDER BY split_part(version,'_',1)::bigint DESC,version DESC LIMIT 1;")"
  MIGRATION_PSQL="$fixture/psql" MIGRATION_LEGACY_CHECKSUM_FILE="$LEGACY" \
    MIGRATION_HEARTBEAT_INTERVAL=30 bash "$RUNNER" --migrations-dir "$ROOT/deploy/migrations" >/dev/null
  after="$(docker exec "$container" psql -X -U jjdguard -d jjdguard -qAt -c "
SELECT version FROM schema_migrations ORDER BY split_part(version,'_',1)::bigint DESC,version DESC LIMIT 1;")"
  invalid="$(docker exec "$container" psql -X -U jjdguard -d jjdguard -qAt -c "
SELECT COUNT(*) FROM pg_index WHERE NOT indisvalid OR NOT indisready;")"
  tasks="$(docker exec "$container" psql -X -U jjdguard -d jjdguard -qAt -c "
SELECT COUNT(*) FROM migration_backfill_tasks WHERE state='pending';")"
  # 期望的终点必须是本仓库当前的迁移 head，而不是某个写死的历史版本号：
  # 写死会在每次新增迁移后变红，掩盖真正的回放回归。
  head_migration="$(cd "$ROOT/deploy/migrations" && ls | sort -t_ -k1,1n | tail -1)"
  [[ "$after" == "$head_migration" && "$invalid" == 0 && "$tasks" -ge 7 ]]
  printf 'historical_upgrade version=%s revision=%s before=%s after=%s invalid_indexes=%s pending_backfills=%s\n' \
    "$version" "$revision" "$before" "$after" "$invalid" "$tasks"
  cleanup_case
  trap - EXIT INT TERM
done
[[ "$executed" -gt 0 ]]
printf 'historical_upgrade_matrix=ok cases=%s\n' "$executed"
