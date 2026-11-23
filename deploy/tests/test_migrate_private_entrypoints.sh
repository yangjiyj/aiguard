#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

assert_contains() {
  local file="$1"
  local needle="$2"
  if ! grep -Fq -- "$needle" "$file"; then
    echo "expected $file to contain: $needle" >&2
    exit 1
  fi
}

assert_not_contains() {
  local file="$1"
  local needle="$2"
  if grep -Fq -- "$needle" "$file"; then
    echo "expected $file not to contain: $needle" >&2
    exit 1
  fi
}

root_script="$ROOT_DIR/deploy/migrate-private.sh"
compose_script="$ROOT_DIR/deploy/docker-compose/migrate-private.sh"
offline_packager="$ROOT_DIR/deploy/docker-compose/package-offline-bundle.sh"

assert_contains "$root_script" "deploy/lib/migration-runner.sh"
assert_contains "$root_script" "--dry-run"
assert_contains "$root_script" "MIGRATION_PSQL"
assert_contains "$root_script" 'psql -h "$MIGRATION_HOST" -p "$MIGRATION_PORT" -U "$MIGRATION_USER" -d "$MIGRATION_DB"'
assert_not_contains "$root_script" "apply_migration()"
assert_not_contains "$root_script" '"$MIGRATIONS_DIR/070_alert_groups.sql"'

assert_contains "$compose_script" "deploy/lib/migration-runner.sh"
assert_contains "$compose_script" 'COMPOSE_WRAPPER="${COMPOSE_WRAPPER:-$SCRIPT_DIR/compose-wrapper.sh}"'
assert_contains "$compose_script" "--dry-run"
assert_contains "$compose_script" 'psql -U "$POSTGRES_USER" -d "$POSTGRES_DB"'
assert_contains "$compose_script" 'COMPOSE_PROJECT_DIR'
assert_contains "$compose_script" 'docker-compose.offline.yml'
assert_contains "$compose_script" '--project-directory "$COMPOSE_PROJECT_DIR"'
assert_not_contains "$compose_script" "run_migration()"
assert_not_contains "$compose_script" "run_migration \"070_alert_groups.sql\""

assert_contains "$offline_packager" 'deploy/lib'
assert_contains "$offline_packager" 'upgrade.sh'

bash -n "$root_script"
sh -n "$compose_script"
bash -n "$offline_packager"

echo "migrate-private entrypoint tests passed"
