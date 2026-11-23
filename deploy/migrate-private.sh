#!/usr/bin/env bash
# migrate-private.sh — apply discovered private-deployment migrations
# Usage: PGPASSWORD=xxx bash deploy/migrate-private.sh [--dry-run] [postgres-host] [postgres-port] [dbname] [user]
# Defaults: host=127.0.0.1 port=15432 db=newapi user=newapi

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
MIGRATIONS_DIR="$SCRIPT_DIR/migrations"
RUNNER="$PROJECT_ROOT/deploy/lib/migration-runner.sh"

DRY_RUN=0
POSITIONAL=()
while (($#)); do
  case "$1" in
    --dry-run)
      DRY_RUN=1
      ;;
    -h|--help)
      sed -n '2,4p' "$0"
      exit 0
      ;;
    *)
      POSITIONAL+=("$1")
      ;;
  esac
  shift
done

HOST="${POSITIONAL[0]:-127.0.0.1}"
PORT="${POSITIONAL[1]:-15432}"
DB="${POSITIONAL[2]:-jjdguard}"
DB_USER="${POSITIONAL[3]:-jjdguard}"

tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT INT TERM
psql_bridge="$tmpdir/private-psql"

cat >"$psql_bridge" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
exec psql -h "$MIGRATION_HOST" -p "$MIGRATION_PORT" -U "$MIGRATION_USER" -d "$MIGRATION_DB" "$@"
EOF
chmod +x "$psql_bridge"

runner_args=(--migrations-dir "$MIGRATIONS_DIR")
if [[ "$DRY_RUN" -eq 1 ]]; then
  runner_args+=(--dry-run)
fi

echo "[info] applying private-deployment migrations from $MIGRATIONS_DIR"
PGPASSWORD="${PGPASSWORD:-jjdguard}" \
MIGRATION_HOST="$HOST" MIGRATION_PORT="$PORT" MIGRATION_DB="$DB" MIGRATION_USER="$DB_USER" MIGRATION_PSQL="$psql_bridge" \
  bash "$RUNNER" "${runner_args[@]}"
