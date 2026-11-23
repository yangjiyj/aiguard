#!/bin/sh
set -eu

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(CDPATH= cd -- "$SCRIPT_DIR/../.." && pwd)"
COMPOSE_WRAPPER="${COMPOSE_WRAPPER:-$SCRIPT_DIR/compose-wrapper.sh}"
MIGRATIONS_DIR="$PROJECT_ROOT/deploy/migrations"
RUNNER="$PROJECT_ROOT/deploy/lib/migration-runner.sh"

load_migration_dotenv() {
  file="$1"
  seen_postgres_user=0
  seen_postgres_db=0
  while IFS= read -r line || [ -n "$line" ]; do
    case "$line" in ''|'#'*) continue ;; esac
    case "$line" in *=*) ;; *) echo "[error] .env is not strict dotenv syntax" >&2; return 1 ;; esac
    key=${line%%=*}
    value=${line#*=}
    case "$key" in ''|[0-9]*|*[!A-Za-z0-9_]*) echo "[error] invalid .env key" >&2; return 1 ;; esac
    case "$value" in
      \"*\"|\'*\') value=${value#?}; value=${value%?} ;;
      \"*|\'*) echo "[error] unterminated quoted .env value: $key" >&2; return 1 ;;
    esac
    case "$key" in
      POSTGRES_USER)
        [ "$seen_postgres_user" -eq 0 ] || { echo "[error] duplicate POSTGRES_USER" >&2; return 1; }
        seen_postgres_user=1
        case "$value" in ''|*[!A-Za-z0-9_.-]*) echo "[error] invalid POSTGRES_USER" >&2; return 1 ;; esac
        POSTGRES_USER=$value; export POSTGRES_USER
        ;;
      POSTGRES_DB)
        [ "$seen_postgres_db" -eq 0 ] || { echo "[error] duplicate POSTGRES_DB" >&2; return 1; }
        seen_postgres_db=1
        case "$value" in ''|*[!A-Za-z0-9_.-]*) echo "[error] invalid POSTGRES_DB" >&2; return 1 ;; esac
        POSTGRES_DB=$value; export POSTGRES_DB
        ;;
    esac
  done <"$file"
}

if [ -f "$SCRIPT_DIR/.env" ]; then
  [ ! -L "$SCRIPT_DIR/.env" ] || { echo "[error] refusing symbolic-link .env" >&2; exit 1; }
  load_migration_dotenv "$SCRIPT_DIR/.env"
fi

DRY_RUN=0
while [ "$#" -gt 0 ]; do
  case "$1" in
    --dry-run)
      DRY_RUN=1
      ;;
    -h|--help)
      echo "Usage: sh migrate-private.sh [--dry-run]"
      exit 0
      ;;
    *)
      echo "[error] unknown argument: $1" >&2
      exit 64
      ;;
  esac
  shift
done

POSTGRES_USER="${POSTGRES_USER:-jjdguard}"
POSTGRES_DB="${POSTGRES_DB:-jjdguard}"
COMPOSE_PROJECT_DIR="$SCRIPT_DIR"
COMPOSE_FILE=""
if [ ! -f "$SCRIPT_DIR/docker-compose.yml" ] && [ -f "$SCRIPT_DIR/docker-compose.offline.yml" ]; then
  COMPOSE_FILE="$SCRIPT_DIR/docker-compose.offline.yml"
fi
if [ -z "${COMPOSE_PROJECT_NAME:-}" ] && [ -n "$COMPOSE_FILE" ]; then
  COMPOSE_PROJECT_NAME="$(basename "$PROJECT_ROOT" | tr "[:upper:]._" "[:lower:]--")"
fi


tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT INT TERM
psql_bridge="$tmpdir/compose-psql"

cat >"$psql_bridge" <<'EOF'
#!/bin/sh
set -eu
exec sh "$COMPOSE_WRAPPER" --project-directory "$COMPOSE_PROJECT_DIR" exec -T postgres psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" "$@"
EOF
chmod +x "$psql_bridge"

echo "[info] applying private-deployment migrations from $MIGRATIONS_DIR"
if [ "$DRY_RUN" -eq 1 ]; then
  COMPOSE_FILE="$COMPOSE_FILE" COMPOSE_PROJECT_NAME="$COMPOSE_PROJECT_NAME" COMPOSE_PROJECT_DIR="$COMPOSE_PROJECT_DIR" COMPOSE_WRAPPER="$COMPOSE_WRAPPER" POSTGRES_USER="$POSTGRES_USER" POSTGRES_DB="$POSTGRES_DB" MIGRATION_PSQL="$psql_bridge" \
    bash "$RUNNER" --migrations-dir "$MIGRATIONS_DIR" --dry-run
else
  COMPOSE_FILE="$COMPOSE_FILE" COMPOSE_PROJECT_NAME="$COMPOSE_PROJECT_NAME" COMPOSE_PROJECT_DIR="$COMPOSE_PROJECT_DIR" COMPOSE_WRAPPER="$COMPOSE_WRAPPER" POSTGRES_USER="$POSTGRES_USER" POSTGRES_DB="$POSTGRES_DB" MIGRATION_PSQL="$psql_bridge" \
    bash "$RUNNER" --migrations-dir "$MIGRATIONS_DIR"
fi
