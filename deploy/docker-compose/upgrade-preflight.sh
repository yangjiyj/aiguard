#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
source "$ROOT/deploy/lib/migration-version.sh"

container="${UPGRADE_PREFLIGHT_POSTGRES_CONTAINER:-}"
pguser="${POSTGRES_USER:-jjdguard}"
pgdb="${POSTGRES_DB:-jjdguard}"
from_version="${UPGRADE_FROM_VERSION:-unknown}"
to_version="${UPGRADE_TO_VERSION:-unknown}"
output=""
while (($#)); do
  case "$1" in
    --output) shift; output="${1:-}" ;;
    *) echo "[preflight][error] unknown argument: $1" >&2; exit 64 ;;
  esac
  shift
done

[[ "$container" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]+$ ]] || {
  echo '[preflight][error] one trusted PostgreSQL container is required' >&2; exit 2;
}
docker inspect "$container" >/dev/null 2>&1 || {
  echo '[preflight][error] PostgreSQL container is unavailable' >&2; exit 2;
}

query() {
  docker exec "$container" psql -X -v ON_ERROR_STOP=1 -U "$pguser" -d "$pgdb" -qAt -c "$1"
}
json_escape() {
  printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g; s/[[:cntrl:]]/ /g'
}
disk_kb() {
  local path="$1"
  while [[ "$path" != / && ! -e "$path" ]]; do path="$(dirname "$path")"; done
  df -Pk "$path" 2>/dev/null | awk 'NR==2 {print $4+0}'
}

current="$(query "$(migration_latest_sql)")"
migration_name_valid "$current" || {
  echo "[preflight][error] invalid schema migration waterline: ${current:-empty}" >&2; exit 2;
}
min_version="$(tr -d '[:space:]' <"$SCRIPT_DIR/upgrade-min-data-version")"
bridge_target="$(tr -d '[:space:]' <"$SCRIPT_DIR/upgrade-bridge-target-version")"
migration_name_valid "$min_version" && migration_name_valid "$bridge_target" || {
  echo '[preflight][error] packaged compatibility contract is invalid' >&2; exit 2;
}

# Pending = every migration file that has no schema_migrations row, exactly as
# deploy/lib/migration-runner.sh decides per file (apply_migration). Comparing
# against the highest applied number would hide an unapplied file whose
# number is below the waterline (e.g. 866 after 869 is already applied).
declare -A applied_versions=()
while IFS= read -r version; do
  [[ -n "$version" ]] && applied_versions["$version"]=1
done < <(query "SELECT version FROM schema_migrations;")

# Keep in sync with EXCLUDES in deploy/lib/migration-runner.sh: the runner never
# applies or records these files, so they must not be reported as pending.
preflight_migration_excluded() {
  case "$1" in
    002_seed_data.sql|*_verify.sql) return 0 ;;
  esac
  return 1
}

pending_json="["
pending_count=0
high_risk=0
separator=""
while IFS= read -r file; do
  name="$(basename "$file")"
  migration_name_valid "$name" || continue
  preflight_migration_excluded "$name" && continue
  if [[ -z "${applied_versions[$name]:-}" ]]; then
    pending_json+="${separator}\"$(json_escape "$name")\""
    separator=","
    pending_count=$((pending_count+1))
    case "$name" in
      104_*|131_*|137_enterprise_*|146_*|148_*|151_*|819_*|827_*|829_*|831_*) high_risk=1 ;;
    esac
  fi
done < <(find "$ROOT/deploy/migrations" -maxdepth 1 -type f -name '*_*.sql' | sort -V)
pending_json+="]"

db_stats="$(query "
SELECT COALESCE(json_agg(row_to_json(s))::text,'[]') FROM (
 SELECT c.relname AS table_name,COALESCE(c.reltuples,0)::bigint AS estimated_rows,
        pg_total_relation_size(c.oid) AS total_bytes
 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
 WHERE n.nspname='public' AND c.relkind IN ('r','m')
 ORDER BY pg_total_relation_size(c.oid) DESC LIMIT 20
) s;")"
activity="$(query "
SELECT json_build_object(
 'long_transactions',COUNT(*) FILTER (WHERE xact_start < NOW()-INTERVAL '30 minutes'),
 'idle_in_transaction',COUNT(*) FILTER (WHERE state='idle in transaction'),
 'lock_waiters',COUNT(*) FILTER (WHERE wait_event_type='Lock'),
 'blocking_sessions',COUNT(*) FILTER (WHERE cardinality(pg_blocking_pids(pid)) > 0)
)::text FROM pg_stat_activity
WHERE datname=current_database() AND pid<>pg_backend_pid();")"
invalid_indexes="$(query "SELECT COUNT(*) FROM pg_index WHERE NOT indisvalid OR NOT indisready;")"
db_bytes="$(query "SELECT pg_database_size(current_database());")"

install_free_kb="$(disk_kb "$SCRIPT_DIR")"
docker_root="$(docker info --format '{{.DockerRootDir}}' 2>/dev/null || true)"
[[ "$docker_root" == /* ]] || docker_root="/var/lib/docker"
docker_free_kb="$(disk_kb "$docker_root")"
data_source="$(docker inspect --format '{{range .Mounts}}{{if eq .Destination "/var/lib/postgresql/data"}}{{.Source}}{{end}}{{end}}' "$container" 2>/dev/null || true)"
[[ "$data_source" == /* ]] || data_source="$docker_root"
data_free_kb="$(disk_kb "$data_source")"
backup_root="${UPGRADE_BACKUP_ROOT:-$SCRIPT_DIR/backups}"
backup_free_kb="$(disk_kb "$backup_root")"

long_tx="$(printf '%s' "$activity" | sed -n 's/.*"long_transactions" : \([0-9]*\).*/\1/p')"
idle_tx="$(printf '%s' "$activity" | sed -n 's/.*"idle_in_transaction" : \([0-9]*\).*/\1/p')"
blockers="$(printf '%s' "$activity" | sed -n 's/.*"blocking_sessions" : \([0-9]*\).*/\1/p')"
long_tx="${long_tx:-0}"; idle_tx="${idle_tx:-0}"; blockers="${blockers:-0}"

risk=SAFE_ONLINE
reason="bounded schema migration"
if (( pending_count > 0 )); then risk=ONLINE_WITH_BACKFILL; reason="pending migrations and resumable backfills"; fi
if (( high_risk == 1 )) || migration_version_lt "$current" "$bridge_target"; then
  risk=MAINTENANCE_REQUIRED; reason="historical bridge requires a quiesced writer window"
fi
# The 10m projection backfill produced WAL equal to 3.61x the pre-backfill
# database size. Reserve 5x plus 1 GiB so WAL, rewritten pages and backup
# staging do not compete for the final bytes.
required_kb=$(( (db_bytes / 1024) * 5 + 1048576 ))
if (( long_tx > 0 || idle_tx > 0 || blockers > 0 || invalid_indexes > 0 ||
      backup_free_kb < required_kb || data_free_kb < required_kb )); then
  risk=BLOCKED
  reason="resolve transactions, invalid indexes, locks, or capacity before mutation"
fi

payload="$(printf '{"schema":"jjdguard-upgrade-preflight/v1","from_version":"%s","to_version":"%s","current_data_version":"%s","minimum_data_version":"%s","bridge_target_version":"%s","risk":"%s","reason":"%s","pending_migrations":%s,"database_tables":%s,"database_activity":%s,"invalid_indexes":%s,"database_bytes":%s,"space_kb":{"install":%s,"docker":%s,"data":%s,"backup":%s,"required":%s},"docker":{"engine":"%s","compose":"%s","root":"%s"},"backup_status":"pending","rollback_anchor":"checked_by_upgrade_entry"}\n' \
  "$(json_escape "$from_version")" "$(json_escape "$to_version")" "$current" "$min_version" "$bridge_target" \
  "$risk" "$(json_escape "$reason")" "$pending_json" "$db_stats" "$activity" "$invalid_indexes" "$db_bytes" \
  "$install_free_kb" "$docker_free_kb" "$data_free_kb" "$backup_free_kb" "$required_kb" \
  "$(json_escape "$(docker version --format '{{.Server.Version}}' 2>/dev/null || echo unavailable)")" \
  "$(json_escape "$(docker compose version --short 2>/dev/null || echo unavailable)")" "$(json_escape "$docker_root")")"
printf '%s' "$payload"
if [[ -n "$output" ]]; then
  mkdir -p "$(dirname "$output")"
  tmp="$output.$$"
  printf '%s' "$payload" >"$tmp"
  chmod 600 "$tmp"
  mv -f "$tmp" "$output"
fi
[[ "$risk" != BLOCKED ]] || exit 20
