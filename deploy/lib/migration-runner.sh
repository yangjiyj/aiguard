#!/usr/bin/env bash
# Shared private-deployment migration runner.
#
# Callers must provide one of:
#   - MIGRATION_PSQL=/path/to/psql-compatible-command
#   - a psql_cmd shell function before sourcing/running this file

set -euo pipefail

MIGRATIONS_DIR=""
DRY_RUN=0
EXCLUDES=("002_seed_data.sql" "*_verify.sql")
SCHEMA_MIGRATIONS_EXISTS=0
SCHEMA_MIGRATIONS_HAS_CHECKSUM=0
MIGRATION_LOCK_PID=""
MIGRATION_LOCK_INPUT_FD=""
MIGRATION_LOCK_OUTPUT_FD=""
LEGACY_CHECKSUM_FILE="${MIGRATION_LEGACY_CHECKSUM_FILE:-}"
declare -A LEGACY_CHECKSUMS=()
LEGACY_CHECKSUMS_LOADED=0
MIGRATION_LOCK_WAIT_TIMEOUT="${MIGRATION_LOCK_WAIT_TIMEOUT:-300}"
MIGRATION_HEARTBEAT_INTERVAL="${MIGRATION_HEARTBEAT_INTERVAL:-10}"
MIGRATION_LOCK_TIMEOUT="${MIGRATION_LOCK_TIMEOUT:-5s}"
MIGRATION_STATEMENT_TIMEOUT="${MIGRATION_STATEMENT_TIMEOUT:-15min}"
MIGRATION_IDLE_TX_TIMEOUT="${MIGRATION_IDLE_TX_TIMEOUT:-60s}"
CURRENT_MIGRATION=""
VERSION_LIB="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/migration-version.sh"
source "$VERSION_LIB"

usage() {
  cat <<'USAGE'
Usage: migration-runner.sh --migrations-dir DIR [--dry-run] [--exclude PATTERN]

Discovers NNN_*.sql files, records applied versions and checksums in
schema_migrations, skips already applied migrations, and refuses to continue if
an applied migration's checksum no longer matches the file on disk.
USAGE
}

while (($#)); do
  case "$1" in
    --migrations-dir)
      shift
      MIGRATIONS_DIR="${1:-}"
      ;;
    --dry-run)
      DRY_RUN=1
      ;;
    --exclude)
      shift
      EXCLUDES+=("${1:-}")
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "[error] unknown argument: $1" >&2
      usage >&2
      exit 64
      ;;
  esac
  shift || true
done

if [[ -z "$MIGRATIONS_DIR" ]]; then
  echo "[error] --migrations-dir is required" >&2
  exit 64
fi

if [[ ! -d "$MIGRATIONS_DIR" ]]; then
  echo "[error] migrations directory not found: $MIGRATIONS_DIR" >&2
  exit 64
fi

run_psql() {
  if declare -F psql_cmd >/dev/null 2>&1; then
    if psql_cmd "$@"; then return 0; else return $?; fi
  fi
  if [[ -n "${MIGRATION_PSQL:-}" ]]; then
    if "$MIGRATION_PSQL" "$@"; then return 0; else return $?; fi
  fi
  echo "[error] no psql command configured" >&2
  exit 64
}

release_migration_lock() {
  if [[ -n "$MIGRATION_LOCK_INPUT_FD" ]]; then
    printf '\\q\n' >&"$MIGRATION_LOCK_INPUT_FD" 2>/dev/null || true
  fi
  if [[ -n "$MIGRATION_LOCK_PID" ]]; then
    wait "$MIGRATION_LOCK_PID" 2>/dev/null || true
  fi
  MIGRATION_LOCK_PID=""
  MIGRATION_LOCK_INPUT_FD=""
  MIGRATION_LOCK_OUTPUT_FD=""
}

acquire_migration_lock() {
  local line acquired=0 started="$SECONDS" last_heartbeat="$SECONDS"
  [[ "$MIGRATION_LOCK_WAIT_TIMEOUT" =~ ^[0-9]+$ ]] || {
    echo "[error] MIGRATION_LOCK_WAIT_TIMEOUT must be seconds" >&2; return 64;
  }

  coproc MIGRATION_LOCK_SESSION {
    run_psql -X -qAt -v ON_ERROR_STOP=1 -v MIGRATION_RUNNER_LOCK_HOLDER=1
  }
  MIGRATION_LOCK_PID="$MIGRATION_LOCK_SESSION_PID"
  MIGRATION_LOCK_OUTPUT_FD="${MIGRATION_LOCK_SESSION[0]}"
  MIGRATION_LOCK_INPUT_FD="${MIGRATION_LOCK_SESSION[1]}"
  trap release_migration_lock EXIT

  while [[ "$acquired" -eq 0 ]]; do
    printf '%s\n' \
      "SELECT CASE WHEN pg_try_advisory_lock(hashtextextended(current_database() || ':' || COALESCE(current_schema(), '') || ':jjdguard:migration-runner', 0)) THEN '__MIGRATION_RUNNER_LOCK_ACQUIRED__' ELSE '__MIGRATION_RUNNER_LOCK_BUSY__' END;" \
      >&"$MIGRATION_LOCK_INPUT_FD"

    if ! IFS= read -r line <&"$MIGRATION_LOCK_OUTPUT_FD"; then
      echo "[error] PostgreSQL migration advisory lock session closed unexpectedly" >&2
      release_migration_lock
      return 1
    fi

    case "$line" in
      __MIGRATION_RUNNER_LOCK_ACQUIRED__) acquired=1 ;;
      __MIGRATION_RUNNER_LOCK_BUSY__)
        if (( SECONDS - started >= MIGRATION_LOCK_WAIT_TIMEOUT )); then
          echo "[error] migration runner lock wait timed out after ${MIGRATION_LOCK_WAIT_TIMEOUT}s" >&2
          release_migration_lock
          return 75
        fi
        if (( SECONDS - last_heartbeat >= MIGRATION_HEARTBEAT_INTERVAL )); then
          echo "[heartbeat] state=waiting_lock object=migration_runner elapsed=$((SECONDS-started))s"
          last_heartbeat="$SECONDS"
        fi
        sleep 1
        ;;
      *)
        echo "[error] unexpected PostgreSQL migration advisory lock response: $line" >&2
        release_migration_lock
        return 1
        ;;
    esac
  done
  echo "[lock] migration runner advisory lock acquired elapsed=$((SECONDS-started))s"
}

sql_escape() {
  printf "%s" "$1" | sed "s/'/''/g"
}

checksum_file() {
  sha256sum "$1" | awk '{print $1}'
}

migration_application_name() {
  local version="$1" prefix identity
  prefix="${version%%_*}"
  identity="$(printf '%s' "$version" | sha256sum | awk '{print substr($1,1,12)}')"
  printf 'jjdguard-migration:%s:%s' "$prefix" "$identity"
}

is_excluded() {
  local name="$1"
  local pattern
  for pattern in "${EXCLUDES[@]}"; do
    case "$name" in
      $pattern) return 0 ;;
    esac
  done
  return 1
}

discover_migrations() {
  local file name prefix
  find "$MIGRATIONS_DIR" -maxdepth 1 -type f -name '*_*.sql' -print \
    | while IFS= read -r file; do
        name="$(basename "$file")"
        if migration_name_valid "$name" && ! is_excluded "$name"; then
          prefix="$(migration_number "$name")"
          printf '%s\t%s\n' "$prefix" "$file"
        fi
      done \
    | sort -t $'\t' -k1,1n -k2,2 \
    | cut -f2-
}

schema_migrations_exists() {
  local result
  result="$(run_psql -tAc "SELECT to_regclass('public.schema_migrations')")"
  [[ "$(printf '%s' "$result" | tr -d '[:space:]')" == "schema_migrations" ]]
}

schema_migrations_has_checksum() {
  local result
  result="$(run_psql -tAc "SELECT 1 FROM information_schema.columns WHERE table_schema = 'public' AND table_name = 'schema_migrations' AND column_name = 'checksum'")"
  [[ "$(printf '%s' "$result" | tr -d '[:space:]')" == "1" ]]
}

initdb_baseline_schema_exists() {
  local result
  result="$(run_psql -tAc "SELECT CASE WHEN to_regclass('public.tenants') IS NOT NULL AND to_regclass('public.users') IS NOT NULL AND to_regclass('public.projects') IS NOT NULL AND to_regclass('public.request_logs') IS NOT NULL AND to_regclass('public.audit_dispositions') IS NOT NULL AND to_regclass('public.proxy_usage_logs') IS NOT NULL AND to_regclass('public.ca_certificates') IS NOT NULL THEN 1 ELSE 0 END")"
  [[ "$(printf '%s' "$result" | tr -d '[:space:]')" == "1" ]]
}

schema_migrations_is_empty() {
  local result
  result="$(run_psql -tAc "SELECT CASE WHEN EXISTS (SELECT 1 FROM schema_migrations) THEN 0 ELSE 1 END")"
  [[ "$(printf '%s' "$result" | tr -d '[:space:]')" == "1" ]]
}

ensure_schema_migrations() {
  run_psql -v ON_ERROR_STOP=1 -c "
CREATE TABLE IF NOT EXISTS schema_migrations (
    version VARCHAR(255) PRIMARY KEY,
    checksum VARCHAR(64) NOT NULL DEFAULT '',
    applied_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);
ALTER TABLE schema_migrations
    ADD COLUMN IF NOT EXISTS checksum VARCHAR(64) NOT NULL DEFAULT '';
ALTER TABLE schema_migrations
    ADD COLUMN IF NOT EXISTS applied_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW();
" >/dev/null
  SCHEMA_MIGRATIONS_EXISTS=1
  SCHEMA_MIGRATIONS_HAS_CHECKSUM=1
}

ensure_migration_execution_status() {
  run_psql -v ON_ERROR_STOP=1 -c "
CREATE TABLE IF NOT EXISTS migration_execution_status (
    version VARCHAR(255) PRIMARY KEY,
    checksum VARCHAR(64) NOT NULL,
    status VARCHAR(32) NOT NULL CHECK (status IN (
      'pending','running','waiting_lock','committed','rollback_running',
      'failed','superseded','background_backfill'
    )),
    backend_pid INTEGER,
    application_name TEXT NOT NULL DEFAULT '',
    wait_event_type TEXT NOT NULL DEFAULT '',
    wait_event TEXT NOT NULL DEFAULT '',
    started_at TIMESTAMPTZ,
    heartbeat_at TIMESTAMPTZ,
    finished_at TIMESTAMPTZ,
    elapsed_seconds BIGINT NOT NULL DEFAULT 0,
    error_summary TEXT NOT NULL DEFAULT '',
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
" >/dev/null
}

mark_migration_status() {
  local version="$1" checksum="$2" state="$3" summary="${4:-}"
  local escaped_version escaped_checksum escaped_state escaped_summary escaped_application
  escaped_version="$(sql_escape "$version")"
  escaped_checksum="$(sql_escape "$checksum")"
  escaped_state="$(sql_escape "$state")"
  escaped_summary="$(sql_escape "${summary:0:500}")"
  escaped_application="$(sql_escape "$(migration_application_name "$version")")"
  run_psql -v ON_ERROR_STOP=1 -c "
INSERT INTO migration_execution_status(
 version,checksum,status,application_name,started_at,heartbeat_at,finished_at,error_summary
) VALUES (
 '$escaped_version','$escaped_checksum','$escaped_state',
 '$escaped_application',
 CASE WHEN '$escaped_state'='running' THEN NOW() ELSE NULL END,
 NOW(),CASE WHEN '$escaped_state' IN ('committed','failed','superseded') THEN NOW() ELSE NULL END,
 '$escaped_summary'
)
ON CONFLICT(version) DO UPDATE SET
 checksum=EXCLUDED.checksum,status=EXCLUDED.status,
 application_name=EXCLUDED.application_name,
 started_at=CASE WHEN EXCLUDED.status='running'
   THEN COALESCE(migration_execution_status.started_at,NOW())
   ELSE migration_execution_status.started_at END,
 heartbeat_at=NOW(),
 finished_at=CASE WHEN EXCLUDED.status IN ('committed','failed','superseded')
   THEN NOW() ELSE NULL END,
 elapsed_seconds=CASE WHEN migration_execution_status.started_at IS NULL THEN 0
   ELSE EXTRACT(EPOCH FROM (NOW()-migration_execution_status.started_at))::bigint END,
 error_summary=EXCLUDED.error_summary,updated_at=NOW();
" >/dev/null
}

migration_wait_snapshot() {
  local version="$1" escaped
  escaped="$(sql_escape "$(migration_application_name "$version")")"
  run_psql -X -qAt -c "
SELECT COALESCE(string_agg(
 'pid='||a.pid||' state='||a.state||
 ' wait='||COALESCE(a.wait_event_type||':'||a.wait_event,'none')||
 ' blockers='||COALESCE(array_to_string(pg_blocking_pids(a.pid),','),''),
 '; '),'no_active_backend')
FROM pg_stat_activity a
WHERE a.application_name='$escaped';" 2>/dev/null || printf '%s\n' diagnostic_unavailable
}

run_sql_with_heartbeat() {
  local file="$1" version="$2" started="$SECONDS" last_heartbeat="$SECONDS"
  local pid status snapshot
  run_psql -v ON_ERROR_STOP=1 <"$file" &
  pid=$!
  while kill -0 "$pid" 2>/dev/null; do
    sleep 0.1
    if (( SECONDS - last_heartbeat >= MIGRATION_HEARTBEAT_INTERVAL )); then
      snapshot="$(migration_wait_snapshot "$version")"
      if [[ "$snapshot" == *"wait=Lock:"* ]]; then
        mark_migration_status "$version" "$(checksum_file "$CURRENT_MIGRATION")" waiting_lock "$snapshot" || true
      else
        mark_migration_status "$version" "$(checksum_file "$CURRENT_MIGRATION")" running "$snapshot" || true
      fi
      echo "[heartbeat] migration=$version elapsed=$((SECONDS-started))s $snapshot"
      last_heartbeat="$SECONDS"
    fi
  done
  if wait "$pid"; then
    status=0
  else
    status=$?
  fi
  return "$status"
}

applied_checksum() {
  local version
  version="$(sql_escape "$1")"
  if [[ "$SCHEMA_MIGRATIONS_EXISTS" -eq 0 ]]; then
    return 20
  fi
  if [[ "$SCHEMA_MIGRATIONS_HAS_CHECKSUM" -eq 0 ]]; then
    if run_psql -tAc "SELECT 1 FROM schema_migrations WHERE version = '$version'" | grep -qx "1"; then
      printf '%s\n' "__EMPTY_CHECKSUM__"
    fi
    return 0
  fi
  run_psql -tAc "SELECT COALESCE(NULLIF(checksum, ''), '__EMPTY_CHECKSUM__') FROM schema_migrations WHERE version = '$version'"
}

backfill_checksum() {
  local version checksum escaped_version escaped_checksum
  version="$1"
  checksum="$2"
  escaped_version="$(sql_escape "$version")"
  escaped_checksum="$(sql_escape "$checksum")"
  run_psql -v ON_ERROR_STOP=1 -c "UPDATE schema_migrations SET checksum = '$escaped_checksum' WHERE version = '$escaped_version' AND COALESCE(checksum, '') = '';" >/dev/null
}

record_migration() {
  local version checksum escaped_version escaped_checksum
  version="$1"
  checksum="$2"
  escaped_version="$(sql_escape "$version")"
  escaped_checksum="$(sql_escape "$checksum")"
  run_psql -v ON_ERROR_STOP=1 -c "INSERT INTO schema_migrations (version, checksum, applied_at) VALUES ('$escaped_version', '$escaped_checksum', NOW()) ON CONFLICT (version) DO NOTHING;" >/dev/null
}

record_baseline_migration() {
  local file version checksum
  file="$1"
  version="$(basename "$file")"
  checksum="$(checksum_file "$file")"
  record_migration "$version" "$checksum"
}

is_initdb_baseline_migration() {
  local name prefix
  name="$(basename "$1")"
  prefix="${name%%_*}"
  migration_name_valid "$name" || return 1
  ((10#$prefix >= 1 && 10#$prefix <= 17))
}

baseline_initdb_migrations() {
  local file count=0
  # 用 FD 3 喂迁移清单：循环体内的 psql 读的是 FD 0，吞不到这条流，
  # 否则 docker exec -i / compose exec -T 会把剩余清单一口吃光，导致只处理第 1 个迁移。
  while IFS= read -r file <&3; do
    [[ -n "$file" ]] || continue
    if is_initdb_baseline_migration "$file"; then
      record_baseline_migration "$file"
      count=$((count + 1))
    fi
  done 3< <(discover_migrations)
  echo "[baseline] recorded initdb migrations through 017_audit_dispositions.sql (count=$count)"
}

strip_goose_down() {
  local file="$1"
  awk '
    /^[[:space:]]*--[[:space:]]*\+?goose[[:space:]]+Down([[:space:]]|$)/ { exit }
    { print }
  ' "$file"
}

uses_self_transaction() {
  local file="$1"
  grep -Eiq '^[[:space:]]*(BEGIN|COMMIT)[[:space:]]*;' "$file"
}

has_no_transaction_directive() {
  local file="$1"
  grep -Eiq '^[[:space:]]*--[[:space:]]*\+?goose[[:space:]]+NO[[:space:]]+TRANSACTION([[:space:]]|$)' "$file"
}

requires_no_outer_transaction() {
  local file="$1"
  grep -Eiq 'CREATE[[:space:]]+(UNIQUE[[:space:]]+)?INDEX[[:space:]]+CONCURRENTLY|REFRESH[[:space:]]+MATERIALIZED[[:space:]]+VIEW[[:space:]]+CONCURRENTLY|VACUUM|ALTER[[:space:]]+SYSTEM|CREATE[[:space:]]+DATABASE|DROP[[:space:]]+DATABASE|REINDEX' "$file"
}

apply_file_plain() {
  local file="$1" version="$2" input status=0
  input="$(mktemp)"
  trap 'rm -f -- "${input:-}"' RETURN
  # psql autocommit keeps each SQL statement atomic without an outer transaction.
  {
    printf "SET application_name = '%s';\n" "$(sql_escape "$(migration_application_name "$version")")"
    printf "SET lock_timeout = '%s';\n" "$(sql_escape "$MIGRATION_LOCK_TIMEOUT")"
    printf "SET statement_timeout = '%s';\n" "$(sql_escape "$MIGRATION_STATEMENT_TIMEOUT")"
    printf "SET idle_in_transaction_session_timeout = '%s';\n" "$(sql_escape "$MIGRATION_IDLE_TX_TIMEOUT")"
    strip_goose_down "$file"
  } >"$input"
  if run_sql_with_heartbeat "$input" "$version"; then status=0; else status=$?; fi
  rm -f -- "$input"
  trap - RETURN
  return "$status"
}

apply_file_transactional() {
  local file version checksum input status=0
  file="$1"
  version="$2"
  checksum="$3"
  input="$(mktemp)"
  trap 'rm -f -- "${input:-}"' RETURN
  {
    printf "SET application_name = '%s';\n" "$(sql_escape "$(migration_application_name "$version")")"
    printf "SET lock_timeout = '%s';\n" "$(sql_escape "$MIGRATION_LOCK_TIMEOUT")"
    printf "SET statement_timeout = '%s';\n" "$(sql_escape "$MIGRATION_STATEMENT_TIMEOUT")"
    printf "SET idle_in_transaction_session_timeout = '%s';\n" "$(sql_escape "$MIGRATION_IDLE_TX_TIMEOUT")"
    printf 'BEGIN;\n'
    strip_goose_down "$file"
    printf "\nINSERT INTO schema_migrations (version, checksum, applied_at) VALUES ('%s', '%s', NOW()) ON CONFLICT (version) DO NOTHING;\n" \
      "$(sql_escape "$version")" "$(sql_escape "$checksum")"
    printf 'COMMIT;\n'
  } >"$input"
  if run_sql_with_heartbeat "$input" "$version" >/dev/null; then status=0; else status=$?; fi
  rm -f -- "$input"
  trap - RETURN
  return "$status"
}

# 加载历史 checksum 白名单。
# 部分迁移文件在发布后被改动过，早期安装的客户库里 schema_migrations
# 记录的是旧 checksum，升级时会被 checksum 校验硬阻断。命中白名单即视为
# 「同一迁移的历史版本」并跳过执行。历史记账必须原样保留：正式离线
# 发版验收会核对升级前的 (version, checksum) 集合是升级后的子集，重写
# checksum 会破坏可审计链。白名单只放行已逐个核对的历史文件版本，不把
# 任意 mismatch 降级为可接受。
load_legacy_checksums() {
  [[ "$LEGACY_CHECKSUMS_LOADED" -eq 1 ]] && return 0
  LEGACY_CHECKSUMS_LOADED=1
  local f="$LEGACY_CHECKSUM_FILE"
  if [[ -z "$f" ]]; then
    f="$(dirname "${BASH_SOURCE[0]}")/legacy-migration-checksums.tsv"
  fi
  [[ -r "$f" ]] || return 0
  local line version ck
  while IFS= read -r line || [[ -n "$line" ]]; do
    [[ -z "$line" ]] && continue
    case "$line" in \#*) continue ;; esac
    version="${line%%$'\t'*}"
    ck="${line#*$'\t'}"
    [[ -z "$version" || -z "$ck" || "$version" == "$ck" ]] && continue
    ck="$(printf '%s' "$ck" | tr -d '[:space:]')"
    [[ -z "$ck" ]] && continue
    LEGACY_CHECKSUMS["${version}:${ck}"]=1
  done < "$f"
}

is_legacy_checksum() {
  local version="$1" recorded="$2"
  load_legacy_checksums
  [[ -n "${LEGACY_CHECKSUMS["${version}:${recorded}"]+x}" ]]
}

apply_migration() {
  local file version checksum recorded status
  file="$1"
  version="$(basename "$file")"
  checksum="$(checksum_file "$file")"
  CURRENT_MIGRATION="$file"
  recorded="$(applied_checksum "$version" | tr -d '[:space:]')"
  status=$?
  if [[ "$status" -eq 20 ]]; then
    recorded=""
    status=0
  fi
  if [[ "$status" -ne 0 ]]; then
    echo "[error] failed to read schema_migrations for $version" >&2
    return 4
  fi

  if [[ -n "$recorded" ]]; then
    if [[ "$recorded" == "__EMPTY_CHECKSUM__" ]]; then
      if [[ "$DRY_RUN" -eq 1 ]]; then
        echo "[skip] $version (legacy checksum would backfill)"
        return 10
      fi
      backfill_checksum "$version" "$checksum"
      status=$?
      if [[ "$status" -ne 0 ]]; then
        echo "[error] failed to backfill checksum for $version" >&2
        return "$status"
      fi
      echo "[skip] $version (legacy checksum recorded)"
      return 10
    fi
    if [[ "$recorded" != "$checksum" ]] && is_legacy_checksum "$version" "$recorded"; then
      [[ "$DRY_RUN" -eq 1 ]] || mark_migration_status "$version" "$recorded" superseded "accepted immutable legacy checksum"
      echo "[skip] $version (accepted immutable legacy checksum ${recorded:0:12})"
      return 10
    fi
    if [[ "$recorded" != "$checksum" ]]; then
      echo "[error] checksum mismatch for $version" >&2
      echo "[error] recorded=$recorded current=$checksum" >&2
      exit 2
    fi
    echo "[skip] $version (already applied)"
    [[ "$DRY_RUN" -eq 1 ]] || mark_migration_status "$version" "$checksum" committed
    return 10
  fi

  if [[ "$DRY_RUN" -eq 1 ]]; then
    echo "[dry-run] $version"
    return 11
  fi

  echo "[apply] $version"
  mark_migration_status "$version" "$checksum" running
  if uses_self_transaction "$file" || has_no_transaction_directive "$file" || requires_no_outer_transaction "$file"; then
    apply_file_plain "$file" "$version"
    status=$?
    if [[ "$status" -ne 0 ]]; then
      mark_migration_status "$version" "$checksum" failed "psql exit status $status" || true
      return "$status"
    fi
    record_migration "$version" "$checksum"
    status=$?
    if [[ "$status" -ne 0 ]]; then
      mark_migration_status "$version" "$checksum" failed "ledger write exit status $status" || true
      return "$status"
    fi
  else
    apply_file_transactional "$file" "$version" "$checksum"
    status=$?
    if [[ "$status" -ne 0 ]]; then
      mark_migration_status "$version" "$checksum" failed "transaction exit status $status" || true
      return "$status"
    fi
  fi
  mark_migration_status "$version" "$checksum" committed
  echo "[done] $version"
  return 12
}

main() {
  local applied=0 skipped=0 pending=0 file status should_baseline=0

  [[ "$MIGRATION_HEARTBEAT_INTERVAL" =~ ^[1-9][0-9]*$ ]] || {
    echo "[error] MIGRATION_HEARTBEAT_INTERVAL must be positive seconds" >&2; exit 64;
  }
  for value in "$MIGRATION_LOCK_TIMEOUT" "$MIGRATION_STATEMENT_TIMEOUT" "$MIGRATION_IDLE_TX_TIMEOUT"; do
    [[ "$value" =~ ^[1-9][0-9]*(ms|s|min|h)$ ]] || {
      echo "[error] invalid PostgreSQL timeout: $value" >&2; exit 64;
    }
  done

  if [[ "$DRY_RUN" -eq 0 ]]; then
    acquire_migration_lock
  fi

  if schema_migrations_exists; then
    SCHEMA_MIGRATIONS_EXISTS=1
    if schema_migrations_has_checksum; then
      SCHEMA_MIGRATIONS_HAS_CHECKSUM=1
    fi
  fi

  if [[ "$DRY_RUN" -eq 0 ]]; then
    if [[ "$SCHEMA_MIGRATIONS_EXISTS" -eq 0 ]] && initdb_baseline_schema_exists; then
      should_baseline=1
    fi
    ensure_schema_migrations
    ensure_migration_execution_status
    if [[ "$should_baseline" -eq 0 ]] && schema_migrations_is_empty && initdb_baseline_schema_exists; then
      should_baseline=1
    fi
    if [[ "$should_baseline" -eq 1 ]]; then
      baseline_initdb_migrations
    fi
  fi

  # 用 FD 3 喂迁移清单：apply_migration 内的 psql 读 FD 0，吞不到这条流（同 baseline 修复）。
  while IFS= read -r file <&3; do
    [[ -n "$file" ]] || continue
    set +e
    apply_migration "$file"
    status=$?
    set -e
    case "$status" in
      10) skipped=$((skipped + 1)) ;;
      11) pending=$((pending + 1)) ;;
      12) applied=$((applied + 1)) ;;
      2) exit 2 ;;
      4) exit 4 ;;
      *)
        echo "[error] migration failed at $(basename "$file")" >&2
        exit "$status"
        ;;
    esac
  done 3< <(discover_migrations)

  if [[ "$DRY_RUN" -eq 1 ]]; then
    echo "[ok] dry-run pending=$pending"
  else
    echo "[ok] applied=$applied skipped=$skipped"
  fi
}

main
