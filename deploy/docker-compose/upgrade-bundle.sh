#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COMPOSE_WRAPPER="${COMPOSE_WRAPPER:-$SCRIPT_DIR/compose-wrapper.sh}"
# 随包 judge 模型灌卷与安装器共用同一实现。只在需要灌卷时强制存在（见
# upgrade_load_judge_model），不让缺库的基础包在发现阶段之前就崩掉。
JUDGE_MODEL_LIB="$SCRIPT_DIR/../lib/judge-model-load.sh"
if [[ -r "$JUDGE_MODEL_LIB" ]]; then
  # shellcheck source=../lib/judge-model-load.sh
  . "$JUDGE_MODEL_LIB"
fi
# .env 里含空格且未加引号的值（如 REDIS_EXTRA_ARGS=--no-appendfsync-on-rewrite yes）：docker compose 能读，
# 但任何用 source 读 .env 的脚本（客户自己的脚本、旧版 jjdctl 等）会把它当命令执行（客户现场事故）。
# 本脚本按字面读 .env（parse_literal_dotenv_value），不受影响，所以这里只给警告、不改客户 .env。
JJD_ENV_LIB="$SCRIPT_DIR/../lib/jjd-env.sh"
if [[ -r "$JJD_ENV_LIB" ]]; then
  # shellcheck source=../lib/jjd-env.sh
  . "$JJD_ENV_LIB"
fi
warn_unquoted_env_whitespace() {
  declare -F jjd_env_warn_unquoted_whitespace >/dev/null || return 0
  jjd_env_warn_unquoted_whitespace "$1" || true
}
if [[ -r "$SCRIPT_DIR/../lib/migration-version.sh" ]]; then
  # shellcheck source=../lib/migration-version.sh
  . "$SCRIPT_DIR/../lib/migration-version.sh"
else
  migration_name_valid() { [[ "${1:-}" =~ ^[0-9]{3,}_[A-Za-z0-9_.-]+\.sql$ ]]; }
  migration_number() { local value="${1##*/}"; migration_name_valid "$value" || return 1; printf '%s\n' "$((10#${value%%_*}))"; }
  migration_version_lt() {
    local left="${1##*/}" right="${2##*/}" left_number right_number
    left_number="$(migration_number "$left")" || return 2
    right_number="$(migration_number "$right")" || return 2
    if (( left_number != right_number )); then (( left_number < right_number )); else [[ "$left" < "$right" ]]; fi
  }
  migration_latest_sql() {
    printf '%s\n' "SELECT COALESCE((SELECT version FROM schema_migrations WHERE version ~ '^[0-9]{3,}_[A-Za-z0-9_.-]+[.]sql$' ORDER BY split_part(version, '_', 1)::bigint DESC, version DESC LIMIT 1), '')"
  }
fi
# Some contract tests exercise a standalone copy of this script. Keep the
# exact safe gate available even when the release support file is not copied.
if [[ -r "$SCRIPT_DIR/customer-environment-scope-repair-lib.sh" ]]; then
  # shellcheck source=customer-environment-scope-repair-lib.sh
  . "$SCRIPT_DIR/customer-environment-scope-repair-lib.sh"
else
  customer_environment_scope_repair_enabled() {
    [[ "${GATEWAY_ENVIRONMENT_SCOPE-}" == customer ]]
  }
fi
# Redis 7.4 -> Valkey 8.1: logical copy of the must-keep keys (Valkey cannot read RDB v12).
if [[ -r "$SCRIPT_DIR/redis-valkey-migrate-lib.sh" ]]; then
  # shellcheck source=redis-valkey-migrate-lib.sh
  . "$SCRIPT_DIR/redis-valkey-migrate-lib.sh"
fi
UPGRADE_FAILURE_HANDLED=0
UPGRADE_EXIT_GUARD_ACTIVE=0
DATABASE_REPAIR_STARTED=0
DATABASE_MUTATION_STARTED=0
SERVICES_QUIESCED=0
UPGRADE_VERIFY_KEY_ID=""
UPGRADE_VERIFY_PROJECT_ID=""
UPGRADE_VERIFY_PROJECT_CODE=""
UPGRADE_VERIFY_PG_CONTAINER=""
UPGRADE_VERIFY_PGUSER=""
UPGRADE_VERIFY_PGDATABASE=""
UPGRADE_VERIFY_PROVIDER_ID=""
UPGRADE_VERIFY_CREDENTIAL_ID=""
UPGRADE_VERIFY_MODEL_ID=""
UPGRADE_VERIFY_OVERRIDE_ID=""
UPGRADE_VERIFY_MODEL_NAME=""
UPGRADE_VERIFY_PROVIDER_NAME=""
UPGRADE_VERIFY_CREDENTIAL_NAME=""
UPGRADE_VERIFY_KEY_HASH=""
UPGRADE_VERIFY_KEY_PREFIX=""
UPGRADE_VERIFY_CLEANUP_ARMED=0
DEVELOPMENT_ROLLBACK_PROOF=""
DEVELOPMENT_ROLLBACK_IMAGE=""
DEVELOPMENT_NORMALIZED_CONFIG=0
UPGRADE_BRIDGE_REQUIRED=0
UPGRADE_SOURCE_DATA_VERSION=""
UNINHERITED_BOOT_OVERRIDES=()

fail() {
  echo "[error] $*" >&2
  exit 1
}

# --- Tier-1 topology persisted by tier1-scale.sh --apply ---------------------
# Without this the upgrade rebuilt tier1 from the base compose file: a scaled-out
# install dropped back to one replica and a GPU host came up on the CPU image,
# while the single-replica /health verdict still said within_limit.
TIER1_TOPOLOGY_LIB="$SCRIPT_DIR/tier1-topology.sh"
[[ -r "$TIER1_TOPOLOGY_LIB" ]] || fail "missing shared Tier-1 topology library: $TIER1_TOPOLOGY_LIB"
# shellcheck source=tier1-topology.sh
. "$TIER1_TOPOLOGY_LIB"
TIER1_GPU_PREFLIGHT_DONE=0

# Overlay path for the topology recorded in an env file; empty when unscaled.
tier1_bundle_overlay() {
  local compose_dir="$1" env_file="$2" mode overlay
  mode="$(tier1_scale_mode "$env_file")" || fail "TIER1_SCALE_MODE in $env_file must be empty, cpu or gpu"
  overlay="$(tier1_scale_overlay "$compose_dir" "$mode")"
  if [[ -z "$overlay" ]]; then
    return 0
  fi
  [[ -f "$overlay" && ! -L "$overlay" ]] || fail "missing Tier-1 overlay for TIER1_SCALE_MODE=$mode: $overlay"
  # Validate the replica count here, in the caller's shell: the --scale flags are
  # built in a process substitution below, where a `fail` would only abort the
  # subshell and let the upgrade continue unscaled.
  tier1_replicas "$env_file" >/dev/null || fail "TIER1_REPLICAS in $env_file must be 1..32"
  printf '%s' "$overlay"
}

# "--scale" only belongs to `up`, so it is returned separately from the -f list.
tier1_bundle_scale_flags() {
  local env_file="$1" mode replicas
  mode="$(tier1_scale_mode "$env_file")" || fail "TIER1_SCALE_MODE in $env_file must be empty, cpu or gpu"
  if [[ -z "$mode" ]]; then
    return 0
  fi
  replicas="$(tier1_replicas "$env_file")" || fail "TIER1_REPLICAS in $env_file must be 1..32"
  printf '%s\n%s\n' --scale "tier1-classifier=$replicas"
}

# A GPU install must never fall back to the CPU image during an upgrade. Same
# preconditions tier1-scale.sh applies when it first rises into GPU mode.
tier1_bundle_gpu_preflight() {
  [[ "$TIER1_GPU_PREFLIGHT_DONE" == 1 ]] && return 0
  if [[ "$(tier1_scale_mode "$SCRIPT_DIR/.env")" == gpu ]]; then
    if ! tier1_gpu_preflight "$(tier1_env_value "$SCRIPT_DIR/.env" TIER1_GPU_IMAGE)"; then
      fail "GPU Tier-1 preflight failed; refusing to upgrade. Fix the GPU stack, or run 'tier1-scale.sh reset --apply' to return to CPU."
    fi
  fi
  TIER1_GPU_PREFLIGHT_DONE=1
  return 0
}

log() {
  printf '[%s] %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$*"
}

normalize_config_files() {
  local work_dir="$1" raw="$2" entry resolved normalized=""
  local -a entries=()
  : "$work_dir"
  [[ -n "$raw" && "$raw" != "<no value>" ]] || return 1
  [[ "$raw" != *$'\n'* && "$raw" != *$'\r'* ]] || return 1
  case "$raw" in ,*|*,|*,,*) return 1 ;; esac

  IFS=',' read -ra entries <<<"$raw"
  (( ${#entries[@]} > 0 )) || return 1
  for entry in "${entries[@]}"; do
    [[ -n "$entry" && "$entry" == /* ]] || return 1
    [[ "$entry" != *$'\n'* && "$entry" != *$'\r'* ]] || return 1
    [[ ! -L "$entry" && -f "$entry" ]] || return 1
    resolved="$(realpath -e -- "$entry")" || return 1
    [[ -f "$resolved" ]] || return 1
    validate_config_policy "$(realpath -e -- "$work_dir")" "$resolved" || return 1
    normalized="${normalized:+$normalized,}$resolved"
  done
  [[ -n "$normalized" ]] || return 1
  printf '%s\n' "$normalized"
}

config_file_fingerprint() {
  local path="$1" metadata digest
  [[ "$path" == /* && "$path" != *'|'* && "$path" != *$'\n'* && "$path" != *$'\r'* ]] || return 1
  [[ ! -L "$path" && -f "$path" ]] || return 1
  metadata="$(stat -Lc '%d|%i|%u|%a|%s|%h' -- "$path")" || return 1
  digest="$(sha256sum -- "$path" | awk '{print $1}')" || return 1
  [[ "$digest" =~ ^[0-9a-f]{64}$ ]] || return 1
  printf '%s|%s|%s\n' "$path" "$metadata" "$digest"
}

validate_config_policy() {
  local work_real="$1" path="$2" uid gid mode links parent parent_uid parent_mode group other
  local owner_uid="${EXISTING_CONFIG_OWNER_UID:-$(id -u)}"
  local owner_gid="${EXISTING_CONFIG_OWNER_GID:-$(id -g)}"
  local trusted_root="${EXISTING_CONFIG_ROOT:-$work_real}"
  uid="$(stat -Lc %u -- "$path")" || return 1
  gid="$(stat -Lc %g -- "$path")" || return 1
  mode="$(stat -Lc %a -- "$path")" || return 1
  links="$(stat -Lc %h -- "$path")" || return 1
  # 兼容历史 home 部署：配置可能由最初部署用户拥有，并使用该用户的
  # 私有同名组写权限。源文件会立即复制到 root 私有快照，切换与回滚
  # 只使用快照；其他用户可写、跨 JJDGuard 根目录和符号链接仍拒绝。
  [[ "$uid" == 0 || "$uid" == "$owner_uid" ]] || return 1
  group="${mode: -2:1}"
  other="${mode: -1}"
  case "$group" in
    2|3|6|7) [[ "$uid" == "$owner_uid" && "$gid" == "$owner_gid" ]] || return 1 ;;
  esac
  case "$other" in 2|3|6|7) return 1 ;; esac
  case "$path" in "$work_real"/*|"$trusted_root"/*) return 0 ;; esac
  if [[ "$path" =~ ^/.*/deploy/docker-compose/backups/[0-9]{8}T[0-9]{6}Z/rollback-compose\.yml$ ]]; then
    :
  elif [[ "$path" =~ ^/.*/deploy/docker-compose/backups/\.config-snapshot\.[A-Za-z0-9]{6}/config-[0-9]{3}\.yml$ ]]; then
    :
  else
    return 1
  fi
  parent="${path%/*}"
  parent_uid="$(stat -Lc %u -- "$parent")" || return 1
  parent_mode="$(stat -Lc %a -- "$parent")" || return 1
  [[ "$uid" == "$parent_uid" && ( "$uid" == 0 || "$uid" == "$(id -u)" ) ]] || return 1
  [[ "$mode" == 600 && "$parent_mode" == 700 && "$links" == 1 ]] || return 1
}

validate_env_source_policy() {
  local path="$1" uid mode links parent parent_uid parent_mode group other
  local owner_uid="${EXISTING_CONFIG_OWNER_UID:-$(id -u)}"
  [[ "$path" == /* && ! -L "$path" && -f "$path" ]] || return 1
  uid="$(stat -Lc %u -- "$path")"; mode="$(stat -Lc %a -- "$path")"; links="$(stat -Lc %h -- "$path")" || return 1
  [[ ( "$uid" == 0 || "$uid" == "$owner_uid" ) && "$links" == 1 ]] || return 1
  group="${mode: -2:1}"; other="${mode: -1}"
  case "$group$other" in *[2367]*) return 1 ;; esac
  if [[ "$path" =~ ^/.*/deploy/docker-compose/backups/\.config-snapshot\.[A-Za-z0-9]{6}/snapshot-env$ ]]; then
    parent="${path%/*}"
    parent_uid="$(stat -Lc %u -- "$parent")"; parent_mode="$(stat -Lc %a -- "$parent")" || return 1
    [[ "$uid" == "$parent_uid" && "$mode" == 600 && "$parent_mode" == 700 ]] || return 1
  fi
}

normalize_environment_file() {
  local work_real="$1" raw="$2" resolved
  if [[ -z "$raw" || "$raw" == "<no value>" ]]; then raw="$work_real/.env"; fi
  [[ "$raw" == /* && "$raw" != *,* && "$raw" != *$'\n'* && "$raw" != *$'\r'* ]] || return 1
  [[ ! -L "$raw" && -f "$raw" ]] || return 1
  resolved="$(realpath -e -- "$raw")" || return 1
  [[ "$raw" == "$resolved" ]] || return 1
  if [[ "$resolved" == "$work_real/.env" ]]; then
    :
  elif [[ "$resolved" =~ ^/.*/deploy/docker-compose/backups/\.config-snapshot\.[A-Za-z0-9]{6}/snapshot-env$ ]]; then
    :
  else
    return 1
  fi
  validate_env_source_policy "$resolved" || return 1
  printf '%s\n' "$resolved"
}

after_config_policy_hook() { :; }

open_source_fingerprint() {
  local fd_path="$1" metadata digest
  metadata="$(stat -Lc '%d|%i|%u|%a|%s|%h|%F' -- "$fd_path")" || return 1
  digest="$(sha256sum -- "$fd_path" | awk '{print $1}')" || return 1
  [[ "$digest" =~ ^[0-9a-f]{64}$ ]] || return 1
  printf '%s|%s\n' "$metadata" "$digest"
}

copy_trusted_source_to_snapshot() {
  local work_real="$1" source="$2" snapshot="$3" policy_kind="${4:-config}"
  local initial_identity path_identity fd_identity fd_path before after snapshot_fingerprint
  local fd_uid fd_gid fd_mode fd_links group other source_identity snapshot_identity
  local owner_uid="${EXISTING_CONFIG_OWNER_UID:-$(id -u)}"
  local owner_gid="${EXISTING_CONFIG_OWNER_GID:-$(id -g)}"
  [[ "$source" == /* && ! -L "$source" && -f "$source" ]] || return 1
  initial_identity="$(stat -Lc '%d:%i' -- "$source")" || return 1
  if [[ "$policy_kind" == env ]]; then validate_env_source_policy "$source" || return 1
  else validate_config_policy "$work_real" "$source" || return 1; fi
  after_config_policy_hook "$source" || return 1
  exec 9<"$source" || return 1
  fd_path="/proc/self/fd/9"
  [[ -r "$fd_path" && ! -L "$source" && -f "$source" ]] || { exec 9<&-; return 1; }
  path_identity="$(stat -Lc '%d:%i' -- "$source")" || { exec 9<&-; return 1; }
  fd_identity="$(stat -Lc '%d:%i' -- "$fd_path")" || { exec 9<&-; return 1; }
  [[ "$path_identity" == "$initial_identity" && "$fd_identity" == "$initial_identity" ]] || { exec 9<&-; return 1; }
  if [[ "$policy_kind" == env ]]; then validate_env_source_policy "$source" || { exec 9<&-; return 1; }
  else validate_config_policy "$work_real" "$source" || { exec 9<&-; return 1; }; fi
  fd_uid="$(stat -Lc %u -- "$fd_path")"; fd_gid="$(stat -Lc %g -- "$fd_path")"; fd_mode="$(stat -Lc %a -- "$fd_path")"; fd_links="$(stat -Lc %h -- "$fd_path")" || { exec 9<&-; return 1; }
  group="${fd_mode: -2:1}"; other="${fd_mode: -1}"
  [[ -f "$fd_path" && ( "$fd_uid" == 0 || "$fd_uid" == "$owner_uid" ) && "$fd_links" == 1 ]] || { exec 9<&-; return 1; }
  case "$group" in
    2|3|6|7) [[ "$fd_uid" == "$owner_uid" && "$fd_gid" == "$owner_gid" ]] || { exec 9<&-; return 1; } ;;
  esac
  case "$other" in 2|3|6|7) exec 9<&-; return 1 ;; esac
  before="$(open_source_fingerprint "$fd_path")" || { exec 9<&-; return 1; }
  cp --reflink=never -- "$fd_path" "$snapshot" || { exec 9<&-; return 1; }
  chmod 0600 "$snapshot" || { exec 9<&-; return 1; }
  after="$(open_source_fingerprint "$fd_path")" || { exec 9<&-; return 1; }
  [[ "$after" == "$before" ]] || { exec 9<&-; return 1; }
  snapshot_fingerprint="$(config_file_fingerprint "$snapshot")" || { exec 9<&-; return 1; }
  source_identity="$fd_identity"; snapshot_identity="$(stat -Lc '%d:%i' -- "$snapshot")" || { exec 9<&-; return 1; }
  [[ "$snapshot_identity" != "$source_identity" && "$(stat -Lc %h -- "$snapshot")" == 1 && "${snapshot_fingerprint##*|}" == "${before##*|}" ]] || { exec 9<&-; return 1; }
  exec 9<&-
  COPIED_SOURCE_FINGERPRINT="$before"
}

capture_config_identities() {
  local csv="$1" entry fingerprint identities=""
  local -a entries=()
  IFS=',' read -ra entries <<<"$csv"
  for entry in "${entries[@]}"; do
    fingerprint="$(config_file_fingerprint "$entry")" || return 1
    identities="${identities:+$identities
}$fingerprint"
  done
  EXISTING_CONFIG_IDENTITIES="$identities"
  export EXISTING_CONFIG_IDENTITIES
}

validate_config_identities() {
  local expected="${EXISTING_CONFIG_IDENTITIES:-}" current
  [[ -n "$expected" ]] || return 1
  capture_config_identities "$EXISTING_CONFIG_FILES" || return 1
  current="$EXISTING_CONFIG_IDENTITIES"
  EXISTING_CONFIG_IDENTITIES="$expected"
  export EXISTING_CONFIG_IDENTITIES
  [[ "$current" == "$expected" ]]
}

create_config_snapshots() {
  local entry snapshot work_real env_source
  local index=0 snapshots=""
  local -a entries=()
  work_real="$(realpath -e -- "$EXISTING_WORK_DIR")" || return 1
  env_source="${EXISTING_ENV_FILE:-}"
  [[ -n "$env_source" && ! -L "$env_source" && -f "$env_source" ]] || return 1
  validate_env_source_policy "$env_source" || return 1
  mkdir -p -m 0700 -- "$SCRIPT_DIR/backups" || return 1
  OLD_CONFIG_SNAPSHOT_DIR="$(mktemp -d "$SCRIPT_DIR/backups/.config-snapshot.XXXXXX")" || return 1
  chmod 0700 "$OLD_CONFIG_SNAPSHOT_DIR" || return 1
  IFS=',' read -ra entries <<<"$EXISTING_CONFIG_FILES"
  for entry in "${entries[@]}"; do
    snapshot="$OLD_CONFIG_SNAPSHOT_DIR/config-$(printf '%03d' "$index").yml"
    copy_trusted_source_to_snapshot "$work_real" "$entry" "$snapshot" || return 1
    snapshots="${snapshots:+$snapshots,}$snapshot"
    index=$((index + 1))
  done
  OLD_ENV_SNAPSHOT_FILE="$OLD_CONFIG_SNAPSHOT_DIR/snapshot-env"
  copy_trusted_source_to_snapshot "$work_real" "$env_source" "$OLD_ENV_SNAPSHOT_FILE" env || return 1
  OLD_ENV_SNAPSHOT_IDENTITY="$(config_file_fingerprint "$OLD_ENV_SNAPSHOT_FILE")" || return 1
  OLD_CONFIG_SNAPSHOT_FILES="$snapshots"
  capture_config_identities "$OLD_CONFIG_SNAPSHOT_FILES" || return 1
  export OLD_CONFIG_SNAPSHOT_DIR OLD_CONFIG_SNAPSHOT_FILES EXISTING_CONFIG_IDENTITIES OLD_ENV_SNAPSHOT_FILE OLD_ENV_SNAPSHOT_IDENTITY
}

validate_config_snapshots() {
  local dir_uid dir_mode entry uid mode links expected current env_current
  local -a entries=()
  [[ -n "${OLD_CONFIG_SNAPSHOT_DIR:-}" && -d "$OLD_CONFIG_SNAPSHOT_DIR" && ! -L "$OLD_CONFIG_SNAPSHOT_DIR" ]] || return 1
  dir_uid="$(stat -Lc %u -- "$OLD_CONFIG_SNAPSHOT_DIR")"; dir_mode="$(stat -Lc %a -- "$OLD_CONFIG_SNAPSHOT_DIR")" || return 1
  [[ ( "$dir_uid" == 0 || "$dir_uid" == "$(id -u)" ) && "$dir_mode" == 700 ]] || return 1
  expected="${EXISTING_CONFIG_IDENTITIES:-}"; [[ -n "$expected" ]] || return 1
  IFS=',' read -ra entries <<<"$OLD_CONFIG_SNAPSHOT_FILES"
  for entry in "${entries[@]}"; do
    [[ "${entry%/*}" == "$OLD_CONFIG_SNAPSHOT_DIR" && ! -L "$entry" && -f "$entry" ]] || return 1
    uid="$(stat -Lc %u -- "$entry")"; mode="$(stat -Lc %a -- "$entry")"; links="$(stat -Lc %h -- "$entry")" || return 1
    [[ ( "$uid" == 0 || "$uid" == "$(id -u)" ) && "$mode" == 600 && "$links" == 1 ]] || return 1
  done
  capture_config_identities "$OLD_CONFIG_SNAPSHOT_FILES" || return 1
  current="$EXISTING_CONFIG_IDENTITIES"; EXISTING_CONFIG_IDENTITIES="$expected"; export EXISTING_CONFIG_IDENTITIES
  [[ "$current" == "$expected" ]] || return 1
  [[ "${OLD_ENV_SNAPSHOT_FILE:-}" == "$OLD_CONFIG_SNAPSHOT_DIR/snapshot-env" && ! -L "$OLD_ENV_SNAPSHOT_FILE" && -f "$OLD_ENV_SNAPSHOT_FILE" ]] || return 1
  uid="$(stat -Lc %u -- "$OLD_ENV_SNAPSHOT_FILE")"; mode="$(stat -Lc %a -- "$OLD_ENV_SNAPSHOT_FILE")"; links="$(stat -Lc %h -- "$OLD_ENV_SNAPSHOT_FILE")" || return 1
  [[ ( "$uid" == 0 || "$uid" == "$(id -u)" ) && "$mode" == 600 && "$links" == 1 ]] || return 1
  env_current="$(config_file_fingerprint "$OLD_ENV_SNAPSHOT_FILE")" || return 1
  [[ "$env_current" == "${OLD_ENV_SNAPSHOT_IDENTITY:-}" ]]
}

cleanup_config_snapshot() {
  local dir="${OLD_CONFIG_SNAPSHOT_DIR:-}" base entry
  local -a snapshot_entries=()
  [[ -n "$dir" ]] || return 0
  base="${dir##*/}"
  [[ "$dir" == "$SCRIPT_DIR/backups/$base" && "$base" =~ ^\.config-snapshot\.[A-Za-z0-9]{6}$ ]] || return 1
  [[ ! -L "$dir" ]] || return 1
  [[ ! -e "$dir" || -d "$dir" ]] || return 1
  shopt -s nullglob
  snapshot_entries=("$dir"/config-[0-9][0-9][0-9].yml)
  shopt -u nullglob
  if [[ -e "$dir/snapshot-env" || -L "$dir/snapshot-env" ]]; then snapshot_entries+=("$dir/snapshot-env"); fi
  for entry in "${snapshot_entries[@]}"; do
    [[ "${entry%/*}" == "$dir" && ! -L "$entry" && -f "$entry" ]] || return 1
    rm -f -- "$entry" || return 1
  done
  rmdir -- "$dir" || return 1
  OLD_CONFIG_SNAPSHOT_DIR=""
  OLD_CONFIG_SNAPSHOT_FILES=""
  OLD_ENV_SNAPSHOT_FILE=""
  OLD_ENV_SNAPSHOT_IDENTITY=""
  EXISTING_CONFIG_IDENTITIES=""
  export OLD_CONFIG_SNAPSHOT_DIR OLD_CONFIG_SNAPSHOT_FILES EXISTING_CONFIG_IDENTITIES OLD_ENV_SNAPSHOT_FILE OLD_ENV_SNAPSHOT_IDENTITY
}

main_snapshot_exit_handler() {
  local status="$1"
  trap - EXIT
  if [[ "${IMAGE_SWITCH_STARTED:-0}" != 1 ]]; then
    cleanup_config_snapshot || echo "[error] 清理原部署 Compose 配置快照失败：${OLD_CONFIG_SNAPSHOT_DIR:-<unknown>}" >&2
  fi
  exit "$status"
}

read_container_metadata() {
  docker inspect --format \
    '{{ index .Config.Labels "com.docker.compose.project" }}|{{ index .Config.Labels "com.docker.compose.project.working_dir" }}|{{ index .Config.Labels "com.docker.compose.project.config_files" }}|{{ index .Config.Labels "com.docker.compose.project.environment_file" }}|{{ .Config.Image }}' \
    "$1"
}

read_gateway_state_and_metadata() {
  docker inspect --format \
    '{{ .State.Running }}|{{ index .Config.Labels "com.docker.compose.project" }}|{{ index .Config.Labels "com.docker.compose.project.working_dir" }}|{{ index .Config.Labels "com.docker.compose.project.config_files" }}|{{ index .Config.Labels "com.docker.compose.project.environment_file" }}|{{ .Config.Image }}' \
    "$1"
}

strict_rollback_override_matches_digest() {
  local file="$1" expected="$2" line service="" image found=0 count=0 expected_fingerprint before after fd_path judge_env=0
  declare -A seen=()
  validate_config_snapshots || return 1
  while IFS= read -r line; do
    if [[ "$line" == "$file|"* ]]; then expected_fingerprint="${line#"$file|"}"; break; fi
  done <<<"$EXISTING_CONFIG_IDENTITIES"
  [[ -n "$expected_fingerprint" ]] || return 1
  exec 8<"$file" || return 1
  fd_path="/proc/self/fd/8"
  before="$(stat -Lc '%d|%i|%u|%a|%s|%h' -- "$fd_path")|$(sha256sum -- "$fd_path" | awk '{print $1}')" || { exec 8<&-; return 1; }
  [[ "$before" == "$expected_fingerprint" ]] || { exec 8<&-; return 1; }
  IFS= read -r line <&8 || { exec 8<&-; return 1; }
  [[ "$line" == "services:" ]] || { exec 8<&-; return 1; }
  while IFS= read -r line <&8 || [[ -n "$line" ]]; do
    if [[ "$line" =~ ^[[:space:]][[:space:]]([a-zA-Z0-9][a-zA-Z0-9._-]*):$ ]]; then
      service="${BASH_REMATCH[1]}"
      IFS= read -r line <&8 || { exec 8<&-; return 1; }
      [[ "$line" =~ ^[[:space:]]{4}image:[[:space:]](sha256:[0-9a-f]{64})$ ]] || { exec 8<&-; return 1; }
      image="${BASH_REMATCH[1]}"
    elif [[ "$line" == "    environment:" && "${service:-}" == llm-judge && "$judge_env" == 0 ]]; then
      # jjdctl rollback keeps the judge on the current release's model because
      # upgrades retire the legacy GGUF; accept exactly that one pinned key.
      IFS= read -r line <&8 || { exec 8<&-; return 1; }
      [[ "$line" =~ ^[[:space:]]{6}JUDGE_MODEL_PATH:[[:space:]]/models/[A-Za-z0-9][A-Za-z0-9._-]*\.gguf$ ]] || { exec 8<&-; return 1; }
      judge_env=1
      continue
    elif [[ "$line" =~ ^[[:space:]][[:space:]]([a-zA-Z0-9][a-zA-Z0-9._-]*):[[:space:]]\{image:[[:space:]](sha256:[0-9a-f]{64})\}$ ]]; then
      # jjdctl versions before the multiline writer used this exact inline form.
      service="${BASH_REMATCH[1]}"
      image="${BASH_REMATCH[2]}"
    else
      exec 8<&-
      return 1
    fi
    valid_service_name "$service" || { exec 8<&-; return 1; }
    [[ -z "${seen[$service]+x}" ]] || { exec 8<&-; return 1; }
    seen[$service]=1
    [[ "$service" != gateway-core || "$image" != "$expected" ]] || found=1
    count=$((count + 1))
  done
  after="$(stat -Lc '%d|%i|%u|%a|%s|%h' -- "$fd_path")|$(sha256sum -- "$fd_path" | awk '{print $1}')" || { exec 8<&-; return 1; }
  exec 8<&-
  [[ "$after" == "$before" ]] && (( count > 0 && found == 1 ))
}

validate_digest_from_historical_rollback() {
  local expected="$1" source snapshot original source_hash original_hash matches=0 matched=0 index=0
  local -a sources=() snapshots=()
  IFS=',' read -ra sources <<<"$EXISTING_CONFIG_FILES"
  IFS=',' read -ra snapshots <<<"$OLD_CONFIG_SNAPSHOT_FILES"
  (( ${#sources[@]} == ${#snapshots[@]} )) || return 1
  for source in "${sources[@]}"; do
    snapshot="${snapshots[$index]}"
    if [[ "$source" =~ ^/.*/deploy/docker-compose/backups/[0-9]{8}T[0-9]{6}Z/rollback-compose\.yml$ ]]; then
      matches=$((matches + 1))
      strict_rollback_override_matches_digest "$snapshot" "$expected" && matched=$((matched + 1))
    elif validate_digest_from_jjdctl_rollback "$expected" "$source" "$snapshot"; then
      matches=$((matches + 1))
      matched=$((matched + 1))
    elif [[ "$source" =~ ^(.*/deploy/docker-compose/backups/([0-9]{8}T[0-9]{6}Z))/legacy-release/deploy/docker-compose/active-config/([0-9]{8}T[0-9]{6}Z)/rollback-images\.override\.yml$ ]] &&
         [[ "${BASH_REMATCH[2]}" == "${BASH_REMATCH[3]}" ]]; then
      original="${BASH_REMATCH[1]}/rollback-compose.yml"
      if validate_config_policy "$EXISTING_WORK_DIR" "$original"; then
        source_hash="$(sha256sum -- "$source" | awk '{print $1}')"
        original_hash="$(sha256sum -- "$original" | awk '{print $1}')"
        if [[ "$source_hash" =~ ^[0-9a-f]{64}$ && "$source_hash" == "$original_hash" ]]; then
          matches=$((matches + 1))
          strict_rollback_override_matches_digest "$snapshot" "$expected" && matched=$((matched + 1))
        fi
      fi
    fi
    index=$((index + 1))
  done
  (( matches == 1 && matched == 1 ))
}

validate_digest_from_jjdctl_rollback() {
  local expected="$1" source="$2" snapshot="$3"
  local state=/etc/jjdguard/last-upgrade.env previous_release current_release backup gateway
  local source_hash snapshot_hash
  [[ "$source" == "$EXISTING_WORK_DIR/.upgrade/compose.upgrade.yml" ]] || return 1
  [[ -f "$state" && ! -L "$state" ]] || return 1
  [[ "$(stat -Lc %u -- "$state" 2>/dev/null || true)" == 0 && "$(stat -Lc %a -- "$state" 2>/dev/null || true)" == 600 ]] || return 1
  previous_release="$(sed -n 's/^PREVIOUS_RELEASE=//p' "$state" | head -1)"
  current_release="$(sed -n 's/^CURRENT_RELEASE=//p' "$state" | head -1)"
  backup="$(sed -n 's/^BACKUP_FILE=//p' "$state" | head -1)"
  gateway="$(sed -n 's/^GATEWAY_CORE_IMAGE=//p' "$state" | head -1)"
  [[ "$(realpath -e -- "$previous_release/deploy/docker-compose" 2>/dev/null || true)" == "$EXISTING_WORK_DIR" ]] || return 1
  [[ "$previous_release" == /opt/jjdguard/releases/*/deploy/docker-compose/backups/*/legacy-release ]] || return 1
  [[ "$current_release" == /opt/jjdguard/releases/* ]] || return 1
  [[ "$backup" == "$current_release/deploy/docker-compose/backups/"* && -s "$backup" && ! -L "$backup" ]] || return 1
  [[ "$gateway" == "$expected" ]] || return 1
  [[ -f "$source" && ! -L "$source" && -f "$snapshot" && ! -L "$snapshot" ]] || return 1
  source_hash="$(sha256sum -- "$source" | awk '{print $1}')" || return 1
  snapshot_hash="$(sha256sum -- "$snapshot" | awk '{print $1}')" || return 1
  [[ "$source_hash" =~ ^[0-9a-f]{64}$ && "$source_hash" == "$snapshot_hash" ]] || return 1
  strict_rollback_override_matches_digest "$snapshot" "$expected"
}

development_normalized_config_matches_receipt() {
  local receipt="$1" release_id="$2" source snapshot expected_hash
  local -a sources=() snapshots=()
  IFS=',' read -ra sources <<<"$EXISTING_CONFIG_FILES"
  IFS=',' read -ra snapshots <<<"$OLD_CONFIG_SNAPSHOT_FILES"
  (( ${#sources[@]} == 1 && ${#snapshots[@]} == 1 )) || return 1
  source="${sources[0]}"
  snapshot="${snapshots[0]}"
  [[ "$source" == "$EXISTING_WORK_DIR/active-config/$release_id.json" ]] || return 1
  [[ -f "$snapshot" && ! -L "$snapshot" ]] || return 1
  [[ "$(grep -Ec '"compose_sha256"[[:space:]]*:' "$receipt")" == 1 ]] || return 1
  expected_hash="$(sed -n 's/.*"compose_sha256"[[:space:]]*:[[:space:]]*"\([0-9a-f]\{64\}\)".*/\1/p' "$receipt" | head -1)"
  [[ "$expected_hash" =~ ^[0-9a-f]{64}$ && "$expected_hash" == "$(sha256_file "$snapshot")" ]]
}

validate_digest_from_development_receipt() {
  local expected="$1" receipt_dir="$SCRIPT_DIR/.upgrade/development-receipt"
  local index receipt receipt_hash expected_hash actual_hash release release_id receipt_release_id status version gateway backup
  local lock=/opt/jjdguard/development-releases/.release.lock
  [[ "$expected" =~ ^sha256:[0-9a-f]{64}$ ]] || return 1
  [[ -d "$receipt_dir" && ! -L "$receipt_dir" ]] || return 1
  if [[ -e "$receipt_dir/chain.tsv" ]]; then
    source "$SCRIPT_DIR/../offline-installer/lib/development-receipt-chain.sh"
    development_receipt_chain_valid "$receipt_dir/chain.tsv" || return 1
  fi
  index="$receipt_dir/current.json"
  receipt="$receipt_dir/receipt.json"
  receipt_hash="$receipt_dir/receipt.sha256"
  for file in "$index" "$receipt" "$receipt_hash"; do
    [[ -f "$file" && ! -L "$file" ]] || return 1
    [[ "$(stat -Lc %u -- "$file")" == 0 && "$(stat -Lc %a -- "$file")" == 600 ]] || return 1
  done
  [[ "$(grep -Ec '"release"[[:space:]]*:' "$index")" == 1 ]] || return 1
  [[ "$(grep -Ec '"receipt_sha256"[[:space:]]*:' "$index")" == 1 ]] || return 1
  release="$(sed -n 's/.*"release"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$index" | head -1)"
  expected_hash="$(sed -n 's/.*"receipt_sha256"[[:space:]]*:[[:space:]]*"\([0-9a-f]\{64\}\)".*/\1/p' "$index" | head -1)"
  actual_hash="$(sha256sum -- "$receipt" | awk '{print $1}')"
  receipt_hash="$(sed -n 's/^[[:space:]]*\([0-9a-f]\{64\}\)[[:space:]]*$/\1/p' "$receipt_hash")"
  [[ "$expected_hash" =~ ^[0-9a-f]{64}$ && "$expected_hash" == "$actual_hash" && "$actual_hash" == "$receipt_hash" ]] || return 1
  case "$release" in
    /opt/jjdguard/development-releases/dev-*) ;;
    *) return 1 ;;
  esac
  [[ "$(realpath -e -- "$release" 2>/dev/null || true)" == "$release" ]] || return 1
  release_id="${release##*/}"
  [[ "$release_id" =~ ^dev-[A-Za-z0-9-]+$ ]] || return 1
  [[ -f "$release/receipt.json" && ! -L "$release/receipt.json" ]] || return 1
  [[ "$(stat -Lc %u -- "$release/receipt.json")" == 0 && "$(stat -Lc %a -- "$release/receipt.json")" == 600 ]] || return 1
  [[ "$(sha256sum -- "$release/receipt.json" | awk '{print $1}')" == "$actual_hash" ]] || return 1
  status="$(sed -n 's/.*"status"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$receipt" | head -1)"
  receipt_release_id="$(sed -n 's/.*"release_id"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$receipt" | head -1)"
  version="$(sed -n 's/.*"version"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$receipt" | head -1)"
  gateway="$(sed -n 's/.*"gateway-core"[[:space:]]*:[[:space:]]*"\(sha256:[0-9a-f]\{64\}\)".*/\1/p' "$receipt" | head -1)"
  backup="$(sed -n 's/.*"backup"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$receipt" | head -1)"
  [[ "$status" == deployed && "$receipt_release_id" == "$release_id" && "$version" =~ ^[0-9A-Za-z.-]+$ && "$gateway" == "$expected" ]] || return 1
  [[ "$backup" == "$release/state/database.dump" && -f "$backup" && ! -L "$backup" ]] || return 1
  [[ "$(stat -Lc %u -- "$backup")" == 0 && "$(stat -Lc %a -- "$backup")" == 600 ]] || return 1
  [[ -f "$lock" && ! -L "$lock" && "$(stat -Lc %u -- "$lock")" == 0 && "$(stat -Lc %a -- "$lock")" == 600 ]] || return 1
  if [[ "${DEVELOPMENT_LOCK_HELD:-0}" != 1 ]]; then
    exec 19<>"$lock" || return 1
    flock -n -x 19 || { exec 19>&-; return 1; }
    DEVELOPMENT_LOCK_HELD=1
  fi
  validate_config_snapshots || return 1
  if development_normalized_config_matches_receipt "$receipt" "$release_id"; then
    DEVELOPMENT_NORMALIZED_CONFIG=1
  else
    DEVELOPMENT_NORMALIZED_CONFIG=0
  fi
  DEVELOPMENT_ROLLBACK_PROOF="$actual_hash"
  DEVELOPMENT_ROLLBACK_IMAGE="$expected"
}

validate_digest_from_installed_release() {
  local expected="$1" release_root stamp manifest compose_manifest provenance sbom inventory
  local expected_keys actual_keys version target_arch source_revision source_tree env_version
  [[ "$expected" =~ ^sha256:[0-9a-f]{64}$ ]] || return 1
  [[ "${EXISTING_WORK_DIR:-}" =~ ^/opt/jjdguard/releases/[A-Za-z0-9._-]+/deploy/docker-compose$ ]] || return 1
  release_root="${EXISTING_WORK_DIR%/deploy/docker-compose}"
  [[ "$(realpath -e -- "$release_root" 2>/dev/null || true)" == "$release_root" ]] || return 1

  stamp="$release_root/.jjdguard-offline-verified.tsv"
  manifest="$release_root/manifest.json"
  compose_manifest="$release_root/deploy/docker-compose/manifest.json"
  provenance="$release_root/image-provenance.json"
  sbom="$release_root/sbom/index.json"
  inventory="$release_root/offline-inventory.tsv"
  for file in "$stamp" "$manifest" "$compose_manifest" "$provenance" "$sbom" "$inventory"; do
    [[ -f "$file" && ! -L "$file" ]] || return 1
  done
  [[ "$(stat -Lc %u -- "$stamp")" == 0 && "$(stat -Lc %a -- "$stamp")" == 400 ]] || return 1

  expected_keys="$(printf '%s\n' schema archive_sha256 handoff_sha256 manifest_sha256 inventory_sha256 source_revision source_tree image_provenance_sha256 sbom_index_sha256 artifact_stage public_key_sha256 verified_files verified_at)"
  actual_keys="$(cut -f1 "$stamp")"
  [[ "$actual_keys" == "$expected_keys" ]] || return 1
  stamp_value() { awk -F '\t' -v wanted="$1" '$1 == wanted { print $2 }' "$stamp"; }
  [[ "$(stamp_value schema)" == jjdguard-offline-verified/v2 ]] || return 1
  for key in archive_sha256 handoff_sha256 manifest_sha256 inventory_sha256 image_provenance_sha256 sbom_index_sha256 public_key_sha256; do
    value="$(stamp_value "$key")"
    [[ "$value" =~ ^[0-9a-f]{64}$ ]] || return 1
  done
  [[ "$(sha256_file "$manifest")" == "$(stamp_value manifest_sha256)" ]] || return 1
  [[ "$(sha256_file "$compose_manifest")" == "$(stamp_value manifest_sha256)" ]] || return 1
  [[ "$(sha256_file "$inventory")" == "$(stamp_value inventory_sha256)" ]] || return 1
  [[ "$(sha256_file "$provenance")" == "$(stamp_value image_provenance_sha256)" ]] || return 1
  [[ "$(sha256_file "$sbom")" == "$(stamp_value sbom_index_sha256)" ]] || return 1
  cmp -s "$manifest" "$compose_manifest" || return 1

  manifest_field() {
    sed -n "s/^[[:space:]]*\"$1\"[[:space:]]*:[[:space:]]*\"\([^\"]*\)\"[[:space:]]*,\?[[:space:]]*$/\1/p" "$manifest" | head -1
  }
  version="$(manifest_field version)"
  target_arch="$(manifest_field target_arch)"
  source_revision="$(manifest_field source_revision)"
  source_tree="$(manifest_field source_tree)"
  [[ "$version" =~ ^[0-9A-Za-z][0-9A-Za-z._+-]{0,63}$ ]] || return 1
  [[ "$target_arch" == amd64 || "$target_arch" == arm64 ]] || return 1
  [[ "$source_revision" =~ ^[0-9a-f]{40}$ && "$source_tree" =~ ^[0-9a-f]{40}$ ]] || return 1
  [[ "$(stamp_value source_revision)" == "$source_revision" ]] || return 1
  [[ "$(stamp_value source_tree)" == "$source_tree" ]] || return 1
  [[ "$(stamp_value artifact_stage)" == candidate ]] || return 1
  env_version="$(sed -n 's/^JJD_VERSION=\(.*\)$/\1/p' "${EXISTING_ENV_FILE:-}" | tail -1)"
  [[ -n "$env_version" && "$env_version" == "$version" ]] || return 1

  if awk -v expected="$expected" '
    /"component"[[:space:]]*:[[:space:]]*"gateway-core"/ { in_gateway = 1; next }
    in_gateway && /^[[:space:]]*}[,]?[[:space:]]*$/ { in_gateway = 0; next }
    in_gateway && /"image_id"[[:space:]]*:/ {
      if (index($0, expected) > 0) found = 1
      in_gateway = 0
    }
    END { exit found ? 0 : 1 }
  ' "$provenance"; then
    return 0
  fi

  # docker save/load 不保留构建期 image id：客户机上 docker load 出来的镜像 ID
  # 与打包时 provenance 记录的 ID 必然不同，仅靠 ID 比对会把「全新装完再升级」
  # 这条最常见的客户路径判成不可信。改用镜像自身携带、且经 save/load 保持不变的
  # 来源标签，把运行中的 gateway-core 绑定到同一份已安装 release 的源码身份上。
  local image_labels revision_label tree_label source_label
  image_labels="$(docker image inspect "$expected" --format \
    '{{index .Config.Labels "org.opencontainers.image.revision"}}|{{index .Config.Labels "com.jjdguard.source.tree"}}|{{index .Config.Labels "org.opencontainers.image.source"}}' 2>/dev/null)" || return 1
  IFS='|' read -r revision_label tree_label source_label <<<"$image_labels"
  [[ "$revision_label" == "$source_revision" ]] || return 1
  [[ "$tree_label" == "$source_tree" ]] || return 1
  [[ "$source_label" == 'git@github.com:yangjiyj/aiguard.git' ]] || return 1
}

discover_existing_deployment() {
  local output metadata project work_dir config_files env_file image normalized_configs normalized_env digest_image=0
  local -a gateway_containers=()

  output="$(docker ps --filter status=running \
    --filter label=com.docker.compose.service=gateway-core --format '{{.ID}}')" || \
    fail "无法查询正在运行的 gateway-core 容器"
  while IFS= read -r container; do [[ -n "$container" ]] && gateway_containers+=("$container"); done <<<"$output"
  (( ${#gateway_containers[@]} == 1 )) || \
    fail "必须恰好存在一个正在运行的 gateway-core Compose 实例，当前发现 ${#gateway_containers[@]} 个"

  EXISTING_GATEWAY_CONTAINER="${gateway_containers[0]}"
  metadata="$(read_container_metadata "$EXISTING_GATEWAY_CONTAINER")" || fail "无法读取原部署 Compose 标签"
  IFS='|' read -r project work_dir config_files env_file image <<<"$metadata"

  [[ "$project" != "<no value>" && "$project" =~ ^[a-z0-9][a-z0-9_-]*$ ]] || fail "原部署 Compose 项目名非法"
  [[ "$work_dir" != "<no value>" && "$work_dir" == /* && -d "$work_dir" ]] || fail "原部署 Compose 工作目录非法"
  work_dir="$(realpath -e -- "$work_dir")" || fail "无法解析原部署 Compose 工作目录"
  EXISTING_CONFIG_OWNER_UID="$(stat -Lc %u -- "$work_dir")" || fail "无法读取原部署目录属主"
  EXISTING_CONFIG_OWNER_GID="$(stat -Lc %g -- "$work_dir")" || fail "无法读取原部署目录属组"
  case "$work_dir" in
    */jjdguard/upgrade-runs/*) EXISTING_CONFIG_ROOT="${work_dir%%/upgrade-runs/*}" ;;
    *) EXISTING_CONFIG_ROOT="$work_dir" ;;
  esac
  [[ -d "$EXISTING_CONFIG_ROOT" && ! -L "$EXISTING_CONFIG_ROOT" ]] || fail "原部署配置根目录非法"
  [[ "$(stat -Lc %u -- "$EXISTING_CONFIG_ROOT")" == "$EXISTING_CONFIG_OWNER_UID" ]] || fail "原部署配置根目录属主不一致"
  normalized_configs="$(normalize_config_files "$work_dir" "$config_files")" || fail "原部署 Compose 配置文件非法"
  normalized_env="$(normalize_environment_file "$work_dir" "$env_file")" || fail "原部署 Compose environment_file 标签非法"
  if [[ "$image" =~ ^(docker-compose-gateway-core|[Jj][Jj][Dd][Gg]uard[-_/]gateway-core)(:.*|@.*)?$ ]]; then
    :
  elif [[ "$image" =~ ^sha256:[0-9a-f]{64}$ ]]; then
    digest_image=1
  else
    fail "运行中的 gateway-core 镜像身份不受信任"
  fi

  EXISTING_PROJECT_NAME="$project"
  EXISTING_WORK_DIR="$work_dir"
  EXISTING_CONFIG_FILES="$normalized_configs"
  EXISTING_CONFIG_FILES_RAW="$config_files"
  EXISTING_ENV_FILE="$normalized_env"
  EXISTING_ENV_FILE_RAW="$env_file"
  create_config_snapshots || {
    cleanup_config_snapshot || true
    fail "无法创建原部署 Compose 配置私有快照"
  }
  if (( digest_image == 1 )); then
    if validate_digest_from_historical_rollback "$image"; then
      :
    elif validate_digest_from_development_receipt "$image"; then
      log "[ok] 已使用本机开发部署回执确认原 gateway-core digest"
    elif validate_digest_from_installed_release "$image"; then
      log "[ok] 已使用旧正式离线 release 的校验戳和 provenance 确认原 gateway-core digest"
    else
      cleanup_config_snapshot || true
      fail "运行中的 gateway-core digest 缺少可信历史回滚证明或开发部署回执"
    fi
  fi
  EXISTING_GATEWAY_METADATA="$metadata"
  DEPLOYMENT_REVALIDATED=0
  export EXISTING_GATEWAY_CONTAINER EXISTING_PROJECT_NAME EXISTING_WORK_DIR EXISTING_CONFIG_FILES EXISTING_CONFIG_FILES_RAW EXISTING_ENV_FILE EXISTING_ENV_FILE_RAW
  export EXISTING_GATEWAY_METADATA DEPLOYMENT_REVALIDATED EXISTING_CONFIG_OWNER_UID EXISTING_CONFIG_OWNER_GID EXISTING_CONFIG_ROOT
}

validate_upgrade_timestamp() {
  UPGRADE_RUN_TIMESTAMP="${UPGRADE_TIMESTAMP-$(date -u +%Y%m%dT%H%M%SZ)}"
  [[ "$UPGRADE_RUN_TIMESTAMP" =~ ^[0-9]{8}T[0-9]{6}Z$ ]] || fail "UPGRADE_TIMESTAMP 格式非法"
  export UPGRADE_RUN_TIMESTAMP
}

revalidate_existing_deployment() {
  local state_and_metadata running metadata
  state_and_metadata="$(read_gateway_state_and_metadata "$EXISTING_GATEWAY_CONTAINER")" || \
    fail "无法重新检查原部署 gateway-core"
  IFS='|' read -r running metadata <<<"$state_and_metadata"
  [[ "$running" == true ]] || fail "原部署 gateway-core 已不在运行"
  [[ "$metadata" == "$EXISTING_GATEWAY_METADATA" ]] || fail "原部署 gateway-core 元数据在升级前发生变化"
  if [[ -n "${DEVELOPMENT_ROLLBACK_PROOF:-}" ]]; then
    validate_digest_from_development_receipt "$DEVELOPMENT_ROLLBACK_IMAGE" || \
      fail "官方开发更新回执或运行配置在升级前发生变化"
  fi
  DEPLOYMENT_REVALIDATED=1
  export DEPLOYMENT_REVALIDATED
}

validate_configuration_source() {
  local source="$1" kind="$2" expected resolved
  [[ ! -L "$source" ]] || return 1
  expected="$EXISTING_WORK_DIR/${source##*/}"
  resolved="$(realpath -e -- "$source")" || return 1
  [[ "$resolved" == "$expected" ]] || return 1
  if [[ "$kind" == file ]]; then [[ -f "$source" ]]; else [[ -d "$source" ]]; fi
}

validate_configuration_sources() {
  local source
  for source in "$EXISTING_WORK_DIR/tls" "$EXISTING_WORK_DIR/.upgrade"; do
    if [[ -e "$source" || -L "$source" ]]; then
      validate_configuration_source "$source" directory || \
        fail "原部署配置目录必须位于工作目录内且不能是符号链接：$source"
    fi
  done
}

inherit_configuration() {
  local name source_dir target_dir
  [[ "${DEPLOYMENT_REVALIDATED:-0}" == 1 ]] || fail "复制配置前必须重新验证原部署"
  validate_config_snapshots || fail "原部署配置私有快照身份已变化"
  cp -- "$OLD_ENV_SNAPSHOT_FILE" "$SCRIPT_DIR/.env" || fail "复制原部署 .env 私有快照失败"
  chmod 0600 "$SCRIPT_DIR/.env" || fail "保护新部署 .env 失败"
  validate_configuration_sources
  for name in tls .upgrade; do
    source_dir="$EXISTING_WORK_DIR/$name"
    [[ -d "$source_dir" ]] || continue
    target_dir="$SCRIPT_DIR/$name"
    mkdir -p -- "$target_dir" || fail "创建配置目录失败：$target_dir"
    if [[ "$name" == .upgrade && -d "$target_dir/development-receipt" ]]; then
      # installer.sh captured the currently running development release before
      # entering this script. Preserve that newer trust proof while inheriting
      # every other historical upgrade artifact from the old release.
      shopt -s dotglob nullglob
      for inherited in "$source_dir"/*; do
        [[ "${inherited##*/}" == development-receipt ]] && continue
        cp -a -- "$inherited" "$target_dir/" || fail "复制原部署 $name/ 失败"
      done
      shopt -u dotglob nullglob
    else
      cp -a -- "$source_dir/." "$target_dir/" || fail "复制原部署 $name/ 失败"
    fi
    chmod --reference="$source_dir" "$target_dir" || fail "保留 $name/ 目录权限失败"
  done
}

parse_literal_dotenv_value() {
  local value="$1"
  if [[ "$value" == \"* ]]; then
    [[ "${#value}" -ge 2 && "$value" == *\" ]] || return 1
    value="${value:1:${#value}-2}"
  elif [[ "$value" == \'* ]]; then
    [[ "${#value}" -ge 2 && "$value" == *\' ]] || return 1
    value="${value:1:${#value}-2}"
  fi
  [[ "$value" != *$'\n'* && "$value" != *$'\r'* ]] || return 1
  printf '%s' "$value"
}

read_literal_dotenv_key() {
  local file="$1" wanted="$2" line key raw parsed found=0
  while IFS= read -r line || [[ -n "$line" ]]; do
    line="${line%$'\r'}"
    [[ -z "$line" || "$line" == \#* ]] && continue
    [[ "$line" =~ ^([A-Za-z_][A-Za-z0-9_]*)=(.*)$ ]] || return 2
    key="${BASH_REMATCH[1]}"; raw="${BASH_REMATCH[2]}"
    [[ "$key" == "$wanted" ]] || continue
    (( found == 0 )) || return 2
    parsed="$(parse_literal_dotenv_value "$raw")" || return 2
    found=1
    printf '%s' "$parsed"
  done <"$file"
  (( found == 1 )) || return 1
}

# Development releases can put an explicit header preference only in their
# canonical Compose environment. Keep it when adopting the new official base;
# an explicit nonempty dotenv preference (including a pending user edit) wins.
preserve_gateway_header_preference() {
  local file="$SCRIPT_DIR/.env" configured status runtime tmp
  [[ -f "$file" && ! -L "$file" ]] || fail "继承后的 .env 缺失或非法"
  set +e
  configured="$(read_literal_dotenv_key "$file" SECURITY_ACTION_HEADER_ENABLED)"
  status=$?
  set -e
  (( status <= 1 )) || fail "安全响应头配置重复或 dotenv 格式非法"
  if (( status == 0 )) && [[ -n "$configured" ]]; then return 0; fi
  runtime="$(docker inspect --format '{{range .Config.Env}}{{println .}}{{end}}' "$EXISTING_GATEWAY_CONTAINER" 2>/dev/null | sed -n 's/^SECURITY_ACTION_HEADER_ENABLED=//p')" ||
    fail "无法核对原网关安全响应头配置"
  [[ -z "$runtime" ]] && return 0
  case "$runtime" in
    true|True|TRUE|1) runtime=true ;;
    false|False|FALSE|0) runtime=false ;;
    *) fail "原网关安全响应头配置不是唯一有效布尔值" ;;
  esac
  tmp="$(mktemp "$SCRIPT_DIR/.env.headers.XXXXXX")" || fail "无法创建响应头配置更新文件"
  if ! sed '/^SECURITY_ACTION_HEADER_ENABLED=/d' "$file" >"$tmp" ||
     ! printf '\nSECURITY_ACTION_HEADER_ENABLED=%s\n' "$runtime" >>"$tmp"; then
    rm -f -- "$tmp"; fail "无法保存原网关安全响应头配置"
  fi
  chmod 0600 "$tmp" || { rm -f -- "$tmp"; fail "无法保护响应头配置文件"; }
  [[ "$(stat -Lc %u -- "$tmp")" == "$(stat -Lc %u -- "$file")" ]] || {
    rm -f -- "$tmp"; fail "响应头配置更新属主不一致";
  }
  mv -f -- "$tmp" "$file" || { rm -f -- "$tmp"; fail "无法原子保存响应头配置"; }
  log "[ok] 已保留原网关显式安全结果响应头配置"
}

upgrade_env_key_allowed() {
  case "$1" in
    GATEWAY_ENVIRONMENT_SCOPE|POSTGRES_USER|POSTGRES_DB|CHAT_BYO_IDP|CHAT_OIDC_HOST|CHAT_OIDC_ISSUER|\
    CONTROL_PORT|GATEWAY_PORT|JJD_SSO_PUBLIC_URL|OIDC_VERIFY_CONNECT_TIMEOUT|OIDC_VERIFY_INTERVAL|\
    OIDC_VERIFY_MAX_ATTEMPTS|OIDC_VERIFY_REQUEST_TIMEOUT|OIDC_VERIFY_TIMEOUT|SECURITY_PORT|TLS_ENABLED|\
    UPGRADE_BASE_HOST|VERIFY_HEALTH_INTERVAL|VERIFY_HEALTH_TIMEOUT|WEB_HTTPS_PORT|WEB_PORT) return 0 ;;
    *) return 1 ;;
  esac
}

# Only the verified offline installer may classify a legacy .env that did not
# yet carry deployment scope. Existing valid scopes have trusted provenance and
# are preserved; malformed or duplicate values fail closed.
persist_trusted_customer_environment_scope() {
  [[ "${JJD_VERIFIED_INSTALLER_CUSTOMER_SCOPE:-0}" == 1 ]] || return 0
  local env_file="$SCRIPT_DIR/.env" tmp existing status
  [[ -f "$env_file" && ! -L "$env_file" ]] || fail "继承后的 .env 缺失或非法"
  set +e
  existing="$(read_literal_dotenv_key "$env_file" GATEWAY_ENVIRONMENT_SCOPE)"
  status=$?
  set -e
  if (( status == 0 )); then
    case "$existing" in customer|home|claude|codex|legacy-unclassified) ;;
      *) fail "继承后的 GATEWAY_ENVIRONMENT_SCOPE 非法" ;;
    esac
    export GATEWAY_ENVIRONMENT_SCOPE="$existing"
    log "[ok] 保留原部署作用域：$existing"
    return 0
  fi
  (( status == 1 )) || fail "继承后的 .env 不是严格的 dotenv 文件或作用域重复"
  tmp="$(mktemp "$SCRIPT_DIR/.env.scope.XXXXXX")" || fail "无法创建 .env 作用域更新文件"
  if ! cp -- "$env_file" "$tmp" ||
     ! printf '\nGATEWAY_ENVIRONMENT_SCOPE=customer\n' >>"$tmp"; then
    rm -f -- "$tmp"
    fail "无法持久化客户部署作用域"
  fi
  chmod 0600 "$tmp" || { rm -f -- "$tmp"; fail "无法保护客户部署作用域文件"; }
  if [[ "$(stat -Lc %u -- "$tmp")" != "$(stat -Lc %u -- "$env_file")" ]]; then
    rm -f -- "$tmp"
    fail "拒绝用不同属主的文件替换 .env"
  fi
  mv -f -- "$tmp" "$env_file" || { rm -f -- "$tmp"; fail "无法原子更新客户部署作用域"; }
  export GATEWAY_ENVIRONMENT_SCOPE=customer
  log "[ok] 已由验签安装器持久化客户部署作用域"
}

manifest_string_value() {
  local field="$1" manifest="$SCRIPT_DIR/manifest.json" count value
  [[ "$field" =~ ^[a-z_]+$ ]] || return 1
  [[ -f "$manifest" && ! -L "$manifest" ]] || return 1
  count="$(grep -Ec "^[[:space:]]*\"${field}\"[[:space:]]*:[[:space:]]*\"[^\"]*\"[[:space:]]*,?[[:space:]]*$" "$manifest")" || return 1
  [[ "$count" == 1 ]] || return 1
  value="$(sed -n "s/^[[:space:]]*\"${field}\"[[:space:]]*:[[:space:]]*\"\([^\"]*\)\"[[:space:]]*,\?[[:space:]]*$/\1/p" "$manifest")" || return 1
  [[ -n "$value" && "$value" != *$'\n'* && "$value" != *$'\r'* ]] || return 1
  printf '%s' "$value"
}

persist_package_metadata() {
  local version source_revision built_at env_file="$SCRIPT_DIR/.env" tmp
  version="$(manifest_string_value version)" || fail "离线包 manifest version 缺失或非法"
  source_revision="$(manifest_string_value source_revision)" || fail "离线包 manifest source_revision 缺失或非法"
  built_at="$(manifest_string_value built_at)" || fail "离线包 manifest built_at 缺失或非法"
  [[ "$version" =~ ^[0-9A-Za-z][0-9A-Za-z._+-]{0,63}$ ]] || fail "离线包版本格式非法"
  [[ "$source_revision" =~ ^[0-9a-f]{40}$ ]] || fail "离线包源码版本格式非法"
  [[ "$built_at" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$ ]] || fail "离线包构建时间格式非法"
  [[ -f "$env_file" && ! -L "$env_file" ]] || fail "继承后的 .env 缺失或非法"

  tmp="$(mktemp "$SCRIPT_DIR/.env.next.XXXXXX")" || fail "无法创建 .env 原子更新文件"
  if ! awk '!/^JJD_(VERSION|COMMIT|BUILT_AT)=/' "$env_file" >"$tmp" ||
     ! printf 'JJD_VERSION=%s\nJJD_COMMIT=%s\nJJD_BUILT_AT=%s\n' \
       "$version" "$source_revision" "$built_at" >>"$tmp"; then
    rm -f -- "$tmp"
    fail "无法写入离线包版本元数据"
  fi
  chmod 0600 "$tmp" || { rm -f -- "$tmp"; fail "无法保护更新后的 .env"; }
  if [[ "$(stat -Lc %u -- "$tmp")" != "$(stat -Lc %u -- "$env_file")" ]]; then
    rm -f -- "$tmp"
    fail "拒绝用不同属主的文件替换 .env"
  fi
  mv -f -- "$tmp" "$env_file" || { rm -f -- "$tmp"; fail "无法原子更新 .env"; }
  log "[ok] 已持久化离线包版本元数据 version=$version revision=${source_revision:0:12}"
}

find_project_service_containers() {
  docker ps --filter status=running \
    --filter "label=com.docker.compose.project=$EXISTING_PROJECT_NAME" \
    --filter "label=com.docker.compose.service=$1" --format '{{.ID}}'
}

assert_container_matches_deployment() {
  local container="$1" metadata project work_dir config_files env_file image
  metadata="$(read_container_metadata "$container")" || return 1
  IFS='|' read -r project work_dir config_files env_file image <<<"$metadata"
  [[ "$project" == "$EXISTING_PROJECT_NAME" ]] || return 1
  [[ "$work_dir" == /* && -d "$work_dir" ]] || return 1
  work_dir="$(realpath -e -- "$work_dir")" || return 1
  [[ "$work_dir" == "$EXISTING_WORK_DIR" ]] || return 1
  [[ "$config_files" == "$EXISTING_CONFIG_FILES_RAW" ]] || return 1
  if [[ "$env_file" != "$EXISTING_ENV_FILE_RAW" ]]; then
    [[ -z "$EXISTING_ENV_FILE_RAW" && "$env_file" == "$EXISTING_ENV_FILE" ]] || return 1
  fi
  validate_config_snapshots
}

# The schema-version probe is read-only. A development release can leave
# postgres on the prior Compose config_files label while gateway-core uses its
# receipt-bound normalized JSON. Verify the same trusted project/workdir and
# admissible historical files here; backup_databases later recreates stale
# containers and applies the strict exact-chain assertion before any backup.
assert_container_matches_readonly_scope() {
  local container="$1" metadata project work_dir config_files env_file image normalized_env
  metadata="$(read_container_metadata "$container")" || return 1
  IFS='|' read -r project work_dir config_files env_file image <<<"$metadata"
  [[ "$project" == "$EXISTING_PROJECT_NAME" && "$work_dir" == /* && -d "$work_dir" ]] || return 1
  work_dir="$(realpath -e -- "$work_dir")" || return 1
  [[ "$work_dir" == "$EXISTING_WORK_DIR" ]] || return 1
  normalize_config_files "$work_dir" "$config_files" >/dev/null || return 1
  normalized_env="$(normalize_environment_file "$work_dir" "$env_file")" || return 1
  [[ "$normalized_env" == "$EXISTING_ENV_FILE" ]] || return 1
  validate_config_snapshots
}

database_identity() {
  local container="$1" env_lines line
  local pguser="" postgres_user="" pgdatabase="" postgres_db=""
  env_lines="$(docker inspect --format '{{range .Config.Env}}{{println .}}{{end}}' "$container")" || return 1
  while IFS= read -r line; do
    case "$line" in
      PGUSER=*) pguser="${line#PGUSER=}" ;;
      POSTGRES_USER=*) postgres_user="${line#POSTGRES_USER=}" ;;
      PGDATABASE=*) pgdatabase="${line#PGDATABASE=}" ;;
      POSTGRES_DB=*) postgres_db="${line#POSTGRES_DB=}" ;;
    esac
  done <<<"$env_lines"
  pguser="${pguser:-$postgres_user}"
  pgdatabase="${pgdatabase:-$postgres_db}"
  [[ -n "$pguser" && -n "$pgdatabase" ]] || return 1
  printf '%s|%s\n' "$pguser" "$pgdatabase"
}

backup_one_database() {
  local container="$1" output_file="$2" identity pguser pgdatabase partial
  identity="$(database_identity "$container")" || return 1
  IFS='|' read -r pguser pgdatabase <<<"$identity"
  partial="$(dirname "$output_file")/.$(basename "$output_file").partial.$$"

  if ! docker exec "$container" pg_dump -U "$pguser" -d "$pgdatabase" -Fc >"$partial"; then
    rm -f -- "$partial"
    return 1
  fi
  if [[ ! -s "$partial" ]]; then
    rm -f -- "$partial"
    return 1
  fi
  if ! docker exec -i "$container" pg_restore --list <"$partial" >/dev/null; then
    rm -f -- "$partial"
    return 1
  fi
  chmod 0600 "$partial" || { rm -f -- "$partial"; return 1; }
  mv -f -- "$partial" "$output_file" || { rm -f -- "$partial"; return 1; }
}

cleanup_backup_run() {
  local backup_dir="$1"
  local -a artifacts=()
  shopt -s nullglob
  artifacts=("$backup_dir"/*.dump "$backup_dir"/.*.partial.*)
  (( ${#artifacts[@]} == 0 )) || rm -f -- "${artifacts[@]}"
  rmdir -- "$backup_dir" 2>/dev/null || true
}

# The minimum file is the oldest supported bridge entry. The bridge target is
# the first historically verified direct-upgrade schema. Older supported
# databases are migrated through the same bounded runner after backup.
validate_minimum_data_version() {
  local min_file="$SCRIPT_DIR/upgrade-min-data-version"
  local bridge_file="$SCRIPT_DIR/upgrade-bridge-target-version"
  local min_version bridge_version current
  local -a postgres_containers=()
  local output

  [[ -f "$min_file" && ! -L "$min_file" ]] || \
    fail "缺少最低数据版本声明文件 upgrade-min-data-version"
  min_version="$(tr -d '[:space:]' <"$min_file")" || fail "无法读取最低数据版本声明"
  migration_name_valid "$min_version" || \
    fail "最低数据版本声明非法: ${min_version:-<空>}"
  [[ -f "$bridge_file" && ! -L "$bridge_file" ]] || fail "缺少桥接目标版本声明"
  bridge_version="$(tr -d '[:space:]' <"$bridge_file")" || fail "无法读取桥接目标版本声明"
  migration_name_valid "$bridge_version" || fail "桥接目标版本声明非法: ${bridge_version:-<空>}"
  migration_version_lt "$bridge_version" "$min_version" &&
    fail "桥接目标不得低于最低数据版本"

  output="$(find_project_service_containers postgres)" || fail "无法查询主 PostgreSQL 容器"
  while IFS= read -r container; do
    [[ -n "$container" ]] && postgres_containers+=("$container")
  done <<<"$output"
  (( ${#postgres_containers[@]} == 1 )) || \
    fail "校验数据版本时必须恰好有一个正在运行的 postgres 容器，当前发现 ${#postgres_containers[@]} 个"
  assert_container_matches_readonly_scope "${postgres_containers[0]}" || \
    fail "postgres 容器不属于已发现的原部署项目作用域"

  current="$(docker exec "${postgres_containers[0]}" \
    psql -U "${POSTGRES_USER:-jjdguard}" -d "${POSTGRES_DB:-jjdguard}" -tAc \
    "$(migration_latest_sql)" 2>/dev/null)" || \
    fail "无法读取当前数据版本（schema_migrations）"
  current="$(printf '%s' "$current" | tr -d '[:space:]')"

  [[ -n "$current" ]] || \
    fail "当前部署没有可识别的数据版本；该库不是受支持的升级来源"

  # 水位必须是合法迁移文件名。否则字符串比较会给出无意义的结果
  # （例如任意字母开头的值都 > 数字前缀下限，从而被误放行）。
  migration_name_valid "$current" || \
    fail "当前数据版本格式非法: $current；该库不是受支持的升级来源"

  if migration_version_lt "$current" "$min_version"; then
    fail "拒绝升级：当前数据版本 $current 低于本包要求的下限 $min_version；请先升级到中间版本"
  fi
  UPGRADE_SOURCE_DATA_VERSION="$current"
  UPGRADE_BRIDGE_REQUIRED=0
  if migration_version_lt "$current" "$bridge_version"; then
    UPGRADE_BRIDGE_REQUIRED=1
    log "[plan] 数据版本桥接 current=$current bridge_target=$bridge_version"
  fi
  log "[ok] 数据版本闸门通过 current=$current supported>=$min_version"
}

run_upgrade_preflight() {
  local tool="$SCRIPT_DIR/upgrade-preflight.sh" output container target
  [[ -x "$tool" ]] || fail "缺少统一升级预检工具"
  output="$(find_project_service_containers postgres)" || fail "无法查询主 PostgreSQL 容器"
  container="$(printf '%s\n' "$output" | awk 'NF {print; exit}')"
  [[ -n "$container" ]] || fail "升级预检未找到 PostgreSQL 容器"
  target="$(manifest_string_value version)" || fail "无法读取目标产品版本"
  UPGRADE_PREFLIGHT_POSTGRES_CONTAINER="$container" \
    UPGRADE_FROM_VERSION="${JJD_VERSION:-unknown}" UPGRADE_TO_VERSION="$target" \
    UPGRADE_BACKUP_ROOT="$SCRIPT_DIR/backups" \
    POSTGRES_USER="${POSTGRES_USER:-jjdguard}" POSTGRES_DB="${POSTGRES_DB:-jjdguard}" \
    bash "$tool" --output "$SCRIPT_DIR/.upgrade/preflight.json" ||
      fail "统一升级预检判定为 BLOCKED"
}

existing_compose_args() {
  local entry
  local -a entries=()
  EXISTING_COMPOSE_ARGS=("$COMPOSE_WRAPPER" --project-name "$EXISTING_PROJECT_NAME" --project-directory "$EXISTING_WORK_DIR")
  [[ -z "${EXISTING_ENV_FILE_RAW:-}" ]] || EXISTING_COMPOSE_ARGS+=(--env-file "$EXISTING_ENV_FILE_RAW")
  IFS=',' read -ra entries <<<"$EXISTING_CONFIG_FILES_RAW"
  (( ${#entries[@]} >= 1 )) || fail "原部署 Compose 配置链为空，无法归一化标签"
  for entry in "${entries[@]}"; do
    [[ -n "$entry" ]] || fail "原部署 Compose 配置链包含空条目"
    EXISTING_COMPOSE_ARGS+=(-f "$entry")
  done
}

# Docker Compose 只重建服务定义发生变化的容器。postgres / redis / chat-postgres
# 这类无变更的有状态服务，会一直持有上一个 release 目录的 project 标签
# （working_dir / config_files / environment_file）。历史版本升级或回滚之后，
# 同一个部署里就会同时存在两条 Compose 链，下一次升级的
# assert_container_matches_deployment 逐字比对必然 fail-closed。
# 这里用「本次发现到的」那条受信链把落后的容器原地重建一次：只更新 Compose 标签，
# 镜像取自同一条链、数据卷不动；重建后必须重新通过归属断言，否则升级停止。
heal_project_container_labels() {
  local container service output
  local -a stale=()
  validate_config_snapshots || fail "原部署配置私有快照身份已变化"
  output="$(docker ps --filter status=running \
    --filter "label=com.docker.compose.project=$EXISTING_PROJECT_NAME" \
    --format '{{.ID}}|{{.Label "com.docker.compose.service"}}')" ||
    fail "无法枚举原项目运行服务"
  while IFS='|' read -r container service; do
    [[ -n "$container" ]] || continue
    valid_service_name "$service" || fail "原项目服务名非法：$service"
    assert_container_matches_deployment "$container" || stale+=("$service")
  done <<<"$output"
  (( ${#stale[@]} > 0 )) || return 0
  log "[step] 归一化历史发布遗留的 Compose 标签：${stale[*]}"
  existing_compose_args
  "${EXISTING_COMPOSE_ARGS[@]}" up -d --no-deps --force-recreate "${stale[@]}" ||
    fail "无法归一化原部署容器 Compose 标签：${stale[*]}"
  for service in "${stale[@]}"; do
    output="$(find_project_service_containers "$service")" || fail "无法重新查询服务容器：$service"
    container="$(printf '%s\n' "$output" | head -n 1)"
    [[ -n "$container" ]] || fail "归一化后未找到服务容器：$service"
    assert_container_matches_deployment "$container" ||
      fail "归一化后容器仍不属于已发现的原部署：$service"
  done
  log "[ok] 原部署 Compose 标签已与当前发现链一致"
}

backup_databases() {
  local backup_root backup_dir output
  local -a postgres_containers=() chat_postgres_containers=()

  [[ -n "${UPGRADE_RUN_TIMESTAMP:-}" ]] || validate_upgrade_timestamp
  heal_project_container_labels

  output="$(find_project_service_containers postgres)" || fail "无法查询主 PostgreSQL 容器"
  while IFS= read -r container; do [[ -n "$container" ]] && postgres_containers+=("$container"); done <<<"$output"
  (( ${#postgres_containers[@]} == 1 )) || \
    fail "原部署必须恰好有一个正在运行的 postgres 容器，当前发现 ${#postgres_containers[@]} 个"

  output="$(find_project_service_containers chat-postgres)" || fail "无法查询门户 PostgreSQL 容器"
  while IFS= read -r container; do [[ -n "$container" ]] && chat_postgres_containers+=("$container"); done <<<"$output"
  (( ${#chat_postgres_containers[@]} <= 1 )) || fail "原部署存在多个正在运行的 chat-postgres 容器"

  assert_container_matches_deployment "${postgres_containers[0]}" || fail "postgres 容器不属于已发现的原部署"
  if (( ${#chat_postgres_containers[@]} == 1 )); then
    assert_container_matches_deployment "${chat_postgres_containers[0]}" || fail "chat-postgres 容器不属于已发现的原部署"
  fi

  revalidate_existing_deployment
  backup_root="$SCRIPT_DIR/backups"
  backup_dir="$backup_root/$UPGRADE_RUN_TIMESTAMP"
  mkdir -p -m 0700 -- "$backup_root" || fail "无法创建数据库备份根目录"
  mkdir -m 0700 -- "$backup_dir" || fail "数据库备份目录已存在或无法创建：$backup_dir"

  if ! backup_one_database "${postgres_containers[0]}" "$backup_dir/postgres.dump"; then
    cleanup_backup_run "$backup_dir"
    fail "主数据库备份失败或归档校验未通过"
  fi
  if (( ${#chat_postgres_containers[@]} == 1 )) && \
     ! backup_one_database "${chat_postgres_containers[0]}" "$backup_dir/chat-postgres.dump"; then
    cleanup_backup_run "$backup_dir"
    fail "门户数据库备份失败或归档校验未通过"
  fi
  BACKUP_DIR="$backup_dir"
  export BACKUP_DIR
}

quiesce_old_database_writers() {
  local service
  local -a application_services=()
  for service in "${OLD_RUNNING_SERVICES[@]}"; do
    case "$service" in postgres|chat-postgres|redis|redis-cache) ;; *) application_services+=("$service") ;; esac
  done
  (( ${#application_services[@]} > 0 )) || return 0
  if [[ -n "${DEVELOPMENT_ROLLBACK_PROOF:-}" ]]; then
    revalidate_existing_deployment
  fi
  SERVICES_QUIESCED=1
  old_compose_args
  log "[step] 在线备份已完成，短暂停止写入以切换 schema 和应用"
  run_old_compose stop --timeout 60 "${application_services[@]}" || fail "停止原部署数据库写入服务失败"
}

valid_service_name() { [[ "$1" =~ ^[a-z0-9][a-z0-9_-]*$ ]]; }

generated_image_pin_layer() {
  local file="$1" line expect=service count=0
  [[ -f "$file" && ! -L "$file" ]] || return 1
  IFS= read -r line <"$file" || return 1
  [[ "$line" == services: ]] || return 1
  while IFS= read -r line || [[ -n "$line" ]]; do
    if [[ "$expect" == service ]]; then
      [[ "$line" =~ ^\ \ [a-z0-9][a-z0-9_-]*:$ ]] || return 1
      expect=image
    else
      [[ "$line" =~ ^\ \ \ \ image:\ sha256:[0-9a-f]{64}$ ]] || return 1
      count=$((count + 1))
      expect=service
    fi
  done < <(tail -n +2 -- "$file")
  [[ "$expect" == service && "$count" -gt 0 ]]
}

append_profile_once() {
  local wanted="$1" item
  for item in "${OLD_PROFILES[@]:-}"; do [[ "$item" == "$wanted" ]] && return; done
  OLD_PROFILES+=("$wanted")
}

prepare_active_configuration() {
  local source snapshot destination index=0 active_files=""
  local -a sources=() snapshots=()
  validate_config_snapshots || fail "原部署 Compose 配置快照身份已变化"
  IFS=',' read -ra sources <<<"$EXISTING_CONFIG_FILES"
  IFS=',' read -ra snapshots <<<"$OLD_CONFIG_SNAPSHOT_FILES"
  (( ${#sources[@]} == ${#snapshots[@]} && ${#sources[@]} >= 1 )) || \
    fail "原部署 Compose 配置快照数量不一致"
  case "${sources[0]}" in
    */docker-compose.offline.yml|*/docker-compose.yml) ;;
    "$EXISTING_WORK_DIR"/active-config/*.json)
      [[ "$DEVELOPMENT_NORMALIZED_CONFIG" == 1 ]] ||
        fail "开发发布 Compose 配置缺少回执哈希证明"
      ;;
    *) fail "原部署首个 Compose 文件不是受支持的基础文件" ;;
  esac

  ACTIVE_CONFIG_DIR="$SCRIPT_DIR/active-config/$UPGRADE_RUN_TIMESTAMP"
  [[ ! -e "$ACTIVE_CONFIG_DIR" && ! -L "$ACTIVE_CONFIG_DIR" ]] || \
    fail "活动配置收口目录已存在：$ACTIVE_CONFIG_DIR"
  mkdir -p -m 0700 -- "$SCRIPT_DIR/active-config" || fail "无法创建活动配置根目录"
  mkdir -m 0700 -- "$ACTIVE_CONFIG_DIR" || fail "无法创建活动配置收口目录"

  for index in "${!sources[@]}"; do
    source="${sources[$index]}"
    snapshot="${snapshots[$index]}"
    # 新 release 自带正式基础 Compose；历史基础文件和旧镜像 pin 文件
    # 不能再次叠加，否则会把 2.6.3 服务定义或镜像覆盖回旧版本。
    # A development release uses one canonical JSON file as its complete
    # Compose model. The receipt authenticates that model as rollback evidence,
    # but a formal release must not layer it over the new official base: list
    # fields would be appended twice and bind mounts would stay pinned to the
    # old release root. Customer settings are inherited through .env and tls/.
    if (( index == 0 )); then continue; fi
    case "$source" in */.upgrade/compose.upgrade.yml) continue ;; esac
    generated_image_pin_layer "$snapshot" && continue
    destination="$ACTIVE_CONFIG_DIR/inherited-$(printf '%03d' "$index").yml"
    install -m 0600 -- "$snapshot" "$destination" || fail "无法收口原部署 Compose override"
    [[ "$(sha256_file "$destination")" == "$(sha256_file "$snapshot")" ]] || \
      fail "收口后的 Compose override 校验失败"
    active_files="${active_files:+$active_files,}$destination"
  done
  ACTIVE_CONFIG_FILES="$active_files"
  export ACTIVE_CONFIG_DIR ACTIVE_CONFIG_FILES
}

# jjdctl 启动读取 .upgrade/compose-files，本升级却只按 gateway-core 容器标签发现配置链，
# 备份前还会把标签不一致的容器按该链重建。现场只给个别服务（如 control-plane）登记、
# 也只重建过该服务的覆盖层不在这条链上：既不会被继承，也会在标签归一化时被摘掉。
# 这里不改变继承范围，只逐条告警并在升级汇总里重复列出，避免现场定制被静默丢弃。
report_uninherited_boot_overrides() {
  local chain="$EXISTING_WORK_DIR/.upgrade/compose-files" entry resolved
  UNINHERITED_BOOT_OVERRIDES=()
  [[ -f "$chain" && ! -L "$chain" && -r "$chain" ]] || return 0
  while IFS= read -r entry || [[ -n "$entry" ]]; do
    [[ -n "$entry" && "$entry" != *[[:cntrl:]]* ]] || continue
    resolved="$(realpath -e -- "$entry" 2>/dev/null)" || resolved="$entry"
    case ",${EXISTING_CONFIG_FILES:-}," in *",$resolved,"*) continue ;; esac
    generated_image_pin_layer "$resolved" && continue
    UNINHERITED_BOOT_OVERRIDES+=("$entry")
    log "[warn] 原部署启动链中的覆盖层未进入升级继承范围，升级后不再生效：$entry"
  done <"$chain"
  if (( ${#UNINHERITED_BOOT_OVERRIDES[@]} > 0 )); then
    log "[warn] 以上覆盖层登记在 $chain（jjdctl 启动链），但不在本次升级发现的配置链（gateway-core 容器标签）中；仍需要其中配置的，请改用 .env 对应变量，或在升级后重新登记"
  fi
}

write_release_image_override() {
  local source_revision mapping service image_ref image_id revision available output=""
  local -a mappings=(
    'gateway-core|docker-compose-gateway-core:latest'
    'control-plane|docker-compose-control-plane:latest'
    'security-engine|docker-compose-security-engine:latest'
    'proxy-server|docker-compose-proxy-server:latest'
    'web-console|docker-compose-web-console:latest'
    'worker|docker-compose-worker:latest'
    'llm-judge|docker-compose-llm-judge:latest'
    'tier1-classifier|docker-compose-tier1-classifier:latest'
    'chat-portal-ui|enterprise-ai-portal:0.2.0-slim'
    'chat-portal-proxy|chat-portal/portal-proxy:0.1.0'
  )
  [[ -d "${ACTIVE_CONFIG_DIR:-}" ]] || fail "生成正式镜像 override 前缺少活动配置目录"
  source_revision="$(manifest_string_value source_revision)" || fail "离线包源码 revision 缺失"
  available="$("$COMPOSE_WRAPPER" --profile '*' -f "$SCRIPT_DIR/docker-compose.offline.yml" config --services)" || \
    fail "无法读取 2.6.3 服务清单"
  RELEASE_IMAGE_OVERRIDE="$ACTIVE_CONFIG_DIR/release-images.override.yml"
  printf 'services:\n' >"$RELEASE_IMAGE_OVERRIDE" || fail "无法创建正式镜像 override"
  for mapping in "${mappings[@]}"; do
    service="${mapping%%|*}"
    image_ref="${mapping#*|}"
    grep -Fxq "$service" <<<"$available" || continue
    image_id="$(docker image inspect --format '{{.Id}}' "$image_ref" 2>/dev/null)" || \
      fail "正式镜像不存在：$image_ref"
    [[ "$image_id" =~ ^sha256:[0-9a-f]{64}$ ]] || fail "正式镜像 ID 非法：$image_ref"
    revision="$(docker image inspect --format '{{ index .Config.Labels "org.opencontainers.image.revision" }}' "$image_ref" 2>/dev/null)" || \
      fail "无法读取正式镜像 provenance：$image_ref"
    [[ "$revision" == "$source_revision" ]] || \
      fail "正式镜像 revision 不一致：$image_ref"
    printf '  %s:\n    image: %s\n' "$service" "$image_id" >>"$RELEASE_IMAGE_OVERRIDE"
    output="${output:+$output,}$service=$image_id"
  done
  chmod 0600 "$RELEASE_IMAGE_OVERRIDE" || fail "无法保护正式镜像 override"
  [[ -n "$output" ]] || fail "正式镜像 override 为空"
  export RELEASE_IMAGE_OVERRIDE
}

write_private_state_line() {
  local destination="$1" value="$2" tmp
  tmp="$(mktemp "${destination}.XXXXXX")" || return 1
  if ! printf '%s\n' "$value" >"$tmp" || ! chmod 0600 "$tmp" || ! mv -f -- "$tmp" "$destination"; then
    rm -f -- "$tmp"
    return 1
  fi
}

persist_active_compose_chain() {
  local manifest="$SCRIPT_DIR/.upgrade/compose-files" tmp entry
  local -a active_entries=()
  [[ -f "${RELEASE_IMAGE_OVERRIDE:-}" ]] || fail "正式镜像 override 缺失"
  mkdir -p -m 0700 -- "$SCRIPT_DIR/.upgrade" || fail "无法创建升级状态目录"
  tmp="$(mktemp "$SCRIPT_DIR/.upgrade/.compose-files.XXXXXX")" || fail "无法创建 Compose 链临时文件"
  IFS=',' read -ra active_entries <<<"${ACTIVE_CONFIG_FILES:-}"
  for entry in "${active_entries[@]}"; do
    [[ -n "$entry" ]] && printf '%s\n' "$entry" >>"$tmp"
  done
  printf '%s\n' "$RELEASE_IMAGE_OVERRIDE" >>"$tmp"
  chmod 0600 "$tmp" || { rm -f -- "$tmp"; fail "无法保护 Compose 链"; }
  mv -f -- "$tmp" "$manifest" || fail "无法原子提交 Compose 链"
  write_private_state_line "$SCRIPT_DIR/.upgrade/project-name" "$EXISTING_PROJECT_NAME" ||
    fail "无法原子提交 Compose 项目名"
  write_private_state_line "$SCRIPT_DIR/.upgrade/project-directory" "$SCRIPT_DIR" ||
    fail "无法原子提交 Compose project directory"
}

new_compose_args() {
  NEW_COMPOSE_ARGS=("$COMPOSE_WRAPPER" --project-name "$EXISTING_PROJECT_NAME" --project-directory "$SCRIPT_DIR" --env-file "$SCRIPT_DIR/.env")
  local profile entry
  local -a active_entries=()
  for profile in "${OLD_PROFILES[@]:-}"; do NEW_COMPOSE_ARGS+=(--profile "$profile"); done
  NEW_COMPOSE_ARGS+=(-f "$SCRIPT_DIR/docker-compose.offline.yml")
  IFS=',' read -ra active_entries <<<"${ACTIVE_CONFIG_FILES:-}"
  for entry in "${active_entries[@]}"; do [[ -n "$entry" ]] && NEW_COMPOSE_ARGS+=(-f "$entry"); done
  [[ -f "${RELEASE_IMAGE_OVERRIDE:-}" ]] || fail "正式镜像 override 缺失"
  NEW_COMPOSE_ARGS+=(-f "$RELEASE_IMAGE_OVERRIDE")
  # Appended last so the Tier-1 overlay wins the sidecar image/provider.
  local tier1_overlay
  tier1_overlay="$(tier1_bundle_overlay "$SCRIPT_DIR" "$SCRIPT_DIR/.env")"
  [[ -z "$tier1_overlay" ]] || NEW_COMPOSE_ARGS+=(-f "$tier1_overlay")
  tier1_bundle_gpu_preflight
}

old_compose_args() {
  validate_config_snapshots || fail "原部署 Compose 配置快照身份已变化"
  local entry index=0 skip_snapshot_base=0 tier1_overlay=""
  local -a config_entries=()
  OLD_COMPOSE_ARGS=("$COMPOSE_WRAPPER" --project-name "$EXISTING_PROJECT_NAME" --project-directory "$EXISTING_WORK_DIR" --env-file "$OLD_ENV_SNAPSHOT_FILE")
  if [[ "$DEVELOPMENT_NORMALIZED_CONFIG" != 1 &&
        -f "$EXISTING_WORK_DIR/docker-compose.offline.yml" &&
        ! -L "$EXISTING_WORK_DIR/docker-compose.offline.yml" ]]; then
    OLD_COMPOSE_ARGS+=(-f "$EXISTING_WORK_DIR/docker-compose.offline.yml")
    skip_snapshot_base=1
  fi
  IFS=',' read -ra config_entries <<<"$OLD_CONFIG_SNAPSHOT_FILES"
  for entry in "${config_entries[@]}"; do
    # config-000 is the historical copy of the base file. Use the original
    # path above so Docker Compose labels remain re-upgradeable after failure
    # recovery; retain only inherited overrides from the snapshot set.
    if (( skip_snapshot_base == 1 && index == 0 )); then
      index=$((index + 1))
      continue
    fi
    OLD_COMPOSE_ARGS+=(-f "$entry")
    index=$((index + 1))
  done
  OLD_COMPOSE_ARGS+=(-f "$BACKUP_DIR/rollback-compose.yml")
  # Keep the sidecar topology the old install was scaled to, when it recorded one.
  tier1_overlay="$(tier1_bundle_overlay "$EXISTING_WORK_DIR" "$OLD_ENV_SNAPSHOT_FILE")"
  [[ -z "$tier1_overlay" ]] || OLD_COMPOSE_ARGS+=(-f "$tier1_overlay")
}

run_old_compose() {
  validate_config_snapshots || return 1
  "${OLD_COMPOSE_ARGS[@]}" "$@"
}

capture_rollback_images() {
  local output line container service image manifest override
  declare -g -a OLD_RUNNING_SERVICES=() OLD_PROFILES=()
  declare -A seen_images=()
  [[ -d "${BACKUP_DIR:-}" ]] || fail "回滚镜像捕获缺少本次备份目录"
  output="$(docker ps --filter status=running --filter "label=com.docker.compose.project=$EXISTING_PROJECT_NAME" \
    --format '{{.ID}}|{{.Label "com.docker.compose.service"}}')" || fail "无法枚举原项目运行服务"
  [[ -n "$output" ]] || fail "原项目没有运行中的 Compose 服务"
  while IFS='|' read -r container service; do
    [[ -n "$container" ]] || continue
    valid_service_name "$service" || fail "原项目服务名非法：$service"
    image="$(docker inspect --format '{{.Image}}' "$container")" || fail "无法读取旧镜像 ID：$service"
    [[ "$image" =~ ^sha256:[0-9a-f]{64}$ ]] || fail "旧镜像 ID 非法：$service"
    if [[ -n "${seen_images[$service]+x}" && "${seen_images[$service]}" != "$image" ]]; then
      fail "同一服务存在不同旧镜像：$service"
    fi
    if [[ -z "${seen_images[$service]+x}" ]]; then
      seen_images[$service]="$image"; OLD_RUNNING_SERVICES+=("$service")
    fi
    case "$service" in
      llm-judge) append_profile_once full ;;
      chat-portal-ui) append_profile_once chat ;;
    esac
  done <<<"$output"

  manifest="$BACKUP_DIR/rollback-images.tsv"; override="$BACKUP_DIR/rollback-compose.yml"
  : >"$manifest"; printf 'services:\n' >"$override"
  for service in "${OLD_RUNNING_SERVICES[@]}"; do
    printf '%s\t%s\n' "$service" "${seen_images[$service]}" >>"$manifest"
    printf '  %s:\n    image: %s\n' "$service" "${seen_images[$service]}" >>"$override"
  done
  chmod 0600 "$manifest" "$override" || fail "无法保护回滚镜像清单"
}

create_legacy_release_anchor() {
  local anchor dc deploy_lib deploy_root active source snapshot destination index entry helper asset
  local -a sources=() snapshots=() active_files=()
  validate_config_snapshots || fail "创建回退 release 前配置快照身份已变化"
  [[ -d "${BACKUP_DIR:-}" && -f "$BACKUP_DIR/rollback-compose.yml" ]] || \
    fail "创建回退 release 前缺少回滚镜像清单"
  IFS=',' read -ra sources <<<"$EXISTING_CONFIG_FILES"
  IFS=',' read -ra snapshots <<<"$OLD_CONFIG_SNAPSHOT_FILES"
  (( ${#sources[@]} == ${#snapshots[@]} && ${#sources[@]} >= 1 )) || \
    fail "创建回退 release 时配置快照数量不一致"

  anchor="$BACKUP_DIR/legacy-release"
  dc="$anchor/deploy/docker-compose"
  deploy_lib="$anchor/deploy/lib"
  active="$dc/active-config/$UPGRADE_RUN_TIMESTAMP"
  [[ ! -e "$anchor" && ! -L "$anchor" ]] || fail "回退 release 已存在"
  mkdir -p -m 0700 -- "$active" "$dc/.upgrade" "$deploy_lib" || fail "无法创建回退 release"
  install -m 0755 -- "$SCRIPT_DIR/../offline-installer/jjdctl" "$anchor/jjdctl" || fail "无法安装回退 jjdctl"
  helper="$SCRIPT_DIR/../offline-installer/wait-docker.sh"
  [[ -f "$helper" && ! -L "$helper" ]] || fail 'rollback release is missing Docker readiness helper'
  mkdir -m 0700 -- "$anchor/deploy/offline-installer" || fail 'cannot create rollback startup directory'
  install -m 0755 -- "$helper" "$anchor/deploy/offline-installer/wait-docker.sh" || fail 'cannot retain rollback Docker readiness helper'
  helper="$SCRIPT_DIR/../lib/captcha-login.sh"
  [[ -f "$helper" && ! -L "$helper" ]] || fail "回退 release 缺少可信登录 helper"
  install -m 0755 -- "$helper" "$deploy_lib/captcha-login.sh" || fail "无法安装回退登录 helper"
  # jjdctl / smoke-test.sh / backup-db.sh / diagnose.sh 都经它安全读取 .env（不 source），回退 release 必须带上，
  # 否则回滚入口会在读 .env 前就退出。
  helper="$SCRIPT_DIR/../lib/jjd-env.sh"
  [[ -f "$helper" && ! -L "$helper" ]] || fail "回退 release 缺少可信 .env 读取库"
  install -m 0755 -- "$helper" "$deploy_lib/jjd-env.sh" || fail "无法安装回退 .env 读取库"
  for entry in compose-wrapper.sh smoke-test.sh backup-db.sh diagnose.sh; do
    [[ -f "$SCRIPT_DIR/$entry" ]] || continue
    install -m 0755 -- "$SCRIPT_DIR/$entry" "$dc/$entry" || fail "无法安装回退工具：$entry"
  done
  if [[ -d "$SCRIPT_DIR/bin" && ! -L "$SCRIPT_DIR/bin" ]]; then
    cp -a -- "$SCRIPT_DIR/bin" "$dc/bin" || fail "无法安装回退 Compose 二进制"
  fi
  install -m 0600 -- "${snapshots[0]}" "$dc/docker-compose.offline.yml" || fail "无法安装回退基础 Compose"
  install -m 0600 -- "$OLD_ENV_SNAPSHOT_FILE" "$dc/.env" || fail "无法安装回退环境文件"
  for asset in identity-runtime.env directory-truststore initdb tls chat agent-kit; do
    source="$EXISTING_WORK_DIR/$asset"
    [[ -e "$source" || -L "$source" ]] || continue
    [[ ! -L "$source" ]] || fail "回退运行资产不能是符号链接：$asset"
    if [[ -d "$source" ]]; then
      if find -P "$source" -mindepth 1 \( -type l -o \( ! -type d ! -type f \) \) -print -quit | grep -q .; then
        fail "回退运行资产包含不安全条目：$asset"
      fi
    elif [[ ! -f "$source" ]]; then
      fail "回退运行资产类型非法：$asset"
    fi
    cp -a -- "$source" "$dc/$asset" || fail "无法安装回退运行资产：$asset"
  done
  deploy_root="$(realpath -e -- "$EXISTING_WORK_DIR/..")" || fail "无法解析原部署 deploy 目录"
  source="$deploy_root/migrations"
  if [[ -d "$source" && ! -L "$source" ]]; then
    if find -P "$source" -mindepth 1 \( -type l -o \( ! -type d ! -type f \) \) -print -quit | grep -q .; then
      fail "回退 migrations 包含不安全条目"
    fi
    cp -a -- "$source" "$anchor/deploy/migrations" || fail "无法安装回退 migrations"
  fi

  for index in "${!sources[@]}"; do
    (( index == 0 )) && continue
    source="${sources[$index]}"
    snapshot="${snapshots[$index]}"
    case "$source" in */.upgrade/compose.upgrade.yml) continue ;; esac
    generated_image_pin_layer "$snapshot" && continue
    destination="$active/inherited-$(printf '%03d' "$index").yml"
    install -m 0600 -- "$snapshot" "$destination" || fail "无法安装回退 Compose override"
    active_files+=("$destination")
  done
  destination="$active/rollback-images.override.yml"
  install -m 0600 -- "$BACKUP_DIR/rollback-compose.yml" "$destination" || fail "无法安装回退镜像 override"
  active_files+=("$destination")
  : >"$dc/.upgrade/compose-files"
  for entry in "${active_files[@]}"; do printf '%s\n' "$entry" >>"$dc/.upgrade/compose-files"; done
  printf '%s\n' "$EXISTING_PROJECT_NAME" >"$dc/.upgrade/project-name"
  printf '%s\n' "$dc" >"$dc/.upgrade/project-directory"
  chmod 0600 "$dc/.upgrade/compose-files" "$dc/.upgrade/project-name" "$dc/.upgrade/project-directory"
  LEGACY_RELEASE_ANCHOR="$anchor"
  export LEGACY_RELEASE_ANCHOR
}

persist_bundle_upgrade_state() {
  local state="$SCRIPT_DIR/.upgrade/bundle-upgrade.env" tmp
  [[ -d "${LEGACY_RELEASE_ANCHOR:-}" && -d "${ACTIVE_CONFIG_DIR:-}" ]] || fail "升级状态缺少回退或活动配置锚点"
  tmp="$(mktemp "$SCRIPT_DIR/.upgrade/.bundle-upgrade.XXXXXX")" || fail "无法创建升级状态文件"
  {
    printf 'EXISTING_PROJECT_NAME=%q\n' "$EXISTING_PROJECT_NAME"
    printf 'PREVIOUS_WORK_DIR=%q\n' "$EXISTING_WORK_DIR"
    printf 'LEGACY_RELEASE_ANCHOR=%q\n' "$LEGACY_RELEASE_ANCHOR"
    printf 'BACKUP_DIR=%q\n' "$BACKUP_DIR"
    printf 'MAIN_BACKUP_FILE=%q\n' "$BACKUP_DIR/postgres.dump"
    printf 'CHAT_BACKUP_FILE=%q\n' "$( [[ -f "$BACKUP_DIR/chat-postgres.dump" ]] && printf '%s' "$BACKUP_DIR/chat-postgres.dump" || true )"
    printf 'ACTIVE_CONFIG_DIR=%q\n' "$ACTIVE_CONFIG_DIR"
    printf 'COMPLETED_AT=%q\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  } >"$tmp"
  chmod 0600 "$tmp" || { rm -f -- "$tmp"; fail "无法保护升级状态文件"; }
  mv -f -- "$tmp" "$state" || fail "无法原子提交升级状态文件"
}

normalize_arch() {
  case "$1" in x86_64|amd64) printf amd64;; aarch64|arm64) printf arm64;; *) printf '%s' "$1";; esac
}

sha256_file() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then shasum -a 256 "$1" | awk '{print $1}'
  else return 1; fi
}

load_offline_images() {
  local archive checksum expected actual manifest_arch host_arch image image_arch output
  local -a archives=() images=()
  if [[ -n "${OFFLINE_IMAGE_ARCHIVE:-}" ]]; then
    [[ -f "$OFFLINE_IMAGE_ARCHIVE" ]] || fail "显式离线镜像归档不存在"
    archives=("$OFFLINE_IMAGE_ARCHIVE")
  else
    shopt -s nullglob
    archives=("$SCRIPT_DIR"/offline-artifacts/jjdguard-offline-images-*.tar.gz)
    shopt -u nullglob
    (( ${#archives[@]} == 1 )) || fail "必须恰好发现一个离线镜像归档，当前 ${#archives[@]} 个"
  fi
  archive="${archives[0]}"; checksum="$archive.sha256"
  [[ -f "$checksum" ]] || fail "离线镜像归档缺少 .sha256"
  expected="$(awk 'NR==1 {print $1}' "$checksum")"
  [[ "$expected" =~ ^[0-9a-fA-F]{64}$ ]] || fail "离线镜像校验值非法"
  actual="$(sha256_file "$archive")" || fail "无法计算离线镜像校验值"
  [[ "${expected,,}" == "${actual,,}" ]] || fail "离线镜像归档校验失败"

  [[ -f "$SCRIPT_DIR/manifest.json" ]] || fail "缺少离线包 manifest.json"
  manifest_arch="$(sed -n 's/.*"target_arch"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$SCRIPT_DIR/manifest.json" | head -1)"
  host_arch="$(normalize_arch "$(uname -m)")"
  [[ "$manifest_arch" == amd64 || "$manifest_arch" == arm64 ]] || fail "bundle architecture must be amd64 or arm64"
  [[ "$host_arch" == "$manifest_arch" ]] || fail "离线包架构与主机不匹配"
  gzip -dc -- "$archive" | docker load || fail "离线镜像导入失败"

  ALL_PROFILES_COMPOSE_ARGS=("$COMPOSE_WRAPPER" --project-name "$EXISTING_PROJECT_NAME" --env-file "$SCRIPT_DIR/.env" \
    --profile '*' -f "$SCRIPT_DIR/docker-compose.offline.yml")
  output="$("${ALL_PROFILES_COMPOSE_ARGS[@]}" config --images)" || fail "无法解析新 Compose 全 profiles 镜像"
  while IFS= read -r image; do [[ -n "$image" ]] && images+=("$image"); done <<<"$output"
  (( ${#images[@]} > 0 )) || fail "新 Compose 未声明镜像"
  for image in "${images[@]}"; do
    image_arch="$(docker image inspect --format '{{.Architecture}}' "$image")" || fail "新镜像不存在：$image"
    [[ "$(normalize_arch "$image_arch")" == "$manifest_arch" ]] || fail "新镜像架构不匹配：$image"
  done
}

run_database_migrations() {
  local profiles="" profile
  [[ -x "$SCRIPT_DIR/migrate-private.sh" ]] || fail "缺少幂等数据库迁移脚本"
  for profile in "${OLD_PROFILES[@]:-}"; do profiles="${profiles:+$profiles,}$profile"; done
  COMPOSE_WRAPPER="$COMPOSE_WRAPPER" \
    COMPOSE_PROJECT_NAME="$EXISTING_PROJECT_NAME" COMPOSE_FILE="$SCRIPT_DIR/docker-compose.offline.yml" \
    COMPOSE_PROFILES="$profiles" sh "$SCRIPT_DIR/migrate-private.sh" || fail "数据库迁移失败"
}

repair_customer_environment_scope() {
  if ! customer_environment_scope_repair_enabled; then
    log "[info] customer environment-scope repair skipped (explicit GATEWAY_ENVIRONMENT_SCOPE=customer is required)"
    return 0
  fi
  local sql="$SCRIPT_DIR/customer-environment-scope-repair.sql" container identity pguser pgdatabase
  [[ -r "$sql" ]] || fail "客户环境作用域修复 SQL 缺失"
  container="$(project_container postgres)"
  [[ -n "$container" ]] || fail "postgres 容器不存在，无法修复客户环境作用域"
  identity="$(database_identity "$container")" || fail "无法读取 postgres 数据库身份"
  IFS='|' read -r pguser pgdatabase <<<"$identity"
  bash "$SCRIPT_DIR/apply-customer-environment-scope-repair.sh" "$container" "$pguser" "$pgdatabase" ||
    fail "客户环境作用域后台任务激活失败"
  log "[ok] 客户 environment-scope 后台修复任务已激活"
}

preflight_old_services_in_new_compose() {
  local output service
  declare -A available=()
  new_compose_args
  output="$("${NEW_COMPOSE_ARGS[@]}" config --services)" || fail "新 Compose 配置预检失败"
  while IFS= read -r service; do valid_service_name "$service" && available[$service]=1; done <<<"$output"
  for service in "${OLD_RUNNING_SERVICES[@]}"; do
    [[ -n "${available[$service]+x}" ]] || fail "新 Compose 缺少旧运行服务：$service"
  done
}

# 旧版 jjdctl 的启动链也必须使用捕获的旧镜像，导入候选镜像后标签可能已变化。
persist_rollback_boot_configuration() {
  local state_dir="$EXISTING_WORK_DIR/.upgrade" active_root="$EXISTING_WORK_DIR/active-config"
  local recovery_dir manifest_tmp entry destination index=0 metadata
  local -a snapshots=() boot_entries=()
  # 仅固化已有的离线安装启动布局；其他布局继续保留完整回退锚点。
  [[ -f "$EXISTING_WORK_DIR/docker-compose.offline.yml" && ! -L "$EXISTING_WORK_DIR/docker-compose.offline.yml" ]] || return 0
  validate_config_snapshots || return 1
  [[ -f "$BACKUP_DIR/rollback-compose.yml" && ! -L "$BACKUP_DIR/rollback-compose.yml" ]] || return 1
  [[ "$(realpath -e -- "$EXISTING_WORK_DIR")" == "$EXISTING_WORK_DIR" ]] || return 1
  for entry in "$state_dir" "$active_root"; do
    [[ ! -L "$entry" && ( ! -e "$entry" || -d "$entry" ) ]] || return 1
  done
  for metadata in compose-files project-name project-directory; do
    entry="$state_dir/$metadata"
    [[ ! -L "$entry" && ( ! -e "$entry" || -f "$entry" ) ]] || return 1
  done
  mkdir -p -m 0700 -- "$state_dir" "$active_root" || return 1
  recovery_dir="$(mktemp -d "$active_root/rollback-${UPGRADE_RUN_TIMESTAMP}.XXXXXX")" || return 1
  IFS=',' read -ra snapshots <<<"$OLD_CONFIG_SNAPSHOT_FILES"
  for entry in "${snapshots[@]}"; do
    if (( index == 0 )) && [[ "$DEVELOPMENT_NORMALIZED_CONFIG" != 1 ]]; then
      index=$((index+1)); continue
    fi
    destination="$recovery_dir/inherited-$(printf '%03d' "$index").yml"
    install -m 0600 -- "$entry" "$destination" || return 1
    boot_entries+=("$destination"); index=$((index+1))
  done
  destination="$recovery_dir/images.override.yml"
  install -m 0600 -- "$BACKUP_DIR/rollback-compose.yml" "$destination" || return 1
  boot_entries+=("$destination")
  manifest_tmp="$(mktemp "$state_dir/.rollback-compose-files.XXXXXX")" || return 1
  printf '%s\n' "${boot_entries[@]}" >"$manifest_tmp" || return 1
  chmod 0600 "$manifest_tmp" || return 1
  write_private_state_line "$state_dir/project-name" "$EXISTING_PROJECT_NAME" || return 1
  write_private_state_line "$state_dir/project-directory" "$EXISTING_WORK_DIR" || return 1
  mv -f -- "$manifest_tmp" "$state_dir/compose-files" || return 1
  log "[ok] 已固化失败回退启动链，保留旧镜像 ID 与原部署配置"
}

# 新版新增、旧部署没在跑的无状态服务（redis-cache）由新 Compose 随 gateway-core 一并创建。
# 回滚到旧链后它会成为带新 release 标签的孤儿容器：下次升级的标签归一化会用旧链重建它，
# 旧链不认识该服务即失败。这里用新链按服务名精确移除（不删卷、不做孤儿清理），恢复升级前状态。
remove_services_added_by_new_release() {
  local service
  # 只在新链已建立时执行（切换前失败或单独调用回滚时没有新链，也就没有新增服务）。
  declare -p NEW_COMPOSE_ARGS >/dev/null 2>&1 || return 0
  (( ${#NEW_COMPOSE_ARGS[@]} > 0 )) || return 0
  for service in redis-cache; do
    old_service_was_running "$service" && continue
    "${NEW_COMPOSE_ARGS[@]}" rm -s -f "$service" ||
      log "[warn] 回滚后未能移除新版新增服务 $service；再次升级前请先在新安装目录执行 compose rm -s -f $service"
  done
}

rollback_old_services() {
  local required container state all_healthy deadline
  local timeout="${ROLLBACK_HEALTH_TIMEOUT:-1200}" interval="${ROLLBACK_HEALTH_INTERVAL:-2}"
  bounded_decimal "$timeout" 1800 || return 1
  [[ "$interval" =~ ^[0-9]+([.][0-9]+)?$ ]] || return 1
  old_compose_args
  local -a tier1_scale=()
  mapfile -t tier1_scale < <(tier1_bundle_scale_flags "$OLD_ENV_SNAPSHOT_FILE")
  run_old_compose up -d --no-deps --force-recreate "${tier1_scale[@]}" "${OLD_RUNNING_SERVICES[@]}" || return 1
  remove_services_added_by_new_release
  deadline=$((SECONDS + timeout))
  while :; do
    all_healthy=1
    for required in "${OLD_RUNNING_SERVICES[@]}"; do
      container="$(run_old_compose ps -q "$required" 2>/dev/null)" || return 1
      if [[ -z "$container" ]]; then all_healthy=0; continue; fi
      state="$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{if .State.Running}}running{{else}}stopped{{end}}{{end}}' "$container" 2>/dev/null)" || state=""
      [[ "$state" == healthy || "$state" == running ]] || all_healthy=0
    done
    if (( all_healthy == 1 )); then
      persist_rollback_boot_configuration || return 1
      return 0
    fi
    (( SECONDS >= deadline )) && return 1
    sleep "$interval"
  done
}

upgrade_failure() {
  local status="$1"
  trap - ERR
  [[ "${UPGRADE_FAILURE_HANDLED:-0}" == 0 ]] || return "$status"
  UPGRADE_FAILURE_HANDLED=1
  if [[ "${IMAGE_SWITCH_STARTED:-0}" == 1 || "${DATABASE_MUTATION_STARTED:-0}" == 1 ]]; then
    echo "[rollback] database preserved：保留已提交迁移与新增业务数据，只回退应用" >&2
    echo "[rollback] 在线备份仅用于显式灾难恢复：$BACKUP_DIR" >&2
  fi
  if [[ "${SERVICES_QUIESCED:-0}" == 1 || "${IMAGE_SWITCH_STARTED:-0}" == 1 ]]; then
    rollback_old_services || echo "[error] 自动回滚健康校验失败，请人工处理；备份保留在 $BACKUP_DIR" >&2
  fi
  return "$status"
}

cleanup_upgrade_verification_artifacts() {
  local require_deleted="${1:-0}" deleted
  [[ "${UPGRADE_VERIFY_CLEANUP_ARMED:-0}" == 1 ]] || return 0
  # 验证事件保留项目外键；沿用项目软删除约定退役自检应用。
  deleted="$(docker exec "$UPGRADE_VERIFY_PG_CONTAINER" psql -U "$UPGRADE_VERIFY_PGUSER" -d "$UPGRADE_VERIFY_PGDATABASE" -tAc \
    "WITH detached AS (UPDATE request_logs SET provider_id=CASE WHEN provider_id='$UPGRADE_VERIFY_PROVIDER_ID' THEN NULL ELSE provider_id END,model_id=CASE WHEN model_id='$UPGRADE_VERIFY_MODEL_ID' THEN NULL ELSE model_id END WHERE client_id='$UPGRADE_VERIFY_KEY_ID' AND (provider_id='$UPGRADE_VERIFY_PROVIDER_ID' OR model_id='$UPGRADE_VERIFY_MODEL_ID') RETURNING 1), doverride AS (DELETE FROM model_endpoint_capability_overrides WHERE id='$UPGRADE_VERIFY_OVERRIDE_ID' AND tenant_id='tenant_default' AND model_id='$UPGRADE_VERIFY_MODEL_ID' AND endpoint_type='chat' AND state='supported' AND reason='upgrade verification' AND actor_user_id='system' RETURNING 1), dm AS (DELETE FROM models WHERE id='$UPGRADE_VERIFY_MODEL_ID' AND provider_id='$UPGRADE_VERIFY_PROVIDER_ID' AND model_name='$UPGRADE_VERIFY_MODEL_NAME' AND (SELECT count(*) FROM detached) >= 0 AND (SELECT count(*) FROM doverride) = 1 RETURNING 1), dc AS (DELETE FROM provider_credentials WHERE id='$UPGRADE_VERIFY_CREDENTIAL_ID' AND provider_id='$UPGRADE_VERIFY_PROVIDER_ID' AND credential_name='$UPGRADE_VERIFY_CREDENTIAL_NAME' RETURNING 1), catalog_entries AS (DELETE FROM model_catalog_entries ce USING providers p WHERE ce.provider_id=p.id AND p.id='$UPGRADE_VERIFY_PROVIDER_ID' AND p.tenant_id='tenant_default' AND p.name='$UPGRADE_VERIFY_PROVIDER_NAME' RETURNING 1), catalog_state AS (DELETE FROM model_catalog_sync_state cs USING providers p WHERE cs.provider_id=p.id AND cs.tenant_id='tenant_default' AND p.id='$UPGRADE_VERIFY_PROVIDER_ID' AND p.tenant_id='tenant_default' AND p.name='$UPGRADE_VERIFY_PROVIDER_NAME' RETURNING 1), dp AS (DELETE FROM providers WHERE id='$UPGRADE_VERIFY_PROVIDER_ID' AND tenant_id='tenant_default' AND name='$UPGRADE_VERIFY_PROVIDER_NAME' AND base_url='http://127.0.0.1:9' AND (SELECT count(*) FROM dm) >= 0 AND (SELECT count(*) FROM dc) >= 0 AND (SELECT count(*) FROM catalog_entries) >= 0 AND (SELECT count(*) FROM catalog_state) >= 0 RETURNING 1), dk AS (DELETE FROM internal_keys WHERE id='$UPGRADE_VERIFY_KEY_ID' AND key_hash='$UPGRADE_VERIFY_KEY_HASH' AND key_prefix='$UPGRADE_VERIFY_KEY_PREFIX' AND (SELECT count(*) FROM dp) >= 0 RETURNING 1), retired AS (UPDATE projects SET status='deleted',updated_at=NOW() WHERE id='$UPGRADE_VERIFY_PROJECT_ID' AND tenant_id='tenant_default' AND name='$UPGRADE_VERIFY_PROVIDER_NAME' AND code='$UPGRADE_VERIFY_PROJECT_CODE' AND environment='production' AND status='active' AND (SELECT count(*) FROM dk)=1 RETURNING 1) SELECT (SELECT count(*) FROM detached)||'|'||(SELECT count(*) FROM doverride)||'|'||(SELECT count(*) FROM dm)||'|'||(SELECT count(*) FROM dc)||'|'||(SELECT count(*) FROM dp)||'|'||(SELECT count(*) FROM dk)||'|'||(SELECT count(*) FROM retired)" 2>/dev/null)" || return 1
  [[ "$deleted" =~ ^[0-9]+\|1\|1\|1\|1\|1\|1$ ]] || return 1
  UPGRADE_VERIFY_KEY_ID=""
  UPGRADE_VERIFY_PROJECT_ID=""
  UPGRADE_VERIFY_PROJECT_CODE=""
  UPGRADE_VERIFY_PG_CONTAINER=""
  UPGRADE_VERIFY_PGUSER=""
  UPGRADE_VERIFY_PGDATABASE=""
  UPGRADE_VERIFY_PROVIDER_ID=""
  UPGRADE_VERIFY_CREDENTIAL_ID=""
  UPGRADE_VERIFY_MODEL_ID=""
  UPGRADE_VERIFY_OVERRIDE_ID=""
  UPGRADE_VERIFY_MODEL_NAME=""
  UPGRADE_VERIFY_PROVIDER_NAME=""
  UPGRADE_VERIFY_CREDENTIAL_NAME=""
  UPGRADE_VERIFY_KEY_HASH=""
  UPGRADE_VERIFY_KEY_PREFIX=""
  UPGRADE_VERIFY_CLEANUP_ARMED=0
}

upgrade_exit_handler() {
  local status="$1"
  trap - EXIT INT TERM ERR
  if [[ "$status" -ne 0 ]]; then
    cleanup_upgrade_verification_artifacts 0 || echo "[error] 清理临时验证资源失败，请按随机验证 id 人工检查" >&2
    if [[ "${UPGRADE_EXIT_GUARD_ACTIVE:-0}" == 1 && "${UPGRADE_FAILURE_HANDLED:-0}" == 0 ]]; then
      upgrade_failure "$status" || true
    fi
  fi
  exit "$status"
}

project_container() {
  local service="$1"
  local name="${EXISTING_PROJECT_NAME}-${service}-1"
  docker inspect --format '{{.State.Running}}' "$name" >/dev/null 2>&1 && printf '%s' "$name" || \
    docker ps --filter status=running --filter "label=com.docker.compose.project=$EXISTING_PROJECT_NAME" \
      --filter "label=com.docker.compose.service=$service" --format '{{.ID}}' | head -1
}

profile_enabled() {
  local needle="$1" p
  for p in "${OLD_PROFILES[@]:-}"; do [[ "$p" == "$needle" ]] && return 0; done
  return 1
}

old_service_was_running() {
  local needle="$1" service
  for service in "${OLD_RUNNING_SERVICES[@]:-}"; do [[ "$service" == "$needle" ]] && return 0; done
  return 1
}

load_inherited_env() {
  local env_file="$SCRIPT_DIR/.env" line key raw value
  declare -A seen=()
  [[ -f "$env_file" && ! -L "$env_file" ]] || fail "继承后的 .env 缺失或非法"
  while IFS= read -r line || [[ -n "$line" ]]; do
    line="${line%$'\r'}"
    [[ -z "$line" || "$line" == \#* ]] && continue
    [[ "$line" =~ ^([A-Za-z_][A-Za-z0-9_]*)=(.*)$ ]] || fail "继承后的 .env 不是严格的 dotenv 文件"
    key="${BASH_REMATCH[1]}"; raw="${BASH_REMATCH[2]}"
    upgrade_env_key_allowed "$key" || continue
    [[ -z "${seen[$key]+x}" ]] || fail "继承后的 .env 包含重复升级变量：$key"
    value="$(parse_literal_dotenv_value "$raw")" || fail "继承后的 .env 变量格式非法：$key"
    printf -v "$key" '%s' "$value"
    export "$key"
    seen[$key]=1
  done <"$env_file"
}

identity_runtime_required_keys() {
  printf '%s\n' \
    JJD_SSO_PUBLIC_URL \
    JJD_IDENTITY_RUNTIME_URL \
    JJD_IDENTITY_RUNTIME_CLIENT_ID \
    JJD_IDENTITY_RUNTIME_CLIENT_SECRET \
    JJD_SSO_ALLOW_INSECURE_PUBLIC_URL
}

validate_identity_runtime_env() {
  local file="$SCRIPT_DIR/identity-runtime.env" key value uid mode links
  [[ -f "$file" && ! -L "$file" ]] ||
    fail "[JJD-ID-001] 内置身份运行配置未生成；请使用正式离线包重新执行升级"
  uid="$(stat -Lc %u -- "$file")"; mode="$(stat -Lc %a -- "$file")"; links="$(stat -Lc %h -- "$file")" ||
    fail "[JJD-ID-001] 无法校验内置身份运行配置"
  [[ "$mode" == 600 && "$links" == 1 ]] ||
    fail "[JJD-ID-001] 内置身份运行配置权限异常（要求 0600 且非链接）"
  if [[ "$(id -u)" == 0 && "$uid" != 0 ]]; then
    fail "[JJD-ID-001] 内置身份运行配置属主异常（要求 root）"
  fi
  while IFS= read -r key; do
    value="$(read_literal_dotenv_key "$file" "$key")" ||
      fail "[JJD-ID-001] 内置身份运行配置缺少或重复：$key"
    [[ -n "$value" ]] || fail "[JJD-ID-001] 内置身份运行配置为空：$key"
  done < <(identity_runtime_required_keys)
  value="$(read_literal_dotenv_key "$file" JJD_SSO_ALLOW_INSECURE_PUBLIC_URL)"
  case "$value" in true|false) ;; *) fail "[JJD-ID-001] 内置身份 HTTP 兼容开关非法" ;; esac
}

identity_compose_environment() {
  local entry files="$SCRIPT_DIR/docker-compose.offline.yml" profiles=""
  local -a active_entries=()
  [[ "$files" != *'|'* ]] || fail "[JJD-ID-002] 离线 Compose 路径包含不支持的分隔符"
  IFS=',' read -ra active_entries <<<"${ACTIVE_CONFIG_FILES:-}"
  for entry in "${active_entries[@]}"; do
    [[ -n "$entry" ]] || continue
    [[ "$entry" != *'|'* ]] || fail "[JJD-ID-002] 继承的 Compose 路径包含不支持的分隔符"
    files="$files|$entry"
  done
  [[ -f "${RELEASE_IMAGE_OVERRIDE:-}" && "$RELEASE_IMAGE_OVERRIDE" != *'|'* ]] ||
    fail "[JJD-ID-002] 正式镜像 Compose override 缺失或路径非法"
  files="$files|$RELEASE_IMAGE_OVERRIDE"
  if (( ${#OLD_PROFILES[@]} > 0 )); then
    local IFS=,
    profiles="${OLD_PROFILES[*]}"
  fi
  IDENTITY_COMPOSE_FILES="$files"
  IDENTITY_COMPOSE_PROFILES="$profiles"
  export IDENTITY_COMPOSE_FILES IDENTITY_COMPOSE_PROFILES
}

verify_control_plane_identity_runtime() {
  local container runtime_env key expected line found
  container="$(project_container control-plane)"
  [[ -n "$container" ]] || fail "[JJD-ID-003] control-plane 未运行，无法验证身份配置加载"
  runtime_env="$(docker inspect --format '{{range .Config.Env}}{{println .}}{{end}}' "$container" 2>/dev/null)" ||
    fail "[JJD-ID-003] 无法读取 control-plane 身份配置状态"
  while IFS= read -r key; do
    expected="$(read_literal_dotenv_key "$SCRIPT_DIR/identity-runtime.env" "$key")" ||
      fail "[JJD-ID-003] 无法读取身份配置：$key"
    found=0
    while IFS= read -r line; do
      if [[ "$line" == "$key=$expected" ]]; then found=1; break; fi
    done <<<"$runtime_env"
    (( found == 1 )) || fail "[JJD-ID-003] control-plane 未加载有效身份配置：$key"
  done < <(identity_runtime_required_keys)
  runtime_env=""; expected=""; line=""
}

ensure_builtin_identity_runtime() {
  profile_enabled chat || return 0
  case "${CHAT_BYO_IDP:-false}" in
    true)
      log "[info] 外部 IdP 模式：跳过 JJDGuard 内置本地身份运行态初始化"
      return 0
      ;;
    false) ;;
    *) fail "[JJD-ID-000] CHAT_BYO_IDP 必须为 true 或 false" ;;
  esac

  [[ -x "$SCRIPT_DIR/chat/bootstrap-identity-runtime.sh" ]] ||
    fail "[JJD-ID-001] 离线包缺少内置身份初始化脚本"
  [[ -x "$SCRIPT_DIR/chat/bootstrap-directory-runtime.sh" ]] ||
    fail "[JJD-ID-001] 离线包缺少目录身份初始化脚本"
  identity_compose_environment

  if [[ -z "$(project_container chat-idp)" ]]; then
    log "[step] 启动内置身份服务"
    "${NEW_COMPOSE_ARGS[@]}" up -d --no-deps chat-idp
  fi
  log "[step] 校验并恢复 JJDGuard 内置身份运行态"
  (
    cd "$SCRIPT_DIR"
    COMPOSE_PROJECT_NAME="$EXISTING_PROJECT_NAME" \
    COMPOSE_FILE="$IDENTITY_COMPOSE_FILES" \
    COMPOSE_PATH_SEPARATOR='|' \
    COMPOSE_PROFILES="$IDENTITY_COMPOSE_PROFILES" \
    JJD_ENV_FILE="$SCRIPT_DIR/.env" \
    IDENTITY_RUNTIME_ENV_FILE="$SCRIPT_DIR/identity-runtime.env" \
    COMPOSE_WRAPPER="$COMPOSE_WRAPPER" \
    FAKE_LOG="${FAKE_LOG:-}" \
      bash "$SCRIPT_DIR/chat/bootstrap-identity-runtime.sh"
    COMPOSE_PROJECT_NAME="$EXISTING_PROJECT_NAME" \
    COMPOSE_FILE="$IDENTITY_COMPOSE_FILES" \
    COMPOSE_PATH_SEPARATOR='|' \
    COMPOSE_PROFILES="$IDENTITY_COMPOSE_PROFILES" \
    JJD_ENV_FILE="$SCRIPT_DIR/.env" \
    IDENTITY_RUNTIME_ENV_FILE="$SCRIPT_DIR/identity-runtime.env" \
    COMPOSE_WRAPPER="$COMPOSE_WRAPPER" \
    FAKE_LOG="${FAKE_LOG:-}" \
      bash "$SCRIPT_DIR/chat/bootstrap-directory-runtime.sh"
  ) || fail "[JJD-ID-001] 内置身份初始化失败；升级已停止并将恢复原版本"
  validate_identity_runtime_env
  "${NEW_COMPOSE_ARGS[@]}" up -d --no-deps --force-recreate --wait control-plane
  verify_control_plane_identity_runtime
  log "[ok] JJDGuard 内置身份运行态已初始化并注入 control-plane"
  # W3 3.8 / D7: existing realms are never auto-tightened; only report the portal login baseline.
  if [[ -x "$SCRIPT_DIR/chat/portal-login-baseline.sh" ]]; then
    (
      cd "$SCRIPT_DIR"
      COMPOSE_PROJECT_NAME="$EXISTING_PROJECT_NAME" \
      COMPOSE_FILE="$IDENTITY_COMPOSE_FILES" \
      COMPOSE_PATH_SEPARATOR='|' \
      COMPOSE_PROFILES="$IDENTITY_COMPOSE_PROFILES" \
      JJD_ENV_FILE="$SCRIPT_DIR/.env" \
      COMPOSE_WRAPPER="$COMPOSE_WRAPPER" \
        bash "$SCRIPT_DIR/chat/portal-login-baseline.sh" check --advisory
    ) || log "[warn] portal login baseline check skipped"
  fi
}

wait_core_services_healthy() {
  local required optional container state deadline
  local -a required_services=(gateway-core control-plane security-engine)
  local timeout="${VERIFY_HEALTH_TIMEOUT:-150}" interval="${VERIFY_HEALTH_INTERVAL:-3}"
  [[ "$timeout" =~ ^[0-9]+$ ]] || fail "VERIFY_HEALTH_TIMEOUT 非法"
  for optional in llm-judge tier1-classifier; do
    old_service_was_running "$optional" && required_services+=("$optional")
  done
  deadline=$((SECONDS + timeout))
  for required in "${required_services[@]}"; do
    while :; do
      container="$(project_container "$required")"
      if [[ -z "$container" ]]; then (( SECONDS >= deadline )) && fail "$required 容器未运行"; sleep "$interval"; continue; fi
      state="$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{if .State.Running}}running{{else}}stopped{{end}}{{end}}' "$container" 2>/dev/null)" || state=""
      [[ "$state" == healthy || "$state" == running ]] && break
      (( SECONDS >= deadline )) && fail "$required 升级后未就绪（最后状态：${state:-unknown}）"
      sleep "$interval"
    done
  done
}

http_ok() {
  local url="$1" connect_timeout="${2:-3}" max_time="${3:-12}" ca_file="${4:-}"
  command -v curl >/dev/null 2>&1 || return 1
  local code
  local -a curl_args=(-s --connect-timeout "$connect_timeout" --max-time "$max_time")
  if [[ -n "$ca_file" ]]; then
    [[ "$url" == https://* && "$ca_file" == /* && -f "$ca_file" && ! -L "$ca_file" ]] || return 1
    curl_args+=(--cacert "$ca_file")
  fi
  code="$(curl "${curl_args[@]}" -o /dev/null -w '%{http_code}' "$url" 2>/dev/null)" || return 1
  [[ "$code" =~ ^2[0-9][0-9]$ ]]
}

oidc_http_ok() {
  local url="$1" connect_timeout="${2:-3}" max_time="${3:-12}"
  case "${CHAT_BYO_IDP:-false}" in
    true)
      http_ok "$url" "$connect_timeout" "$max_time"
      ;;
    false)
      if [[ "$url" == https://* ]]; then
        http_ok "$url" "$connect_timeout" "$max_time" "$SCRIPT_DIR/tls/web-console.crt"
      else
        http_ok "$url" "$connect_timeout" "$max_time"
      fi
      ;;
    *) return 1 ;;
  esac
}

bounded_decimal() {
  local value="$1" max="$2" allow_zero="${3:-0}" value_len max_len
  local LC_ALL=C
  [[ "$value" =~ ^(0|[1-9][0-9]*)$ ]] || return 1
  [[ "$allow_zero" == 1 || "$value" != 0 ]] || return 1
  value_len="${#value}"; max_len="${#max}"
  (( value_len < max_len )) && return 0
  (( value_len == max_len )) || return 1
  [[ "$value" == "$max" || "$value" < "$max" ]]
}

oidc_discovery_url() {
  local external="${CHAT_BYO_IDP:-false}" issuer rest authority authority_port scheme suffix
  local host="${CHAT_OIDC_HOST-${UPGRADE_BASE_HOST:-127.0.0.1}}"
  local web_port="${WEB_PORT-3000}" web_https_port="${WEB_HTTPS_PORT-443}"
  local tls_enabled="${TLS_ENABLED-true}"
  case "$external" in
    true)
      issuer="${CHAT_OIDC_ISSUER:-}"
      while [[ "$issuer" == */ ]]; do issuer="${issuer%/}"; done
      case "$issuer" in http://*|https://*) ;; *) return 1 ;; esac
      [[ "$issuer" != *[[:space:]]* && "$issuer" != *'?'* && "$issuer" != *'#'* ]] || return 1
      rest="${issuer#http://}"
      [[ "$rest" != "$issuer" ]] || rest="${issuer#https://}"
      authority="${rest%%/*}"
      [[ "$authority" =~ ^(\[[0-9A-Fa-f:.]+\]|[A-Za-z0-9][A-Za-z0-9.-]*)(:([0-9]+))?$ ]] || return 1
      authority_port="${BASH_REMATCH[3]:-}"
      [[ -z "$authority_port" ]] || bounded_decimal "$authority_port" 65535 || return 1
      printf '%s/.well-known/openid-configuration\n' "$issuer"
      ;;
    false)
      issuer="${JJD_SSO_PUBLIC_URL:-}"
      if [[ -n "$issuer" ]]; then
        while [[ "$issuer" == */ ]]; do issuer="${issuer%/}"; done
        case "$issuer" in http://*|https://*) ;; *) return 1 ;; esac
        [[ "$issuer" != *[[:space:]]* && "$issuer" != *'?'* && "$issuer" != *'#'* ]] || return 1
        rest="${issuer#http://}"
        [[ "$rest" != "$issuer" ]] || rest="${issuer#https://}"
        authority="${rest%%/*}"
        [[ "$rest" == "$authority" ]] || return 1
        [[ "$authority" =~ ^(\[[0-9A-Fa-f:.]+\]|[A-Za-z0-9][A-Za-z0-9.-]*)(:([0-9]+))?$ ]] || return 1
        authority_port="${BASH_REMATCH[3]:-}"
        [[ -z "$authority_port" ]] || bounded_decimal "$authority_port" 65535 || return 1
        printf '%s/sso/realms/jjdguard/.well-known/openid-configuration\n' "$issuer"
        return
      fi
      [[ -n "$host" && "$host" != *[[:space:]/?#@]* ]] || return 1
      if [[ "$host" == \[*\] ]]; then
        [[ "$host" =~ ^\[[0-9A-Fa-f:.]+\]$ && "$host" == *:* ]] || return 1
      else
        [[ "$host" =~ ^[A-Za-z0-9][A-Za-z0-9.-]*$ ]] || return 1
      fi
      case "$tls_enabled" in
        false|0|no|off)
          bounded_decimal "$web_port" 65535 || return 1
          scheme=http
          [[ "$web_port" == 80 ]] && suffix='' || suffix=":$web_port"
          ;;
        *)
          bounded_decimal "$web_https_port" 65535 || return 1
          scheme=https
          [[ "$web_https_port" == 443 ]] && suffix='' || suffix=":$web_https_port"
          ;;
      esac
      printf '%s://%s%s/sso/realms/jjdguard/.well-known/openid-configuration\n' "$scheme" "$host" "$suffix"
      ;;
    *) return 1 ;;
  esac
}

wait_oidc_discovery() {
  local url="$1" attempt=0 deadline remaining request_timeout connect_timeout sleep_for
  local timeout="${OIDC_VERIFY_TIMEOUT:-1200}" interval="${OIDC_VERIFY_INTERVAL:-2}"
  local request_limit="${OIDC_VERIFY_REQUEST_TIMEOUT:-5}" connect_limit="${OIDC_VERIFY_CONNECT_TIMEOUT:-2}"
  local max_attempts="${OIDC_VERIFY_MAX_ATTEMPTS:-0}"
  bounded_decimal "$timeout" 1800 || fail "OIDC_VERIFY_TIMEOUT 非法"
  bounded_decimal "$interval" 10 1 || fail "OIDC_VERIFY_INTERVAL 非法"
  bounded_decimal "$request_limit" 15 || fail "OIDC_VERIFY_REQUEST_TIMEOUT 非法"
  bounded_decimal "$connect_limit" 10 || fail "OIDC_VERIFY_CONNECT_TIMEOUT 非法"
  bounded_decimal "$max_attempts" 1000 1 || fail "OIDC_VERIFY_MAX_ATTEMPTS 非法"
  deadline=$((SECONDS + timeout))
  while (( SECONDS < deadline )); do
    remaining=$((deadline - SECONDS))
    request_timeout="$request_limit"
    (( request_timeout > remaining )) && request_timeout="$remaining"
    connect_timeout="$connect_limit"
    (( connect_timeout > request_timeout )) && connect_timeout="$request_timeout"
    oidc_http_ok "$url" "$connect_timeout" "$request_timeout" && return 0
    attempt=$((attempt + 1))
    (( max_attempts > 0 && attempt >= max_attempts )) && return 1
    (( SECONDS >= deadline )) && return 1
    remaining=$((deadline - SECONDS))
    sleep_for="$interval"
    (( sleep_for > remaining )) && sleep_for="$remaining"
    sleep "$sleep_for"
  done
  return 1
}

verify_core_health() {
  local base="${UPGRADE_BASE_HOST:-127.0.0.1}" service port container
  for service in gateway-core:8080 control-plane:8081 security-engine:8000; do
    service="${service%%:*}"
    case "$service" in
      gateway-core) port="${GATEWAY_PORT:-8080}" ;;
      control-plane) port="${CONTROL_PORT:-8081}" ;;
      security-engine) port="${SECURITY_PORT:-8000}" ;;
    esac
    if ! http_ok "http://${base}:${port}/health"; then
      container="$(project_container "$service")"
      [[ -n "$container" ]] || fail "$service 容器不存在"
      case "$service" in
        gateway-core|control-plane) docker exec "$container" wget -qO- http://127.0.0.1:8080/health >/dev/null 2>&1 ;;
        security-engine) docker exec "$container" python -c "import urllib.request;urllib.request.urlopen('http://127.0.0.1:8000/health',timeout=10)" >/dev/null 2>&1 ;;
      esac || fail "$service /health 不可达"
    fi
  done
  log "[ok] 核心服务 /health 通过（gateway-core / control-plane / security-engine）"
}

verify_web_console() {
  local base="${UPGRADE_BASE_HOST:-127.0.0.1}" port="${WEB_PORT:-3000}" container
  old_service_was_running web-console || return 0
  if ! http_ok "http://${base}:${port}/health"; then
    container="$(project_container web-console)"
    [[ -n "$container" ]] || fail "web-console 容器不存在"
    docker exec "$container" wget -qO- http://127.0.0.1:3000/health >/dev/null 2>&1 || fail "web-console /health 不可达"
  fi
  log "[ok] web-console /health 通过"
}

verify_portal_image_identity() {
  local container configured_image actual_image expected_image
  local expected_ref=enterprise-ai-portal:0.2.0-slim
  container="$(project_container chat-portal-ui)"
  [[ -n "$container" ]] || fail "chat-portal-ui 容器不存在"
  configured_image="$(docker inspect --format '{{.Config.Image}}' "$container" 2>/dev/null)" ||
    fail "无法读取 chat-portal-ui 镜像引用"
  actual_image="$(docker inspect --format '{{.Image}}' "$container" 2>/dev/null)" ||
    fail "无法读取 chat-portal-ui 实际镜像 ID"
  expected_image="$(docker image inspect --format '{{.Id}}' "$expected_ref" 2>/dev/null)" ||
    fail "无法读取正式门户镜像 ID"
  [[ "$actual_image" =~ ^sha256:[0-9a-f]{64}$ &&
     "$expected_image" =~ ^sha256:[0-9a-f]{64}$ ]] ||
    fail "门户镜像 ID 非法"
  [[ "$actual_image" == "$expected_image" ]] ||
    fail "门户实际镜像与正式镜像不一致：$actual_image"
  [[ "$configured_image" == "$expected_ref" || "$configured_image" == "$expected_image" ]] ||
    fail "门户镜像引用不受信任：$configured_image"
}

verify_chat_profile() {
  verify_portal_image_identity
  log "[ok] 门户镜像身份为 enterprise-ai-portal:0.2.0-slim"

  local container base="${UPGRADE_BASE_HOST:-127.0.0.1}"
  container="$(project_container chat-portal-proxy)"
  [[ -n "$container" ]] || fail "chat-portal-proxy 容器不存在"
  docker exec "$container" node -e "fetch('http://127.0.0.1:8788/healthz').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))" >/dev/null 2>&1 || \
    fail "chat-portal-proxy /healthz 不可达"
  log "[ok] chat-portal-proxy /healthz 通过"

  local discovery_url
  discovery_url="$(oidc_discovery_url)" || fail "OIDC discovery 配置非法"
  wait_oidc_discovery "$discovery_url" || fail "OIDC discovery 在有界等待后仍不可达"
  log "[ok] OIDC discovery 通过"
}

verify_full_profile() {
  local container result
  container="$(project_container llm-judge)"
  [[ -n "$container" ]] || fail "llm-judge 容器不存在"
  result="$(docker exec "$container" wget -qO- --header='Authorization: Bearer bundled-judge' http://127.0.0.1:8080/v1/models 2>/dev/null)" || \
    fail "llm-judge /v1/models 不可达"
  printf '%s' "$result" | grep -qi 'judge' || fail "llm-judge /v1/models 未返回模型"
  log "[ok] llm-judge /v1/models 通过"

  container="$(project_container tier1-classifier)"
  [[ -n "$container" ]] || fail "tier1-classifier 容器不存在"
  docker exec "$container" python -c "import urllib.request,sys;sys.stdout.write(urllib.request.urlopen('http://127.0.0.1:8000/health',timeout=10).read().decode())" >/dev/null 2>&1 || \
    fail "tier1-classifier /health 不可达"
  log "[ok] tier1-classifier /health 通过"
}

verify_security_events_persistence() {
  local pg_container identity pguser pgdatabase before after
  local random_hex raw_key key_hash key_id key_prefix inserted http_status request_status=0
  local project_id project_code provider_id credential_id model_id override_id model_name
  local provider_name credential_name
  pg_container="$(project_container postgres)"
  [[ -n "$pg_container" ]] || fail "postgres 容器不存在，无法验证 security_events 落库"
  identity="$(database_identity "$pg_container")" || fail "无法识别主库身份，无法验证 security_events 落库"
  IFS='|' read -r pguser pgdatabase <<<"$identity"

  command -v openssl >/dev/null 2>&1 || fail "缺少 openssl，无法生成临时验证 key"
  random_hex="$(openssl rand -hex 24 2>/dev/null)" || fail "生成临时验证 key 失败"
  [[ "$random_hex" =~ ^[0-9a-f]{48}$ ]] || fail "生成的临时验证 key 非法"
  raw_key="sk-upgrade-${random_hex}"
  key_id="key_upgrade_verify_${random_hex:0:16}"
  project_id="project_upgrade_verify_${random_hex:0:16}"
  project_code="upv_${random_hex:0:16}"
  key_prefix="${raw_key:0:8}"
  provider_id="prov_upgrade_${random_hex:0:16}"
  credential_id="cred_upgrade_${random_hex:0:16}"
  model_id="model_upgrade_${random_hex:0:16}"
  override_id="meco_upgrade_${random_hex:0:16}"
  model_name="upgrade-verify-${random_hex:0:16}"
  provider_name="UpgradeVerify-${random_hex}"
  credential_name="verify-${random_hex}"
  if command -v sha256sum >/dev/null 2>&1; then
    key_hash="$(printf '%s' "$raw_key" | sha256sum | awk '{print $1}')"
  elif command -v shasum >/dev/null 2>&1; then
    key_hash="$(printf '%s' "$raw_key" | shasum -a 256 | awk '{print $1}')"
  else
    fail "缺少 SHA-256 工具，无法创建临时验证 key"
  fi
  [[ "$key_hash" =~ ^[0-9a-f]{64}$ ]] || fail "临时验证 key 哈希失败"

  before="$(docker exec "$pg_container" psql -U "$pguser" -d "$pgdatabase" -tAc \
    "SELECT count(*) FROM security_events se JOIN request_logs rl ON rl.request_id=se.request_id WHERE se.tenant_id='tenant_default' AND rl.client_id='$key_id' AND rl.provider_id='$provider_id' AND rl.model_id='$model_id' AND se.event_type='security_check' AND se.matched_summary->>'category'='ssh_private_key' AND se.severity IN ('high','critical')" 2>/dev/null)" || \
    fail "查询本次验证 key 的 security_events 初始计数失败"
  [[ "$before" =~ ^[0-9]+$ ]] || fail "本次验证 key 的 security_events 初始计数非法"

  UPGRADE_VERIFY_KEY_ID="$key_id"
  UPGRADE_VERIFY_PROJECT_ID="$project_id"
  UPGRADE_VERIFY_PROJECT_CODE="$project_code"
  UPGRADE_VERIFY_PG_CONTAINER="$pg_container"
  UPGRADE_VERIFY_PGUSER="$pguser"
  UPGRADE_VERIFY_PGDATABASE="$pgdatabase"
  UPGRADE_VERIFY_PROVIDER_ID="$provider_id"
  UPGRADE_VERIFY_CREDENTIAL_ID="$credential_id"
  UPGRADE_VERIFY_MODEL_ID="$model_id"
  UPGRADE_VERIFY_OVERRIDE_ID="$override_id"
  UPGRADE_VERIFY_MODEL_NAME="$model_name"
  UPGRADE_VERIFY_PROVIDER_NAME="$provider_name"
  UPGRADE_VERIFY_CREDENTIAL_NAME="$credential_name"
  UPGRADE_VERIFY_KEY_HASH="$key_hash"
  UPGRADE_VERIFY_KEY_PREFIX="$key_prefix"
  # 自检应用独立建档，客户应用的模型策略保持原样。
  inserted="$(docker exec "$pg_container" psql -U "$pguser" -d "$pgdatabase" -tAc \
    "WITH pj AS (INSERT INTO projects (id,tenant_id,name,code,environment,status) VALUES ('$project_id','tenant_default','$provider_name','$project_code','production','active') RETURNING id), p AS (INSERT INTO providers (id,tenant_id,name,provider_type,base_url,auth_mode,is_default,status) VALUES ('$provider_id','tenant_default','$provider_name','openai','http://127.0.0.1:9','api_key',false,'active') RETURNING id), c AS (INSERT INTO provider_credentials (id,provider_id,credential_name,secret_ciphertext,status) SELECT '$credential_id',id,'$credential_name','blackhole-$random_hex','active' FROM p RETURNING id), m AS (INSERT INTO models (id,provider_id,model_name,model_label,status) SELECT '$model_id',id,'$model_name','$model_name','active' FROM p RETURNING id), o AS (INSERT INTO model_endpoint_capability_overrides (id,tenant_id,model_id,endpoint_type,state,reason,actor_user_id) SELECT '$override_id','tenant_default',id,'chat','supported','upgrade verification','system' FROM m RETURNING id), k AS (INSERT INTO internal_keys (id,tenant_id,project_id,user_id,key_hash,key_prefix,scopes_json,expires_at,status) VALUES ('$key_id','tenant_default','$project_id',NULL,'$key_hash','$key_prefix','[\"chat\"]'::jsonb,NOW() + INTERVAL '10 minutes','active') RETURNING id) SELECT (SELECT count(*) FROM p)||'|'||(SELECT count(*) FROM c)||'|'||(SELECT count(*) FROM m)||'|'||(SELECT count(*) FROM o)||'|'||(SELECT count(*) FROM k)||'|'||(SELECT count(*) FROM pj)" 2>/dev/null)" || fail "创建临时验证资源失败"
  [[ "$inserted" == "1|1|1|1|1|1" ]] || fail "临时验证资源未唯一写入"
  UPGRADE_VERIFY_CLEANUP_ARMED=1
  # Allow the configured 60s gateway security check plus response overhead on a cold host.
  local base="${UPGRADE_BASE_HOST:-127.0.0.1}" gw_port="${GATEWAY_PORT:-8080}"
  http_status="$(printf 'header = "Authorization: Bearer %s"\n' "$raw_key" | \
    curl --config - -sS --connect-timeout 5 -m 75 -o /dev/null -w '%{http_code}' -X POST \
      "http://${base}:${gw_port}/v1/chat/completions" -H 'Content-Type: application/json' \
      -d "{\"model\":\"$model_name\",\"messages\":[{\"role\":\"user\",\"content\":\"-----BEGIN RSA PRIVATE KEY-----\\nMIIEowIBAAKCAQEA-----END RSA PRIVATE KEY-----\\nupgrade-verification-$random_hex\"}]}" 2>/dev/null)" || request_status=$?
  (( request_status == 0 )) || fail "网关高置信检测样本请求失败（curl=${request_status}，HTTP ${http_status:-unknown}）"
  case "$http_status" in
    ''|000|401) fail "网关高置信检测样本请求被拒绝（HTTP ${http_status:-unknown}）" ;;
    *[!0-9]*|????*) fail "网关高置信检测样本 HTTP 状态非法" ;;
  esac

  local i=0
  while [[ "$i" -lt 15 ]]; do
    after="$(docker exec "$pg_container" psql -U "$pguser" -d "$pgdatabase" -tAc \
      "SELECT count(*) FROM security_events se JOIN request_logs rl ON rl.request_id=se.request_id WHERE se.tenant_id='tenant_default' AND rl.client_id='$key_id' AND rl.provider_id='$provider_id' AND rl.model_id='$model_id' AND se.event_type='security_check' AND se.matched_summary->>'category'='ssh_private_key' AND se.severity IN ('high','critical')" 2>/dev/null)" || {
      fail "轮询 security_events 计数失败"
    }
    if [[ "$after" =~ ^[0-9]+$ && "$after" -gt "$before" ]]; then
      cleanup_upgrade_verification_artifacts 1 || fail "清理临时验证资源失败"
      log "[ok] security_events 落库验证通过（$before → $after）"
      return 0
    fi
    i=$((i + 1)); sleep 1
  done
  fail "网关检测样本未写入 security_events（HTTP ${http_status:-unknown}，$before → ${after:-?}）"
}

# Compose 的 `config --hash` 不会解析 env_file（真正载入发生在创建容器时），而容器的
# com.docker.compose.config-hash 含 env_file 解析后的环境。因此凡声明 env_file 的服务
# （本产品是 control-plane 的 identity-runtime.env），两侧天然不相等，直接比较会把
# 「配置其实一致」误报成「重启即变样」。这里退一步用同口径复现：按开机链
# `up --no-deps --no-start` 建一个同配置、不启动的探针容器（只建目标服务、不牵连依赖），
# 读它的 config-hash 再删掉。容器 config-hash 与 Compose 项目名无关（v5.3.0 / v5.3.1 实测），
# 所以探针项目名不影响比较结果。
# 注意：compose 仍会按项目声明建出空命名卷；契约禁止删卷，故不清理，只在出现时告警一次。
# 若将来有 env_file 服务落在 profile 里，这里需要把对应 --profile 一并传进来。
boot_chain_probe_hash() {
  local service="$1" probe container hash entry
  local -a probe_files=(-f "$SCRIPT_DIR/docker-compose.offline.yml")
  [[ -f "$SCRIPT_DIR/.upgrade/compose-files" ]] || return 1
  while IFS= read -r entry || [[ -n "$entry" ]]; do
    [[ -n "$entry" ]] && probe_files+=(-f "$entry")
  done <"$SCRIPT_DIR/.upgrade/compose-files"
  probe="bootchk-$$-$RANDOM"
  # 用 up --no-deps --no-start：只创建目标服务、不拉起、不牵连依赖，避免多建容器与命名卷。
  if ! "$COMPOSE_WRAPPER" --project-name "$probe" --project-directory "$SCRIPT_DIR" \
    --env-file "$SCRIPT_DIR/.env" "${probe_files[@]}" up --no-deps --no-start "$service" >/dev/null 2>&1; then
    boot_chain_probe_cleanup "$probe" >&2
    return 1
  fi
  container="$(docker ps -aq --filter "label=com.docker.compose.project=$probe" \
    --filter "label=com.docker.compose.service=$service" 2>/dev/null | head -1)"
  hash=""
  if [[ -n "$container" ]]; then
    hash="$(docker inspect --format '{{index .Config.Labels "com.docker.compose.config-hash"}}' "$container" 2>/dev/null || true)"
  fi
  # 清理过程的日志必须走 stderr：本函数的 stdout 只允许是哈希，否则会被调用方的
  # 命令替换当成哈希值的一部分（探针建卷告警曾把结果污染成 "[warn] ...\n<hash>"）。
  boot_chain_probe_cleanup "$probe" >&2
  [[ "$hash" =~ ^[0-9a-f]{64}$ ]] || return 1
  printf '%s\n' "$hash"
}

# 只清理本次探针自己创建的容器与网络；契约禁止删除数据卷，所以这里不碰卷——
# 探针用 up --no-deps --no-start 只建目标容器，正常情况下不会产生命名卷。
boot_chain_probe_cleanup() {
  local probe="$1" id
  while read -r id; do
    [[ -n "$id" ]] && docker rm -f "$id" >/dev/null 2>&1
  done < <(docker ps -aq --filter "label=com.docker.compose.project=$probe" 2>/dev/null)
  while read -r id; do
    [[ -n "$id" ]] && docker network rm "$id" >/dev/null 2>&1
  done < <(docker network ls -q --filter "label=com.docker.compose.project=$probe" 2>/dev/null)
  if docker volume ls -q --filter "label=com.docker.compose.project=$probe" 2>/dev/null | grep -q .; then
    log "[warn] 探针项目 $probe 产生了命名卷，按契约不自动删除，请人工确认：$(docker volume ls -q --filter "label=com.docker.compose.project=$probe" 2>/dev/null | tr '\n' ' ')"
  fi
  return 0
}

# verify_boot_chain_matches_running 按开机时 jjdctl start 的文件链（基础 offline.yml + .upgrade/compose-files）
# 渲染配置，逐个比对正在运行的服务：Compose 对该服务渲染出的 config-hash 必须等于容器创建时记录的
# com.docker.compose.config-hash 标签（镜像、环境变量、挂载、命令等任一不同，哈希都不同）。
# 客户机升级路径不依赖 Python/jq，只用 Compose 自带的 `config --hash`；仅当两侧不等时才落一次探针容器。
# 客户现场 2026-10-22：开发发布在启动链之外又叠了一份 active-config，现场改动只写进了后者，
# 虚机一重启就按另一套配置拉起、改动全丢。这里在升级收尾处拦住这种「重启即变样」。
verify_boot_chain_matches_running() {
  local chain="$SCRIPT_DIR/.upgrade/compose-files" entry service container boot_line boot_hash live_hash probe_hash
  local -a files=(-f "$SCRIPT_DIR/docker-compose.offline.yml")
  # 正式升级流程在切换前由 persist_active_compose_chain 写好启动链；只调用切换段的路径（测试夹具）没有它。
  if [[ ! -f "$chain" ]]; then
    log "[warn] 未找到开机启动链 $chain，跳过开机配置一致性检查"
    return 0
  fi
  while IFS= read -r entry || [[ -n "$entry" ]]; do
    [[ -n "$entry" ]] && files+=(-f "$entry")
  done <"$chain"
  for service in "${OLD_RUNNING_SERVICES[@]}"; do
    container="$(project_container "$service")"
    [[ -n "$container" ]] || continue
    boot_line="$("$COMPOSE_WRAPPER" --project-name "$EXISTING_PROJECT_NAME" --project-directory "$SCRIPT_DIR" \
      --env-file "$SCRIPT_DIR/.env" "${files[@]}" config --hash "$service" 2>/dev/null)" ||
      fail "按开机启动链渲染 Compose 配置失败：$service"
    # 输出形如 "<service> <hash>"；服务不在启动链里时没有输出
    boot_hash="$(awk -v s="$service" '$1 == s { print $2 }' <<<"$boot_line")"
    if [[ ! "$boot_hash" =~ ^[0-9a-f]{64}$ ]]; then
      fail "开机启动链与当前运行配置不一致：$service 开机启动链里没有这个服务，虚机重启后服务会按另一套配置拉起"
      return 1
    fi
    live_hash="$(docker inspect --format '{{index .Config.Labels "com.docker.compose.config-hash"}}' "$container" 2>/dev/null)" ||
      fail "无法读取运行容器的配置哈希：$service"
    if [[ "$boot_hash" != "$live_hash" ]]; then
      # 先排除 env_file 造成的口径差异，再判定真正的配置漂移。
      if ! probe_hash="$(boot_chain_probe_hash "$service")"; then
        fail "开机启动链与当前运行配置不一致：$service 无法按开机启动链复现容器配置哈希（探针容器创建失败）"
        return 1
      fi
      if [[ "$probe_hash" != "$live_hash" ]]; then
        fail "开机启动链与当前运行配置不一致：$service 的运行配置哈希与开机启动链渲染结果不同，虚机重启后服务会按另一套配置拉起"
        return 1
      fi
      log "[ok] $service 的 config --hash 与容器标签口径不同（env_file），已用探针容器确认配置一致"
    fi
  done
  log "[ok] 开机启动链与当前运行配置一致（重启后不会变样）"
}

verify_upgrade() {
  wait_core_services_healthy
  verify_core_health
  verify_web_console
  profile_enabled chat && verify_chat_profile
  profile_enabled full && verify_full_profile
  verify_security_events_persistence
  verify_boot_chain_matches_running
}

print_upgrade_summary() {
  local portal_backup="(未运行门户库)"
  [[ -f "$BACKUP_DIR/chat-postgres.dump" ]] && portal_backup="$BACKUP_DIR/chat-postgres.dump"
  cat <<SUMMARY

==================== 升级成功 ====================
原安装目录    : $EXISTING_WORK_DIR
新安装目录    : $SCRIPT_DIR
Compose 项目名: $EXISTING_PROJECT_NAME
活动配置目录  : $ACTIVE_CONFIG_DIR
主库备份      : $BACKUP_DIR/postgres.dump
门户库备份    : $portal_backup
回滚清单      : $BACKUP_DIR/rollback-images.tsv
建议观察窗口  : 24~48 小时（关注安全事件、流量和登录）

⚠  原安装目录暂时不要删除，作为人工回滚锚点至少保留到观察窗口结束。
SUMMARY
  if (( ${#UNINHERITED_BOOT_OVERRIDES[@]} > 0 )); then
    printf '⚠  以下原部署启动链覆盖层未带入新版本，升级后不再生效；仍需要的请改用 .env 或重新登记：\n'
    printf '     %s\n' "${UNINHERITED_BOOT_OVERRIDES[@]}"
  fi
}

# Runs after the application writers are stopped and before the image switch.
# The old redis keeps its redis-data volume; rollback_old_services recreates it.
migrate_redis_service_to_valkey() {
  declare -F migrate_redis_to_valkey >/dev/null || fail "upgrade bundle is missing redis-valkey-migrate-lib.sh"
  local service
  for service in "${OLD_RUNNING_SERVICES[@]}"; do
    [[ "$service" == redis ]] || continue
    rvm_hook_old_container() { run_old_compose ps -q redis; }
    rvm_hook_stop_old() { run_old_compose stop --timeout 60 redis; }
    rvm_hook_start_new() { "${NEW_COMPOSE_ARGS[@]}" up -d --no-deps --force-recreate redis; }
    rvm_hook_new_container() { "${NEW_COMPOSE_ARGS[@]}" ps -q redis; }
    old_compose_args
    log "[step] Redis -> Valkey: copy must-keep keys (pause/budget/daily_tokens/monthly_tokens)"
    migrate_redis_to_valkey "$BACKUP_DIR" || fail "Redis -> Valkey migration failed; rolling back to the old Redis (redis-data volume untouched)"
    return 0
  done
}

# 升级前共享状态（valkey）命名空间探测——与 upgrade.sh 的 verify_shared_state_namespace 是同一个探测。
# security-engine 对共享状态默认 fail-closed：SECURITY_SHARED_STATE_REQUIRED 缺省为 true，共享状态 URL
# 指向 redis:6379/3，valkey 连不上或 DB 3 不可用时引擎启动即拒绝服务，整条检测链停摆。所以必须在
# `up -d --force-recreate` 重建应用容器之前探测新 valkey：失败就中止并自动回退到旧版本，
# 而不是等新栈全部起来、检测链已经停了才发现。离线 .run 包走的 upgrade-bundle.sh 原先缺这一步
# （只有 upgrade.sh 有），2.9.13 候选包的 CHANGELOG 因此没有写“升级前探测”。
# 读取优先级与 compose 插值一致：进程环境 > 继承后的 .env > 默认值；结果放在 REPLY。
shared_state_setting() {
  local key="$1" status=0
  REPLY="${!key-}"
  if [[ -z "$REPLY" ]]; then
    REPLY="$(read_literal_dotenv_key "$SCRIPT_DIR/.env" "$key")" || status=$?
    (( status <= 1 )) || fail "[共享状态探测] 继承后的 .env 中 $key 重复或格式非法"
  fi
}

verify_shared_state_namespace() {
  local required db password output timeout interval deadline
  shared_state_setting SECURITY_SHARED_STATE_REQUIRED
  required="${REPLY:-true}"
  if [[ "$required" != true ]]; then
    log "[shared-state] SECURITY_SHARED_STATE_REQUIRED=$required：跳过 valkey DB 探测"
    return 0
  fi
  shared_state_setting SECURITY_SHARED_STATE_DB
  db="${REPLY:-3}"
  [[ "$db" =~ ^[0-9]+$ ]] || fail "[共享状态探测] SECURITY_SHARED_STATE_DB 必须是数字，当前值：$db"
  shared_state_setting REDIS_PASSWORD
  password="$REPLY"
  [[ -n "$password" ]] ||
    fail "[共享状态探测] .env 里的 REDIS_PASSWORD 为空，无法验证 valkey DB $db；compose 要求它非空，请补上后重新升级"
  timeout="${SHARED_STATE_PROBE_TIMEOUT:-30}"
  interval="${SHARED_STATE_PROBE_INTERVAL:-2}"
  [[ "$timeout" =~ ^[0-9]+$ && "$interval" =~ ^[0-9]+$ ]] ||
    fail "[共享状态探测] SHARED_STATE_PROBE_TIMEOUT / SHARED_STATE_PROBE_INTERVAL 必须是整数秒"
  # 新 valkey 还没在运行（例如旧栈没有 redis 服务）：先单独拉起；后面的整体重建本来也会拉起它。
  if ! "${NEW_COMPOSE_ARGS[@]}" ps -q redis 2>/dev/null | grep -q .; then
    "${NEW_COMPOSE_ARGS[@]}" up -d --no-deps redis >/dev/null 2>&1 || true
  fi
  deadline=$((SECONDS + timeout))
  while :; do
    # -n 选库：一次调用同时证明连接可用和引擎要用的命名空间可用（SELECT 后 PING）。
    output="$("${NEW_COMPOSE_ARGS[@]}" exec -T redis redis-cli --no-auth-warning -a "$password" -n "$db" ping 2>&1)" || true
    [[ "$output" != *PONG* ]] || break
    if (( SECONDS >= deadline )); then
      output="${output//"$password"/***}"
      fail "[共享状态探测] valkey DB $db 不可用（探测输出：${output:-无}）。SECURITY_SHARED_STATE_REQUIRED=true 时 security-engine 拒绝启动，整条检测链会停摆，所以本次升级已中止：应用自动回退到旧版本，已执行的数据库迁移按既有机制保留。请检查：1) valkey 容器是否在运行且健康（docker ps --filter name=${EXISTING_PROJECT_NAME}-redis，日志 docker logs ${EXISTING_PROJECT_NAME}-redis-1）；2) .env 里的 REDIS_PASSWORD 是否与 valkey 实际口令一致；3) SECURITY_SHARED_STATE_DB（默认 3）是否在 valkey 的 databases 范围内。修好后重新执行升级。"
    fi
    sleep "$interval"
  done
  log "[shared-state] valkey DB $db 应答 PONG"
}

run_in_place_upgrade() {
  IMAGE_SWITCH_STARTED=0
	DATABASE_REPAIR_STARTED=0
  DATABASE_MUTATION_STARTED=0
  SERVICES_QUIESCED=0
  UPGRADE_FAILURE_HANDLED=0
  UPGRADE_EXIT_GUARD_ACTIVE=0
  trap 'upgrade_failure $?' ERR
  preflight_old_services_in_new_compose
  persist_package_metadata
  new_compose_args
  UPGRADE_EXIT_GUARD_ACTIVE=1
  trap 'upgrade_exit_handler $?' EXIT
  trap 'exit 130' INT
  trap 'exit 143' TERM
	quiesce_old_database_writers
	persist_bundle_upgrade_state
	load_inherited_env
	DATABASE_MUTATION_STARTED=1
	run_database_migrations
	DATABASE_REPAIR_STARTED=1
	repair_customer_environment_scope
	IMAGE_SWITCH_STARTED=1
	migrate_redis_service_to_valkey
	verify_shared_state_namespace
  local -a tier1_scale=()
  mapfile -t tier1_scale < <(tier1_bundle_scale_flags "$SCRIPT_DIR/.env")
  "${NEW_COMPOSE_ARGS[@]}" up -d --force-recreate "${tier1_scale[@]}" "${OLD_RUNNING_SERVICES[@]}"
  ensure_builtin_identity_runtime
  [[ "${UPGRADE_TEST_FAIL_AFTER_SWITCH:-0}" != 1 ]] || false
  load_inherited_env
  verify_upgrade
  SERVICES_QUIESCED=0
  UPGRADE_EXIT_GUARD_ACTIVE=0
  trap - ERR EXIT INT TERM
}

# full 包升级：新 compose 指向新的 judge 模型文件，已装客户卷里只有旧文件。
# 在切换服务前把锁定的模型灌进原 judge-models 卷（以文件名为键，不覆盖旧文件；
# 已存在且哈希一致则跳过），失败即中止升级，不会切到一个没有模型的 judge。
upgrade_load_judge_model() {
  compgen -G "$SCRIPT_DIR/models/*.gguf" >/dev/null || return 0
  declare -F load_judge_model >/dev/null ||
    fail "full bundle is missing the shared judge model loader: $JUDGE_MODEL_LIB"
  COMPOSE_PROJECT_NAME="$EXISTING_PROJECT_NAME" load_judge_model
}

# 继承的客户 override 层可能把 JUDGE_MODEL_PATH 写死成旧随包模型（如不可商用的 3B），
# 会盖掉新包默认值。切换前渲染新 Compose 链检查：历史随包模型 -> 追加一层强制改回锁定
# 模型；未知文件 -> 拦截（JUDGE_MODEL_PATH_ALLOW_CUSTOM=1 可保留客户自带模型）。
pin_judge_model_path() {
  local rendered value decision pin
  JUDGE_MODEL_ACTIVE_PATH=""
  compgen -G "$SCRIPT_DIR/models/*.gguf" >/dev/null || return 0
  declare -F judge_model_path_decision >/dev/null ||
    fail "full bundle is missing the shared judge model loader: $JUDGE_MODEL_LIB"
  new_compose_args
  rendered="$("${NEW_COMPOSE_ARGS[@]}" config)" || fail "无法渲染新 Compose 以检查 JUDGE_MODEL_PATH"
  value="$(judge_model_path_from_rendered <<<"$rendered")" || fail "JUDGE_MODEL_PATH 配置冲突"
  decision="$(judge_model_path_decision "$value")"
  case "$decision" in
    ok) ;;
    custom) log "[warn] 保留客户自定义 JUDGE_MODEL_PATH=$value（JUDGE_MODEL_PATH_ALLOW_CUSTOM=1）" ;;
    repin)
      pin="$ACTIVE_CONFIG_DIR/judge-model-pin.override.yml"
      printf 'services:\n  llm-judge:\n    environment:\n      JUDGE_MODEL_PATH: /models/%s\n' "$GGUF_NAME" >"$pin" ||
        fail "无法写入 judge 模型路径覆盖层"
      chmod 0600 "$pin" || fail "无法保护 judge 模型路径覆盖层"
      ACTIVE_CONFIG_FILES="${ACTIVE_CONFIG_FILES:+$ACTIVE_CONFIG_FILES,}$pin"
      export ACTIVE_CONFIG_FILES
      new_compose_args
      rendered="$("${NEW_COMPOSE_ARGS[@]}" config)" || fail "覆盖后无法渲染新 Compose"
      value="$(judge_model_path_from_rendered <<<"$rendered")" || fail "覆盖后 JUDGE_MODEL_PATH 仍冲突"
      [[ "$value" == "/models/$GGUF_NAME" ]] || fail "覆盖后 JUDGE_MODEL_PATH 未指向锁定模型：$value"
      log "[ok] 继承配置写死了旧 judge 模型，已追加覆盖层改回 /models/$GGUF_NAME"
      ;;
    *)
      fail "继承配置把 JUDGE_MODEL_PATH 指向未知模型：$value；如确为客户自带模型，设置 JUDGE_MODEL_PATH_ALLOW_CUSTOM=1 后重试"
      ;;
  esac
  JUDGE_MODEL_ACTIVE_PATH="$value"
}

# 升级验证通过后执行；失败只告警，不触发回滚（服务已在新版本上健康运行）。
retire_legacy_judge_model_after_upgrade() {
  compgen -G "$SCRIPT_DIR/models/*.gguf" >/dev/null || return 0
  declare -F retire_legacy_judge_models >/dev/null || return 0
  ( COMPOSE_PROJECT_NAME="$EXISTING_PROJECT_NAME" \
      retire_legacy_judge_models "$BACKUP_DIR" "${JUDGE_MODEL_ACTIVE_PATH:-}" ) ||
    log "[warn] 旧 judge 模型未能移出卷，不影响本次升级；可稍后按 README 手工清理"
}

# 宿主机诊断采集器：.env 与开机链（compose-files）都已就绪，在重建服务之前安装，
# 这样 run_in_place_upgrade 里的一次重建就带上 DIAG_AGENT_HMAC_KEY。失败只告警，不加 --apply。
install_diag_agent() {
  local dir="$SCRIPT_DIR/../diag-agent"
  [[ "${JJD_SKIP_DIAG_AGENT:-0}" != 1 ]] || return 0
  [[ -x "$dir/install-diag-agent.sh" && -x "$dir/jjdguard-diag-agent" ]] || return 0
  log "[info] 安装宿主机诊断采集器"
  if ! sh "$dir/install-diag-agent.sh" --deploy-dir "$SCRIPT_DIR" --binary "$dir/jjdguard-diag-agent"; then
    log "[warn] 诊断采集器安装失败（不影响升级）；可稍后手动执行 $dir/install-diag-agent.sh --deploy-dir $SCRIPT_DIR"
  fi
  return 0
}

main() {
  validate_upgrade_timestamp
  discover_existing_deployment
  trap 'main_snapshot_exit_handler $?' EXIT
  revalidate_existing_deployment
  inherit_configuration
  preserve_gateway_header_preference
	persist_trusted_customer_environment_scope
  # The data-version preflight must use the database identity inherited from
  # the existing deployment instead of falling back to the default database.
  load_inherited_env
  warn_unquoted_env_whitespace "$SCRIPT_DIR/.env"
  if compgen -G "$SCRIPT_DIR/models/*.gguf" >/dev/null; then
    bash "$SCRIPT_DIR/judge-resource-autotune.sh" "$SCRIPT_DIR/.env"
    bash "$SCRIPT_DIR/engine-resource-autotune.sh" "$SCRIPT_DIR/.env"
  fi
  prepare_active_configuration
  report_uninherited_boot_overrides
  validate_minimum_data_version
  run_upgrade_preflight
  backup_databases
  capture_rollback_images
  create_legacy_release_anchor
  load_offline_images
  upgrade_load_judge_model
  write_release_image_override
  pin_judge_model_path
  persist_active_compose_chain
  install_diag_agent
  preflight_old_services_in_new_compose
  run_in_place_upgrade
  retire_legacy_judge_model_after_upgrade
  cleanup_config_snapshot || log "[warn] 原部署临时配置快照未能清理，已保留为私有恢复证据"
  trap - EXIT
  print_upgrade_summary
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  main "$@"
fi
