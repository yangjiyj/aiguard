#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

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
# 随包 judge 模型灌卷：安装器、upgrade-bundle.sh 与本入口共用同一实现。
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

# Redis 7.4 -> Valkey 8.1: logical copy of the must-keep keys (Valkey cannot read RDB v12).
if [[ -r "$SCRIPT_DIR/redis-valkey-migrate-lib.sh" ]]; then
  # shellcheck source=redis-valkey-migrate-lib.sh
  . "$SCRIPT_DIR/redis-valkey-migrate-lib.sh"
fi

if [[ -r "$SCRIPT_DIR/customer-environment-scope-repair-lib.sh" ]]; then
  # shellcheck source=customer-environment-scope-repair-lib.sh
  . "$SCRIPT_DIR/customer-environment-scope-repair-lib.sh"
else
  customer_environment_scope_repair_enabled() {
    [[ "${GATEWAY_ENVIRONMENT_SCOPE-}" == customer ]]
  }
fi

ENV_FILE="$SCRIPT_DIR/.env"

stat_file_owner_uid() {
  if stat -c '%u' "$1" 2>/dev/null; then
    return 0
  fi
  stat -f '%u' "$1" 2>/dev/null
}

stat_file_mode() {
  if stat -c '%a' "$1" 2>/dev/null; then
    return 0
  fi
  stat -f '%Lp' "$1" 2>/dev/null
}

secure_env_file() {
  if [[ -L "$ENV_FILE" ]]; then
    echo "[error] refusing symbolic-link environment file: $ENV_FILE" >&2
    return 1
  fi
  if [[ ! -e "$ENV_FILE" ]]; then
    return 0
  fi
  if [[ ! -f "$ENV_FILE" ]]; then
    echo "[error] environment file must be a regular file: $ENV_FILE" >&2
    return 1
  fi

  local current_uid owner_uid verified_owner_uid verified_mode
  current_uid="$(id -u)"
  owner_uid="$(stat_file_owner_uid "$ENV_FILE")" || {
    echo "[error] unable to verify environment file owner: $ENV_FILE" >&2
    return 1
  }
  if [[ "$owner_uid" != "$current_uid" ]]; then
    echo "[error] environment file is not owned by the executing user: $ENV_FILE" >&2
    return 1
  fi

  chmod 600 "$ENV_FILE" || {
    echo "[error] unable to secure environment file permissions: $ENV_FILE" >&2
    return 1
  }
  if [[ -L "$ENV_FILE" || ! -f "$ENV_FILE" ]]; then
    echo "[error] environment file changed during permission validation: $ENV_FILE" >&2
    return 1
  fi
  verified_owner_uid="$(stat_file_owner_uid "$ENV_FILE")" || return 1
  verified_mode="$(stat_file_mode "$ENV_FILE")" || return 1
  if [[ "$verified_owner_uid" != "$current_uid" || "$verified_mode" != "600" ]]; then
    echo "[error] environment file failed owner/mode validation: $ENV_FILE" >&2
    return 1
  fi
}

random_hex() {
  local bytes="$1"
  if command -v openssl >/dev/null 2>&1; then
    openssl rand -hex "$bytes"
    return
  fi
  if command -v od >/dev/null 2>&1; then
    od -An -N "$bytes" -tx1 /dev/urandom | tr -d ' \n'
    printf '\n'
    return
  fi
  echo "[error] missing random generator: openssl or od" >&2
  return 1
}

append_env_if_missing() {
  local key="$1"
  local value="$2"
  if ! grep -q "^${key}=" "$ENV_FILE" 2>/dev/null; then
    printf '%s=%s\n' "$key" "$value" >>"$ENV_FILE"
  fi
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

upgrade_env_key_allowed() {
  case "$1" in
    GATEWAY_ENVIRONMENT_SCOPE|POSTGRES_USER|POSTGRES_DB|CHAT_POSTGRES_DB|COMPOSE_PROFILES|COMPOSE_PROJECT_NAME|\
    CHAT_BYO_IDP|CHAT_POSTGRES_PASSWORD|AUTH_SECRET|CHAT_PORTAL_UI_OIDC_SECRET|PORTAL_INTERNAL_TOKEN|\
    POSTGRES_PASSWORD|REDIS_PASSWORD|JJD_PROVIDER_SECRET_KEY|JJD_INTERNAL_API_SECRET|\
    JJD_SEMANTIC_GATEWAY_ATTESTATION_KEY|MCP_CONFIRMATION_SCOPE_SECRET|JJD_TIER1_INTERNAL_TOKEN|\
    JJD_RULE_PACK_ATTESTATION_TOKEN|BOOTSTRAP_ADMIN_PASSWORD|UAG_AUDIT_HMAC_KEY|\
    CONTROL_PORT|GATEWAY_PORT|SECURITY_PORT|WEB_PORT|WEB_HTTPS_PORT|JJD_PORTAL_CP_NETWORK) return 0 ;;
    *) return 1 ;;
  esac
}

persist_trusted_customer_environment_scope() {
  [[ "${UPGRADE_OFFLINE_MODE:-0}" == 1 || "${CUSTOMER_DEPLOYMENT_REQUESTED:-0}" == 1 ]] || return 0
  local existing status tmp
  set +e
  existing="$(read_literal_dotenv_key "$ENV_FILE" GATEWAY_ENVIRONMENT_SCOPE)"
  status=$?
  set -e
  if (( status == 0 )); then
    case "$existing" in customer|home|claude|codex|legacy-unclassified) ;;
      *) fail "existing GATEWAY_ENVIRONMENT_SCOPE is invalid"; return 1 ;;
    esac
    export GATEWAY_ENVIRONMENT_SCOPE="$existing"
    return 0
  fi
  (( status == 1 )) || { fail "environment file is invalid or has duplicate deployment scope"; return 1; }
  tmp="$(mktemp "$SCRIPT_DIR/.env.scope.XXXXXX")" || return 1
  if ! cp -- "$ENV_FILE" "$tmp" || ! printf '\nGATEWAY_ENVIRONMENT_SCOPE=customer\n' >>"$tmp"; then
    rm -f -- "$tmp"
    return 1
  fi
  chmod 0600 "$tmp" || { rm -f -- "$tmp"; return 1; }
  [[ "$(stat_file_owner_uid "$tmp")" == "$(stat_file_owner_uid "$ENV_FILE")" ]] || {
    rm -f -- "$tmp"; fail "refusing deployment-scope update with changed owner"; return 1;
  }
  mv -f -- "$tmp" "$ENV_FILE" || { rm -f -- "$tmp"; return 1; }
  export GATEWAY_ENVIRONMENT_SCOPE=customer
}

COMPOSE_FILE_EXPLICIT="${COMPOSE_FILE:-}"
COMPOSE_FILE="${COMPOSE_FILE:-docker-compose.yml}"
COMPOSE_WRAPPER="$SCRIPT_DIR/compose-wrapper.sh"
STATE_FILE="${UPGRADE_STATE_FILE:-$SCRIPT_DIR/.upgrade/current-digests.env}"
OVERRIDE_DIR="$SCRIPT_DIR/.upgrade"
OVERRIDE_FILE="$OVERRIDE_DIR/compose.upgrade.yml"
HISTORY_FILE="$OVERRIDE_DIR/upgrade-history.tsv"
LOG_DIR="${UPGRADE_LOG_DIR:-$SCRIPT_DIR/upgrade-logs}"
BACKUP_DIR="${UPGRADE_BACKUP_DIR:-$SCRIPT_DIR/backups}"
TIMESTAMP="$(date +%Y%m%d-%H%M%S)"
LOG_FILE="$LOG_DIR/upgrade-$TIMESTAMP.log"

FROM_VERSION="${FROM_VERSION:-unknown}"
TO_VERSION=""
MIN_DATA_VERSION="${UPGRADE_MIN_DATA_VERSION:-}"
BASE_HOST="${UPGRADE_BASE_HOST:-127.0.0.1}"
WEB_PORT="${WEB_PORT:-3000}"
WEB_HTTPS_PORT="${WEB_HTTPS_PORT:-443}"
GATEWAY_PORT="${GATEWAY_PORT:-8080}"
CONTROL_PORT="${CONTROL_PORT:-8081}"
SECURITY_PORT="${SECURITY_PORT:-8000}"
FORWARD_PROBE_URL="${UPGRADE_FORWARD_PROBE_URL:-}"

GATEWAY_CORE_IMAGE=""
CONTROL_PLANE_IMAGE=""
SECURITY_ENGINE_IMAGE=""
PROXY_SERVER_IMAGE=""
WEB_CONSOLE_IMAGE=""
WORKER_IMAGE=""
LLM_JUDGE_IMAGE=""
TIER1_CLASSIFIER_IMAGE=""
CHAT_PORTAL_UI_IMAGE=""
CHAT_PORTAL_PROXY_IMAGE=""

MIGRATION_STARTED=0
IMAGE_SWITCH_STARTED=0
SERVICES_QUIESCED=0
SERVICE_RUNTIME_MUTATION_STARTED=0
REDIS_ROLLBACK_IMAGE=""
BACKUP_FILE=""
CUSTOMER_DEPLOYMENT_REQUESTED=0

usage() {
  cat <<'USAGE'
Usage: bash upgrade.sh --to-version VERSION [--from-version VERSION] [image digest options]

Image digest options:
  --gateway-core IMAGE@sha256:...
  --control-plane IMAGE@sha256:...
  --security-engine IMAGE@sha256:...
  --proxy-server IMAGE@sha256:...
  --web-console IMAGE@sha256:...
  --worker IMAGE@sha256:...
  --llm-judge IMAGE@sha256:...
  --tier1-classifier IMAGE@sha256:...
  --chat-portal-ui IMAGE@sha256:...
  --chat-portal-proxy IMAGE@sha256:...
  --customer-deployment     classify a legacy one-click customer .env only when scope is absent

Environment:
  UPGRADE_MIN_DATA_VERSION     required minimum schema_migrations version
  UPGRADE_FORWARD_PROBE_URL    real or near-real upstream URL through the gateway/proxy
  UPGRADE_LOG_DIR              upgrade log directory
  UPGRADE_BACKUP_DIR           pg_dump output directory
  UPGRADE_STATE_FILE           last known-good digest state file
USAGE
}

while (($#)); do
  case "$1" in
    --from-version)
      shift
      FROM_VERSION="${1:-}"
      ;;
    --to-version)
      shift
      TO_VERSION="${1:-}"
      ;;
    --min-data-version)
      shift
      MIN_DATA_VERSION="${1:-}"
      ;;
    --gateway-core)
      shift
      GATEWAY_CORE_IMAGE="${1:-}"
      ;;
    --control-plane)
      shift
      CONTROL_PLANE_IMAGE="${1:-}"
      ;;
    --security-engine)
      shift
      SECURITY_ENGINE_IMAGE="${1:-}"
      ;;
    --proxy-server)
      shift
      PROXY_SERVER_IMAGE="${1:-}"
      ;;
    --web-console)
      shift
      WEB_CONSOLE_IMAGE="${1:-}"
      ;;
    --worker)
      shift
      WORKER_IMAGE="${1:-}"
      ;;
    --llm-judge) shift; LLM_JUDGE_IMAGE="${1:-}" ;;
    --tier1-classifier) shift; TIER1_CLASSIFIER_IMAGE="${1:-}" ;;
    --chat-portal-ui) shift; CHAT_PORTAL_UI_IMAGE="${1:-}" ;;
    --chat-portal-proxy) shift; CHAT_PORTAL_PROXY_IMAGE="${1:-}" ;;
    --forward-probe-url)
      shift
      FORWARD_PROBE_URL="${1:-}"
      ;;
    --customer-deployment)
      CUSTOMER_DEPLOYMENT_REQUESTED=1
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

# Validate the dotenv file before logging starts or any selected value is read.
# Values are later assigned literally from an allowlist; the file is never sourced.
secure_env_file
append_env_if_missing JJD_SEMANTIC_GATEWAY_ATTESTATION_KEY "$(random_hex 32)"
append_env_if_missing MCP_CONFIRMATION_SCOPE_SECRET "$(random_hex 32)"
append_env_if_missing JJD_TIER1_INTERNAL_TOKEN "$(random_hex 32)"
append_env_if_missing JJD_RULE_PACK_ATTESTATION_TENANT tenant_default
append_env_if_missing JJD_RULE_PACK_ATTESTATION_TOKEN "$(random_hex 32)"
append_env_if_missing JJD_RULE_PACK_ATTESTATION_TOKENS_JSON ""
mkdir -p "$LOG_DIR"
exec > >(tee -a "$LOG_FILE") 2>&1

log() {
  printf '[%s] %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$*"
}

fail() {
  log "[error] $*"
  return 1
}

persist_trusted_customer_environment_scope

step() {
  log "[step] $*"
}

timed_step() {
  local name="$1"
  shift
  local start end duration status
  start="$(date +%s)"
  step "$name"
  if "$@"; then
    status=0
  else
    status=$?
  fi
  if [[ "$status" -eq 0 ]]; then
    end="$(date +%s)"
    duration=$((end - start))
    log "[step-result] $name result=ok duration_s=$duration"
    return 0
  fi
  end="$(date +%s)"
  duration=$((end - start))
  log "[step-result] $name result=failed status=$status duration_s=$duration"
  return "$status"
}

require_digest() {
  local label="$1"
  local image="$2"
  [[ -n "$image" ]] || return 0
  if ! is_digest_ref "$image"; then
    fail "$label digest is required; use immutable IMAGE@sha256:<64 hex chars> or sha256:<64 hex chars>, not tags like :latest"
  fi
}

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || fail "required command not found: $1"
}

load_env() {
  local line key raw value
  declare -A seen=()
  if [[ -f "$ENV_FILE" ]]; then
    while IFS= read -r line || [[ -n "$line" ]]; do
      line="${line%$'\r'}"
      [[ -z "$line" || "$line" == \#* ]] && continue
      [[ "$line" =~ ^([A-Za-z_][A-Za-z0-9_]*)=(.*)$ ]] || { fail "environment file is not strict dotenv syntax"; return 1; }
      key="${BASH_REMATCH[1]}"; raw="${BASH_REMATCH[2]}"
      upgrade_env_key_allowed "$key" || continue
      [[ -z "${seen[$key]+x}" ]] || { fail "duplicate upgrade environment key: $key"; return 1; }
      value="$(parse_literal_dotenv_value "$raw")" || { fail "invalid environment value for $key"; return 1; }
      printf -v "$key" '%s' "$value"
      export "$key"
      seen[$key]=1
    done <"$ENV_FILE"
  fi
  POSTGRES_USER="${POSTGRES_USER:-jjdguard}"
  POSTGRES_DB="${POSTGRES_DB:-jjdguard}"
}

validate_required_config() {
  local missing=0 var
  for var in POSTGRES_PASSWORD REDIS_PASSWORD JJD_PROVIDER_SECRET_KEY JJD_INTERNAL_API_SECRET JJD_SEMANTIC_GATEWAY_ATTESTATION_KEY MCP_CONFIRMATION_SCOPE_SECRET JJD_TIER1_INTERNAL_TOKEN JJD_RULE_PACK_ATTESTATION_TOKEN BOOTSTRAP_ADMIN_PASSWORD UAG_AUDIT_HMAC_KEY; do
    if [[ -z "${!var:-}" ]]; then
      log "[error] missing required config: $var"
      missing=1
    fi
  done
  [[ "$missing" -eq 0 ]] || return 1
}

# --- Tier-1 topology (persisted by tier1-scale.sh --apply) -------------------
# The replica count and the cpu/gpu overlay only ever existed inside the
# tier1-scale.sh invocation that created them, so every upgrade converged the
# sidecar back to one base-compose replica: a GPU host silently returned to CPU
# inference and a scaled-out install lost its capacity, while /health still read
# within_limit from the single-replica point of view.
TIER1_TOPOLOGY_LIB="$SCRIPT_DIR/tier1-topology.sh"
[[ -r "$TIER1_TOPOLOGY_LIB" ]] || fail "missing shared Tier-1 topology library: $TIER1_TOPOLOGY_LIB"
# shellcheck source=tier1-topology.sh
. "$TIER1_TOPOLOGY_LIB"
TIER1_TOPOLOGY_MODE=""
TIER1_TOPOLOGY_REPLICAS="1"
TIER1_TOPOLOGY_OVERLAY=""

tier1_topology_prepare() {
  local mode replicas
  if ! mode="$(tier1_scale_mode "$ENV_FILE")"; then
    fail "TIER1_SCALE_MODE in $ENV_FILE must be empty, cpu or gpu"
    return 1
  fi
  if ! replicas="$(tier1_replicas "$ENV_FILE")"; then
    fail "TIER1_REPLICAS in $ENV_FILE must be 1..32"
    return 1
  fi
  TIER1_TOPOLOGY_MODE="$mode"
  TIER1_TOPOLOGY_REPLICAS="$replicas"
  TIER1_TOPOLOGY_OVERLAY="$(tier1_scale_overlay "$SCRIPT_DIR" "$mode")"
  if [[ -n "$mode" ]]; then
    log "[tier1] restoring scaled topology: mode=$mode replicas=$replicas overlay=${TIER1_TOPOLOGY_OVERLAY##*/}"
  fi
  return 0
}

compose() {
  local -a files=(-f "$COMPOSE_FILE")
  if [[ -f "$OVERRIDE_FILE" ]]; then
    files+=(-f "$OVERRIDE_FILE")
  fi
  # Appended last so the Tier-1 overlay wins the image/provider for the sidecar.
  if [[ -n "${TIER1_TOPOLOGY_OVERLAY:-}" ]]; then
    files+=(-f "$TIER1_TOPOLOGY_OVERLAY")
  fi
  sh "$COMPOSE_WRAPPER" "${files[@]}" "$@"
}

# --scale is only valid for `up`, so it cannot live in compose().
compose_up() {
  local -a scale=()
  if [[ -n "${TIER1_TOPOLOGY_MODE:-}" ]]; then
    scale=(--scale "tier1-classifier=$TIER1_TOPOLOGY_REPLICAS")
  fi
  compose up "${scale[@]}" "$@"
}

compose_base() {
  sh "$COMPOSE_WRAPPER" -f "$COMPOSE_FILE" "$@"
}

stop_database_writers() {
  local output service
  local -a application_services=()
  output="$(compose config --services)" || return 1
  while IFS= read -r service; do
    [[ -z "$service" ]] && continue
    [[ "$service" =~ ^[a-z0-9][a-z0-9_-]*$ ]] || return 1
    case "$service" in postgres|chat-postgres|redis|redis-cache) ;; *) application_services+=("$service") ;; esac
  done <<<"$output"
  (( ${#application_services[@]} == 0 )) || compose stop --timeout 60 "${application_services[@]}"
}

quiesce_database_writers() {
  SERVICES_QUIESCED=1
  step "stop database writers for schema and application cutover"
  stop_database_writers || return 1
  log "[ok] database writers stopped"
}

persist_bundle_profiles() {
  local profiles=""
  if compgen -G "$SCRIPT_DIR/models/*.gguf" >/dev/null; then
    profiles="full"
  fi
  if [[ -d "$SCRIPT_DIR/chat" ]]; then
    # Existing full-chat installations already have these secrets. A base-only
    # installation remains on the prior explicit activation path so an upgrade
    # cannot invent portal credentials or expose a new surface unexpectedly.
    local chat_ready=true required
    for required in CHAT_POSTGRES_PASSWORD AUTH_SECRET CHAT_PORTAL_UI_OIDC_SECRET PORTAL_INTERNAL_TOKEN; do
      if [[ -z "${!required:-}" ]]; then
        chat_ready=false
        break
      fi
    done
    if [[ "$chat_ready" == true ]]; then
      profiles="${profiles:+$profiles,}chat"
      if [[ "${CHAT_BYO_IDP:-false}" != "true" ]]; then
        profiles="${profiles},chat-idp"
      fi
    else
      log "[warn] chat payload is present but this base-only installation has no portal credentials; chat profiles remain inactive"
    fi
  fi

  [[ -n "$profiles" ]] || return 0
  COMPOSE_PROFILES="$profiles"
  export COMPOSE_PROFILES
  if grep -q '^COMPOSE_PROFILES=' "$ENV_FILE" 2>/dev/null; then
    sed -i "s/^COMPOSE_PROFILES=.*/COMPOSE_PROFILES=${COMPOSE_PROFILES}/" "$ENV_FILE"
  else
    printf 'COMPOSE_PROFILES=%s\n' "$COMPOSE_PROFILES" >>"$ENV_FILE"
  fi
  log "[info] persisted upgrade profiles: $COMPOSE_PROFILES"
}

ensure_chat_public_sso_url() {
  [[ -d "$SCRIPT_DIR/chat" ]] || return 0
  [[ -f "$ENV_FILE" ]] || return 0
  [[ -x "$SCRIPT_DIR/chat/ensure-public-sso-url.sh" ]] ||
    fail "缺少 Chat SSO 公开地址解析器"
  JJD_ENV_FILE="$ENV_FILE" bash "$SCRIPT_DIR/chat/ensure-public-sso-url.sh" >/dev/null ||
    fail "无法自动补齐 Chat SSO 公开地址"
  log "[ok] Chat SSO 公开地址已幂等写入部署环境"
}
refresh_chat_identity_runtime() {
  [[ -d "$SCRIPT_DIR/chat" ]] || return 0
  [[ -f "$ENV_FILE" ]] || return 0
  [[ "${CHAT_BYO_IDP:-false}" == "true" ]] && return 0
  local chat_idp
  chat_idp="$(compose ps -q chat-idp 2>/dev/null || true)"
  [[ -n "$chat_idp" ]] || return 0
  [[ -x "$SCRIPT_DIR/chat/bootstrap-identity-runtime.sh" ]] ||
    fail "缺少 Chat 身份运行态引导脚本"
  [[ -x "$SCRIPT_DIR/chat/bootstrap-directory-runtime.sh" ]] ||
    fail "缺少目录运行态引导脚本"

  log "[step] refreshing Chat SSO identity runtime"
  compose up -d --no-deps --force-recreate chat-idp
  JJD_ENV_FILE="$ENV_FILE" \
  IDENTITY_RUNTIME_ENV_FILE="$SCRIPT_DIR/identity-runtime.env" \
  COMPOSE_WRAPPER="$COMPOSE_WRAPPER" \
    bash "$SCRIPT_DIR/chat/bootstrap-identity-runtime.sh"
  # 目录同步用独立的最小权限服务账号；老版本升上来时该凭据可能从未写过，
  # 必须在 control-plane 重建之前补齐，否则升级后激活/同步继续失败。
  log "[step] refreshing directory synchronization runtime"
  JJD_ENV_FILE="$ENV_FILE" \
  IDENTITY_RUNTIME_ENV_FILE="$SCRIPT_DIR/identity-runtime.env" \
  COMPOSE_WRAPPER="$COMPOSE_WRAPPER" \
    bash "$SCRIPT_DIR/chat/bootstrap-directory-runtime.sh"
  compose up -d --no-deps --force-recreate --wait control-plane
  log "[ok] Chat SSO identity runtime refreshed"
  # W3 3.8 / D7: existing realms are never auto-tightened; only report the portal login baseline.
  if [[ -x "$SCRIPT_DIR/chat/portal-login-baseline.sh" ]]; then
    JJD_ENV_FILE="$ENV_FILE" \
    COMPOSE_WRAPPER="$COMPOSE_WRAPPER" \
      bash "$SCRIPT_DIR/chat/portal-login-baseline.sh" check --advisory ||
      log "[warn] portal login baseline check skipped"
  fi
}

resolve_compose_file() {
  # 离线包内只随包提供 docker-compose.offline.yml，不含 docker-compose.yml。
  # 调用方未显式设置 COMPOSE_FILE，且默认的 docker-compose.yml 缺失、offline 版存在时，
  # 自动改用 offline compose，使离线升级开箱即用；显式指定或默认文件存在时保持原行为。
  if [[ -z "$COMPOSE_FILE_EXPLICIT" && ! -f "$SCRIPT_DIR/$COMPOSE_FILE" && -f "$SCRIPT_DIR/docker-compose.offline.yml" ]]; then
    COMPOSE_FILE="docker-compose.offline.yml"
  fi
}

derive_compose_project_name() {
  if [[ -n "${COMPOSE_PROJECT_NAME:-}" ]]; then
    printf '%s' "${COMPOSE_PROJECT_NAME}"
    return 0
  fi

  # Prefer the project label on the currently running gateway. This avoids
  # recreating a second stack when the extracted package directory name differs
  # from the original Compose project name.
  local existing
  existing="$(docker ps --filter 'label=com.docker.compose.service=gateway-core'     --format '{{.Label "com.docker.compose.project"}}' 2>/dev/null | awk 'NF { print; exit }' || true)"
  if [[ "$existing" =~ ^[a-z0-9][a-z0-9_-]*$ ]]; then
    printf '%s' "$existing"
    return 0
  fi

  local persisted="${OVERRIDE_DIR}/project-name"
  if [[ -s "$persisted" ]]; then
    existing="$(head -n 1 "$persisted" | tr -d '[:space:]')"
    if [[ "$existing" =~ ^[a-z0-9][a-z0-9_-]*$ ]]; then
      printf '%s' "$existing"
      return 0
    fi
  fi

  local root_base
  root_base="$(basename "$(cd "$SCRIPT_DIR/../.." && pwd)")"
  root_base="$(printf '%s' "$root_base" | tr '[:upper:]' '[:lower:]' | tr -cs 'a-z0-9' '-')"
  root_base="${root_base#-}"
  root_base="${root_base%-}"
  printf '%s' "${root_base:-jjdguard}"
}

pin_compose_project_name() {
  COMPOSE_PROJECT_NAME="$(derive_compose_project_name)"
  export COMPOSE_PROJECT_NAME
  mkdir -p "$OVERRIDE_DIR"
  printf '%s
' "$COMPOSE_PROJECT_NAME" >"${OVERRIDE_DIR}/project-name"
  chmod 600 "${OVERRIDE_DIR}/project-name" 2>/dev/null || true
  log "[info] compose project: $COMPOSE_PROJECT_NAME"
}

write_override() {
  local gateway="$1" control="$2" security="$3" proxy="$4" web="$5" worker="$6"
  local judge="${7:-}" tier1="${8:-}" portal_ui="${9:-}" portal_proxy="${10:-}"
  local base_services proxy_service
  # An image-only override creates a service when the base does not declare it.
  # Inspect the base alone before opening the existing override for writing.
  base_services="$("$COMPOSE_WRAPPER" --env-file "$ENV_FILE" --profile '*' -f "$COMPOSE_FILE" config --services)" || {
    fail 'cannot read base Compose services for image override'; return 1;
  }
  mkdir -p "$OVERRIDE_DIR"
  {
    printf 'services:\n'
    if [[ -n "$gateway" ]]; then
      printf '  gateway-core:\n    image: %s\n' "$gateway"
    fi
    if [[ -n "$control" ]]; then
      printf '  control-plane:\n    image: %s\n' "$control"
    fi
    if [[ -n "$security" ]]; then
      printf '  security-engine:\n    image: %s\n' "$security"
    fi
    if [[ -n "$proxy" ]]; then
      for proxy_service in proxy-server proxy-server-vm; do
        if grep -Fxq "$proxy_service" <<<"$base_services"; then
          printf '  %s:\n    image: %s\n' "$proxy_service" "$proxy"
        fi
      done
    fi
    if [[ -n "$web" ]]; then
      printf '  web-console:\n    image: %s\n' "$web"
    fi
    if [[ -n "$worker" ]]; then
      printf '  worker:\n    image: %s\n' "$worker"
    fi
    if [[ -n "$judge" ]]; then printf '  llm-judge:\n    image: %s\n' "$judge"; fi
    if [[ -n "$tier1" ]]; then printf '  tier1-classifier:\n    image: %s\n' "$tier1"; fi
    if [[ -n "$portal_ui" ]]; then printf '  chat-portal-ui:\n    image: %s\n' "$portal_ui"; fi
    if [[ -n "$portal_proxy" ]]; then printf '  chat-portal-proxy:\n    image: %s\n' "$portal_proxy"; fi
  } >"$OVERRIDE_FILE"
}

write_state() {
  inherit_missing_images
  mkdir -p "$(dirname "$STATE_FILE")"
  {
    printf 'VERSION=%q\n' "$TO_VERSION"
    printf 'FROM_VERSION=%q\n' "$FROM_VERSION"
    printf 'TO_VERSION=%q\n' "$TO_VERSION"
    printf 'GATEWAY_CORE_IMAGE=%q\n' "$GATEWAY_CORE_IMAGE"
    printf 'CONTROL_PLANE_IMAGE=%q\n' "$CONTROL_PLANE_IMAGE"
    printf 'SECURITY_ENGINE_IMAGE=%q\n' "$SECURITY_ENGINE_IMAGE"
    printf 'PROXY_SERVER_IMAGE=%q\n' "$PROXY_SERVER_IMAGE"
    printf 'WEB_CONSOLE_IMAGE=%q\n' "$WEB_CONSOLE_IMAGE"
    printf 'WORKER_IMAGE=%q\n' "$WORKER_IMAGE"
    printf 'LLM_JUDGE_IMAGE=%q\n' "$LLM_JUDGE_IMAGE"
    printf 'TIER1_CLASSIFIER_IMAGE=%q\n' "$TIER1_CLASSIFIER_IMAGE"
    printf 'CHAT_PORTAL_UI_IMAGE=%q\n' "$CHAT_PORTAL_UI_IMAGE"
    printf 'CHAT_PORTAL_PROXY_IMAGE=%q\n' "$CHAT_PORTAL_PROXY_IMAGE"
    printf 'UPDATED_AT=%q\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
  } >"$STATE_FILE"
}

load_previous_state() {
  PREV_VERSION=""
  PREV_GATEWAY_CORE_IMAGE=""
  PREV_CONTROL_PLANE_IMAGE=""
  PREV_SECURITY_ENGINE_IMAGE=""
  PREV_PROXY_SERVER_IMAGE=""
  PREV_WEB_CONSOLE_IMAGE=""
  PREV_WORKER_IMAGE=""
  PREV_LLM_JUDGE_IMAGE=""
  PREV_TIER1_CLASSIFIER_IMAGE=""
  PREV_CHAT_PORTAL_UI_IMAGE=""
  PREV_CHAT_PORTAL_PROXY_IMAGE=""
  if [[ -f "$STATE_FILE" ]]; then
    PREV_VERSION="$(bash -c '. "$1"; printf "%s" "${TO_VERSION:-${VERSION:-}}"' bash "$STATE_FILE")"
    PREV_GATEWAY_CORE_IMAGE="$(bash -c '. "$1"; printf "%s" "${GATEWAY_CORE_IMAGE:-}"' bash "$STATE_FILE")"
    PREV_CONTROL_PLANE_IMAGE="$(bash -c '. "$1"; printf "%s" "${CONTROL_PLANE_IMAGE:-}"' bash "$STATE_FILE")"
    PREV_SECURITY_ENGINE_IMAGE="$(bash -c '. "$1"; printf "%s" "${SECURITY_ENGINE_IMAGE:-}"' bash "$STATE_FILE")"
    PREV_PROXY_SERVER_IMAGE="$(bash -c '. "$1"; printf "%s" "${PROXY_SERVER_IMAGE:-}"' bash "$STATE_FILE")"
    PREV_WEB_CONSOLE_IMAGE="$(bash -c '. "$1"; printf "%s" "${WEB_CONSOLE_IMAGE:-}"' bash "$STATE_FILE")"
    PREV_WORKER_IMAGE="$(bash -c '. "$1"; printf "%s" "${WORKER_IMAGE:-}"' bash "$STATE_FILE")"
    PREV_LLM_JUDGE_IMAGE="$(bash -c '. "$1"; printf "%s" "${LLM_JUDGE_IMAGE:-}"' bash "$STATE_FILE")"
    PREV_TIER1_CLASSIFIER_IMAGE="$(bash -c '. "$1"; printf "%s" "${TIER1_CLASSIFIER_IMAGE:-}"' bash "$STATE_FILE")"
    PREV_CHAT_PORTAL_UI_IMAGE="$(bash -c '. "$1"; printf "%s" "${CHAT_PORTAL_UI_IMAGE:-}"' bash "$STATE_FILE")"
    PREV_CHAT_PORTAL_PROXY_IMAGE="$(bash -c '. "$1"; printf "%s" "${CHAT_PORTAL_PROXY_IMAGE:-}"' bash "$STATE_FILE")"
  fi
}

resolve_from_version() {
  if [[ -z "$FROM_VERSION" || "$FROM_VERSION" == "unknown" ]]; then
    FROM_VERSION="${PREV_VERSION:-unknown}"
  fi
}

export_upgrade_version() {
  export JJD_VERSION="$TO_VERSION"
}

write_history() {
  mkdir -p "$OVERRIDE_DIR"
  if [[ ! -f "$HISTORY_FILE" ]]; then
    printf 'updated_at\tfrom_version\tto_version\tbackup\tlog_file\n' >"$HISTORY_FILE"
  fi
  printf '%s\t%s\t%s\t%s\t%s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$FROM_VERSION" "$TO_VERSION" "${BACKUP_FILE:-}" "$LOG_FILE" >>"$HISTORY_FILE"
}

json_field() {
  local line="$1" field="$2"
  sed -n "s/.*\"$field\"[[:space:]]*:[[:space:]]*\"\([^\"]*\)\".*/\1/p" <<<"$line"
}

is_digest_ref() {
  local image="$1"
  [[ "$image" =~ (^|@)sha256:[0-9a-fA-F]{64}$ ]]
}

repo_digest_for_image_id() {
  local repository="$1" image_id="$2"
  local digest
  while IFS= read -r digest; do
    if is_digest_ref "$digest" && [[ "$digest" == "$repository@sha256:"* ]]; then
      printf '%s\n' "$digest"
      return 0
    fi
  done < <(docker image inspect "$image_id" --format '{{range .RepoDigests}}{{println .}}{{end}}' 2>/dev/null || true)

  if [[ "$image_id" =~ ^sha256:[0-9a-fA-F]{64}$ ]]; then
    printf '%s\n' "$image_id"
    return 0
  fi

  return 1
}

set_previous_image_for_service() {
  local service="$1" image="$2"
  [[ -n "$image" ]] || return 0
  case "$service" in
    gateway-core)
      PREV_GATEWAY_CORE_IMAGE="${PREV_GATEWAY_CORE_IMAGE:-$image}"
      ;;
    control-plane)
      PREV_CONTROL_PLANE_IMAGE="${PREV_CONTROL_PLANE_IMAGE:-$image}"
      ;;
    security-engine)
      PREV_SECURITY_ENGINE_IMAGE="${PREV_SECURITY_ENGINE_IMAGE:-$image}"
      ;;
    proxy-server)
      PREV_PROXY_SERVER_IMAGE="${PREV_PROXY_SERVER_IMAGE:-$image}"
      ;;
    web-console)
      PREV_WEB_CONSOLE_IMAGE="${PREV_WEB_CONSOLE_IMAGE:-$image}"
      ;;
    worker)
      PREV_WORKER_IMAGE="${PREV_WORKER_IMAGE:-$image}"
      ;;
    llm-judge) PREV_LLM_JUDGE_IMAGE="${PREV_LLM_JUDGE_IMAGE:-$image}" ;;
    tier1-classifier) PREV_TIER1_CLASSIFIER_IMAGE="${PREV_TIER1_CLASSIFIER_IMAGE:-$image}" ;;
    chat-portal-ui) PREV_CHAT_PORTAL_UI_IMAGE="${PREV_CHAT_PORTAL_UI_IMAGE:-$image}" ;;
    chat-portal-proxy) PREV_CHAT_PORTAL_PROXY_IMAGE="${PREV_CHAT_PORTAL_PROXY_IMAGE:-$image}" ;;
  esac
}

collect_previous_images_from_compose() {
  local output line service repository image_id image_ref
  output="$(compose_base images --format json 2>/dev/null)" || return 1
  while IFS= read -r line; do
    [[ -n "$line" ]] || continue
    service="$(json_field "$line" "Service")"
    repository="$(json_field "$line" "Repository")"
    image_id="$(json_field "$line" "ID")"
    if [ -z "$service" ]; then
      # 新版 compose 的 images --format json 已无 Service 字段，
      # 从 ContainerName(<project>-<service>-<replica>) 回推服务名。
      cname="$(json_field "$line" "ContainerName")"
      service="$(printf '%s' "$cname" | sed "s/^${COMPOSE_PROJECT_NAME}-//; s/-[0-9][0-9]*$//")"
    fi
    [[ -n "$service" && -n "$repository" && -n "$image_id" ]] || continue
    image_ref="$(repo_digest_for_image_id "$repository" "$image_id" || true)"
    set_previous_image_for_service "$service" "$image_ref"
  done < <(sed 's/},{/}\
{/g; s/^\[//; s/\]$//' <<<"$output")
}

prepare_rollback_anchor() {
  collect_previous_images_from_compose || true

  local missing=0
  if [[ -n "$GATEWAY_CORE_IMAGE" && -z "$PREV_GATEWAY_CORE_IMAGE" ]]; then
    log "[error] missing rollback anchor for gateway-core"
    missing=1
  fi
  if [[ -n "$CONTROL_PLANE_IMAGE" && -z "$PREV_CONTROL_PLANE_IMAGE" ]]; then
    log "[error] missing rollback anchor for control-plane"
    missing=1
  fi
  if [[ -n "$SECURITY_ENGINE_IMAGE" && -z "$PREV_SECURITY_ENGINE_IMAGE" ]]; then
    log "[error] missing rollback anchor for security-engine"
    missing=1
  fi
  if [[ -n "$PROXY_SERVER_IMAGE" && -z "$PREV_PROXY_SERVER_IMAGE" ]]; then
    log "[error] missing rollback anchor for proxy-server"
    missing=1
  fi
  if [[ -n "$WEB_CONSOLE_IMAGE" && -z "$PREV_WEB_CONSOLE_IMAGE" ]]; then
    log "[error] missing rollback anchor for web-console"
    missing=1
  fi
  if [[ -n "$WORKER_IMAGE" && -z "$PREV_WORKER_IMAGE" ]]; then
    log "[error] missing rollback anchor for worker"
    missing=1
  fi
  for label in llm-judge tier1-classifier chat-portal-ui chat-portal-proxy; do
    case "$label" in
      llm-judge) target="$LLM_JUDGE_IMAGE"; previous="$PREV_LLM_JUDGE_IMAGE" ;;
      tier1-classifier) target="$TIER1_CLASSIFIER_IMAGE"; previous="$PREV_TIER1_CLASSIFIER_IMAGE" ;;
      chat-portal-ui) target="$CHAT_PORTAL_UI_IMAGE"; previous="$PREV_CHAT_PORTAL_UI_IMAGE" ;;
      chat-portal-proxy) target="$CHAT_PORTAL_PROXY_IMAGE"; previous="$PREV_CHAT_PORTAL_PROXY_IMAGE" ;;
    esac
    if [[ -n "$target" && -z "$previous" ]]; then
      log "[error] missing rollback anchor for $label"
      missing=1
    fi
  done
  if [[ "$missing" -ne 0 ]]; then
    fail "preflight failed: rollback anchor is incomplete"
    return 1
  fi
  log "[ok] captured rollback anchor from compose/state"
}

inherit_missing_images() {
  GATEWAY_CORE_IMAGE="${GATEWAY_CORE_IMAGE:-$PREV_GATEWAY_CORE_IMAGE}"
  CONTROL_PLANE_IMAGE="${CONTROL_PLANE_IMAGE:-$PREV_CONTROL_PLANE_IMAGE}"
  SECURITY_ENGINE_IMAGE="${SECURITY_ENGINE_IMAGE:-$PREV_SECURITY_ENGINE_IMAGE}"
  PROXY_SERVER_IMAGE="${PROXY_SERVER_IMAGE:-$PREV_PROXY_SERVER_IMAGE}"
  WEB_CONSOLE_IMAGE="${WEB_CONSOLE_IMAGE:-$PREV_WEB_CONSOLE_IMAGE}"
  WORKER_IMAGE="${WORKER_IMAGE:-$PREV_WORKER_IMAGE}"
  LLM_JUDGE_IMAGE="${LLM_JUDGE_IMAGE:-$PREV_LLM_JUDGE_IMAGE}"
  TIER1_CLASSIFIER_IMAGE="${TIER1_CLASSIFIER_IMAGE:-$PREV_TIER1_CLASSIFIER_IMAGE}"
  CHAT_PORTAL_UI_IMAGE="${CHAT_PORTAL_UI_IMAGE:-$PREV_CHAT_PORTAL_UI_IMAGE}"
  CHAT_PORTAL_PROXY_IMAGE="${CHAT_PORTAL_PROXY_IMAGE:-$PREV_CHAT_PORTAL_PROXY_IMAGE}"
}

baseline_schema_present() {
  local baseline_ok
  baseline_ok="$(query_db_scalar "SELECT CASE WHEN to_regclass('public.tenants') IS NOT NULL AND to_regclass('public.users') IS NOT NULL AND to_regclass('public.projects') IS NOT NULL AND to_regclass('public.request_logs') IS NOT NULL THEN 1 ELSE 0 END")"
  [[ "$baseline_ok" == "1" ]]
}

health_url() {
  local name="$1" url="$2"
  if command -v curl >/dev/null 2>&1; then
    log "[check] $name -> $url"
    case "$url" in
      https://*) curl -kfsS "$url" >/dev/null ;;
      *) curl -fsS "$url" >/dev/null ;;
    esac
    return
  fi
  log "[warn] curl missing; using compose health state for $name"
  compose ps >/dev/null
}

query_db_scalar() {
  local sql="$1"
  compose exec -T postgres psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -tAc "$sql" | tr -d '\r' | awk 'NF { print; exit }'
}

preflight_data_version() {
  if [[ -z "$MIN_DATA_VERSION" ]]; then
    fail "preflight failed: minimum data version is required; set UPGRADE_MIN_DATA_VERSION or --min-data-version"
    return 1
  fi
  local exists current
  exists="$(query_db_scalar "SELECT to_regclass('public.schema_migrations')")"
  if [[ "$exists" != "schema_migrations" ]]; then
    if baseline_schema_present; then
      log "[ok] schema_migrations missing; initdb baseline detected and will be recorded by migration runner"
      return 0
    fi
    fail "preflight failed: schema_migrations is missing and initdb baseline tables are incomplete"
    return 1
  fi
  current="$(query_db_scalar "$(migration_latest_sql)")"
  if [[ -z "$current" ]] || ! migration_name_valid "$current" || migration_version_lt "$current" "$MIN_DATA_VERSION"; then
    fail "preflight failed: data version $current is lower than required $MIN_DATA_VERSION"
    return 1
  fi
  log "[ok] data version current=$current required=$MIN_DATA_VERSION"
}

preflight_disk() {
  local target="$BACKUP_DIR"
  mkdir -p "$target"
  local available_kb required_kb
  available_kb="$(df -Pk "$target" | awk 'NR == 2 { print $4 }')"
  required_kb="${UPGRADE_MIN_FREE_KB:-1048576}"
  if [[ "${available_kb:-0}" -lt "$required_kb" ]]; then
    fail "preflight failed: free disk ${available_kb}KB is lower than required ${required_kb}KB"
    return 1
  fi
  log "[ok] disk free ${available_kb}KB"
}

preflight_health() {
  compose ps >/dev/null || {
    fail "preflight failed: current compose services are not healthy"
    return 1
  }
  health_url "gateway-core" "http://$BASE_HOST:$GATEWAY_PORT/health" || {
    fail "preflight failed: gateway-core is not healthy"
    return 1
  }
  health_url "control-plane" "http://$BASE_HOST:$CONTROL_PORT/health" || {
    fail "preflight failed: control-plane is not healthy"
    return 1
  }
  health_url "security-engine" "http://$BASE_HOST:$SECURITY_PORT/health" || {
    fail "preflight failed: security-engine is not healthy"
    return 1
  }
}

backup_db() {
  mkdir -p "$BACKUP_DIR"
  BACKUP_FILE="$BACKUP_DIR/jjdguard-${POSTGRES_DB}-${TIMESTAMP}.sql"
  step "backup database -> $BACKUP_FILE"
  local partial="$BACKUP_FILE.partial"
  compose exec -T postgres pg_dump -U "$POSTGRES_USER" -d "$POSTGRES_DB" >"$partial" || return 1
  [[ -s "$partial" ]] || { fail "database backup is empty"; return 1; }
  mv -- "$partial" "$BACKUP_FILE" || return 1
  log "[ok] online backup completed -> $BACKUP_FILE"
  if [ -n "$(compose ps -q chat-postgres 2>/dev/null)" ]; then
    local CHAT_DB="${CHAT_POSTGRES_DB:-enterprise_ai_portal}"
    CHAT_BACKUP_FILE="$BACKUP_DIR/chat-${CHAT_DB}-${TIMESTAMP}.sql"
    step "backup chat database -> $CHAT_BACKUP_FILE"
    compose exec -T chat-postgres pg_dump -U postgres -d "$CHAT_DB" >"$CHAT_BACKUP_FILE" || return 1
    log "[ok] chat backup completed -> $CHAT_BACKUP_FILE"
  fi
}

run_migrations() {
  step "run migrations"
  MIGRATION_STARTED=1
  bash "$SCRIPT_DIR/migrate-private.sh" || return 1
  validate_database_after_migration
}

repair_customer_environment_scope() {
  if ! customer_environment_scope_repair_enabled; then
    log "[info] customer environment-scope repair skipped (explicit GATEWAY_ENVIRONMENT_SCOPE=customer is required)"
    return 0
  fi
  local sql="$SCRIPT_DIR/customer-environment-scope-repair.sql"
  [[ -r "$sql" ]] || { fail "customer environment-scope repair SQL is missing"; return 1; }
  step "activate resumable customer retention-scope repair"
  compose exec -T postgres psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -v ON_ERROR_STOP=1 <"$sql" || return 1
  log "[ok] customer environment-scope background repair activated"
}

validate_database_after_migration() {
  step "validate real PostgreSQL schema state"
  local migration_summary current private_egress_columns
  if ! baseline_schema_present; then
    fail "database validation failed: baseline schema tables are missing"
    return 1
  fi
  current="$(query_db_scalar "$(migration_latest_sql)")"
  if [[ -z "$current" ]] || ! migration_name_valid "$current" || migration_version_lt "$current" "$MIN_DATA_VERSION"; then
    fail "database validation failed: data version $current is lower than required $MIN_DATA_VERSION"
    return 1
  fi
  migration_summary="$(query_db_scalar "SELECT COUNT(*)::text || '|' || COALESCE((SELECT version FROM schema_migrations WHERE version ~ '^[0-9]{3,}_[A-Za-z0-9_.-]+[.]sql$' ORDER BY split_part(version, '_', 1)::bigint DESC, version DESC LIMIT 1), '') FROM schema_migrations")"
  log "[ok] schema_migrations summary: $migration_summary"
  private_egress_columns="$(query_db_scalar "SELECT count(*) = 2 FROM information_schema.columns WHERE table_schema='public' AND table_name='reverse_proxy_routes' AND column_name IN ('allow_private_egress','private_egress_cidrs')")"
  if [[ "$private_egress_columns" != "t" ]]; then
    fail "database validation failed: reverse_proxy_routes private egress columns are missing"
    return 1
  fi
  log "[ok] reverse_proxy_routes private egress columns present"
}

write_detection_flip_overrides() {
  step "write detection flip overrides into system_settings (P1-A default flip)"
  # 显式写 DB override，防被存量 semantic-config 覆盖导致翻转不生效；幂等 upsert。
  compose exec -T postgres psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -v ON_ERROR_STOP=1 -c "
    INSERT INTO system_settings (key, value) VALUES
      ('source_aware_enabled', 'true'),
      ('confidence_gating_enabled', 'true'),
      ('coding_traffic_downgrade_enabled', 'true')
    ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = NOW();
  " || return 1
  log "[ok] detection flip overrides written (source_aware/confidence_gating/coding_traffic_downgrade = true)"
}

run_basic_health() {
  step "run basic health checks"
  health_url "web-console-http-health" "http://$BASE_HOST:$WEB_PORT/health" || return 1
  health_url "web-console-https-health" "https://$BASE_HOST:$WEB_HTTPS_PORT/health" || return 1
  health_url "gateway-core" "http://$BASE_HOST:$GATEWAY_PORT/health" || return 1
  health_url "control-plane" "http://$BASE_HOST:$CONTROL_PORT/health" || return 1
  health_url "security-engine" "http://$BASE_HOST:$SECURITY_PORT/health" || return 1
}

run_smoke() {
  step "run GW-01 smoke/self-check"
  bash "$SCRIPT_DIR/smoke-test.sh" "$BASE_HOST"
}

run_forward_probe() {
  if [[ "${UPGRADE_OFFLINE_MODE:-0}" == "1" ]]; then
    log "[ok] offline mode: external forward probe skipped"
    return 0
  fi
  if [[ -z "$FORWARD_PROBE_URL" ]]; then
    fail "real forward probe failed: UPGRADE_FORWARD_PROBE_URL or --forward-probe-url is required"
    return 1
  fi
  require_cmd curl
  step "run real forward probe"
  curl -kfsS "$FORWARD_PROBE_URL" >/dev/null || {
    fail "real forward probe failed: $FORWARD_PROBE_URL"
    return 1
  }
  log "[ok] real forward probe passed -> $FORWARD_PROBE_URL"
}

# A GPU install must not fall back to the CPU image during an upgrade: the stack
# would come up "healthy" while tier1 lost its GPU. Abort before any container
# changes, with the reason, instead of converging silently.
preflight_tier1_topology() {
  [[ "${TIER1_TOPOLOGY_MODE:-}" == gpu ]] || return 0
  if ! declare -F tier1_gpu_preflight >/dev/null; then
    fail "GPU Tier-1 is configured but the shared Tier-1 topology library is missing"
    return 1
  fi
  if ! tier1_gpu_preflight "${TIER1_GPU_IMAGE:-${TIER1_CLASSIFIER_IMAGE:-}}"; then
    fail "GPU Tier-1 preflight failed; refusing to upgrade. Fix the GPU stack, or run 'tier1-scale.sh reset --apply' to return to CPU."
    return 1
  fi
  return 0
}

preflight() {
  require_cmd docker || return 1
  validate_required_config || {
    fail "preflight failed: required config missing"
    return 1
  }
  prepare_rollback_anchor || return 1
  preflight_disk || return 1
  preflight_health || return 1
  preflight_data_version || return 1
  preflight_tier1_topology || return 1
}

# 与 deploy/lib/judge-model-load.sh 的同名函数等价；这里保留一份，因为非 full 包不带该库。
sha256_file() {
  local file="$1"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$file" | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$file" | awk '{print $1}'
  else
    log "[error] no checksum command found: need sha256sum or shasum" >&2
    return 1
  fi
}

# full 包升级（installer 对已停止实例走本入口）：新 compose 指向新 judge 模型文件，
# 旧卷里只有旧文件。必须在任何服务变更之前灌卷，失败即中止、旧服务不受影响。
upgrade_load_judge_model() {
  compgen -G "$SCRIPT_DIR/models/*.gguf" >/dev/null || return 0
  if ! declare -F load_judge_model >/dev/null; then
    fail "full bundle is missing the shared judge model loader: $JUDGE_MODEL_LIB"
    return 1
  fi
  load_judge_model
}

# 本入口只叠加随包基础 Compose 与镜像 override；JUDGE_MODEL_PATH 与锁定模型不一致
# 说明基础 Compose 被手工改过（例如写死旧 3B），在任何服务变更前拦截。
JUDGE_MODEL_ACTIVE_PATH=""
check_judge_model_path() {
  local rendered value decision
  compgen -G "$SCRIPT_DIR/models/*.gguf" >/dev/null || return 0
  if ! declare -F judge_model_path_decision >/dev/null; then
    fail "full bundle is missing the shared judge model loader: $JUDGE_MODEL_LIB"
    return 1
  fi
  rendered="$(compose --profile full config)" || { fail "无法渲染 Compose 以检查 JUDGE_MODEL_PATH"; return 1; }
  value="$(judge_model_path_from_rendered <<<"$rendered")" || { fail "JUDGE_MODEL_PATH 配置冲突"; return 1; }
  decision="$(judge_model_path_decision "$value")"
  case "$decision" in
    ok) ;;
    custom) log "[warn] 保留客户自定义 JUDGE_MODEL_PATH=$value（JUDGE_MODEL_PATH_ALLOW_CUSTOM=1）" ;;
    *)
      fail "Compose 把 JUDGE_MODEL_PATH 指向 $value，而本包锁定模型是 /models/$GGUF_NAME；请恢复随包 $COMPOSE_FILE 后重试"
      return 1
      ;;
  esac
  JUDGE_MODEL_ACTIVE_PATH="$value"
}

# 升级完成后执行；失败只告警，不回滚已健康的新版本。
retire_legacy_judge_model_after_upgrade() {
  compgen -G "$SCRIPT_DIR/models/*.gguf" >/dev/null || return 0
  declare -F retire_legacy_judge_models >/dev/null || return 0
  ( retire_legacy_judge_models "$BACKUP_DIR" "$JUDGE_MODEL_ACTIVE_PATH" ) ||
    log "[warn] 旧 judge 模型未能移出卷，不影响本次升级；可稍后按 README 手工清理"
  return 0
}

load_offline_images() {
  # 幂等的离线镜像导入：仅当 offline-artifacts 下存在镜像归档时才 docker load，
  # 参照 deploy-offline.sh 的 load_images（自动发现归档 -> 校验 .sha256 -> gzip -dc | docker load）。
  # 归档缺失则跳过（兼容镜像已由 CI 预 staged 的现有用法），不视为失败，
  # 使气隙主机无需操作员手动 docker load 即可平滑升级。
  local archive="${OFFLINE_IMAGE_ARCHIVE:-}"
  if [[ -z "$archive" ]]; then
    archive="$(ls -1 "$SCRIPT_DIR"/offline-artifacts/jjdguard-offline-images-*.tar.gz 2>/dev/null | tail -n 1 || true)"
  fi
  if [[ -z "$archive" || ! -f "$archive" ]]; then
    log "[info] no offline image archive found; skipping docker load (images assumed pre-staged)"
    return 0
  fi

  require_cmd docker || return 1
  require_cmd gzip || return 1

  local checksum_file="${archive}.sha256"
  if [[ -f "$checksum_file" ]]; then
    step "verify offline image archive checksum"
    local expected actual
    expected="$(awk '{print $1}' "$checksum_file")"
    actual="$(sha256_file "$archive")" || return 1
    if [[ "$expected" != "$actual" ]]; then
      log "[error] offline image archive checksum mismatch"
      log "[error] expected: $expected"
      log "[error] actual:   $actual"
      return 1
    fi
  else
    log "[warn] checksum file not found for offline image archive: $checksum_file"
  fi

  step "load offline images from $archive"
  gzip -dc "$archive" | docker load
}

ensure_portal_control_network() {
  bash "$SCRIPT_DIR/ensure-jjdguard-portal-cp-network.sh" --name "${JJD_PORTAL_CP_NETWORK:-jjdguard-portal-control-net}" --owner jjdguard
}

migrate_redis_service_to_valkey() {
  declare -F migrate_redis_to_valkey >/dev/null || fail "upgrade bundle is missing redis-valkey-migrate-lib.sh"
  local old_redis
  rvm_hook_old_container() { compose ps -q redis; }
  old_redis="$(compose ps -q redis 2>/dev/null)" || old_redis=""
  if [[ -n "$old_redis" && "$(rvm_flavor "$old_redis")" == redis ]]; then
    # upgrade.sh reuses one Compose file, so rollback must pin the old Redis
    # image back onto redis-data explicitly (see write_redis_rollback_override).
    REDIS_ROLLBACK_IMAGE="$(docker inspect --format '{{.Config.Image}}' "$old_redis")" || return 1
  fi
  rvm_hook_stop_old() { compose stop --timeout 60 redis; }
  rvm_hook_start_new() {
    write_override "$GATEWAY_CORE_IMAGE" "$CONTROL_PLANE_IMAGE" "$SECURITY_ENGINE_IMAGE" "$PROXY_SERVER_IMAGE" "$WEB_CONSOLE_IMAGE" "$WORKER_IMAGE" "$LLM_JUDGE_IMAGE" "$TIER1_CLASSIFIER_IMAGE" "$CHAT_PORTAL_UI_IMAGE" "$CHAT_PORTAL_PROXY_IMAGE" || return 1
    compose up -d --no-deps --force-recreate redis
  }
  rvm_hook_new_container() { compose ps -q redis; }
  mkdir -p "$BACKUP_DIR"
  migrate_redis_to_valkey "$BACKUP_DIR"
}

write_redis_rollback_override() {
  [[ -n "${REDIS_ROLLBACK_IMAGE:-}" ]] || return 0
  # shellcheck disable=SC2016
  printf '%s\n' \
    '  redis:' \
    "    image: $REDIS_ROLLBACK_IMAGE" \
    '    command: ["sh", "-c", "exec redis-server --appendonly yes --requirepass \"$${REDIS_PASSWORD}\""]' \
    '    volumes:' \
    '      - redis-data:/data' \
    '    healthcheck:' \
    '      test: ["CMD-SHELL", "redis-cli -a \"$${REDIS_PASSWORD}\" ping | grep PONG"]' >>"$OVERRIDE_FILE"
}

# The engine is fail-closed on shared state (SECURITY_SHARED_STATE_REQUIRED
# defaults to true and the URL points at redis:6379/3), so an unreachable valkey
# or an unusable DB 3 stops the whole detection chain at boot. Probe it BEFORE
# switch_images recreates containers: discovering it afterwards turns a config
# typo into an outage with the old stack already down.
verify_shared_state_namespace() {
  local required db password output
  required="${SECURITY_SHARED_STATE_REQUIRED:-true}"
  if [[ "$required" != "true" ]]; then
    log "[shared-state] SECURITY_SHARED_STATE_REQUIRED=$required: skipping the valkey DB probe"
    return 0
  fi
  db="${SECURITY_SHARED_STATE_DB:-3}"
  password="${REDIS_PASSWORD:-}"
  if [[ -z "$password" ]]; then
    fail "[shared-state] REDIS_PASSWORD is empty; cannot verify valkey DB $db"
  fi
  # -n selects the database, so one call proves both the connection and the
  # namespace the engine needs (SELECT 3 then PING).
  if compose ps -q redis 2>/dev/null | grep -q .; then
    output="$(compose exec -T redis redis-cli --no-auth-warning -a "$password" -n "$db" ping 2>&1)" || true
  else
    output="$(compose run --rm --no-deps -T --entrypoint redis-cli redis --no-auth-warning -a "$password" -n "$db" ping 2>&1)" || true
  fi
  if [[ "$output" != *PONG* ]]; then
    fail "[shared-state] valkey DB $db is not usable (probe output: ${output:-none}). SECURITY_SHARED_STATE_REQUIRED=true means security-engine refuses to boot and detection stops. Fix the valkey service or the DB number before upgrading."
  fi
  log "[shared-state] valkey DB $db answered PONG"
}

switch_images() {
  IMAGE_SWITCH_STARTED=1
  write_override "$GATEWAY_CORE_IMAGE" "$CONTROL_PLANE_IMAGE" "$SECURITY_ENGINE_IMAGE" "$PROXY_SERVER_IMAGE" "$WEB_CONSOLE_IMAGE" "$WORKER_IMAGE" "$LLM_JUDGE_IMAGE" "$TIER1_CLASSIFIER_IMAGE" "$CHAT_PORTAL_UI_IMAGE" "$CHAT_PORTAL_PROXY_IMAGE" || return 1
  ensure_portal_control_network
  compose_up -d
}

rollback() {
  local reason="$1"
  log "[rollback] starting rollback because: $reason"
  if [[ -z "${PREV_GATEWAY_CORE_IMAGE}${PREV_CONTROL_PLANE_IMAGE}${PREV_SECURITY_ENGINE_IMAGE}${PREV_PROXY_SERVER_IMAGE}${PREV_WEB_CONSOLE_IMAGE}${PREV_WORKER_IMAGE}${PREV_LLM_JUDGE_IMAGE}${PREV_TIER1_CLASSIFIER_IMAGE}${PREV_CHAT_PORTAL_UI_IMAGE}${PREV_CHAT_PORTAL_PROXY_IMAGE}" ]]; then
    log "[rollback] no previous digest state found; manual rollback required"
    return 1
  fi
  write_override "$PREV_GATEWAY_CORE_IMAGE" "$PREV_CONTROL_PLANE_IMAGE" "$PREV_SECURITY_ENGINE_IMAGE" "$PREV_PROXY_SERVER_IMAGE" "$PREV_WEB_CONSOLE_IMAGE" "$PREV_WORKER_IMAGE" "$PREV_LLM_JUDGE_IMAGE" "$PREV_TIER1_CLASSIFIER_IMAGE" "$PREV_CHAT_PORTAL_UI_IMAGE" "$PREV_CHAT_PORTAL_PROXY_IMAGE"
  write_redis_rollback_override
  ensure_portal_control_network
  if ! compose_up -d; then
    log "[rollback][error] rollback services failed to reach their Compose state"
    return 1
  fi
  log "[rollback] rollback completed"
}

on_failure() {
  local status=$?
  trap - ERR
  log "[error] upgrade failed with status $status"
  if [[ -n "$BACKUP_FILE" ]]; then
    log "[error] backup: $BACKUP_FILE"
  fi
  if [[ "$MIGRATION_STARTED" -eq 1 ]]; then
    log "[rollback] database preserved: committed migrations and new writes are retained"
    log "[rollback] backup is for explicit disaster recovery only: $BACKUP_FILE"
  fi
  if [[ "$SERVICE_RUNTIME_MUTATION_STARTED" -eq 1 || "$SERVICES_QUIESCED" -eq 1 || "$IMAGE_SWITCH_STARTED" -eq 1 ]]; then
    rollback "upgrade failure" || true
  fi
  exit "$status"
}

trap on_failure ERR

require_digest "gateway-core" "$GATEWAY_CORE_IMAGE"
require_digest "control-plane" "$CONTROL_PLANE_IMAGE"
require_digest "security-engine" "$SECURITY_ENGINE_IMAGE"
require_digest "proxy-server" "$PROXY_SERVER_IMAGE"
require_digest "web-console" "$WEB_CONSOLE_IMAGE"
require_digest "worker" "$WORKER_IMAGE"
require_digest "llm-judge" "$LLM_JUDGE_IMAGE"
require_digest "tier1-classifier" "$TIER1_CLASSIFIER_IMAGE"
require_digest "chat-portal-ui" "$CHAT_PORTAL_UI_IMAGE"
require_digest "chat-portal-proxy" "$CHAT_PORTAL_PROXY_IMAGE"
[[ -n "$TO_VERSION" ]] || fail "--to-version is required"
[[ -n "${GATEWAY_CORE_IMAGE}${CONTROL_PLANE_IMAGE}${SECURITY_ENGINE_IMAGE}${PROXY_SERVER_IMAGE}${WEB_CONSOLE_IMAGE}${WORKER_IMAGE}" ]] || fail "at least one target image digest is required"

load_env
warn_unquoted_env_whitespace "$ENV_FILE"
persist_bundle_profiles
if [[ ",${COMPOSE_PROFILES:-}," == *,full,* ]]; then
  bash "$SCRIPT_DIR/judge-resource-autotune.sh" "$ENV_FILE"
  bash "$SCRIPT_DIR/engine-resource-autotune.sh" "$ENV_FILE"
  load_env
fi
# autotune may have rewritten .env (legacy tier1 defaults), so read the topology
# only after it has run.
tier1_topology_prepare
resolve_compose_file
pin_compose_project_name
load_previous_state
resolve_from_version
require_digest "gateway-core" "$GATEWAY_CORE_IMAGE"
require_digest "control-plane" "$CONTROL_PLANE_IMAGE"
require_digest "security-engine" "$SECURITY_ENGINE_IMAGE"
require_digest "proxy-server" "$PROXY_SERVER_IMAGE"
require_digest "web-console" "$WEB_CONSOLE_IMAGE"
require_digest "worker" "$WORKER_IMAGE"
require_digest "llm-judge" "$LLM_JUDGE_IMAGE"
require_digest "tier1-classifier" "$TIER1_CLASSIFIER_IMAGE"
require_digest "chat-portal-ui" "$CHAT_PORTAL_UI_IMAGE"
require_digest "chat-portal-proxy" "$CHAT_PORTAL_PROXY_IMAGE"

log "[info] upgrade from=$FROM_VERSION to=$TO_VERSION"
log "[info] log file: $LOG_FILE"
log "[info] compose file: $COMPOSE_FILE"
log "[info] current target digests gateway=$GATEWAY_CORE_IMAGE control=$CONTROL_PLANE_IMAGE security=$SECURITY_ENGINE_IMAGE proxy=$PROXY_SERVER_IMAGE web=$WEB_CONSOLE_IMAGE"

timed_step "preflight" preflight
timed_step "load_offline_images" load_offline_images
timed_step "load_judge_model" upgrade_load_judge_model
timed_step "check_judge_model_path" check_judge_model_path
# Take the consistent database snapshot while the old application is serving.
# Application rollback preserves all writes after this recovery point.
timed_step "backup_db" backup_db
SERVICE_RUNTIME_MUTATION_STARTED=1
ensure_chat_public_sso_url
refresh_chat_identity_runtime
export_upgrade_version
timed_step "quiesce_database_writers" quiesce_database_writers
timed_step "run_migrations" run_migrations
timed_step "repair_customer_environment_scope" repair_customer_environment_scope
# 宿主机诊断采集器：先写好 .env 的 DIAG_AGENT_HMAC_KEY，随后 switch_images 重建控制面一次即生效。
# 失败只告警，不影响升级；不加 --apply（升级自己会重建控制面）。
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
install_diag_agent
IMAGE_SWITCH_STARTED=1
timed_step "migrate_redis_to_valkey" migrate_redis_service_to_valkey
timed_step "verify_shared_state_namespace" verify_shared_state_namespace
timed_step "switch_images" switch_images
timed_step "write_flip_overrides" write_detection_flip_overrides
timed_step "run_basic_health" run_basic_health
timed_step "run_smoke" run_smoke
timed_step "run_forward_probe" run_forward_probe
timed_step "write_state" write_state
timed_step "write_history" write_history
SERVICES_QUIESCED=0
SERVICE_RUNTIME_MUTATION_STARTED=0
timed_step "retire_legacy_judge_model" retire_legacy_judge_model_after_upgrade
log "[ok] upgrade completed from=$FROM_VERSION to=$TO_VERSION backup=$BACKUP_FILE"

# chat 门户激活提示：本包若含 chat 载荷，升级流程只覆盖基础网关、不自动激活 chat。
# 从「基础版」升级到「full-chat 版」时，chat 镜像已装但未启动——检测并提示运维如何启用。
if [ -d "$SCRIPT_DIR/chat" ] && [ -z "$(compose ps -q chat-portal-ui 2>/dev/null)" ]; then
  log "[warn] 本离线包含 chat 门户，但升级流程只覆盖基础网关、未激活 chat 组件（chat 镜像已装、未启动）。"
  log "[warn] 启用 chat：在本目录（deploy/docker-compose）执行  sh deploy-offline.sh"
  log "[warn]   —— 该操作幂等，会补齐 chat 配置（公开 SSO 地址 / 密钥 / 内部身份运行配置）并拉起门户，基础服务与数据不受影响。"
fi
