#!/bin/sh
set -eu

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"
PROJECT_ROOT="$(CDPATH= cd -- "$SCRIPT_DIR/../.." && pwd)"
COMPOSE_WRAPPER="$SCRIPT_DIR/compose-wrapper.sh"
# 安全读取 .env（逐行按字面解析，不 source，见 deploy/lib/jjd-env.sh）。
if [ ! -f "$SCRIPT_DIR/../lib/jjd-env.sh" ]; then
  echo "[error] 缺少安全读取 .env 的库: $SCRIPT_DIR/../lib/jjd-env.sh" >&2
  exit 1
fi
. "$SCRIPT_DIR/../lib/jjd-env.sh"

ENV_FILE="$SCRIPT_DIR/.env"
RESULT_FILE="$SCRIPT_DIR/.deploy-result"
RESERVED_PORTS=""

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "[error] missing required command: $1" >&2
    exit 1
  fi
}

require_docker_compose() {
  if ! sh "$COMPOSE_WRAPPER" version >/dev/null 2>&1; then
    echo "[error] Docker Compose v2 is required; bundled fallback not found or not executable" >&2
    exit 1
  fi
}

sha256_file() {
  if command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | awk '{print $1}'
    return
  fi
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
    return
  fi
  echo "[error] missing checksum command: shasum or sha256sum" >&2
  exit 1
}

random_hex() {
  bytes="$1"
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
  exit 1
}

random_password() {
  printf 'Napi#%s!\n' "$(random_hex 6)"
}

port_in_use() {
  port="$1"
  for reserved in $RESERVED_PORTS; do
    if [ "$reserved" = "$port" ]; then
      return 0
    fi
  done
  if command -v ss >/dev/null 2>&1; then
    ss -ltn "sport = :$port" 2>/dev/null | grep -q ":$port"
    return $?
  fi
  if command -v netstat >/dev/null 2>&1; then
    netstat -ltn 2>/dev/null | awk '{print $4}' | grep -Eq "(^|[.:])$port$"
    return $?
  fi
  if command -v lsof >/dev/null 2>&1; then
    lsof -iTCP:"$port" -sTCP:LISTEN >/dev/null 2>&1
    return $?
  fi
  return 1
}

allocate_port() {
  var_name="$1"
  port="$2"
  while port_in_use "$port"; do
    port=$((port + 1))
  done
  RESERVED_PORTS="${RESERVED_PORTS} ${port}"
  eval "$var_name=$port"
}

detect_host() {
  if command -v hostname >/dev/null 2>&1; then
    for ip in $(hostname -I 2>/dev/null || true); do
      case "$ip" in
        127.*|169.254.*) ;;
        *)
          printf '%s' "$ip"
          return
          ;;
      esac
    done
  fi
  if command -v ip >/dev/null 2>&1; then
    ip route get 1.1.1.1 2>/dev/null | awk '/src/ {for (i=1;i<=NF;i++) if ($i=="src") {print $(i+1); exit}}'
    return
  fi
  printf '127.0.0.1'
}

detect_hosts() {
  printed=""
  if command -v ip >/dev/null 2>&1; then
    for ip in $(ip -o -4 addr show scope global 2>/dev/null | awk '$2 !~ /^(docker|br-|veth|virbr)/ {split($4,a,"/"); print a[1]}'); do
      case "$ip" in
        127.*|169.254.*) continue ;;
      esac
      case " $printed " in
        *" $ip "*) continue ;;
      esac
      printed="${printed} ${ip}"
      printf '%s\n' "$ip"
    done
  fi
  if [ -z "$printed" ]; then
    for ip in $(hostname -I 2>/dev/null || true); do
      case "$ip" in
        *.*) ;;
        *) continue ;;
      esac
      case "$ip" in
        127.*|169.254.*) continue ;;
      esac
      case " $printed " in
        *" $ip "*) continue ;;
      esac
      printed="${printed} ${ip}"
      printf '%s\n' "$ip"
    done
  fi
  if [ -z "$printed" ]; then
    printf '127.0.0.1\n'
  fi
}

detect_hosts_csv() {
  hosts="$(detect_hosts | paste -sd, -)"
  printf '%s' "${hosts:-127.0.0.1}"
}

default_external_bind() {
  if [ -n "${JJD_EXTERNAL_BIND:-}" ]; then
    printf '%s' "$JJD_EXTERNAL_BIND"
    return
  fi
  printf '0.0.0.0'
}

append_env_if_missing() {
  key="$1"
  value="$2"
  if ! grep -q "^${key}=" "$ENV_FILE"; then
    printf '%s=%s\n' "$key" "$value" >>"$ENV_FILE"
  fi
}

ensure_license_defaults() {
  if [ -z "$(grep '^JJD_LICENSE_PUBLIC_KEY=' "$ENV_FILE" 2>/dev/null | tail -n 1 | cut -d= -f2-)" ] && [ -f "$SCRIPT_DIR/license/public-key.txt" ]; then
    append_env_if_missing JJD_LICENSE_PUBLIC_KEY "$(cat "$SCRIPT_DIR/license/public-key.txt" | tr -d '\r\n')"
  fi
  append_env_if_missing JJD_LICENSE_ENFORCE false
}

default_package_version() {
  if [ -f "$PROJECT_ROOT/VERSION" ]; then
    sed -n '1{s/[[:space:]]//g;p;q;}' "$PROJECT_ROOT/VERSION"
    return
  fi
  printf 'unknown'
}

default_commit() {
  git -C "$PROJECT_ROOT" rev-parse --short HEAD 2>/dev/null || true
}

default_built_at() {
  date -u '+%Y-%m-%dT%H:%M:%SZ'
}

ensure_version_defaults() {
  append_env_if_missing JJD_VERSION "$(default_package_version)"
  append_env_if_missing JJD_COMMIT "$(default_commit)"
  append_env_if_missing JJD_BUILT_AT "$(default_built_at)"
}

ensure_hardening_defaults() {
  external_bind="$(default_external_bind)"
  append_env_if_missing WEB_BIND "$external_bind"
  append_env_if_missing WEB_HTTPS_BIND "$external_bind"
  append_env_if_missing GATEWAY_BIND "$external_bind"
  append_env_if_missing PROXY_BIND "$external_bind"
  append_env_if_missing FORWARD_PROXY_BIND "$external_bind"
  append_env_if_missing CONTROL_BIND 127.0.0.1
  append_env_if_missing SECURITY_BIND 127.0.0.1
  append_env_if_missing POSTGRES_BIND 127.0.0.1
  append_env_if_missing REDIS_BIND 127.0.0.1
  append_env_if_missing REDIS_PASSWORD "$(random_hex 32)"
  append_env_if_missing JJD_SEMANTIC_GATEWAY_ATTESTATION_KEY "$(random_hex 32)"
  append_env_if_missing MCP_CONFIRMATION_SCOPE_SECRET "$(random_hex 32)"
  append_env_if_missing JJD_TIER1_INTERNAL_TOKEN "$(random_hex 32)"
  append_env_if_missing JJD_RULE_PACK_ATTESTATION_TENANT tenant_default
  append_env_if_missing JJD_RULE_PACK_ATTESTATION_TOKEN "$(random_hex 32)"
  append_env_if_missing JJD_RULE_PACK_ATTESTATION_TOKENS_JSON ""
}

ensure_https_defaults() {
  host_addrs="$(detect_hosts_csv)"
  if ! grep -q '^WEB_HTTPS_PORT=' "$ENV_FILE"; then
    allocate_port WEB_HTTPS_PORT 443
    append_env_if_missing WEB_HTTPS_PORT "$WEB_HTTPS_PORT"
  fi
  append_env_if_missing TLS_ENABLED true
  append_env_if_missing TLS_CERT_HOSTS "localhost,127.0.0.1,$host_addrs"
}

format_https_url() {
  host="$1"
  port="$2"
  if [ "$port" = "443" ]; then
    printf 'https://%s' "$host"
  else
    printf 'https://%s:%s' "$host" "$port"
  fi
}

derive_project_name() {
  if [ -n "${COMPOSE_PROJECT_NAME:-}" ]; then
    printf '%s' "$COMPOSE_PROJECT_NAME"
    return
  fi
  root_base="$(basename "$PROJECT_ROOT")"
  if [ "$root_base" = "newapi-enterprise-local" ]; then
    base="$(basename "$(dirname "$PROJECT_ROOT")")"
  else
    base="$root_base"
  fi
  base="$(printf '%s' "$base" | tr '[:upper:]' '[:lower:]' | tr -cs 'a-z0-9' '-')"
  base="${base#-}"
  base="${base%-}"
  if [ -z "$base" ]; then
    base="jjdguard"
  fi
  printf '%s' "$base"
}

ensure_env() {
  if [ -f "$ENV_FILE" ]; then
    return
  fi

  allocate_port WEB_PORT 3000
  allocate_port WEB_HTTPS_PORT 443
  allocate_port GATEWAY_PORT 8080
  allocate_port PROXY_PORT 8082
  allocate_port CONTROL_PORT 8081
  allocate_port SECURITY_PORT 8000
  allocate_port FORWARD_PROXY_PORT 3128
  allocate_port POSTGRES_PORT 5432
  allocate_port REDIS_PORT 6379
  SECRET_KEY="$(random_hex 32)"
  INTERNAL_SECRET="$(random_hex 32)"
  AUDIT_HMAC_KEY="$(random_hex 32)"
  ADMIN_PASSWORD="$(random_password)"
  POSTGRES_PASSWORD="$(random_hex 24)"
  REDIS_PASSWORD="$(random_hex 32)"
  EXTERNAL_BIND="$(default_external_bind)"

  cat >"$ENV_FILE" <<EOF
JJD_PROVIDER_SECRET_KEY=$SECRET_KEY
UAG_AUDIT_HMAC_KEY=$AUDIT_HMAC_KEY
JJD_INTERNAL_API_SECRET=$INTERNAL_SECRET
BOOTSTRAP_ADMIN_USERNAME=admin
BOOTSTRAP_ADMIN_EMAIL=admin@local
BOOTSTRAP_ADMIN_PASSWORD=$ADMIN_PASSWORD
WEB_PORT=$WEB_PORT
WEB_HTTPS_PORT=$WEB_HTTPS_PORT
WEB_BIND=$EXTERNAL_BIND
WEB_HTTPS_BIND=$EXTERNAL_BIND
GATEWAY_PORT=$GATEWAY_PORT
PROXY_PORT=$PROXY_PORT
GATEWAY_BIND=$EXTERNAL_BIND
PROXY_BIND=$EXTERNAL_BIND
CONTROL_PORT=$CONTROL_PORT
SECURITY_PORT=$SECURITY_PORT
FORWARD_PROXY_PORT=$FORWARD_PROXY_PORT
FORWARD_PROXY_BIND=$EXTERNAL_BIND
POSTGRES_PORT=$POSTGRES_PORT
REDIS_PORT=$REDIS_PORT
CONTROL_BIND=127.0.0.1
SECURITY_BIND=127.0.0.1
POSTGRES_BIND=127.0.0.1
REDIS_BIND=127.0.0.1
REDIS_PASSWORD=$REDIS_PASSWORD
GATEWAY_ENVIRONMENT_SCOPE=customer
SECURITY_AUDIT_ONLY=false
SECURITY_PII_CHECKSUM_ENABLED=true
TLS_ENABLED=true
TLS_CERT_HOSTS=localhost,127.0.0.1,$(detect_hosts_csv)
OPENAI_API_KEY=
ANTHROPIC_API_KEY=
DEFAULT_PROVIDER_NAME=
DEFAULT_PROVIDER_TYPE=openai
DEFAULT_PROVIDER_BASE_URL=
DEFAULT_PROVIDER_API_KEY=
DEFAULT_KEY_PROJECT_ID=project_default
DEFAULT_KEY_USER_ID=user_admin
DEFAULT_KEY_SCOPES=["chat","responses","embeddings","models"]
JJD_VERSION=$(default_package_version)
JJD_COMMIT=$(default_commit)
JJD_BUILT_AT=$(default_built_at)
POSTGRES_USER=jjdguard
POSTGRES_PASSWORD=$POSTGRES_PASSWORD
POSTGRES_DB=jjdguard
EOF
  ensure_license_defaults
  echo "[ok] generated .env automatically"
}

load_env() {
  # 不能 source .env（含空格的未加引号值会被当命令执行），经 deploy/lib/jjd-env.sh 按字面读取并 export。
  jjd_load_env_file "$ENV_FILE" || return 1
  WEB_HTTPS_PORT="${WEB_HTTPS_PORT:-443}"
  PROXY_PORT="${PROXY_PORT:-8082}"
  FORWARD_PROXY_PORT="${FORWARD_PROXY_PORT:-3128}"
  TLS_ENABLED="${TLS_ENABLED:-true}"
  TLS_CERT_HOSTS="${TLS_CERT_HOSTS:-localhost,127.0.0.1,$(detect_hosts_csv)}"
  WEB_BIND="${WEB_BIND:-0.0.0.0}"
  WEB_HTTPS_BIND="${WEB_HTTPS_BIND:-0.0.0.0}"
  GATEWAY_BIND="${GATEWAY_BIND:-0.0.0.0}"
  PROXY_BIND="${PROXY_BIND:-0.0.0.0}"
  FORWARD_PROXY_BIND="${FORWARD_PROXY_BIND:-0.0.0.0}"
  CONTROL_BIND="${CONTROL_BIND:-127.0.0.1}"
  SECURITY_BIND="${SECURITY_BIND:-127.0.0.1}"
  POSTGRES_BIND="${POSTGRES_BIND:-127.0.0.1}"
  REDIS_BIND="${REDIS_BIND:-127.0.0.1}"
  JJD_VERSION="${JJD_VERSION:-$(default_package_version)}"
  JJD_COMMIT="${JJD_COMMIT:-$(default_commit)}"
  JJD_BUILT_AT="${JJD_BUILT_AT:-$(default_built_at)}"
  export WEB_HTTPS_PORT PROXY_PORT FORWARD_PROXY_PORT TLS_ENABLED TLS_CERT_HOSTS
  export WEB_BIND WEB_HTTPS_BIND GATEWAY_BIND PROXY_BIND FORWARD_PROXY_BIND CONTROL_BIND SECURITY_BIND POSTGRES_BIND REDIS_BIND
  export JJD_VERSION JJD_COMMIT JJD_BUILT_AT
}

write_result() {
  HOST_ADDR="$(detect_host)"
  HOST_ADDRS="$(detect_hosts_csv)"
  cat >"$RESULT_FILE" <<EOF
WEB_URLS=$(for h in $(printf '%s' "$HOST_ADDRS" | tr ',' ' '); do printf '%s ' "$(format_https_url "$h" "$WEB_HTTPS_PORT")"; done | awk '{$1=$1; print}')
WEB_URL=$(format_https_url "$HOST_ADDR" "$WEB_HTTPS_PORT")
WEB_HTTP_REDIRECT_URL=http://$HOST_ADDR:$WEB_PORT
TLS_CERT_FILE=$SCRIPT_DIR/tls/web-console.crt
GATEWAY_URLS=$(for h in $(printf '%s' "$HOST_ADDRS" | tr ',' ' '); do printf 'http://%s:%s ' "$h" "$GATEWAY_PORT"; done | awk '{$1=$1; print}')
GATEWAY_URL=http://$HOST_ADDR:$GATEWAY_PORT
REVERSE_PROXY_URL=http://$HOST_ADDR:$PROXY_PORT
CONTROL_URL=http://127.0.0.1:$CONTROL_PORT
SECURITY_URL=http://127.0.0.1:$SECURITY_PORT
FORWARD_PROXY_URL=http://$HOST_ADDR:$FORWARD_PROXY_PORT
BOOTSTRAP_ADMIN_USERNAME=$BOOTSTRAP_ADMIN_USERNAME
BOOTSTRAP_ADMIN_PASSWORD=$BOOTSTRAP_ADMIN_PASSWORD
ENV_FILE=$ENV_FILE
EOF
}

require_cmd docker
require_docker_compose

export COMPOSE_PROJECT_NAME="$(derive_project_name)"

ensure_env
ensure_hardening_defaults
ensure_https_defaults
ensure_version_defaults
ensure_license_defaults
load_env

echo "[step] building web console image for TLS certificate generation"
sh "$COMPOSE_WRAPPER" build web-console

echo "[step] preparing web console TLS certificate"
sh ./ensure-web-tls.sh

echo "[step] ensuring isolated Portal-to-control-plane network"
bash "$SCRIPT_DIR/ensure-jjdguard-portal-cp-network.sh" --name "${JJD_PORTAL_CP_NETWORK:-jjdguard-portal-control-net}" --owner jjdguard

echo "[step] starting database services first (postgres/redis/redis-cache)"
# 先起 DB 层并等健康，再迁移，最后起应用服务：避免整栈并发起时 control-plane 抢在
# postgres 尚未接受 TCP 前连库失败→不健康→装机中断；也保证应用服务面对已迁移到最新的 schema。
# 与 deploy-offline.sh 一致，区别仅 --build（本地从源码构建镜像）。
sh "$COMPOSE_WRAPPER" up -d --build --wait postgres redis redis-cache

echo "[step] bootstrapping base schema (manual psql -f /bootstrap)"
# docker-entrypoint-initdb.d 直跑 001_init_enterprise.sql 会只建到 001 就停(入口点执行方式与 psql -f 不同,
# 实测残缺 13 表→迁移基线失败→装机中断)。故 initdb 改挂 /bootstrap(入口点不自跑),起库后手动 psql -f
# (实测建全 33 表+种子),再由 migrate-private 基线并施加其余迁移。仅空库(无 tenants 表)执行,幂等;升级走 upgrade.sh。
if [ "$(sh "$COMPOSE_WRAPPER" exec -T postgres psql -U "${POSTGRES_USER:-jjdguard}" -d "${POSTGRES_DB:-jjdguard}" -tAc "SELECT to_regclass('public.tenants') IS NOT NULL" 2>/dev/null | tr -d "[:space:]")" != "t" ]; then
  sh "$COMPOSE_WRAPPER" exec -T postgres psql -U "${POSTGRES_USER:-jjdguard}" -d "${POSTGRES_DB:-jjdguard}" -v ON_ERROR_STOP=1 -f /bootstrap/001_init_enterprise.sql
fi

echo "[step] applying private migrations"
sh ./migrate-private.sh

echo "[step] starting services"
sh "$COMPOSE_WRAPPER" up -d --build

echo "[step] initializing runtime defaults"
sh ./bootstrap-runtime.sh

echo "[step] running smoke test"
sh ./smoke-test.sh

write_result

HOST_ADDR="$(detect_host)"
HOST_ADDRS="$(detect_hosts_csv)"
echo
echo "[ok] deployment completed"
echo "[info] web console: $(for h in $(printf '%s' "$HOST_ADDRS" | tr ',' ' '); do printf '%s ' "$(format_https_url "$h" "$WEB_HTTPS_PORT")"; done | awk '{$1=$1; print}')"
echo "[info] http redirect: http://$HOST_ADDR:$WEB_PORT"
echo "[info] gateway api:  http://$HOST_ADDR:$GATEWAY_PORT"
echo "[info] reverse proxy: http://$HOST_ADDR:$PROXY_PORT"
echo "[info] control api:  http://127.0.0.1:$CONTROL_PORT"
echo "[info] forward proxy: http://$HOST_ADDR:$FORWARD_PROXY_PORT"
echo "[info] admin user:   $BOOTSTRAP_ADMIN_USERNAME"
echo "[info] admin pass:   $BOOTSTRAP_ADMIN_PASSWORD"
echo "[info] saved result: $RESULT_FILE"
echo "[info] compose project: $COMPOSE_PROJECT_NAME"
