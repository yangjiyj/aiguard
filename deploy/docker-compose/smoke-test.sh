#!/bin/sh
set -eu

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"
COMPOSE_WRAPPER="$SCRIPT_DIR/compose-wrapper.sh"
LOGIN_HELPER="$SCRIPT_DIR/../lib/captcha-login.sh"
if [ ! -f "$LOGIN_HELPER" ]; then
  echo "[error] captcha login helper missing: $LOGIN_HELPER" >&2
  exit 1
fi
. "$LOGIN_HELPER"

# 读 .env 不能用 source：未加引号且含空格的值（如 REDIS_EXTRA_ARGS=--a yes）会被当成命令执行，
# 值里的 $(...) / 反引号 / 分号也会被执行。统一经共享库按字面解析，见 deploy/lib/jjd-env.sh。
JJD_ENV_LIB="$SCRIPT_DIR/../lib/jjd-env.sh"
if [ ! -f "$JJD_ENV_LIB" ]; then
  echo "[error] 缺少安全读取 .env 的库: $JJD_ENV_LIB" >&2
  exit 1
fi
# shellcheck source=../lib/jjd-env.sh
. "$JJD_ENV_LIB"
if [ -f ./.env ]; then
  jjd_load_env_file ./.env
fi

BASE_HOST="${1:-127.0.0.1}"
WEB_PORT="${WEB_PORT:-3000}"
WEB_HTTPS_PORT="${WEB_HTTPS_PORT:-443}"
GATEWAY_PORT="${GATEWAY_PORT:-8080}"
CONTROL_PORT="${CONTROL_PORT:-8081}"
SECURITY_PORT="${SECURITY_PORT:-8000}"
BOOTSTRAP_ADMIN_USERNAME="${BOOTSTRAP_ADMIN_USERNAME:-admin}"
BOOTSTRAP_ADMIN_PASSWORD="${BOOTSTRAP_ADMIN_PASSWORD:-}"

check_host() {
  name="$1"
  url="$2"
  if ! command -v curl >/dev/null 2>&1; then
    return 2
  fi
  echo "[check] $name -> $url"
  case "$url" in
    https://*) curl -kfsS "$url" >/dev/null ;;
    *) curl -fsS "$url" >/dev/null ;;
  esac
}

check_container() {
  name="$1"
  service="$2"
  command="$3"
  echo "[check] $name -> container health fallback"
  sh "$COMPOSE_WRAPPER" exec -T "$service" sh -c "$command" >/dev/null
}

check() {
  name="$1"
  url="$2"
  service="$3"
  command="$4"
  if check_host "$name" "$url"; then
    return
  fi
  check_container "$name" "$service" "$command"
}

bootstrap_password_rotated() {
  local state
  state="$(printf '%s\n' \
    "SELECT CASE WHEN COUNT(*) = 1 AND BOOL_AND(NOT must_change_password) THEN 'rotated' ELSE 'bootstrap' END FROM users WHERE username = :'smoke_username';" |
    sh "$COMPOSE_WRAPPER" exec -T postgres \
      psql -U "${POSTGRES_USER:-jjdguard}" \
        -d "${POSTGRES_DB:-jjdguard}" \
        -v "smoke_username=$BOOTSTRAP_ADMIN_USERNAME" \
        -At \
      2>/dev/null | tr -d '[:space:]')" || return 1
  [ "$state" = rotated ]
}

check_login() {
  if [ "${SMOKE_SKIP_LOGIN:-false}" = "true" ]; then
    echo "[skip] bootstrap admin login check"
    return
  fi
  if [ -z "$BOOTSTRAP_ADMIN_PASSWORD" ]; then
    return
  fi
  if ! command -v curl >/dev/null 2>&1; then
    echo "[warn] curl not found; skip bootstrap admin HTTP login check"
    return
  fi
  echo "[check] bootstrap admin login -> ${BOOTSTRAP_ADMIN_USERNAME}"
  LOGIN_RESPONSE="$(captcha_login_json "https://${BASE_HOST}:${WEB_HTTPS_PORT}/admin/v1" \
    "$BOOTSTRAP_ADMIN_USERNAME" "$BOOTSTRAP_ADMIN_PASSWORD")"
  if ! captcha_login_response_succeeded "$LOGIN_RESPONSE"; then
    if bootstrap_password_rotated; then
      echo "[warn] bootstrap admin credential is no longer valid; administrator password was already rotated"
      return
    fi
    echo "[error] bootstrap admin login did not return a valid session" >&2
    return 1
  fi
  echo "[ok] bootstrap admin login returned success"
  if captcha_login_password_change_required "$LOGIN_RESPONSE"; then
    echo "[ok] bootstrap admin is forced to rotate the initial password"
  else
    echo "[ok] administrator password was already rotated"
  fi
}

echo "[info] running smoke test against host ${BASE_HOST}"

check "web-console-http-health" "http://${BASE_HOST}:${WEB_PORT}/health" "web-console" "wget -qO- http://127.0.0.1:3000/health"
check "web-console-https" "https://${BASE_HOST}:${WEB_HTTPS_PORT}/health" "web-console" "wget --no-check-certificate -qO- https://127.0.0.1:3443/health"
check "gateway-core" "http://${BASE_HOST}:${GATEWAY_PORT}/health" "gateway-core" "wget -qO- http://127.0.0.1:8080/health"
check "control-plane" "http://${BASE_HOST}:${CONTROL_PORT}/health" "control-plane" "wget -qO- http://127.0.0.1:8081/health"
check "security-engine" "http://${BASE_HOST}:${SECURITY_PORT}/health" "security-engine" "python -c \"import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health')\""

echo "[ok] all health endpoints returned success"
check_login

echo "[next] sign in to the HTTPS web console and rotate the bootstrap admin password immediately"
