#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname "$0")" && pwd)"
COMPOSE_DIR="$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)"
COMPOSE_WRAPPER="${COMPOSE_WRAPPER:-$COMPOSE_DIR/compose-wrapper.sh}"
JJD_ENV_FILE="${JJD_ENV_FILE:-$COMPOSE_DIR/.env}"
IDENTITY_RUNTIME_ENV_FILE="${IDENTITY_RUNTIME_ENV_FILE:-$COMPOSE_DIR/identity-runtime.env}"
RUNTIME_REALM="jjdguard"
RUNTIME_CLIENT_ID="jjdguard-directory-orchestrator"
RUNTIME_URL="http://chat-idp:8180/sso"
tmp_file=""
bootstrap_password=""
runtime_secret=""

fail() {
  echo "[error] $*" >&2
  exit 1
}

cleanup() {
  bootstrap_password=""
  runtime_secret=""
  if [ -n "$tmp_file" ] && [ -f "$tmp_file" ]; then
    rm -f "$tmp_file"
  fi
}
trap cleanup EXIT HUP INT TERM

read_env_value() {
  local key="$1"
  [ -f "$JJD_ENV_FILE" ] || return 0
  sed -n "s/^${key}=//p" "$JJD_ENV_FILE" | tail -n 1
}

json_field() {
  local field="$1"
  sed -n "s/.*\"${field}\"[[:space:]]*:[[:space:]]*\"\([^\"]*\)\".*/\1/p" | head -n 1
}

kcadm() {
  if [ -n "${KCADM_BIN:-}" ]; then
    "$KCADM_BIN" "$@"
    return
  fi
  sh "$COMPOSE_WRAPPER" exec -T chat-idp /opt/keycloak/bin/kcadm.sh "$@"
}

if [ "${BOOTSTRAP_TEST_MODE:-0}" != "1" ] && [ "$(id -u)" -ne 0 ]; then
  fail "目录运行态引导需要 root；请使用 sudo 执行"
fi

bootstrap_password="${KEYCLOAK_ADMIN_PASSWORD:-}"
[ -n "$bootstrap_password" ] || bootstrap_password="$(read_env_value KEYCLOAK_ADMIN_PASSWORD)"
[ -n "$bootstrap_password" ] || fail "缺少身份引擎 bootstrap 凭据"

# Match the identity bootstrap's bounded six-minute default so first-start
# Keycloak augmentation does not make directory bootstrap fail spuriously.
max_attempts="${IDENTITY_BOOTSTRAP_MAX_ATTEMPTS:-180}"
interval="${IDENTITY_BOOTSTRAP_INTERVAL_SECONDS:-2}"
attempt=1
while ! kcadm config credentials \
  --server http://localhost:8180/sso \
  --realm master \
  --user "${KC_BOOTSTRAP_ADMIN_USERNAME:-admin}" \
  --password "$bootstrap_password" >/dev/null 2>&1; do
  [ "$attempt" -lt "$max_attempts" ] || fail "身份引擎在有界等待后仍未就绪"
  sleep "$interval"
  attempt=$((attempt + 1))
done

client_json="$(kcadm get clients -r "$RUNTIME_REALM" -q "clientId=$RUNTIME_CLIENT_ID" --fields id)" ||
  fail "无法查询目录运行态服务账号"
client_uuid="$(printf '%s' "$client_json" | json_field id)"

if [ -z "$client_uuid" ]; then
  kcadm create clients -r "$RUNTIME_REALM" \
    -s "clientId=$RUNTIME_CLIENT_ID" \
    -s 'enabled=true' \
    -s 'protocol=openid-connect' \
    -s 'publicClient=false' \
    -s 'clientAuthenticatorType=client-secret' \
    -s 'serviceAccountsEnabled=true' \
    -s 'standardFlowEnabled=false' \
    -s 'implicitFlowEnabled=false' \
    -s 'directAccessGrantsEnabled=false' >/dev/null ||
    fail "无法创建目录运行态服务账号"
  client_json="$(kcadm get clients -r "$RUNTIME_REALM" -q "clientId=$RUNTIME_CLIENT_ID" --fields id)"
  client_uuid="$(printf '%s' "$client_json" | json_field id)"
fi
[ -n "$client_uuid" ] || fail "目录运行态服务账号创建后无法读取"

kcadm update "clients/$client_uuid" -r "$RUNTIME_REALM" \
  -s 'enabled=true' \
  -s 'publicClient=false' \
  -s 'serviceAccountsEnabled=true' \
  -s 'standardFlowEnabled=false' \
  -s 'implicitFlowEnabled=false' \
  -s 'directAccessGrantsEnabled=false' >/dev/null ||
  fail "无法收紧目录运行态服务账号"

service_account_json="$(kcadm get "clients/$client_uuid/service-account-user" -r "$RUNTIME_REALM" --fields id)" ||
  fail "无法读取目录运行态 service account"
service_account_id="$(printf '%s' "$service_account_json" | json_field id)"
[ -n "$service_account_id" ] || fail "目录运行态 service account 不存在"

management_json="$(kcadm get clients -r "$RUNTIME_REALM" -q clientId=realm-management --fields id)" ||
  fail "无法读取 realm-management"
management_id="$(printf '%s' "$management_json" | json_field id)"
[ -n "$management_id" ] || fail "realm-management 不存在"

for forbidden_role in realm-admin manage-identity-providers manage-clients view-users query-users; do
  kcadm remove-roles -r "$RUNTIME_REALM" --uid "$service_account_id" \
    --cclientid realm-management --rolename "$forbidden_role" >/dev/null 2>&1 || true
done
for allowed_role in view-realm manage-realm manage-users; do
  kcadm add-roles -r "$RUNTIME_REALM" --uid "$service_account_id" \
    --cclientid realm-management --rolename "$allowed_role" >/dev/null ||
    fail "无法绑定目录运行态最小权限"
done

assigned_roles="$(kcadm get "users/$service_account_id/role-mappings/clients/$management_id" -r "$RUNTIME_REALM")" ||
  fail "无法复核目录运行态权限"
for allowed_role in view-realm manage-realm manage-users; do
  printf '%s' "$assigned_roles" | grep -Eq "\"name\"[[:space:]]*:[[:space:]]*\"${allowed_role}\"" ||
    fail "目录运行态最小权限不完整"
done
for forbidden_role in realm-admin manage-identity-providers manage-clients; do
  if printf '%s' "$assigned_roles" | grep -Eq "\"name\"[[:space:]]*:[[:space:]]*\"${forbidden_role}\""; then
    fail "目录运行态服务账号仍持有越界权限"
  fi
done

secret_json="$(kcadm get "clients/$client_uuid/client-secret" -r "$RUNTIME_REALM")" ||
  fail "无法读取目录运行态 client secret"
runtime_secret="$(printf '%s' "$secret_json" | json_field value)"
if [ -z "$runtime_secret" ]; then
  kcadm create "clients/$client_uuid/client-secret" -r "$RUNTIME_REALM" >/dev/null ||
    fail "无法生成目录运行态 client secret"
  secret_json="$(kcadm get "clients/$client_uuid/client-secret" -r "$RUNTIME_REALM")"
  runtime_secret="$(printf '%s' "$secret_json" | json_field value)"
fi
[ -n "$runtime_secret" ] || fail "目录运行态 client secret 为空"
case "$runtime_secret" in
  *[!A-Za-z0-9._~+/=-]*) fail "目录运行态 client secret 格式非法" ;;
esac

mkdir -p "$(dirname "$IDENTITY_RUNTIME_ENV_FILE")"
umask 077
tmp_file="$(mktemp "${IDENTITY_RUNTIME_ENV_FILE}.tmp.XXXXXX")"
if [ -f "$IDENTITY_RUNTIME_ENV_FILE" ]; then
  grep -Ev '^DIRECTORY_RUNTIME_(URL|CLIENT_ID|CLIENT_SECRET)=' "$IDENTITY_RUNTIME_ENV_FILE" >"$tmp_file" || true
fi
{
  printf 'DIRECTORY_RUNTIME_URL=%s\n' "$RUNTIME_URL"
  printf 'DIRECTORY_RUNTIME_CLIENT_ID=%s\n' "$RUNTIME_CLIENT_ID"
  printf 'DIRECTORY_RUNTIME_CLIENT_SECRET=%s\n' "$runtime_secret"
} >>"$tmp_file"
chmod 600 "$tmp_file"
if [ "$(id -u)" -eq 0 ]; then
  chown 0:0 "$tmp_file"
fi
mv -f "$tmp_file" "$IDENTITY_RUNTIME_ENV_FILE"
tmp_file=""

echo "[ok] JJDGuard 目录运行态最小权限凭据已就绪"
