#!/usr/bin/env bash
# 为 control-plane 创建仅能编排 jjdguard realm 身份源的服务账号。
# 密钥只写入 0600 的专用 env 文件，不输出到终端。

set -euo pipefail

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname "$0")" && pwd)"
COMPOSE_DIR="$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)"
COMPOSE_WRAPPER="${COMPOSE_WRAPPER:-$COMPOSE_DIR/compose-wrapper.sh}"
JJD_ENV_FILE="${JJD_ENV_FILE:-$COMPOSE_DIR/.env}"
IDENTITY_RUNTIME_ENV_FILE="${IDENTITY_RUNTIME_ENV_FILE:-$COMPOSE_DIR/identity-runtime.env}"
RUNTIME_REALM="jjdguard"
RUNTIME_CLIENT_ID="jjdguard-identity-orchestrator"
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

scope_uuid_by_name() {
  local scope_name="$1"
  local scopes_json attempt max_attempts interval
  # A freshly upgraded offline Keycloak image can spend more than two minutes
  # performing its one-time Quarkus augmentation before kcadm is available.
  # Keep the wait bounded, but allow six minutes by default for slow customer VMs.
  max_attempts="${IDENTITY_BOOTSTRAP_MAX_ATTEMPTS:-180}"
  interval="${IDENTITY_BOOTSTRAP_INTERVAL_SECONDS:-2}"
  attempt=1
  while :; do
    if scopes_json="$(kcadm get client-scopes -r "$RUNTIME_REALM" \
      --fields id,name --format csv --noquotes 2>/dev/null)"; then
      printf '%s' "$scopes_json" |
        awk -F, -v wanted="$scope_name" '$2 == wanted { print $1; exit }'
      return 0
    fi
    if [ "$attempt" -ge "$max_attempts" ]; then
      return 1
    fi
    sleep "$interval"
    attempt=$((attempt + 1))
  done
}

ensure_scope_attribute_mapper() {
  local scope_uuid="$1"
  local mapper_name="$2"
  local protocol_mapper="$3"
  local user_attribute="$4"
  local claim_name="$5"
  local json_type="$6"
  local mappers_json mapper_payload

  mappers_json="$(kcadm get "client-scopes/$scope_uuid/protocol-mappers/models" \
    -r "$RUNTIME_REALM")" ||
    fail "无法查询 Chat $mapper_name mapper"
  if printf '%s' "$mappers_json" | grep -Fq "\"name\":\"$mapper_name\"" ||
    printf '%s' "$mappers_json" | grep -Fq "\"name\" : \"$mapper_name\""; then
    return
  fi
  mapper_payload="$(printf '{\"name\":\"%s\",\"protocol\":\"openid-connect\",\"protocolMapper\":\"%s\",\"consentRequired\":false,\"config\":{\"user.attribute\":\"%s\",\"claim.name\":\"%s\",\"jsonType.label\":\"%s\",\"id.token.claim\":\"true\",\"access.token.claim\":\"true\",\"userinfo.token.claim\":\"true\"}}' "$mapper_name" "$protocol_mapper" "$user_attribute" "$claim_name" "$json_type")"
  kcadm create "client-scopes/$scope_uuid/protocol-mappers/models" \
    -r "$RUNTIME_REALM" \
    -b "$mapper_payload" >/dev/null ||
    fail "无法创建 Chat $mapper_name mapper"
}

ensure_scope_full_name_mapper() {
  local scope_uuid="$1"
  local mappers_json

  mappers_json="$(kcadm get "client-scopes/$scope_uuid/protocol-mappers/models" \
    -r "$RUNTIME_REALM")" ||
    fail "无法查询 Chat full name mapper"
  if printf '%s' "$mappers_json" | grep -Fq "\"name\":\"full name\"" ||
    printf '%s' "$mappers_json" | grep -Fq "\"name\" : \"full name\""; then
    return
  fi
  local mapper_payload='{"name":"full name","protocol":"openid-connect","protocolMapper":"oidc-full-name-mapper","consentRequired":false,"config":{"id.token.claim":"true","access.token.claim":"true","userinfo.token.claim":"true"}}'
  kcadm create "client-scopes/$scope_uuid/protocol-mappers/models" \
    -r "$RUNTIME_REALM" \
    -b "$mapper_payload" >/dev/null ||
    fail "无法创建 Chat full name mapper"
}

ensure_portal_standard_scope() {
  local portal_client_uuid="$1"
  local scope_name="$2"
  local scope_uuid

  case "$scope_name" in
    profile|email) ;;
    *) fail "不支持的 Chat 标准 scope: $scope_name" ;;
  esac

  scope_uuid="$(scope_uuid_by_name "$scope_name")" ||
    fail "无法查询 Chat $scope_name scope"
  if [ -z "$scope_uuid" ]; then
    scope_uuid="$(kcadm create client-scopes -r "$RUNTIME_REALM" \
      -s "name=$scope_name" \
      -s 'protocol=openid-connect' \
      -s 'attributes."include.in.token.scope"=true' -i)" ||
      fail "无法创建 Chat $scope_name scope"
  fi
  [ -n "$scope_uuid" ] || fail "Chat $scope_name scope 为空"

  case "$scope_name" in
    profile)
      ensure_scope_attribute_mapper "$scope_uuid" username \
        oidc-usermodel-attribute-mapper username preferred_username String
      ensure_scope_full_name_mapper "$scope_uuid"
      ;;
    email)
      ensure_scope_attribute_mapper "$scope_uuid" email \
        oidc-usermodel-attribute-mapper email email String
      ensure_scope_attribute_mapper "$scope_uuid" "email verified" \
        oidc-usermodel-property-mapper emailVerified email_verified boolean
      ;;
  esac

  kcadm update \
    "clients/$portal_client_uuid/default-client-scopes/$scope_uuid" \
    -r "$RUNTIME_REALM" >/dev/null ||
    fail "无法绑定 Chat $scope_name 默认 scope"
}

ensure_portal_user_profile_department() {
  local profile_json

  profile_json="$(kcadm get users/profile -r "$RUNTIME_REALM")" ||
    fail "无法查询 Chat 用户属性配置"
  if printf '%s' "$profile_json" | grep -Eq '"name"[[:space:]]*:[[:space:]]*"department"'; then
    return
  fi

  # 旧 realm 缺失时不重写用户属性配置：该配置可能包含客户自定义字段，
  # 且客户主机不应依赖 Python JSON 工具。department protocol mapper 仍可
  # 读取企业 IdP 返回的同名用户属性。
  echo "[warn] Chat 用户属性配置未声明 department，保留现有配置并继续安装" >&2
}

# 门户 UI 与身份协议复用 Web 的公开 origin，浏览器登录后固定回到 /chat。
portal_ui_origin() {
  local origin
  origin="${JJD_SSO_PUBLIC_URL:-}"
  [ -n "$origin" ] || origin="$(read_env_value JJD_SSO_PUBLIC_URL)"
  origin="${origin%/}"
  [ -n "$origin" ] || return 1
  printf '%s/chat' "$origin"
}

# 门户 client 的可达性配置必须每次幂等对账。
# --import-realm 只在 realm 不存在时注入这些值；realm 建好之后公开地址变更、
# 端口调整或 secret 轮换都不会被写回去 —— 现场因此只能手工校准 client secret。
reconcile_portal_client_reachability() {
  local portal_client_uuid="$1"
  local portal_url public_origin account_redirect sso_redirect redirect_uris portal_secret
  portal_url="$(portal_ui_origin)" || {
    echo "[warn] 无法确定门户对外地址，跳过门户 client 可达性对账" >&2
    return 0
  }
  portal_url="${portal_url%/}"
  public_origin="${JJD_SSO_PUBLIC_URL:-}"
  [ -n "$public_origin" ] || public_origin="$(read_env_value JJD_SSO_PUBLIC_URL)"
  public_origin="${public_origin%/}"
  account_redirect="$portal_url/api/auth/callback/account-login"
  sso_redirect="$portal_url/api/auth/callback/enterprise-sso"
  redirect_uris="$(printf '["%s","%s"]' "$account_redirect" "$sso_redirect")"

  portal_secret="${CHAT_PORTAL_UI_OIDC_SECRET:-}"
  [ -n "$portal_secret" ] || portal_secret="$(read_env_value CHAT_PORTAL_UI_OIDC_SECRET)"

  set -- \
    -s "redirectUris=$redirect_uris" \
    -s "webOrigins=$(printf '["%s"]' "$public_origin")" \
    -s "attributes.\"post.logout.redirect.uris\"=$portal_url##$portal_url/*"
  # secret 缺失时不写空值：宁可保留 realm 里的现值，也不要把门户彻底锁死。
  if [ -n "$portal_secret" ]; then
    set -- "$@" -s "secret=$portal_secret"
  fi
  kcadm update "clients/$portal_client_uuid" -r "$RUNTIME_REALM" "$@" >/dev/null ||
    fail "无法对账门户 client 的可达性配置"
}

reconcile_portal_admin_reachability() {
  local origin redirect_uri admin_client_json admin_client_uuid
  origin="${JJD_SSO_PUBLIC_URL:-}"
  [ -n "$origin" ] || origin="$(read_env_value JJD_SSO_PUBLIC_URL)"
  origin="${origin%/}"
  [ -n "$origin" ] || return 0
  redirect_uri="$origin/portal/auth/callback"

  admin_client_json="$(kcadm get clients -r "$RUNTIME_REALM" \
    -q "clientId=chat-portal-admin" --fields id)" ||
    fail "无法查询 Chat 管理门户 client"
  admin_client_uuid="$(printf '%s' "$admin_client_json" | json_field id)"
  [ -n "$admin_client_uuid" ] || return 0

  kcadm update "clients/$admin_client_uuid" -r "$RUNTIME_REALM" \
    -s "redirectUris=$(printf '["%s"]' "$redirect_uri")" \
    -s "webOrigins=$(printf '["%s"]' "$origin")" \
    -s "attributes.\"post.logout.redirect.uris\"=$origin##$origin/*" >/dev/null ||
    fail "无法对账 Chat 管理门户 client 的可达性配置"
}

reconcile_portal_scopes() {

  local portal_client_json portal_client_uuid groups_scope_uuid
  portal_client_json="$(kcadm get clients -r "$RUNTIME_REALM" \
    -q "clientId=enterprise-ai-portal" --fields id)" ||
    fail "无法查询 Chat 门户 client"
  portal_client_uuid="$(printf '%s' "$portal_client_json" | json_field id)"
  [ -n "$portal_client_uuid" ] || fail "Chat 门户 client 不存在"

  ensure_portal_standard_scope "$portal_client_uuid" profile
  ensure_portal_standard_scope "$portal_client_uuid" email
  reconcile_portal_client_reachability "$portal_client_uuid"
  reconcile_portal_admin_reachability

  groups_scope_uuid="$(scope_uuid_by_name groups)" ||
    fail "无法查询 Chat groups scope"
  if [ -z "$groups_scope_uuid" ]; then
    groups_scope_uuid="$(kcadm create client-scopes -r "$RUNTIME_REALM" \
      -s 'name=groups' \
      -s 'protocol=openid-connect' \
      -s 'attributes."include.in.token.scope"=true' -i)" ||
      fail "无法创建 Chat groups scope"
  fi
  [ -n "$groups_scope_uuid" ] || fail "Chat groups scope 为空"
  kcadm update \
    "clients/$portal_client_uuid/optional-client-scopes/$groups_scope_uuid" \
    -r "$RUNTIME_REALM" >/dev/null ||
    fail "无法绑定 Chat groups scope"
}

if [ "${BOOTSTRAP_TEST_MODE:-0}" != "1" ] && [ "$(id -u)" -ne 0 ]; then
  fail "身份运行态引导需要 root；请使用 sudo 执行"
fi

bootstrap_password="${KEYCLOAK_ADMIN_PASSWORD:-}"
[ -n "$bootstrap_password" ] || bootstrap_password="$(read_env_value KEYCLOAK_ADMIN_PASSWORD)"
[ -n "$bootstrap_password" ] || fail "缺少身份引擎 bootstrap 凭据"

public_url="${JJD_SSO_PUBLIC_URL:-}"
[ -n "$public_url" ] || public_url="$(read_env_value JJD_SSO_PUBLIC_URL)"
if [ -z "$public_url" ]; then
  [ -x "$SCRIPT_DIR/ensure-public-sso-url.sh" ] ||
    fail "缺少 Chat SSO 公开地址解析器"
  JJD_ENV_FILE="$JJD_ENV_FILE" bash "$SCRIPT_DIR/ensure-public-sso-url.sh" >/dev/null ||
    fail "无法自动生成 Chat SSO 公开地址"
  public_url="$(read_env_value JJD_SSO_PUBLIC_URL)"
fi
public_url="${public_url%/}"
case "$public_url" in
  https://*) allow_insecure="false" ;;
  http://*)
    allow_insecure="${JJD_SSO_ALLOW_INSECURE_PUBLIC_URL:-}"
    [ -n "$allow_insecure" ] || allow_insecure="$(read_env_value JJD_SSO_ALLOW_INSECURE_PUBLIC_URL)"
    [ -n "$allow_insecure" ] || allow_insecure="true"
    ;;
  *) fail "JJD_SSO_PUBLIC_URL 必须是 http(s) origin" ;;
esac
case "$public_url" in
  *[[:space:]\"\']*|*\?*|*\#*|*@*) fail "JJD_SSO_PUBLIC_URL 含非法字符" ;;
esac

# 等待内部身份引擎就绪。失败只给稳定错误，不回显凭据或底层响应。
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

# Gateway-created local accounts intentionally need no email or personal names.
# VERIFY_PROFILE otherwise interrupts the successful login to collect them.
# Reconcile existing realms too; preserve explicit password/MFA required actions.
kcadm update authentication/required-actions/VERIFY_PROFILE -r "$RUNTIME_REALM" \
  -s enabled=false -s defaultAction=false >/dev/null ||
  fail "无法关闭本地账号登录后的重复资料补填"

reconcile_portal_scopes
ensure_portal_user_profile_department
client_json="$(kcadm get clients -r "$RUNTIME_REALM" -q "clientId=$RUNTIME_CLIENT_ID" --fields id)" ||
  fail "无法查询运行态服务账号"
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
    fail "无法创建运行态服务账号"
  client_json="$(kcadm get clients -r "$RUNTIME_REALM" -q "clientId=$RUNTIME_CLIENT_ID" --fields id)"
  client_uuid="$(printf '%s' "$client_json" | json_field id)"
fi
[ -n "$client_uuid" ] || fail "运行态服务账号创建后无法读取"

kcadm update "clients/$client_uuid" -r "$RUNTIME_REALM" \
  -s 'enabled=true' \
  -s 'publicClient=false' \
  -s 'serviceAccountsEnabled=true' \
  -s 'standardFlowEnabled=false' \
  -s 'implicitFlowEnabled=false' \
  -s 'directAccessGrantsEnabled=false' >/dev/null ||
  fail "无法收紧运行态服务账号"

service_account_json="$(kcadm get "clients/$client_uuid/service-account-user" -r "$RUNTIME_REALM" --fields id)" ||
  fail "无法读取运行态 service account"
service_account_id="$(printf '%s' "$service_account_json" | json_field id)"
[ -n "$service_account_id" ] || fail "运行态 service account 不存在"

management_json="$(kcadm get clients -r "$RUNTIME_REALM" -q clientId=realm-management --fields id)" ||
  fail "无法读取 realm-management"
management_id="$(printf '%s' "$management_json" | json_field id)"
[ -n "$management_id" ] || fail "realm-management 不存在"

# manage-realm 默认不授予（最小权限）。只有部署显式设置 JJD_IDENTITY_RUNTIME_GRANT_MANAGE_REALM=1，
# 才授予 manage-realm：启用身份源「首次登录不弹资料页」需要修改 realm 的认证流与用户资料，
# Keycloak 把这两类写操作都归在 manage-realm 下。其余高权限角色在任何模式下都不授予。
grant_manage_realm="${JJD_IDENTITY_RUNTIME_GRANT_MANAGE_REALM:-}"
[ -n "$grant_manage_realm" ] || grant_manage_realm="$(read_env_value JJD_IDENTITY_RUNTIME_GRANT_MANAGE_REALM)"
case "$(printf '%s' "$grant_manage_realm" | tr '[:upper:]' '[:lower:]')" in
  1|true|yes|on) grant_manage_realm=1 ;;
  *) grant_manage_realm=0 ;;
esac
allowed_roles="manage-identity-providers view-realm manage-users"
forbidden_roles="realm-admin manage-realm view-users manage-clients"
if [ "$grant_manage_realm" = "1" ]; then
  allowed_roles="$allowed_roles manage-realm"
  forbidden_roles="realm-admin view-users manage-clients"
  echo "[warn] 已按 JJD_IDENTITY_RUNTIME_GRANT_MANAGE_REALM=1 授予 manage-realm（用于身份源首次登录资料页设置）" >&2
fi

# 先移除任何历史遗留高权限，再只绑定身份源与本地用户生命周期所需的最小权限。
for forbidden_role in $forbidden_roles; do
  kcadm remove-roles -r "$RUNTIME_REALM" --uid "$service_account_id" \
    --cclientid realm-management --rolename "$forbidden_role" >/dev/null 2>&1 || true
done
for allowed_role in $allowed_roles; do
  kcadm add-roles -r "$RUNTIME_REALM" --uid "$service_account_id" \
    --cclientid realm-management --rolename "$allowed_role" >/dev/null ||
    fail "无法绑定运行态最小权限"
done

assigned_roles="$(kcadm get "users/$service_account_id/role-mappings/clients/$management_id" -r "$RUNTIME_REALM")" ||
  fail "无法复核运行态权限"
for allowed_role in $allowed_roles; do
  printf '%s' "$assigned_roles" | grep -Eq "\"name\"[[:space:]]*:[[:space:]]*\"${allowed_role}\"" ||
    fail "运行态最小权限不完整"
done
for forbidden_role in $forbidden_roles; do
  if printf '%s' "$assigned_roles" | grep -Eq "\"name\"[[:space:]]*:[[:space:]]*\"${forbidden_role}\""; then
    fail "运行态服务账号仍持有越界权限"
  fi
done

secret_json="$(kcadm get "clients/$client_uuid/client-secret" -r "$RUNTIME_REALM")" ||
  fail "无法读取运行态 client secret"
runtime_secret="$(printf '%s' "$secret_json" | json_field value)"
if [ -z "$runtime_secret" ]; then
  kcadm create "clients/$client_uuid/client-secret" -r "$RUNTIME_REALM" >/dev/null ||
    fail "无法生成运行态 client secret"
  secret_json="$(kcadm get "clients/$client_uuid/client-secret" -r "$RUNTIME_REALM")"
  runtime_secret="$(printf '%s' "$secret_json" | json_field value)"
fi
[ -n "$runtime_secret" ] || fail "运行态 client secret 为空"
case "$runtime_secret" in
  *[!A-Za-z0-9._~+/=-]*) fail "运行态 client secret 格式非法" ;;
esac

# 文件存在不等于凭据可用。用刚读取的最小权限 client 做一次真实认证与
# realm 读取，确认 secret、账号状态和角色授权一致；所有输出均丢弃。
kcadm config credentials \
  --server http://localhost:8180/sso \
  --realm "$RUNTIME_REALM" \
  --client "$RUNTIME_CLIENT_ID" \
  --secret "$runtime_secret" >/dev/null 2>&1 ||
  fail "身份运行态服务账号认证失败"
kcadm get "realms/$RUNTIME_REALM" --fields realm,enabled >/dev/null 2>&1 ||
  fail "身份运行态服务账号权限校验失败"

mkdir -p "$(dirname "$IDENTITY_RUNTIME_ENV_FILE")"
umask 077
tmp_file="$(mktemp "${IDENTITY_RUNTIME_ENV_FILE}.tmp.XXXXXX")"
if [ -f "$IDENTITY_RUNTIME_ENV_FILE" ]; then
  grep -Ev '^JJD_SSO_(PUBLIC_URL|ALLOW_INSECURE_PUBLIC_URL)=|^JJD_IDENTITY_RUNTIME_(URL|CLIENT_ID|CLIENT_SECRET)=' "$IDENTITY_RUNTIME_ENV_FILE" >"$tmp_file" || true
fi
{
  printf 'JJD_SSO_PUBLIC_URL=%s\n' "$public_url"
  printf 'JJD_IDENTITY_RUNTIME_URL=%s\n' "$RUNTIME_URL"
  printf 'JJD_IDENTITY_RUNTIME_CLIENT_ID=%s\n' "$RUNTIME_CLIENT_ID"
  printf 'JJD_IDENTITY_RUNTIME_CLIENT_SECRET=%s\n' "$runtime_secret"
  printf 'JJD_SSO_ALLOW_INSECURE_PUBLIC_URL=%s\n' "$allow_insecure"
} >>"$tmp_file"
chmod 600 "$tmp_file"
if [ "$(id -u)" -eq 0 ]; then
  chown 0:0 "$tmp_file"
fi
mv -f "$tmp_file" "$IDENTITY_RUNTIME_ENV_FILE"
tmp_file=""

echo "[ok] JJDGuard 身份运行态最小权限凭据已就绪"
