#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(CDPATH= cd -- "$(dirname "$0")/../../.." && pwd)"
SIM_DIR="$ROOT_DIR/deploy/docker-compose/directory-sim"
SIM_COMPOSE="$SIM_DIR/docker-compose.yml"
OVERRIDE="$SIM_DIR/jjdguard-home.override.yml"
BOOTSTRAP="$SIM_DIR/bootstrap-home-identity-test.sh"
VERIFY="$SIM_DIR/verify-home-identity-test.sh"
UPSTREAM_REALM="$SIM_DIR/realm-enterprise-test.json"
DEPLOY_OFFLINE="$ROOT_DIR/deploy/docker-compose/deploy-offline.sh"
UPGRADE="$ROOT_DIR/deploy/docker-compose/upgrade.sh"
PUBLIC_URL_HELPER="$ROOT_DIR/deploy/docker-compose/chat/ensure-public-sso-url.sh"

fail() {
  echo "FAIL: $*" >&2
  exit 1
}

has() {
  local file="$1"
  local pattern="$2"
  grep -Eq "$pattern" "$file" || fail "$file 缺少合约：$pattern"
}

[ -f "$SIM_COMPOSE" ] || fail "缺少 home 身份测试环境 compose"
[ -f "$OVERRIDE" ] || fail "缺少 JJDGuard home override"
[ -x "$BOOTSTRAP" ] || fail "缺少可执行的 home 身份环境引导脚本"
[ -x "$VERIFY" ] || fail "缺少可执行的 home 身份环境验证脚本"
[ -f "$UPSTREAM_REALM" ] || fail "缺少上游企业 SSO realm"
[ -x "$DEPLOY_OFFLINE" ] || fail "缺少可执行 deploy-offline.sh"
[ -x "$UPGRADE" ] || fail "缺少可执行 upgrade.sh"
[ -x "$PUBLIC_URL_HELPER" ] || fail "缺少公开 SSO 地址解析器"

has "$SIM_COMPOSE" 'givenName: Alice'
has "$SIM_COMPOSE" 'givenName: Bob'
has "$SIM_COMPOSE" 'givenName: Carol'

has "$OVERRIDE" 'DIRECTORY_LDAP_TARGET_ALLOWLIST'
has "$OVERRIDE" 'ldap-sim\.jjdguard\.test:636'
has "$OVERRIDE" 'dc-sim\.ad\.jjdguard\.test:636'
has "$OVERRIDE" '^  chat-idp:'
has "$OVERRIDE" 'DIRECTORY_LDAP_ALLOWED_CIDRS'
has "$OVERRIDE" '172\.30\.0\.0/24'
has "$OVERRIDE" 'JJD_IDP_ALLOW_CIDRS'
has "$OVERRIDE" '172\.30\.0\.20/32'

has "$BOOTSTRAP" 'umask 077'
has "$BOOTSTRAP" 'openssl rand'
has "$BOOTSTRAP" 'bootstrap-identity-runtime\.sh'
has "$BOOTSTRAP" 'bootstrap-directory-runtime\.sh'
has "$BOOTSTRAP" 'JJD_SSO_PUBLIC_URL='
has "$BOOTSTRAP" 'upsert_env_value "\$RUNTIME_ENV" JJD_SSO_PUBLIC_URL'
has "$BOOTSTRAP" 'upsert_env_value "\$RUNTIME_ENV" CHAT_OIDC_ISSUER'
has "$BOOTSTRAP" 'upsert_env_value "\$RUNTIME_ENV" CHAT_POSTGRES_PASSWORD'
has "$BOOTSTRAP" 'install -m 0644 "\$SOURCE_COMPOSE_DIR/chat/Caddyfile"'
has "$BOOTSTRAP" 'up -d --no-deps --force-recreate chat-edge'
has "$BOOTSTRAP" 'reconcile_portal_client_secret'
has "$BOOTSTRAP" 'reconcile_upstream_portal_client'
has "$BOOTSTRAP" 'clientId=enterprise-ai-portal'
has "$BOOTSTRAP" 'CHAT_PORTAL_UI_OIDC_SECRET'
has "$BOOTSTRAP" 'api/auth/callback/account-login'
has "$DEPLOY_OFFLINE" 'ensure-public-sso-url\.sh'
has "$UPGRADE" 'ensure-public-sso-url\.sh'
has "$UPGRADE" 'compose ps -q chat-idp'
has "$UPGRADE" 'bootstrap-identity-runtime\.sh'
has "$UPGRADE" 'force-recreate.*control-plane'
has "$BOOTSTRAP" 'api/auth/callback/enterprise-sso'
has "$BOOTSTRAP" 'redirectUris='
has "$BOOTSTRAP" 'client-scopes'
has "$BOOTSTRAP" 'optional-client-scopes'
has "$BOOTSTRAP" 'name=groups'
has "$BOOTSTRAP" '[\-][\-]format csv [\-][\-]noquotes'
has "$BOOTSTRAP" 'default-client-scopes'
has "$BOOTSTRAP" 'preferred username'
has "$BOOTSTRAP" 'post.logout.redirect.uris'
has "$BOOTSTRAP" 'logout_response'
has "$BOOTSTRAP" 'ensure_ad_tls_san'
has "$BOOTSTRAP" 'checkhost dc-sim.ad.jjdguard.test'
has "$BOOTSTRAP" 'verify_hostname dc-sim.ad.jjdguard.test'
has "$BOOTSTRAP" 'supervisorctl restart samba'
has "$BOOTSTRAP" '/etc/samba/external/jjdguard-tls/cert.pem'
has "$BOOTSTRAP" 'run_compose'
has "$BOOTSTRAP" 'sh "\$RUNTIME_COMPOSE_WRAPPER"'
has "$BOOTSTRAP" 'bash "\$SOURCE_COMPOSE_DIR/chat/bootstrap-identity-runtime.sh"'
has "$BOOTSTRAP" 'COMPOSE_FILE='
has "$BOOTSTRAP" 'COMPOSE_PROJECT_NAME='
has "$BOOTSTRAP" 'COMPOSE_ENV_FILES='
has "$BOOTSTRAP" 'samba-tool'
has "$BOOTSTRAP" 'ldappasswd'
has "$BOOTSTRAP" 'command -v jq'
has "$BOOTSTRAP" 'ldap-sim.jjdguard.test:636'

has "$VERIFY" 'openldap'
has "$VERIFY" 'active-directory'
has "$VERIFY" 'svc-jjdguard@ad\.jjdguard\.test'
has "$VERIFY" 'openid-configuration'
has "$VERIFY" 'curl.*--resolve'
has "$VERIFY" 'DIRECTORY_RUNTIME_CLIENT_ID'
has "$VERIFY" 'JJD_IDENTITY_RUNTIME_CLIENT_ID'

if grep -Eq 'Napi#|simulated-admin-only|Simulated-Domain-Admin-Only' "$OVERRIDE" "$BOOTSTRAP" "$VERIFY"; then
  fail "home 部署文件含明文测试凭据"
fi

if grep -Eq 'host-gateway' "$OVERRIDE"; then
  fail "OIDC 不得经 host-gateway 绕行"
fi

if grep -Eq '(^|[[:space:]])awk([[:space:]]|$)' "$BOOTSTRAP"; then
  fail "Keycloak 运行镜像不含 awk，bootstrap 不得依赖 awk"
fi

jq -e '.clientScopes[] | select(.name == "groups" and .protocol == "openid-connect")' "$UPSTREAM_REALM" >/dev/null ||
  fail "上游企业 SSO realm 缺少 groups client scope"
jq -e '.clients[] | select(.clientId == "jjdguard-enterprise-test") | .optionalClientScopes | index("groups")' "$UPSTREAM_REALM" >/dev/null ||
  fail "上游企业 SSO client 未登记 groups 可选 scope"

for scope in profile email; do
  jq -e --arg scope "$scope" '.clientScopes[] | select(.name == $scope and .protocol == "openid-connect")' "$UPSTREAM_REALM" >/dev/null ||
    fail "上游企业 SSO realm 缺少 $scope client scope"
  jq -e --arg scope "$scope" '.clients[] | select(.clientId == "jjdguard-enterprise-test") | .defaultClientScopes | index($scope)' "$UPSTREAM_REALM" >/dev/null ||
    fail "上游企业 SSO client 未默认启用 $scope scope"
done
jq -e '.clients[] | select(.clientId == "jjdguard-enterprise-test") | .attributes["post.logout.redirect.uris"] == "${JJDGUARD_ENTERPRISE_CALLBACK}/logout_response"' "$UPSTREAM_REALM" >/dev/null ||
  fail "上游企业 SSO client 退出回调不是 broker 精确 logout_response"
for mapper in "preferred username" email "full name"; do
  jq -e --arg mapper "$mapper" '.clients[] | select(.clientId == "jjdguard-enterprise-test") | .protocolMappers[] | select(.name == $mapper)' "$UPSTREAM_REALM" >/dev/null ||
    fail "上游企业 SSO client 缺少 $mapper mapper"
done

echo "ok: home 身份测试环境部署合约通过"
