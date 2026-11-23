#!/usr/bin/env bash
# 使用假的 kcadm 锁定最小权限服务账号引导合约；不需要 Docker 或网络。

set -euo pipefail

ROOT_DIR="$(CDPATH= cd -- "$(dirname "$0")/../../.." && pwd)"
SCRIPT="$ROOT_DIR/deploy/docker-compose/chat/bootstrap-identity-runtime.sh"
REALM_FILE="$ROOT_DIR/deploy/docker-compose/chat/keycloak-realm/realm-jjdguard.json"

fail() { echo "FAIL: $*" >&2; exit 1; }
ok() { echo "ok: $*"; }

[ -x "$SCRIPT" ] || fail "缺少可执行 bootstrap-identity-runtime.sh"
[ -f "$REALM_FILE" ] || fail "缺少 realm-jjdguard.json"
! grep -Fq 'python3' "$SCRIPT" || fail "客户身份引导不得依赖宿主机 Python"

fixture="$(mktemp -d)"
trap 'rm -rf "$fixture"' EXIT
actions="$fixture/actions.log"
state="$fixture/client-created"
runtime_env="$fixture/identity-runtime.env"
scope_dir="$fixture/scopes"

fake="$fixture/kcadm"
profile_file="$fixture/profile.json"
printf '%s\n' '{"attributes":[{"name":"username"},{"name":"department"}],"groups":[]}' >"$profile_file"
cat >"$fake" <<'FAKE'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >>"$FAKE_ACTIONS"
mkdir -p "$FAKE_SCOPE_DIR"

case "$*" in
  "update authentication/required-actions/VERIFY_PROFILE -r jjdguard -s enabled=false -s defaultAction=false")
    ;;
  "config credentials"*)
    exit 0
    ;;
	"get users/profile -r jjdguard")
	  cat "$FAKE_PROFILE"
	  ;;
	"update users/profile -r jjdguard -f -")
	  cat >"$FAKE_PROFILE"
	  ;;

  "get clients -r jjdguard -q clientId=enterprise-ai-portal --fields id")
    printf '[{"id":"portal-client-id"}]\n'
    ;;
  "get clients -r jjdguard -q clientId=chat-portal-admin --fields id")
    printf '[{"id":"portal-admin-client-id"}]\n'
    ;;
  "get client-scopes -r jjdguard --fields id,name --format csv --noquotes")
    printf 'groups-scope-id,groups\n'
    if [ -f "$FAKE_SCOPE_DIR/profile" ]; then
      printf 'profile-scope-id,profile\n'
    fi
    if [ -f "$FAKE_SCOPE_DIR/email" ]; then
      printf 'email-scope-id,email\n'
    fi
    ;;
  "update clients/portal-client-id/optional-client-scopes/groups-scope-id -r jjdguard")
    ;;
  "create client-scopes -r jjdguard -s name=profile"*)
    : >"$FAKE_SCOPE_DIR/profile"
    printf 'profile-scope-id\n'
    ;;
  "create client-scopes -r jjdguard -s name=email"*)
    : >"$FAKE_SCOPE_DIR/email"
    printf 'email-scope-id\n'
    ;;
  "get client-scopes/profile-scope-id/protocol-mappers/models -r jjdguard")
    printf '['
    [ -f "$FAKE_SCOPE_DIR/profile-username" ] && printf '{"name":"username"}'
    [ -f "$FAKE_SCOPE_DIR/profile-full-name" ] && printf '{"name":"full name"}'
    printf ']\n'
    ;;
  "get client-scopes/email-scope-id/protocol-mappers/models -r jjdguard")
    printf '['
    [ -f "$FAKE_SCOPE_DIR/email-email" ] && printf '{"name":"email"}'
    [ -f "$FAKE_SCOPE_DIR/email-email-verified" ] && printf '{"name":"email verified"}'
    printf ']\n'
    ;;
  "create client-scopes/profile-scope-id/protocol-mappers/models -r jjdguard"*)
    case "$*" in
      *'"name":"username"'*) : >"$FAKE_SCOPE_DIR/profile-username" ;;
      *'"name":"full name"'*) : >"$FAKE_SCOPE_DIR/profile-full-name" ;;
    esac
    ;;
  "create client-scopes/email-scope-id/protocol-mappers/models -r jjdguard"*)
    case "$*" in
      *'"name":"email verified"'*) : >"$FAKE_SCOPE_DIR/email-email-verified" ;;
      *'"name":"email"'*) : >"$FAKE_SCOPE_DIR/email-email" ;;
    esac
    ;;
  "update clients/portal-client-id/default-client-scopes/profile-scope-id -r jjdguard")
    ;;
  "update clients/portal-client-id/default-client-scopes/email-scope-id -r jjdguard")
    ;;
  "update clients/portal-client-id -r jjdguard"*)
    printf '%s\n' "$*" >>"$FAKE_ACTIONS.portal-client-reconcile"
    ;;
  "update clients/portal-admin-client-id -r jjdguard"*)
    printf '%s\n' "$*" >>"$FAKE_ACTIONS.portal-admin-reconcile"
    ;;
  "get clients -r jjdguard -q clientId=jjdguard-identity-orchestrator --fields id")
    if [ -f "$FAKE_STATE" ]; then
      printf '[{"id":"runtime-client-id"}]\n'
    else
      printf '[]\n'
    fi
    ;;
  "create clients -r jjdguard"*)
    : >"$FAKE_STATE"
    ;;
  "get clients/runtime-client-id/service-account-user -r jjdguard --fields id")
    printf '{"id":"service-account-id"}\n'
    ;;
  "get clients -r jjdguard -q clientId=realm-management --fields id")
    printf '[{"id":"realm-management-id"}]\n'
    ;;
  "get users/service-account-id/role-mappings/clients/realm-management-id -r jjdguard")
    if [ "${FAKE_GRANT_MANAGE_REALM:-}" = "1" ]; then
      printf '[{"name":"manage-identity-providers"},{"name":"view-realm"},{"name":"manage-users"},{"name":"manage-realm"}]\n'
    else
      printf '[{"name":"manage-identity-providers"},{"name":"view-realm"},{"name":"manage-users"}]\n'
    fi
    ;;
  "get clients/runtime-client-id/client-secret -r jjdguard")
    printf '{"value":"runtime-client-secret"}\n'
    ;;
esac
FAKE
chmod 700 "$fake"

run_bootstrap() {
  FAKE_ACTIONS="$actions" \
  FAKE_STATE="$state" \
  FAKE_SCOPE_DIR="$scope_dir" \
	  FAKE_PROFILE="$profile_file" \
  KCADM_BIN="$fake" \
  BOOTSTRAP_TEST_MODE=1 \
  KEYCLOAK_ADMIN_PASSWORD='bootstrap-password-must-not-leak' \
  JJD_SSO_PUBLIC_URL='https://sso.example.com' \
  CHAT_OIDC_HOST='10.0.0.9' \
  CHAT_UI_PORT='3100' \
  CHAT_ADMIN_PORT='8280' \
  CHAT_PORTAL_UI_OIDC_SECRET='portal-ui-secret-must-not-leak' \
  IDENTITY_RUNTIME_ENV_FILE="$runtime_env" \
    "$SCRIPT"
}

cat >"$runtime_env" <<'EOF'
DIRECTORY_RUNTIME_URL=http://chat-idp:8180/sso
DIRECTORY_RUNTIME_CLIENT_ID=jjdguard-directory-orchestrator
DIRECTORY_RUNTIME_CLIENT_SECRET=directory-client-secret
UNRELATED_RUNTIME_SETTING=keep-me
EOF
run_bootstrap
run_bootstrap

[ "$(grep -c '^create clients -r jjdguard ' "$actions")" -eq 1 ] ||
  fail "专用 client 未幂等创建"
[ "$(grep -c '^update clients/portal-client-id/optional-client-scopes/groups-scope-id -r jjdguard$' "$actions")" -eq 2 ] ||
  fail "两次引导都应幂等绑定门户 groups scope"

[ "$(grep -c '^update users/profile -r jjdguard -f -$' "$actions")" -eq 0 ] ||
  fail "客户安装不得通过宿主机 Python 重写 Chat 用户属性"
grep -Eq '"name"[[:space:]]*:[[:space:]]*"department"' "$profile_file" ||
  fail "department user profile 属性未写入"
for scope in profile email; do
  [ "$(grep -c "^create client-scopes -r jjdguard -s name=$scope " "$actions")" -eq 1 ] ||
    fail "$scope scope 应只创建一次"
  [ "$(grep -c "^update clients/portal-client-id/default-client-scopes/${scope}-scope-id -r jjdguard$" "$actions")" -eq 2 ] ||
    fail "两次引导都应幂等绑定门户 $scope 默认 scope"
done
[ "$(grep -c '^create client-scopes/profile-scope-id/protocol-mappers/models -r jjdguard ' "$actions")" -eq 2 ] ||
  fail "profile scope mapper 应只各创建一次"
[ "$(grep -c '^create client-scopes/email-scope-id/protocol-mappers/models -r jjdguard ' "$actions")" -eq 2 ] ||
  fail "email scope mapper 应只各创建一次"

grep -q 'create clients -r jjdguard .*clientId=jjdguard-identity-orchestrator' "$actions" ||
  fail "未创建专用运行态 client"
grep -q 'create clients -r jjdguard .*serviceAccountsEnabled=true' "$actions" ||
  fail "未开启 service account"

[ "$(grep -c '^add-roles ' "$actions")" -eq 6 ] ||
  fail "两次幂等执行应各绑定三个允许角色"
grep -q '^add-roles .*--rolename manage-identity-providers$' "$actions" ||
  fail "缺少 manage-identity-providers"
grep -q '^add-roles .*--rolename view-realm$' "$actions" ||
  fail "缺少 view-realm"
grep -q '^add-roles .*--rolename manage-users$' "$actions"
! grep '^add-roles ' "$actions" | grep -Eq -- '--rolename (realm-admin|manage-realm|view-users|manage-clients)$' ||
  fail "绑定了超出身份源编排范围的高权限角色"
grep -q '^config credentials --server http://localhost:8180/sso --realm jjdguard --client jjdguard-identity-orchestrator --secret runtime-client-secret$' "$actions" ||
  fail "未使用最小权限服务账号验证运行态凭据"
grep -q '^get realms/jjdguard --fields realm,enabled$' "$actions" ||
  fail "未验证运行态服务账号的实际权限"

[ "$(stat -c '%a' "$runtime_env" 2>/dev/null || stat -f '%Lp' "$runtime_env")" = "600" ] ||
  fail "运行态环境文件权限不是 0600"
grep -qx 'JJD_SSO_PUBLIC_URL=https://sso.example.com' "$runtime_env" || fail "缺少公开 SSO 地址"
grep -qx 'JJD_IDENTITY_RUNTIME_URL=http://chat-idp:8180/sso' "$runtime_env" || fail "缺少固定内网运行地址"
grep -qx 'JJD_IDENTITY_RUNTIME_CLIENT_ID=jjdguard-identity-orchestrator' "$runtime_env" || fail "缺少运行态 client id"
grep -qx 'JJD_IDENTITY_RUNTIME_CLIENT_SECRET=runtime-client-secret' "$runtime_env" || fail "缺少运行态 client secret"
! grep -q 'bootstrap-password-must-not-leak' "$runtime_env" || fail "bootstrap 密码泄漏到 control-plane 环境文件"
grep -qx 'DIRECTORY_RUNTIME_URL=http://chat-idp:8180/sso' "$runtime_env" || fail "身份引导覆盖了目录运行态地址"
grep -qx 'DIRECTORY_RUNTIME_CLIENT_ID=jjdguard-directory-orchestrator' "$runtime_env" || fail "身份引导覆盖了目录运行态 client id"
grep -qx 'DIRECTORY_RUNTIME_CLIENT_SECRET=directory-client-secret' "$runtime_env" || fail "身份引导覆盖了目录运行态 client secret"
grep -qx 'UNRELATED_RUNTIME_SETTING=keep-me' "$runtime_env" || fail "身份引导未保留其他运行态配置"

# 门户 client 的可达性配置必须每次幂等对账。
# 首装 --import-realm 只在 realm 不存在时注入这些值：公开地址变更或 secret
# 轮换之后，realm 里留的是旧值 —— 现场就是因此只能手工校准 client secret。
portal_reconcile="$actions.portal-client-reconcile"
[ -s "$portal_reconcile" ] || fail "未对账门户 client 的可达性配置"
[ "$(wc -l <"$portal_reconcile")" -eq 2 ] ||
  fail "两次引导都应各对账门户 client 一次（幂等）"
# 两个 provider 的回调都要在册，少一个就有一条登录路径打不通。
grep -q 'api/auth/callback/account-login' "$portal_reconcile" ||
  fail "门户 client 未登记 account-login 回调"
grep -q 'api/auth/callback/enterprise-sso' "$portal_reconcile" ||
  fail "门户 client 未登记 enterprise-sso 回调"
grep -q 'webOrigins=' "$portal_reconcile" ||
  fail "门户 client 未对账 webOrigins"
grep -q 'webOrigins=\["https://sso\.example\.com"\]' "$portal_reconcile" ||
  fail "门户 client webOrigins 不是统一公开 origin"
grep -q 'post.logout.redirect.uris' "$portal_reconcile" ||
  fail "门户 client 未对账登出回跳白名单"
grep -q 'secret=' "$portal_reconcile" ||
  fail "门户 client secret 未对账"
! grep -q 'bootstrap-password-must-not-leak' "$portal_reconcile" ||
  fail "bootstrap 密码泄漏到门户 client 对账参数"
# 回调挂在门户 UI 自己的 origin 上（浏览器登录后跳回门户，不是跳回身份引擎），
# 且绝不能是通配绑定地址 —— 现场坏的就是 callbackUrl=http://0.0.0.0:3100/。
grep -q 'https://sso\.example\.com/chat/api/auth/callback/account-login' "$portal_reconcile" ||
  fail "门户 client 回调未使用门户 UI origin"
grep -Fq 'post.logout.redirect.uris"=https://sso.example.com/chat##https://sso.example.com/chat/*' "$portal_reconcile" ||
  fail "门户 client 登出回跳未覆盖精确 /chat 与其子路径"
! grep -q '0\.0\.0\.0' "$portal_reconcile" ||
  fail "门户 client 回调写入了通配绑定地址"
portal_admin_reconcile="$actions.portal-admin-reconcile"
[ "$(wc -l <"$portal_admin_reconcile")" -eq 2 ] ||
  fail "两次引导都应各对账管理门户 client 一次（幂等）"
grep -q 'https://sso\.example\.com/portal/auth/callback' "$portal_admin_reconcile" ||
  fail "管理门户 client 回调未使用统一入口 /portal"
grep -q 'webOrigins=\["https://sso\.example\.com"\]' "$portal_admin_reconcile" ||
  fail "管理门户 client 未使用统一公开 origin"
# 没有显式公开地址时，bootstrap 必须调用统一解析器并持久化结果。
derived_env="$fixture/derived.env"
cat >"$derived_env" <<'EOF'
CHAT_OIDC_HOST=10.0.0.5
CHAT_IDP_PORT=8180
WEB_HTTPS_PORT=443
TLS_ENABLED=true
EOF
derived_actions="$fixture/derived-actions.log"
derived_state="$fixture/derived-client-created"
derived_runtime="$fixture/derived-identity-runtime.env"
JJD_SSO_PUBLIC_URL="" \
FAKE_ACTIONS="$derived_actions" \
FAKE_STATE="$derived_state" \
FAKE_SCOPE_DIR="$scope_dir" \
FAKE_PROFILE="$profile_file" \
KCADM_BIN="$fake" \
BOOTSTRAP_TEST_MODE=1 \
KEYCLOAK_ADMIN_PASSWORD='bootstrap-password-must-not-leak' \
JJD_ENV_FILE="$derived_env" \
CHAT_OIDC_HOST=10.0.0.5 \
CHAT_IDP_PORT=8180 \
IDENTITY_RUNTIME_ENV_FILE="$derived_runtime" \
  "$SCRIPT"
grep -qx 'JJD_SSO_PUBLIC_URL=https://10.0.0.5' "$derived_env" ||
  fail "缺少自动生成的公开 SSO 地址"
grep -qx 'JJD_SSO_ALLOW_INSECURE_PUBLIC_URL=false' "$derived_env" ||
  fail "自动生成的 HTTPS 地址未关闭不安全兼容模式"
grep -qx 'JJD_SSO_PUBLIC_URL=https://10.0.0.5' "$derived_runtime" ||
  fail "运行态环境未使用自动生成的公开 SSO 地址"

jq -e '.duplicateEmailsAllowed == true' "$REALM_FILE" >/dev/null ||
  fail "realm 必须允许同邮箱的不同稳定身份共存"
for standard_scope in profile email; do
  jq -e --arg scope "$standard_scope" '.clientScopes[] | select(.name == $scope and .protocol == "openid-connect")' "$REALM_FILE" >/dev/null ||
    fail "realm 缺少 $standard_scope client scope"
done
jq -e '.clients[] | select(.clientId == "enterprise-ai-portal") | .defaultClientScopes | index("profile") and index("email")' "$REALM_FILE" >/dev/null ||
  fail "门户 client 未登记 profile/email 默认 scope"
grep -q '"realm"[[:space:]]*:[[:space:]]*"jjdguard"' "$REALM_FILE" || fail "realm 不是 jjdguard"
grep -q '"clientId"[[:space:]]*:[[:space:]]*"enterprise-ai-portal"' "$REALM_FILE" || fail "缺少企业 AI 门户 client"
grep -q '"pkce.code.challenge.method"[[:space:]]*:[[:space:]]*"S256"' "$REALM_FILE" || fail "门户 client 未强制 PKCE S256"
grep -q '"name"[[:space:]]*:[[:space:]]*"department"' "$REALM_FILE" || fail "缺少 department mapper"
grep -q '"name"[[:space:]]*:[[:space:]]*"groups"' "$REALM_FILE" || fail "缺少 groups mapper"
grep -q '"secret"[[:space:]]*:[[:space:]]*"${CHAT_PORTAL_UI_OIDC_SECRET}"' "$REALM_FILE" || fail "realm 文件未使用环境变量密钥占位"
grep -q '"${PORTAL_UI_ACCOUNT_REDIRECT}"' "$REALM_FILE" || fail "门户 client 缺少账号登录回调"
grep -q '"${PORTAL_UI_SSO_REDIRECT}"' "$REALM_FILE" || fail "门户 client 缺少企业 SSO 回调"
jq -e '.clientScopes[] | select(.name == "groups" and .protocol == "openid-connect")' "$REALM_FILE" >/dev/null ||
  fail "realm 缺少 groups client scope"
jq -e '.clients[] | select(.clientId == "enterprise-ai-portal") | .optionalClientScopes | index("groups")' "$REALM_FILE" >/dev/null ||
  fail "门户 client 未登记 groups 可选 scope"
grep -Eq '"users"[[:space:]]*:[[:space:]]*\[[[:space:]]*\]' "$REALM_FILE" || fail "realm 文件不得预置用户"

# Existing realms must be reconciled on every bootstrap, not only at import.
[ "$(grep -Fc 'update authentication/required-actions/VERIFY_PROFILE -r jjdguard -s enabled=false -s defaultAction=false' "$actions")" -eq 2 ] ||
  fail "本地账号登录不应再次强制补填资料（包括已有 realm）"
jq -e '.requiredActions[] | select(.alias == "VERIFY_PROFILE" and .enabled == false and .defaultAction == false)' "$REALM_FILE" >/dev/null ||
  fail "全新安装必须关闭自动资料补填"
! grep -Fq 'update authentication/required-actions/UPDATE_PASSWORD' "$actions" ||
  fail "不能改变管理员要求的密码更新策略"
ok "身份运行态最小权限引导合约通过"

# 可选开关：JJD_IDENTITY_RUNTIME_GRANT_MANAGE_REALM=1 才授予 manage-realm，且仍不授予其他高权限角色。
# 默认（未设置）行为已由上方断言锁定：不绑定、会移除 manage-realm，并校验其不存在。
grep -Eq '^remove-roles .*--rolename manage-realm$' "$actions" ||
  fail "默认模式必须移除历史遗留的 manage-realm"
actions="$fixture/actions-grant.log"
: >"$actions"
FAKE_GRANT_MANAGE_REALM=1 JJD_IDENTITY_RUNTIME_GRANT_MANAGE_REALM=1 run_bootstrap 2>"$fixture/grant.stderr"
grep -q '^add-roles .*--rolename manage-realm$' "$actions" ||
  fail "开关开启时应授予 manage-realm"
for must in manage-identity-providers view-realm manage-users; do
  grep -q "^add-roles .*--rolename ${must}\$" "$actions" || fail "开关开启时仍应绑定 $must"
done
! grep '^add-roles ' "$actions" | grep -Eq -- '--rolename (realm-admin|view-users|manage-clients)$' ||
  fail "开关开启时也不得授予 manage-realm 以外的高权限角色"
! grep -Eq '^remove-roles .*--rolename manage-realm$' "$actions" ||
  fail "开关开启时不应再移除 manage-realm"
grep -q 'manage-realm' "$fixture/grant.stderr" || fail "开启开关时应有明确的权限提示"
! grep -q 'bootstrap-password-must-not-leak' "$fixture/grant.stderr" || fail "提示泄漏了密码"
# 值为 0/空 时与默认一致。
: >"$actions"
JJD_IDENTITY_RUNTIME_GRANT_MANAGE_REALM=0 run_bootstrap
! grep '^add-roles ' "$actions" | grep -q 'manage-realm' || fail "开关为 0 时不得授予 manage-realm"
ok "manage-realm 可选开关合约通过"
