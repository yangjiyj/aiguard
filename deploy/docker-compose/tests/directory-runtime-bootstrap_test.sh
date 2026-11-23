#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(CDPATH= cd -- "$(dirname "$0")/../../.." && pwd)"
SCRIPT="$ROOT_DIR/deploy/docker-compose/chat/bootstrap-directory-runtime.sh"

fail() {
  echo "FAIL: $*" >&2
  exit 1
}

[ -x "$SCRIPT" ] || fail "缺少可执行 bootstrap-directory-runtime.sh"

fixture="$(mktemp -d)"
trap 'rm -rf "$fixture"' EXIT
actions="$fixture/actions.log"
state="$fixture/client-created"
runtime_env="$fixture/identity-runtime.env"
printf '%s\n' \
  'JJD_SSO_PUBLIC_URL=https://sso.example.com' \
  'JJD_IDENTITY_RUNTIME_CLIENT_ID=jjdguard-identity-orchestrator' >"$runtime_env"
chmod 600 "$runtime_env"

fake="$fixture/kcadm"
cat >"$fake" <<'FAKE'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >>"$FAKE_ACTIONS"

case "$*" in
  "config credentials"*)
    exit 0
    ;;
  "get clients -r jjdguard -q clientId=jjdguard-directory-orchestrator --fields id")
    if [ -f "$FAKE_STATE" ]; then
      printf '[{"id":"directory-client-id"}]\n'
    else
      printf '[]\n'
    fi
    ;;
  "create clients -r jjdguard"*)
    : >"$FAKE_STATE"
    ;;
  "get clients/directory-client-id/service-account-user -r jjdguard --fields id")
    printf '{"id":"directory-service-account-id"}\n'
    ;;
  "get clients -r jjdguard -q clientId=realm-management --fields id")
    printf '[{"id":"realm-management-id"}]\n'
    ;;
  "get users/directory-service-account-id/role-mappings/clients/realm-management-id -r jjdguard")
    printf '[{"name":"view-realm"},{"name":"manage-realm"},{"name":"manage-users"}]\n'
    ;;
  "get clients/directory-client-id/client-secret -r jjdguard")
    printf '{"value":"directory-runtime-secret"}\n'
    ;;
esac
FAKE
chmod 700 "$fake"

run_bootstrap() {
  FAKE_ACTIONS="$actions" \
  FAKE_STATE="$state" \
  KCADM_BIN="$fake" \
  BOOTSTRAP_TEST_MODE=1 \
  KEYCLOAK_ADMIN_PASSWORD='bootstrap-password-must-not-leak' \
  IDENTITY_RUNTIME_ENV_FILE="$runtime_env" \
    "$SCRIPT"
}

run_bootstrap
run_bootstrap

[ "$(grep -c '^create clients -r jjdguard ' "$actions")" -eq 1 ] ||
  fail "目录运行态 client 未幂等创建"
grep -q 'create clients -r jjdguard .*clientId=jjdguard-directory-orchestrator' "$actions" ||
  fail "未创建目录运行态 client"
grep -q 'create clients -r jjdguard .*serviceAccountsEnabled=true' "$actions" ||
  fail "目录运行态未开启 service account"

[ "$(grep -c '^add-roles ' "$actions")" -eq 6 ] ||
  fail "两次幂等执行应各绑定三个允许角色"
for role in view-realm manage-realm manage-users; do
  grep -q "^add-roles .*--rolename ${role}$" "$actions" ||
    fail "缺少目录运行态角色 $role"
done
! grep '^add-roles ' "$actions" | grep -Eq -- '--rolename (realm-admin|manage-identity-providers|manage-clients)$' ||
  fail "目录运行态绑定了越界角色"

[ "$(stat -c '%a' "$runtime_env" 2>/dev/null || stat -f '%Lp' "$runtime_env")" = "600" ] ||
  fail "运行态环境文件权限不是 0600"
grep -qx 'JJD_SSO_PUBLIC_URL=https://sso.example.com' "$runtime_env" ||
  fail "覆盖了既有身份运行态配置"
grep -qx 'DIRECTORY_RUNTIME_URL=http://chat-idp:8180/sso' "$runtime_env" ||
  fail "缺少目录运行态 URL"
grep -qx 'DIRECTORY_RUNTIME_CLIENT_ID=jjdguard-directory-orchestrator' "$runtime_env" ||
  fail "缺少目录运行态 client id"
grep -qx 'DIRECTORY_RUNTIME_CLIENT_SECRET=directory-runtime-secret' "$runtime_env" ||
  fail "缺少目录运行态 client secret"
! grep -q 'bootstrap-password-must-not-leak' "$runtime_env" ||
  fail "bootstrap 密码泄漏到运行态环境文件"

echo "ok: 目录运行态最小权限引导合约通过"
