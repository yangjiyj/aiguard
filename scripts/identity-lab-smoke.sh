#!/usr/bin/env bash
# identity-lab smoke — 验证三套身份源 + 本地身份运行服务 + 10 个企业身份验收点
#
# 默认模式（不带参数）：尝试对已启动的 lab 容器做端到端检查（完整模式要求全部服务健康并执行真实验收）。
# --check-only：只做静态/config/依赖齐全性检查，不启动容器，不连服务（任务 13 强制要求此模式通过）。
#
# 安全红线：
#   - 永不把口令/token 写到 stdout/stderr（验收脚本输出绝不泄密）
#   - --check-only 不读 .env（只验证模板与 schema），不要求任何凭据
#   - 失败立即退出（set -eu），不给假绿
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
LAB_DIR="${IDENTITY_LAB_CONFIG_DIR:-$REPO_ROOT/deploy/identity-lab}"
COMPOSE_FILE="$LAB_DIR/docker-compose.identity-lab.yml"
LDAP_LDIF="$LAB_DIR/openldap/bootstrap.ldif"
SMB_PROVISION="$LAB_DIR/samba/provision.sh"
ENTERPRISE_REALM="$LAB_DIR/keycloak/enterprise-realm.json"
JJDGUARD_REALM="$LAB_DIR/keycloak/jjdguard-realm.json"
ENV_EXAMPLE="$LAB_DIR/.env.example"

CHECK_ONLY=0
for arg in "$@"; do
  case "$arg" in
    --check-only) CHECK_ONLY=1 ;;
    -h|--help) sed -n '2,15p' "$0"; exit 0 ;;
    *) echo "unknown arg: $arg" >&2; exit 2 ;;
  esac
done

say_ok()   { [ "$CHECK_ONLY" -eq 0 ] || printf '  \033[32mOK\033[0m   %s\n' "$1"; }
say_fail() { printf '  \033[31mFAIL\033[0m %s\n' "$1" >&2; }
section()  { [ "$CHECK_ONLY" -eq 0 ] || printf '\n=== %s ===\n' "$1"; }

FAIL_COUNT=0
assert_file() {
  local f="$1" desc="$2"
  if [ -s "$f" ]; then say_ok "$desc"; else say_fail "$desc 缺失或空: $f"; FAIL_COUNT=$((FAIL_COUNT+1)); fi
}
assert_grep() {
  local pattern="$1" file="$2" desc="$3"
  if grep -Eq "$pattern" "$file" 2>/dev/null; then say_ok "$desc"; else say_fail "$desc ($pattern in $file)"; FAIL_COUNT=$((FAIL_COUNT+1)); fi
}
assert_py() {
  local file="$1" expr="$2" desc="$3"
  if python3 -c "import json,sys; d=json.load(open(sys.argv[1])); $expr" "$file" >/dev/null 2>&1; then
    say_ok "$desc"
  else
    say_fail "$desc"; FAIL_COUNT=$((FAIL_COUNT+1))
  fi
}

section "Phase 0：静态检查（不启动容器）"
bash -n "$0" 2>/dev/null && say_ok "smoke 脚本自身语法" || { say_fail "smoke 脚本语法"; FAIL_COUNT=$((FAIL_COUNT+1)); }

assert_file "$COMPOSE_FILE" "compose 文件"
assert_file "$LDAP_LDIF" "OpenLDAP bootstrap LDIF"
assert_file "$SMB_PROVISION" "Samba AD provision 脚本"
assert_file "$ENTERPRISE_REALM" "enterprise Keycloak realm"
assert_file "$JJDGUARD_REALM" "jjdguard Keycloak realm"
assert_file "$ENV_EXAMPLE" ".env.example 模板"

if bash -n "$SMB_PROVISION" 2>/dev/null; then say_ok "samba/provision.sh 语法"; else say_fail "samba/provision.sh 语法"; FAIL_COUNT=$((FAIL_COUNT+1)); fi

if python3 -c "import json; json.load(open('$ENTERPRISE_REALM'))" 2>/dev/null; then say_ok "enterprise-realm.json 合法 JSON"; else say_fail "enterprise-realm.json 非法 JSON"; FAIL_COUNT=$((FAIL_COUNT+1)); fi
if python3 -c "import json; json.load(open('$JJDGUARD_REALM'))" 2>/dev/null; then say_ok "jjdguard-realm.json 合法 JSON"; else say_fail "jjdguard-realm.json 非法 JSON"; FAIL_COUNT=$((FAIL_COUNT+1)); fi

section "Phase 1：docker compose config 验证"
if [ "$CHECK_ONLY" -eq 1 ]; then
  ENV_FILE="$ENV_EXAMPLE"
else
  ENV_FILE="${IDENTITY_LAB_ENV_FILE:-$LAB_DIR/.env}"
fi
[ -f "$ENV_FILE" ] || { say_fail "identity-lab env file is missing"; exit 1; }
export IDENTITY_LAB_ENV_FILE="$ENV_FILE"

if docker compose -f "$COMPOSE_FILE" --env-file "$ENV_FILE" config >/dev/null 2>&1; then
  say_ok "docker compose config 通过"
else
  say_fail "docker compose config 失败"; FAIL_COUNT=$((FAIL_COUNT+1))
fi

for svc in openldap samba-ad enterprise-keycloak jjdguard-keycloak; do
  assert_grep "^  $svc:" "$COMPOSE_FILE" "compose 声明服务 $svc"
done

section "Phase 2：10 验收点配置完整性（--check-only 范围内）"

# AP1 本地账号默认可登录 Chat
assert_py "$JJDGUARD_REALM" "assert any(u.get('username')=='local-alice' and u.get('enabled') for u in d['users'])" "AP1 本地账号 local-alice enabled"
assert_py "$JJDGUARD_REALM" "assert any(c.get('clientId')=='enterprise-ai-portal' for c in d['clients'])" "AP1 OIDC client enterprise-ai-portal（account-login/enterprise-sso 共用）"

# AP2 LDAP 用户走账号登录
assert_py "$JJDGUARD_REALM" "assert any(comp.get('name')=='jjdguard-directory' for comp in d['components']['org.keycloak.storage.UserStorageProvider'])" "AP2 LDAP federation 组件"
assert_grep "ldaps://openldap:636" "$JJDGUARD_REALM" "AP2 LDAP federation connectionUrl"

# AP3 AD 用户走账号登录
assert_py "$JJDGUARD_REALM" "assert any(comp.get('name')=='ad-federation' and comp['config'].get('vendor')==['ad'] for comp in d['components']['org.keycloak.storage.UserStorageProvider'])" "AP3 AD federation 组件 vendor=ad"
assert_grep "ldaps://samba-ad:636" "$JJDGUARD_REALM" "AP3 AD federation connectionUrl"

# AP4 外部 OIDC 用户走企业 SSO 登录（broker alias=enterprise）
assert_py "$JJDGUARD_REALM" "assert any(idp.get('alias')=='enterprise' and idp.get('providerId')=='oidc' and idp.get('enabled') for idp in d['identityProviders'])" "AP4 enterprise broker enabled"
assert_grep "realms/enterprise/protocol/openid-connect/auth" "$JJDGUARD_REALM" "AP4 broker 指向 enterprise authorize"

# AP5 同邮箱不同 subject 不合并（LDAP carol vs enterprise oidc-carol 同邮箱）
assert_grep "mail: oidc-carol@jjdguard-lab.test" "$LDAP_LDIF" "AP5 LDAP 侧 oidc-carol 邮箱"
assert_py "$ENTERPRISE_REALM" "assert any(u.get('username')=='oidc-carol' and u.get('email')=='oidc-carol@jjdguard-lab.test' for u in d['users'])" "AP5 enterprise 侧同邮箱 oidc-carol"
# 两 issuer（jjdguard-directory vs enterprise broker）→ 稳定键不同，由 portal-identity.ts 保证不合并

# AP6 未映射用户无模型权限（local-admin 不在 dept-* 组）
assert_py "$JJDGUARD_REALM" "assert any(u.get('username')=='local-admin-jjdguard' for u in d['users'])" "AP6 未映射用户 local-admin-jjdguard"
assert_grep "cn=dept-" "$LDAP_LDIF" "AP6 dept 组限于目录源（本地账号不在 dept-* 内）"

# AP7 映射后获得对应部门模型
assert_grep "cn=dept-research" "$LDAP_LDIF" "AP7 dept-research 组（ldap-alice 成员）"
assert_grep "lab-research-model" "$LDAP_LDIF" "AP7 部门→模型映射注释"

# AP8 迁移部门后旧模型权限立即撤销
assert_py "$JJDGUARD_REALM" "assert any(idp.get('alias')=='enterprise' and idp['config'].get('syncMode')=='FORCE' for idp in d['identityProviders'])" "AP8 broker syncMode=FORCE"
assert_grep "cn=dept-marketing" "$LDAP_LDIF" "AP8 迁移目标组 dept-marketing"

# AP9 禁用目录用户登录失败
assert_grep "ou=Disabled" "$LDAP_LDIF" "AP9 LDAP Disabled OU"
assert_grep "uid=ldap-dave,ou=Disabled" "$LDAP_LDIF" "AP9 禁用用户 ldap-dave"
assert_py "$JJDGUARD_REALM" "assert any(comp.get('name')=='jjdguard-directory' and comp['config'].get('cachePolicy')==['NO_CACHE'] for comp in d['components']['org.keycloak.storage.UserStorageProvider'])" "AP9 LDAP cachePolicy=NO_CACHE"
assert_grep "user disable" "$SMB_PROVISION" "AP9 Samba 禁用用户操作"
assert_py "$ENTERPRISE_REALM" "assert any(u.get('username')=='enterprise-frank' and u.get('enabled')==False for u in d['users'])" "AP9 外部 IdP 禁用用户 enterprise-frank"

# AP10 两个管理卡片独立启停（federation/broker 各自独立 component）
assert_py "$JJDGUARD_REALM" "assert all(any(comp.get('name')==n for comp in d['components']['org.keycloak.storage.UserStorageProvider']) for n in ['jjdguard-directory','ad-federation'])" "AP10 LDAP/AD federation 各自独立 component"
assert_py "$JJDGUARD_REALM" "assert any(idp.get('alias')=='enterprise' for idp in d['identityProviders'])" "AP10 broker enterprise 独立 identityProvider"

section "Phase 3：安全红线"
for realm in "$JJDGUARD_REALM" "$ENTERPRISE_REALM"; do
  if python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); values=[c.get("value","") for u in d.get("users",[]) for c in u.get("credentials",[])]+[c.get("secret","") for c in d.get("clients",[]) if "secret" in c]; assert all(isinstance(v,str) and v.startswith("${") and v.endswith("}") for v in values)' "$realm" >/dev/null 2>&1; then
    :
  else
    say_fail "realm.json suspected secret (category: realm configuration)"; FAIL_COUNT=$((FAIL_COUNT+1))
  fi
done
assert_grep "lab-only|不可用于生产|never use in production" "$ENV_EXAMPLE" ".env.example 标注 lab-only/不可用于生产"

if awk '/^userPassword:/ && $0 !~ /^userPassword:: __LDAP_[A-Z]+_PASSWORD_B64__$/ {exit 1}' "$LDAP_LDIF" &&
   [ "$(grep -Ec '^userPassword:: __LDAP_[A-Z]+_PASSWORD_B64__$' "$LDAP_LDIF")" -eq 4 ] &&
   grep -Fq 'AD_BOB_PASSWORD=${AD_BOB_PASSWORD:?' "$SMB_PROVISION" &&
   grep -Fq 'AD_DISABLED_PASSWORD=${AD_DISABLED_PASSWORD:?' "$SMB_PROVISION" &&
   ! grep -Eq 'user create [^[:space:]]+ [^"$]' "$SMB_PROVISION"; then
  say_ok "directory seed credential scan"
else
  say_fail "directory seed suspected credential (category: LDIF/provision)"; FAIL_COUNT=$((FAIL_COUNT+1))
fi

section "Phase 4：依赖与运行态"
if command -v docker >/dev/null 2>&1; then say_ok "docker CLI 可用"; else say_fail "docker CLI 缺失"; FAIL_COUNT=$((FAIL_COUNT+1)); fi
if command -v python3 >/dev/null 2>&1; then say_ok "python3 可用"; else say_fail "python3 缺失"; FAIL_COUNT=$((FAIL_COUNT+1)); fi

if [ "$CHECK_ONLY" -eq 1 ]; then
  say_ok "--check-only: runtime acceptance intentionally skipped"
  if [ "$FAIL_COUNT" -eq 0 ]; then
    printf '\033[32mALL CHECKS PASSED\033[0m (check-only mode)\n'
    exit 0
  fi
  printf '\033[31m%d FAILED\033[0m\n' "$FAIL_COUNT"
  exit 1
fi

if [ "$FAIL_COUNT" -ne 0 ]; then
  printf '\033[31m%d FAILED\033[0m\n' "$FAIL_COUNT" >&2
  exit 1
fi
"$SCRIPT_DIR/identity-lab-wait.sh"
exec "$SCRIPT_DIR/identity-lab-runtime-acceptance.sh"
