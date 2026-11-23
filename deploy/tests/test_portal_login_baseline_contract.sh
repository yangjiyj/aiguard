#!/usr/bin/env bash
# W3 3.8 门户登录安全基线契约（决策 D7）：
#   1. 新装模板满足基线，且与脚本目标值、control-plane portalbaseline.Target 一致；
#   2. 升级流程只做只读检查（check --advisory），不自动修改 realm；
#   3. check 对旧 realm 报"门户登录安全基线未达标"、退出 3；读取失败退出 2；--advisory 恒 0；
#   4. apply 必须 --yes；HTTP 门户默认跳过 sslRequired；保留已有更严格的密码子句；
#   5. 已比基线更严格的值视为达标，不被放宽。
# 用假的 kcadm，不需要 Docker 或网络。
set -euo pipefail

ROOT_DIR="$(CDPATH= cd -- "$(dirname "$0")/../.." && pwd)"
SCRIPT="$ROOT_DIR/deploy/docker-compose/chat/portal-login-baseline.sh"
REALM_FILE="$ROOT_DIR/deploy/docker-compose/chat/keycloak-realm/realm-jjdguard.json"
GO_TARGET="$ROOT_DIR/apps/control-plane/internal/portalbaseline/baseline.go"

fail() { echo "[fail] $*" >&2; exit 1; }

[ -x "$SCRIPT" ] || fail "缺少可执行 portal-login-baseline.sh"
bash -n "$SCRIPT"
! grep -Fq 'python3' "$SCRIPT" || fail "门户基线脚本不得依赖宿主机 Python"

# ---- 1. 三处目标值一致 ----
json_value() {
  sed -n "s/^[[:space:]]*\"$1\"[[:space:]]*:[[:space:]]*\(.*\)$/\1/p" "$REALM_FILE" | head -n 1 |
    sed 's/,[[:space:]]*$//; s/^"//; s/"$//'
}
while IFS='|' read -r key target _mode; do
  [ -n "$key" ] || continue
  [ "$(json_value "$key")" = "$target" ] || fail "realm 模板 $key=$(json_value "$key")，脚本目标=$target"
  go_line="$(grep -F "\"$key\":" "$GO_TARGET" | head -n 1 | sed 's/^[^:]*:[[:space:]]*//; s/,[[:space:]]*$//')"
  case "$go_line" in "\"$target\""|"float64($target)"|"$target") ;; *) false ;; esac ||
    fail "portalbaseline.Target 与脚本目标不一致：$key=$target"
done < <(sed -n '/^BASELINE_ITEMS=(/,/^)/p' "$SCRIPT" | sed -n 's/^[[:space:]]*"\(.*\)"$/\1/p')
[ "$(json_value otpPolicyType)" = "totp" ] || fail "realm 模板缺少 TOTP OTP 策略"

# ---- 2. 升级流程只读 ----
for entry in upgrade-bundle.sh upgrade.sh; do
  f="$ROOT_DIR/deploy/docker-compose/$entry"
  grep -q 'portal-login-baseline.sh" check --advisory' "$f" || fail "$entry 未在升级后做门户基线只读检查"
  ! grep -q 'portal-login-baseline.sh" apply' "$f" || fail "$entry 不得自动收紧已装客户的门户配置（D7）"
done

# ---- 假 kcadm ----
fixture="$(mktemp -d)"
trap 'rm -rf "$fixture"' EXIT
fake="$fixture/kcadm"
cat >"$fake" <<'FAKE'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >>"$FAKE_ACTIONS"
case "$1" in
  config) [ "${FAKE_LOGIN_FAIL:-0}" = 1 ] && exit 1; exit 0 ;;
  get) cat "$FAKE_REALM" ;;
  update)
    shift 2
    while [ "$#" -gt 0 ]; do
      [ "$1" = "-s" ] || { shift; continue; }
      kv="$2"; k="${kv%%=*}"; v="${kv#*=}"
      case "$v" in true|false|[0-9]*) val="$v" ;; *) val="\"$v\"" ;; esac
      grep -v "^  \"$k\" :" "$FAKE_REALM" | sed '$d' >"$FAKE_REALM.new"
      sed -i '$s/$/,/' "$FAKE_REALM.new"
      printf '  "%s" : %s\n}\n' "$k" "$val" >>"$FAKE_REALM.new"
      mv "$FAKE_REALM.new" "$FAKE_REALM"
      shift 2
    done
    ;;
esac
FAKE
chmod 700 "$fake"

legacy_realm() {
  cat >"$fixture/realm.json" <<'JSON'
{
  "realm" : "jjdguard",
  "sslRequired" : "none",
  "bruteForceProtected" : true,
  "failureFactor" : 30,
  "passwordPolicy" : "specialChars(2)"
}
JSON
}

run() {
  FAKE_ACTIONS="$fixture/actions.log" FAKE_REALM="$fixture/realm.json" KCADM_BIN="$fake" \
    KEYCLOAK_ADMIN_PASSWORD='bootstrap-password-must-not-leak' JJD_ENV_FILE="$fixture/none.env" \
    JJD_SSO_PUBLIC_URL="${PUBLIC_URL:-https://sso.example.com}" FAKE_LOGIN_FAIL="${LOGIN_FAIL:-0}" \
    bash "$SCRIPT" "$@"
}

banner="$(sed -n 's/^NOT_MET_BANNER="\(.*\)"$/\1/p' "$SCRIPT")"
[ -n "$banner" ] || fail "缺少未达标提示文案"

# ---- 3. check ----
legacy_realm
set +e
out="$(run check 2>&1)"; rc=$?
set -e
[ "$rc" -eq 3 ] || fail "旧 realm check 应退出 3，实际 $rc"
printf '%s' "$out" | grep -Fq "$banner" || fail "check 未输出未达标提示"
printf '%s' "$out" | grep -q 'apply --yes' || fail "check 未给出一键收紧命令"
! printf '%s' "$out" | grep -q 'bootstrap-password-must-not-leak' || fail "check 泄露了管理员凭据"
! grep -q '^update ' "$fixture/actions.log" || fail "check 不得修改 realm"
run check --advisory >/dev/null || fail "--advisory 必须恒退出 0"
set +e
LOGIN_FAIL=1 run check >/dev/null 2>&1; rc=$?
set -e
[ "$rc" -eq 2 ] || fail "读取失败 check 应退出 2，实际 $rc"
LOGIN_FAIL=1 run check --advisory >/dev/null || fail "读取失败时 --advisory 也必须退出 0（不阻断升级）"

# ---- 4. apply ----
if run apply >/dev/null 2>&1; then fail "apply 未加 --yes 不得执行"; fi
! grep -q '^update ' "$fixture/actions.log" || fail "未确认的 apply 修改了 realm"

run apply --yes >"$fixture/apply.out" 2>&1 || { cat "$fixture/apply.out" >&2; fail "HTTPS 门户 apply 失败"; }
grep -q '"sslRequired" : "external"' "$fixture/realm.json" || fail "apply 未收紧 sslRequired"
grep -q '"failureFactor" : 5' "$fixture/realm.json" || fail "apply 未收紧 failureFactor"
grep -q 'passwordHistory(5)' "$fixture/realm.json" || fail "apply 未写入密码策略"
grep -q 'specialChars(2)' "$fixture/realm.json" || fail "apply 丢弃了客户已有的更严格密码子句"
run check >/dev/null || fail "apply 后 check 应达标"

legacy_realm
: >"$fixture/actions.log"
PUBLIC_URL='http://100.64.1.2:8180' run apply --yes >"$fixture/apply-http.out" 2>&1 ||
  { cat "$fixture/apply-http.out" >&2; fail "HTTP 门户 apply 失败"; }
grep -q '"sslRequired" : "none"' "$fixture/realm.json" || fail "HTTP 门户默认不得改 sslRequired（会锁死非内网登录）"
grep -q '已跳过：sslRequired' "$fixture/apply-http.out" || fail "HTTP 门户 apply 未说明跳过项"
grep -q '"failureFactor" : 5' "$fixture/realm.json" || fail "HTTP 门户 apply 未收紧其余项"
PUBLIC_URL='http://100.64.1.2:8180' run apply --yes --include-ssl >/dev/null 2>&1 || fail "--include-ssl apply 失败"
grep -q '"sslRequired" : "external"' "$fixture/realm.json" || fail "--include-ssl 未收紧 sslRequired"

# ---- 5. 更严格的值不被放宽 ----
cat >"$fixture/realm.json" <<'JSON'
{
  "realm" : "jjdguard",
  "sslRequired" : "external",
  "bruteForceProtected" : true,
  "permanentLockout" : false,
  "failureFactor" : 3,
  "waitIncrementSeconds" : 3600,
  "maxFailureWaitSeconds" : 3600,
  "maxDeltaTimeSeconds" : 3600,
  "passwordPolicy" : "length(12) and upperCase(1) and lowerCase(1) and digits(1) and notUsername(undefined) and passwordHistory(5) and specialChars(1)",
  "ssoSessionIdleTimeout" : 900,
  "ssoSessionMaxLifespan" : 28800
}
JSON
: >"$fixture/actions.log"
run check >/dev/null || fail "更严格的 realm 应判定达标"
run apply --yes >/dev/null || fail "达标 realm apply 应直接成功"
! grep -q '^update ' "$fixture/actions.log" || fail "达标 realm 不得被 apply 修改"

echo '[ok] portal login baseline: template/target aligned, upgrade read-only, apply confirmed and non-loosening'
