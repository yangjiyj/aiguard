#!/usr/bin/env bash
# 门户登录安全基线（W3 3.8，决策 D7）。
#
# 新装：realm-jjdguard.json 模板已包含基线，首次导入即生效。
# 已装：升级不自动改 realm（--import-realm 只在 realm 不存在时导入），由本脚本只读检查并提示；
#       管理员确认后执行 apply --yes 一键收紧。
#
#   portal-login-baseline.sh check              只读比对；达标退出 0，未达标退出 3，无法读取退出 2
#   portal-login-baseline.sh check --advisory   升级流程用：只输出提示，恒退出 0
#   portal-login-baseline.sh apply --yes        收紧未达标项（已比基线更严格的项保持不变）
#
# 冲突：门户以 HTTP 对外（JJD_SSO_PUBLIC_URL=http://...）时，sslRequired=external 会让非内网来源
# （含 Tailscale 100.64.0.0/10）无法登录。apply 默认跳过该项并提示，确认已启用 HTTPS 后加 --include-ssl。
#
# 目标值与 deploy/docker-compose/chat/keycloak-realm/realm-jjdguard.json、
# apps/control-plane/internal/portalbaseline 保持一致（有契约测试）。

set -euo pipefail

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname "$0")" && pwd)"
COMPOSE_DIR="$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)"
COMPOSE_WRAPPER="${COMPOSE_WRAPPER:-$COMPOSE_DIR/compose-wrapper.sh}"
JJD_ENV_FILE="${JJD_ENV_FILE:-$COMPOSE_DIR/.env}"
REALM="jjdguard"
NOT_MET_BANNER="门户登录安全基线未达标"

# key|target|compare（eq 相等；le 不大于且大于 0 算达标；ge 不小于算达标；policy 子句全包含）
BASELINE_ITEMS=(
  "sslRequired|external|eq"
  "bruteForceProtected|true|eq"
  "permanentLockout|false|eq"
  "failureFactor|5|le"
  "waitIncrementSeconds|1800|ge"
  "maxFailureWaitSeconds|1800|ge"
  "maxDeltaTimeSeconds|1800|ge"
  "passwordPolicy|length(12) and upperCase(1) and lowerCase(1) and digits(1) and notUsername(undefined) and passwordHistory(5)|policy"
  "ssoSessionIdleTimeout|1800|le"
  "ssoSessionMaxLifespan|43200|le"
)

bootstrap_password=""
cleanup() { bootstrap_password=""; }
trap cleanup EXIT HUP INT TERM

fail() {
  echo "[error] $*" >&2
  exit 1
}

usage() {
  sed -n '8,10p' "$0" | sed 's/^# \{0,1\}//'
  exit 64
}

read_env_value() {
  local key="$1"
  [ -f "$JJD_ENV_FILE" ] || return 0
  sed -n "s/^${key}=//p" "$JJD_ENV_FILE" | tail -n 1
}

kcadm() {
  if [ -n "${KCADM_BIN:-}" ]; then
    "$KCADM_BIN" "$@"
    return
  fi
  sh "$COMPOSE_WRAPPER" exec -T chat-idp /opt/keycloak/bin/kcadm.sh "$@"
}

login_admin() {
  bootstrap_password="${KEYCLOAK_ADMIN_PASSWORD:-}"
  [ -n "$bootstrap_password" ] || bootstrap_password="$(read_env_value KEYCLOAK_ADMIN_PASSWORD)"
  [ -n "$bootstrap_password" ] || return 1
  kcadm config credentials \
    --server http://localhost:8180/sso \
    --realm master \
    --user "${KC_BOOTSTRAP_ADMIN_USERNAME:-admin}" \
    --password "$bootstrap_password" >/dev/null 2>&1
}

# 从 kcadm 输出的 realm JSON 中取顶层标量字段（字符串去引号；缺失输出空）。
realm_field() {
  local json="$1" key="$2"
  printf '%s\n' "$json" | awk -v k="\"$key\"" '
    index($0, k) {
      line = $0
      sub(/^[^:]*:[[:space:]]*/, "", line)
      sub(/,[[:space:]]*$/, "", line)
      if (line ~ /^"/) { sub(/^"/, "", line); sub(/"$/, "", line) }
      print line
      exit
    }'
}

policy_has_all() {
  local current="$1" target="$2" clause
  local IFS=$'\n'
  for clause in $(printf '%s\n' "$target" | sed 's/ and /\n/g'); do
    printf '%s\n' "$current" | sed 's/ and /\n/g' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//' | grep -Fxq "$clause" || return 1
  done
  return 0
}

# 合并密码策略：保留现有且不在目标中的子句类型（如 specialChars），目标子句覆盖同名类型。
merge_policy() {
  local current="$1" target="$2" clause name merged="$target"
  local IFS=$'\n'
  for clause in $(printf '%s\n' "$current" | sed 's/ and /\n/g' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//'); do
    [ -n "$clause" ] || continue
    name="${clause%%(*}"
    case " and $target" in
      *" and ${name}("*) ;;
      *) merged="$merged and $clause" ;;
    esac
  done
  printf '%s' "$merged"
}

item_compliant() {
  local current="$1" target="$2" mode="$3"
  case "$mode" in
    eq) [ "$current" = "$target" ] ;;
    le) [[ "$current" =~ ^[0-9]+$ ]] && [ "$current" -gt 0 ] && [ "$current" -le "$target" ] ;;
    ge) [[ "$current" =~ ^[0-9]+$ ]] && [ "$current" -ge "$target" ] ;;
    policy) policy_has_all "$current" "$target" ;;
    *) return 1 ;;
  esac
}

public_url_is_http() {
  local url="${JJD_SSO_PUBLIC_URL:-}"
  [ -n "$url" ] || url="$(read_env_value JJD_SSO_PUBLIC_URL)"
  case "$url" in http://*) return 0 ;; esac
  return 1
}

REALM_JSON=""
NOT_COMPLIANT=()

load_realm() {
  login_admin || return 1
  local fields="realm" item key
  for item in "${BASELINE_ITEMS[@]}"; do
    key="${item%%|*}"
    fields="$fields,$key"
  done
  REALM_JSON="$(kcadm get "realms/$REALM" --fields "$fields" 2>/dev/null)" || return 1
  [ -n "$(realm_field "$REALM_JSON" realm)" ] || return 1
}

evaluate() {
  local item key target mode current
  NOT_COMPLIANT=()
  for item in "${BASELINE_ITEMS[@]}"; do
    IFS='|' read -r key target mode <<<"$item"
    current="$(realm_field "$REALM_JSON" "$key")"
    if item_compliant "$current" "$target" "$mode"; then
      printf '  [达标]   %-22s 当前=%s\n' "$key" "${current:-<未设置>}"
    else
      printf '  [未达标] %-22s 当前=%s  目标=%s\n' "$key" "${current:-<未设置>}" "$target"
      NOT_COMPLIANT+=("$key")
    fi
  done
}

print_conflicts() {
  local key
  for key in "${NOT_COMPLIANT[@]}"; do
    if [ "$key" = "sslRequired" ] && public_url_is_http; then
      echo "  [冲突] 门户当前以 HTTP 对外，sslRequired=external 会让非内网来源（含 Tailscale）无法登录；"
      echo "         请先启用 HTTPS，再执行 apply --yes --include-ssl。"
    fi
    if [ "$key" = "passwordPolicy" ]; then
      echo "  [提示] 收紧密码策略后，门户用户下次改密/管理员重置密码需满足新规则；已有密码不受影响。"
    fi
  done
}

cmd_check() {
  local advisory=0
  [ "${1:-}" = "--advisory" ] && advisory=1
  echo "[step] 检查门户登录安全基线（realm=$REALM）"
  if ! load_realm; then
    echo "[warn] 无法读取门户身份引擎配置，跳过门户登录安全基线检查"
    [ "$advisory" -eq 1 ] && return 0
    return 2
  fi
  evaluate
  if [ "${#NOT_COMPLIANT[@]}" -eq 0 ]; then
    echo "[ok] 门户登录安全基线已达标"
    return 0
  fi
  echo "[warn] ${NOT_MET_BANNER}（${#NOT_COMPLIANT[@]} 项）。升级不会自动修改门户配置。"
  print_conflicts
  echo "       确认后执行：sudo bash $SCRIPT_DIR/portal-login-baseline.sh apply --yes"
  [ "$advisory" -eq 1 ] && return 0
  return 3
}

cmd_apply() {
  local confirmed=0 include_ssl=0 arg key k target mode item current
  for arg in "$@"; do
    case "$arg" in
      --yes) confirmed=1 ;;
      --include-ssl) include_ssl=1 ;;
      *) usage ;;
    esac
  done
  [ "$confirmed" -eq 1 ] || fail "收紧会修改门户登录配置，请确认后加 --yes"
  load_realm || fail "无法读取门户身份引擎配置"
  echo "[step] 收紧前"
  evaluate
  if [ "${#NOT_COMPLIANT[@]}" -eq 0 ]; then
    echo "[ok] 门户登录安全基线已达标，无需修改"
    return 0
  fi
  local args=() skipped=()
  for key in "${NOT_COMPLIANT[@]}"; do
    for item in "${BASELINE_ITEMS[@]}"; do
      IFS='|' read -r k target mode <<<"$item"
      [ "$k" = "$key" ] || continue
      if [ "$key" = "sslRequired" ] && public_url_is_http && [ "$include_ssl" -ne 1 ]; then
        skipped+=("$key")
        continue
      fi
      if [ "$mode" = "policy" ]; then
        current="$(realm_field "$REALM_JSON" "$key")"
        target="$(merge_policy "$current" "$target")"
      fi
      args+=(-s "$key=$target")
    done
  done
  if [ "${#args[@]}" -gt 0 ]; then
    kcadm update "realms/$REALM" "${args[@]}" >/dev/null || fail "更新门户登录配置失败"
  fi
  load_realm || fail "收紧后无法复核门户身份引擎配置"
  echo "[step] 收紧后"
  evaluate
  if [ "${#skipped[@]}" -gt 0 ]; then
    echo "[warn] 已跳过：${skipped[*]}（门户当前以 HTTP 对外，见上方冲突说明）"
  fi
  local remaining=0
  for key in "${NOT_COMPLIANT[@]}"; do
    case " ${skipped[*]:-} " in *" $key "*) ;; *) remaining=$((remaining + 1)) ;; esac
  done
  [ "$remaining" -eq 0 ] || fail "仍有 $remaining 项未达标，请检查身份引擎日志"
  echo "[ok] 门户登录安全基线已收紧"
}

case "${1:-}" in
  check) shift; cmd_check "$@" ;;
  apply) shift; cmd_apply "$@" ;;
  *) usage ;;
esac
