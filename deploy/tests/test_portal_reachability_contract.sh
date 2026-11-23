#!/usr/bin/env bash
set -Eeuo pipefail

# 根因 #6 的打包闸门：门户「绑定地址 ≠ 公开地址」与 client 可达性对账。
#
# 现场故障是 callbackUrl=http://0.0.0.0:3100/：0.0.0.0 是监听地址，
# 浏览器永远回不来。两个半边都必须常驻：
#   1) ensure-public-sso-url.sh 要把已持久化的通配地址迁移成可达地址；
#   2) bootstrap-identity-runtime.sh 要幂等对账门户 client 的
#      redirectUris/webOrigins/post.logout.redirect.uris/secret，
#      因为 --import-realm 只在 realm 不存在时生效，升级不会修旧值。
#
# 这里只做静态合约。行为验收在：
#   deploy/docker-compose/tests/public-sso-url_test.sh
#   deploy/docker-compose/tests/identity-runtime-bootstrap_test.sh

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PUBLIC_URL="$ROOT_DIR/deploy/docker-compose/chat/ensure-public-sso-url.sh"
BOOTSTRAP="$ROOT_DIR/deploy/docker-compose/chat/bootstrap-identity-runtime.sh"
BEHAVIOUR_TESTS=(
  "$ROOT_DIR/deploy/docker-compose/tests/public-sso-url_test.sh"
  "$ROOT_DIR/deploy/docker-compose/tests/identity-runtime-bootstrap_test.sh"
)

fail() {
  echo "[fail] $*" >&2
  exit 1
}

has() {
  local file="$1" pattern="$2" why="$3"
  grep -Eq -- "$pattern" "$file" || fail "$(basename "$file") 缺少合约（$why）：$pattern"
}

[ -x "$PUBLIC_URL" ] || fail "缺少可执行的公开 SSO 地址解析器"
[ -x "$BOOTSTRAP" ] || fail "缺少可执行的身份运行态引导脚本"
for behaviour_test in "${BEHAVIOUR_TESTS[@]}"; do
  [ -f "$behaviour_test" ] || fail "缺少行为验收脚本：$behaviour_test"
done

# --- 合约 1：通配绑定地址必须被识别并迁移 ---
has "$PUBLIC_URL" 'is_wildcard_host' '通配地址判定'
has "$PUBLIC_URL" '0\.0\.0\.0' 'IPv4 通配地址'
has "$PUBLIC_URL" '\|::\|' 'IPv6 通配地址'
has "$PUBLIC_URL" 'replace_origin_host' '只换主机名、保留协议与端口'
has "$PUBLIC_URL" 'is_wildcard_host "\$normalized_host"' '已持久化值也要走通配检查'
# 迁移路径必须复用既有的 detect_host + validate_host，
# 否则会把一个非法地址写回 .env，比 0.0.0.0 更难查。
has "$PUBLIC_URL" 'detect_host' '迁移时重新推导可达地址'
has "$PUBLIC_URL" 'validate_host' '迁移结果必须过校验'

# --- 合约 2：门户 client 可达性必须在生产路径上幂等对账 ---
has "$BOOTSTRAP" 'reconcile_portal_client_reachability' '门户可达性对账函数'
has "$BOOTSTRAP" 'portal_ui_origin' '门户 UI 源（bind 与公开地址分离）'
has "$BOOTSTRAP" "printf '%s/chat'" '门户固定挂在统一入口 /chat'
has "$BOOTSTRAP" 'redirectUris=' 'redirectUris 对账'
has "$BOOTSTRAP" 'webOrigins=' 'webOrigins 对账'
has "$BOOTSTRAP" 'post\.logout\.redirect\.uris' '登出回跳对账'
has "$BOOTSTRAP" 'api/auth/callback/account-login' '本地账号登录回调'
has "$BOOTSTRAP" 'api/auth/callback/enterprise-sso' '企业 SSO 登录回调'
# 两条回调必须都在，缺一条就是「本地能登企业不能登」或反之。
grep -q 'reconcile_portal_client_reachability "' "$BOOTSTRAP" ||
  fail "bootstrap-identity-runtime.sh 定义了可达性对账但没有调用"
has "$BOOTSTRAP" 'reconcile_portal_admin_reachability' '管理门户 /portal 可达性对账'

# secret 缺失时不得写空值：宁可保留 realm 现值，也不要把门户彻底锁死。
grep -Eq 'if \[ -n "\$portal_secret" \]' "$BOOTSTRAP" ||
  fail "bootstrap-identity-runtime.sh 必须在 secret 缺失时跳过写入，而不是写空串"

echo '[ok] 门户可达性与通配绑定地址迁移合约通过'
