#!/usr/bin/env bash
# keycloak-routing_test.sh — 锁定 JJDGuard SSO 公共协议入口的允许/拒绝边界

set -euo pipefail

CADDYFILE="deploy/docker-compose/chat/Caddyfile"
COMPOSE_FILE="deploy/docker-compose/docker-compose.yml"
COMPOSE_OFFLINE="deploy/docker-compose/docker-compose.offline.yml"

fail() { echo "FAIL: $*" >&2; exit 1; }
ok() { echo "ok: $*"; }

test_static_caddyfile() {
  [ -f "$CADDYFILE" ] || fail "Caddyfile 不存在：$CADDYFILE"
  grep -q ':8180' "$CADDYFILE" || fail ":8180 段缺失"

  grep -Fq '@sso_realm path /sso/realms/jjdguard /sso/realms/jjdguard/*' "$CADDYFILE" ||
    fail "未配置 /sso/realms/jjdguard 白名单"
  grep -Fq '@sso_resources path /sso/resources/*' "$CADDYFILE" ||
    fail "未配置 /sso/resources 白名单"

  grep -Fq '@raw_identity_paths path /admin /admin/* /realms /realms/* /resources /resources/*' "$CADDYFILE" ||
    fail "未显式拒绝原始身份引擎路径"
  grep -Fq '@private_identity_paths path /sso/admin /sso/admin/* /sso/realms/master /sso/realms/master/*' "$CADDYFILE" ||
    fail "未显式拒绝 /sso 管理面和 master realm"

  ! grep -q 'chat-portal-dev' "$CADDYFILE" || fail "仍公开旧 chat-portal-dev realm"
  grep -q 'header_down -Server' "$CADDYFILE" || fail "代理响应未移除 Server 识别头"
  awk '/^:8180 \{/,/^\}$/' "$CADDYFILE" | tail -5 | grep -q 'respond' ||
    fail ":8180 兜底未改为 respond 拒绝"

  ok "Caddyfile :8180 仅开放 JJDGuard SSO 协议边界"
}

test_static_compose() {
  for f in "$COMPOSE_FILE" "$COMPOSE_OFFLINE"; do
    [ -f "$f" ] || fail "compose 文件不存在：$f"
    local block control_block
    block=$(sed -n '/^  chat-idp:/,/^  [a-z]/p' "$f" | sed '$d')
    [ -n "$block" ] || fail "$f 无法提取 chat-idp 段"

    ! echo "$block" | grep -q 'start-dev' || fail "$f chat-idp 仍是 dev 模式"
    echo "$block" | grep -q 'command:.*"start"' || fail "$f chat-idp 未用 start 生产模式"
    echo "$block" | grep -q 'KEYCLOAK_ADMIN_PASSWORD.*:?' || fail "$f bootstrap 密码未强约束"
    echo "$block" | grep -q 'KC_HTTP_ENABLED=true' || fail "$f 缺少 KC_HTTP_ENABLED=true"
    echo "$block" | grep -q 'KC_HEALTH_ENABLED=false' || fail "$f 缺少 KC_HEALTH_ENABLED=false"
    echo "$block" | grep -Fq 'KC_HTTP_RELATIVE_PATH=/sso' || fail "$f 缺少 KC_HTTP_RELATIVE_PATH=/sso"
    echo "$block" | grep -Fq 'KC_HOSTNAME=${JJD_SSO_PUBLIC_URL:-http://chat-edge:8180}/sso' ||
      fail "$f KC_HOSTNAME 必须包含 /sso，确保 discovery issuer 与门户配置一致"
    echo "$block" | grep -q '^    expose:' || fail "$f chat-idp 未声明内部 expose"
    ! echo "$block" | grep -q '^    ports:' || fail "$f chat-idp 不得直接发布宿主端口"

    control_block=$(sed -n '/^  control-plane:/,/^  [a-z]/p' "$f" | sed '$d')
    [ -n "$control_block" ] || fail "$f 无法提取 control-plane 段"
    echo "$control_block" | grep -Fq 'identity-runtime.env' || fail "$f control-plane 未加载专用运行态凭据文件"
    echo "$control_block" | grep -Fq 'required: false' || fail "$f 运行态凭据文件必须允许基础包缺省"
    ! echo "$control_block" | grep -q 'KEYCLOAK_ADMIN_PASSWORD' ||
      fail "$f 不得把身份引擎 bootstrap 密码传给 control-plane"

    grep -Fq 'OIDC_ISSUER=${CHAT_OIDC_ISSUER:-http://chat-edge:8180/sso/realms/jjdguard}' "$f" ||
      fail "$f 门户 issuer 未保留 JJDGuard 默认值与旧 BYO IdP 兼容入口"
    grep -Fq '/sso/realms/jjdguard' "$f" || fail "$f 门户 issuer 缺少 /sso/realms/jjdguard"
  done
  ok "compose 身份引擎内网隔离 + /sso 相对路径 + 控制面凭据边界"
}

test_live_routes() {
  local host="${CHAT_OIDC_HOST:-localhost}"
  local port="${WEB_HTTPS_PORT:-443}"
  local base="${JJD_SSO_PUBLIC_URL:-}"
  if [ -z "$base" ]; then
    if [ "$port" = 443 ]; then
      base="https://$host"
    else
      base="https://$host:$port"
    fi
  fi
  base="${base%/}"
  local code

  echo "活体校验目标：$base"

  code=$(curl -s -o /dev/null -w '%{http_code}' "$base/sso/realms/jjdguard/.well-known/openid-configuration" || echo 000)
  [ "$code" = "200" ] || fail "业务 realm discovery 应 200，实际 $code"

  code=$(curl -s -o /dev/null -w '%{http_code}' "$base/admin" || echo 000)
  [ "$code" = "404" ] || [ "$code" = "403" ] || fail "/admin 应 404/403，实际 $code"
  code=$(curl -s -o /dev/null -w '%{http_code}' "$base/realms/jjdguard" || echo 000)
  [ "$code" = "404" ] || [ "$code" = "403" ] || fail "原始 /realms 应 404/403，实际 $code"

  code=$(curl -s -o /dev/null -w '%{http_code}' "$base/sso/admin" || echo 000)
  [ "$code" = "403" ] || [ "$code" = "404" ] || fail "/sso/admin 应 403/404，实际 $code"
  code=$(curl -s -o /dev/null -w '%{http_code}' "$base/sso/realms/master" || echo 000)
  [ "$code" = "403" ] || [ "$code" = "404" ] || fail "master realm 应 403/404，实际 $code"

  code=$(curl -s -o /dev/null -w '%{http_code}' "$base/resources/foo.css" || echo 000)
  [ "$code" = "404" ] || [ "$code" = "403" ] || fail "原始 /resources 应 404/403，实际 $code"
  code=$(curl -s -o /dev/null -w '%{http_code}' "$base/sso/resources/foo.css" || echo 000)
  [ "$code" != "403" ] || fail "/sso/resources 应走代理非 403，实际 $code"

  code=$(curl -s -o /dev/null -w '%{http_code}' "$base/sso/realms/jjdguard/protocol/openid-connect/token" || echo 000)
  [ "$code" != "404" ] || fail "token 端点不应 404"

  ! curl -sI "$base/sso/realms/jjdguard" | grep -Eiq '^Server:.*(Keycloak|Caddy)' ||
    fail "公共响应泄漏实现 Server 头"

  ok "JJDGuard SSO 活体路径边界校验通过"
}

case "${1:-static}" in
  static)
    test_static_caddyfile
    test_static_compose
    echo "=== 静态校验全部通过 ==="
    ;;
  live)
    test_live_routes
    echo "=== 活体校验全部通过 ==="
    ;;
  both)
    test_static_caddyfile
    test_static_compose
    test_live_routes
    echo "=== 全部校验通过 ==="
    ;;
  *)
    echo "用法: $0 {static|live|both}"
    exit 2
    ;;
esac
