#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(CDPATH= cd -- "$(dirname "$0")/../../.." && pwd)"
SIM_DIR="$ROOT_DIR/deploy/docker-compose/directory-sim"
COMPOSE="$SIM_DIR/docker-compose.yml"
REALM="$SIM_DIR/realm-enterprise-test.json"

fail() {
  echo "FAIL: $*" >&2
  exit 1
}

has() {
  local file="$1"
  local pattern="$2"
  grep -Eq "$pattern" "$file" || fail "$file 缺少合约：$pattern"
}

[ -f "$COMPOSE" ] || fail "缺少目录模拟 Compose"
[ -f "$REALM" ] || fail "缺少上游 OIDC realm"

has "$COMPOSE" '^  ldap:'
has "$COMPOSE" '^  ad:'
has "$COMPOSE" '^  oidc-idp:'
has "$COMPOSE" 'UPSTREAM_OIDC_CLIENT_SECRET'
has "$COMPOSE" 'UPSTREAM_OIDC_TEST_PASSWORD'
has "$COMPOSE" 'JJDGUARD_ENTERPRISE_CALLBACK'
has "$COMPOSE" 'UPSTREAM_OIDC_BIND'
has "$COMPOSE" 'UPSTREAM_OIDC_PORT:-8380'
has "$COMPOSE" 'http-port=\$\{UPSTREAM_OIDC_PORT:-8380\}'
has "$COMPOSE" 'aliases:.*UPSTREAM_OIDC_HOST'
has "$COMPOSE" 'KC_HOSTNAME: "\$\{UPSTREAM_OIDC_ORIGIN:'
has "$COMPOSE" '^  oidc-publish:'
has "$COMPOSE" 'internal:[[:space:]]*false'
has "$COMPOSE" 'LDAP_BIND_PASSWORD'
has "$COMPOSE" 'AD_DOMAIN_ADMIN_PASSWORD'

has "$REALM" '"realm"[[:space:]]*:[[:space:]]*"enterprise-test"'
has "$REALM" '"clientId"[[:space:]]*:[[:space:]]*"jjdguard-enterprise-test"'
has "$REALM" '"secret"[[:space:]]*:[[:space:]]*"\$\{UPSTREAM_OIDC_CLIENT_SECRET\}"'
has "$REALM" '"value"[[:space:]]*:[[:space:]]*"\$\{UPSTREAM_OIDC_TEST_PASSWORD\}"'
has "$REALM" '"claim.name"[[:space:]]*:[[:space:]]*"department"'
has "$REALM" '"claim.name"[[:space:]]*:[[:space:]]*"groups"'

if grep -Eq 'Napi#|simulated-admin-only|Simulated-Domain-Admin-Only' "$REALM" "$COMPOSE"; then
  fail "身份模拟环境含明文测试凭据"
fi

echo "ok: home LDAP、AD、OIDC 测试环境合约通过"
