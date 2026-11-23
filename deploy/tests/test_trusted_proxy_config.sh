#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENV_EXAMPLE="$ROOT_DIR/docker-compose/.env.example"
CADDYFILE="$ROOT_DIR/docker-compose/gateway-tls.Caddyfile"
OFFLINE_COMPOSE="$ROOT_DIR/docker-compose/docker-compose.offline.yml"

fail() {
  echo "trusted proxy config contract failed: $*" >&2
  exit 1
}

grep -Fqx 'TRUSTED_PROXY_CIDRS=' "$ENV_EXAMPLE" ||
  fail "TRUSTED_PROXY_CIDRS missing from env example"
grep -Fq 'TRUSTED_PROXY_CIDRS=${TRUSTED_PROXY_CIDRS:-}' "$OFFLINE_COMPOSE" ||
  fail "TRUSTED_PROXY_CIDRS missing from offline compose"
grep -Fq '仅填写实际反向代理 TCP 对端的精确 CIDR' "$ENV_EXAMPLE" ||
  fail "env example must warn operators to trust only exact proxy peers"
grep -Fq '信任实际 TCP 对端' "$CADDYFILE" ||
  fail "gateway TLS comment must describe the real proxy trust boundary"
if grep -Fq '信任 127.0.0.1' "$CADDYFILE"; then
  fail "gateway TLS comment must not claim the peer is always loopback"
fi

echo "trusted proxy config contract passed"
