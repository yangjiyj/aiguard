#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
DEV_COMPOSE="$ROOT_DIR/deploy/docker-compose/docker-compose.yml"
OFFLINE_COMPOSE="$ROOT_DIR/deploy/docker-compose/docker-compose.offline.yml"
ENV_EXAMPLE="$ROOT_DIR/deploy/docker-compose/.env.example"
REAL_E2E="$ROOT_DIR/deploy/tests/mcp_real_e2e/run.sh"
DEPLOY_ONECLICK="$ROOT_DIR/deploy/docker-compose/deploy-oneclick.sh"
DEPLOY_OFFLINE="$ROOT_DIR/deploy/docker-compose/deploy-offline.sh"
UPGRADE="$ROOT_DIR/deploy/docker-compose/upgrade.sh"

fail() { echo "[fail] $*" >&2; exit 1; }

assert_count() {
  local file="$1" needle="$2" want="$3" got
  got="$(grep -Fxc -- "$needle" "$file" || true)"
  [[ "$got" == "$want" ]] || fail "expected $file to contain $want exact lines for $needle, got $got"
}

for compose in "$DEV_COMPOSE" "$OFFLINE_COMPOSE"; do
  assert_count "$compose" '      - MCP_CONFIRMATION_SCOPE_SECRET=${MCP_CONFIRMATION_SCOPE_SECRET:-}' 2
done

grep -Fqx 'MCP_CONFIRMATION_SCOPE_SECRET=' "$ENV_EXAMPLE" || fail "dedicated scope secret placeholder missing from env example"
grep -Fq 'MCP confirmation exact-once identity' "$ENV_EXAMPLE" || fail "scope secret independence is not documented"

for script in "$DEPLOY_ONECLICK" "$DEPLOY_OFFLINE" "$UPGRADE"; do
  grep -Fq 'append_env_if_missing MCP_CONFIRMATION_SCOPE_SECRET "$(random_hex 32)"' "$script" || fail "$script does not generate/backfill the dedicated scope secret"
done

grep -Fqx 'MCP_CONFIRMATION_SCOPE_SECRET="$(secret)"' "$REAL_E2E" || fail "real MCP E2E must generate a dedicated scope secret"
grep -Fqx 'MCP_CONFIRMATION_SCOPE_SECRET=$MCP_CONFIRMATION_SCOPE_SECRET' "$REAL_E2E" || fail "real MCP E2E must pass the dedicated scope secret"
grep -Fqx 'MCP_GATEWAY_ENABLED=true' "$REAL_E2E" || fail "real MCP E2E must enable the gateway"

if grep -Fq 'MCP_CONFIRMATION_SCOPE_SECRET="$INTERNAL_SECRET"' "$REAL_E2E" ||
   grep -Fq 'MCP_CONFIRMATION_SCOPE_SECRET="$PROVIDER_SECRET"' "$REAL_E2E" ||
   grep -Fq 'MCP_CONFIRMATION_SCOPE_SECRET="$RULE_ATTESTATION_SECRET"' "$REAL_E2E" ||
   grep -Fq 'MCP_CONFIRMATION_SCOPE_SECRET="$AUDIT_HMAC_SECRET"' "$REAL_E2E"; then
  fail "real MCP E2E reuses another credential as the confirmation scope secret"
fi

echo '[ok] MCP confirmation scope secret is independently wired'
