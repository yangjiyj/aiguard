#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ONLINE="$ROOT/docker-compose/docker-compose.yml"
OFFLINE="$ROOT/docker-compose/docker-compose.offline.yml"
ENV_EXAMPLE="$ROOT/docker-compose/.env.example"
DEPLOY_ONLINE="$ROOT/docker-compose/deploy-oneclick.sh"
DEPLOY_OFFLINE="$ROOT/docker-compose/deploy-offline.sh"
UPGRADE="$ROOT/docker-compose/upgrade.sh"

fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }
assert_count() {
  local file="$1" pattern="$2" expected="$3" count
  count="$(grep -Fxc "$pattern" "$file" || true)"
  [[ "$count" == "$expected" ]] || fail "$file expected $expected copies of: $pattern; got $count"
}

for compose in "$ONLINE" "$OFFLINE"; do
  assert_count "$compose" '      - JJD_SEMANTIC_GATEWAY_ATTESTATION_KEY=${JJD_SEMANTIC_GATEWAY_ATTESTATION_KEY:?JJD_SEMANTIC_GATEWAY_ATTESTATION_KEY is required}' 2
  assert_count "$compose" '      - SECURITY_TIER1_API_TOKEN=${JJD_TIER1_INTERNAL_TOKEN:-}' 1
done

assert_count "$OFFLINE" '      - JJD_TIER1_INTERNAL_TOKEN=${JJD_TIER1_INTERNAL_TOKEN:?JJD_TIER1_INTERNAL_TOKEN is required}' 1
tier1_block="$(sed -n '/^  tier1-classifier:/,/^  [a-zA-Z0-9_-]*:/p' "$OFFLINE")"
grep -Fq 'JJD_INTERNAL_API_SECRET=' <<<"$tier1_block" && fail "Tier-1 service still receives JJD_INTERNAL_API_SECRET"

grep -Fqx 'JJD_SEMANTIC_GATEWAY_ATTESTATION_KEY=' "$ENV_EXAMPLE" || fail "gateway semantic attestation key missing from env example"
grep -Fqx 'JJD_TIER1_INTERNAL_TOKEN=' "$ENV_EXAMPLE" || fail "Tier-1 token missing from env example"

for script in "$DEPLOY_ONLINE" "$DEPLOY_OFFLINE"; do
  grep -Fq 'append_env_if_missing JJD_SEMANTIC_GATEWAY_ATTESTATION_KEY "$(random_hex 32)"' "$script" || fail "$script does not backfill gateway attestation key"
  grep -Fq 'append_env_if_missing JJD_TIER1_INTERNAL_TOKEN "$(random_hex 32)"' "$script" || fail "$script does not backfill Tier-1 token"
done

grep -Fq 'append_env_if_missing JJD_SEMANTIC_GATEWAY_ATTESTATION_KEY "$(random_hex 32)"' "$UPGRADE" || fail "upgrade does not backfill gateway attestation key"
grep -Fq 'append_env_if_missing JJD_TIER1_INTERNAL_TOKEN "$(random_hex 32)"' "$UPGRADE" || fail "upgrade does not backfill Tier-1 token"

printf 'semantic secret isolation static checks passed\n'
