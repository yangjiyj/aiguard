#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
DEV_COMPOSE="$ROOT_DIR/deploy/docker-compose/docker-compose.yml"
OFFLINE_COMPOSE="$ROOT_DIR/deploy/docker-compose/docker-compose.offline.yml"
ENV_EXAMPLE="$ROOT_DIR/deploy/docker-compose/.env.example"
OFFLINE_DEPLOY="$ROOT_DIR/deploy/docker-compose/deploy-offline.sh"
ONECLICK_DEPLOY="$ROOT_DIR/deploy/docker-compose/deploy-oneclick.sh"
UPGRADE="$ROOT_DIR/deploy/docker-compose/upgrade.sh"

fail() { echo "[fail] $*" >&2; exit 1; }

assert_count() {
  local file="$1" needle="$2" want="$3" got
  got="$(grep -Fxc -- "$needle" "$file" || true)"
  [[ "$got" == "$want" ]] || fail "expected $file to contain $want exact lines for $needle, got $got"
}

for compose in "$DEV_COMPOSE" "$OFFLINE_COMPOSE"; do
  assert_count "$compose" '      - JJD_RULE_PACK_ATTESTATION_TENANT=${JJD_RULE_PACK_ATTESTATION_TENANT:-tenant_default}' 1
  assert_count "$compose" '      - JJD_RULE_PACK_ATTESTATION_TOKEN=${JJD_RULE_PACK_ATTESTATION_TOKEN:?JJD_RULE_PACK_ATTESTATION_TOKEN is required}' 1
  assert_count "$compose" '      - JJD_RULE_PACK_ATTESTATION_TOKENS_JSON=${JJD_RULE_PACK_ATTESTATION_TOKENS_JSON:-}' 1
  assert_count "$compose" '      - SECURITY_TENANT_ID=${JJD_RULE_PACK_ATTESTATION_TENANT:-tenant_default}' 1
  assert_count "$compose" '      - SECURITY_RULE_PACK_ATTESTATION_TOKEN=${JJD_RULE_PACK_ATTESTATION_TOKEN:?JJD_RULE_PACK_ATTESTATION_TOKEN is required}' 1
done

grep -Fqx 'JJD_RULE_PACK_ATTESTATION_TENANT=tenant_default' "$ENV_EXAMPLE" || fail "tenant default missing from env example"
grep -Fqx 'JJD_RULE_PACK_ATTESTATION_TOKEN=' "$ENV_EXAMPLE" || fail "dedicated token placeholder missing from env example"
grep -Fqx 'JJD_RULE_PACK_ATTESTATION_TOKENS_JSON=' "$ENV_EXAMPLE" || fail "multi-tenant token map placeholder missing from env example"

grep -Fq 'RULE_PACK_ATTESTATION_TOKEN="$(random_hex 32)"' "$OFFLINE_DEPLOY" || fail "offline install must generate a dedicated token"
grep -Fq 'JJD_RULE_PACK_ATTESTATION_TOKEN=$RULE_PACK_ATTESTATION_TOKEN' "$OFFLINE_DEPLOY" || fail "offline install must persist the generated token"
grep -Fq 'append_env_if_missing JJD_RULE_PACK_ATTESTATION_TENANT tenant_default' "$UPGRADE" || fail "upgrade must backfill the rule-pack tenant"
grep -Fq 'append_env_if_missing JJD_RULE_PACK_ATTESTATION_TOKEN "$(random_hex 32)"' "$UPGRADE" || fail "upgrade must independently backfill the rule-pack token"
grep -Fq 'append_env_if_missing JJD_RULE_PACK_ATTESTATION_TOKENS_JSON ""' "$UPGRADE" || fail "upgrade must initialize the multi-tenant token map"

grep -Fq 'append_env_if_missing JJD_RULE_PACK_ATTESTATION_TENANT tenant_default' "$ONECLICK_DEPLOY" || fail "one-click install must set the rule-pack tenant"
grep -Fq 'append_env_if_missing JJD_RULE_PACK_ATTESTATION_TOKEN "$(random_hex 32)"' "$ONECLICK_DEPLOY" || fail "one-click install must independently generate the rule-pack token"
grep -Fq 'append_env_if_missing JJD_RULE_PACK_ATTESTATION_TOKENS_JSON ""' "$ONECLICK_DEPLOY" || fail "one-click install must initialize the multi-tenant token map"

if grep -Fq 'append_env_if_missing JJD_RULE_PACK_ATTESTATION_TOKEN "$INTERNAL_SECRET"' "$ONECLICK_DEPLOY" ||
   grep -Fq 'append_env_if_missing JJD_RULE_PACK_ATTESTATION_TOKEN "$SECRET_KEY"' "$ONECLICK_DEPLOY" ||
   grep -Fq 'JJD_RULE_PACK_ATTESTATION_TOKEN=$INTERNAL_SECRET' "$ONECLICK_DEPLOY" ||
   grep -Fq 'JJD_RULE_PACK_ATTESTATION_TOKEN=$SECRET_KEY' "$ONECLICK_DEPLOY"; then
  fail "one-click install reuses another credential as the rule-pack attestation token"
fi

echo '[ok] rule-pack attestation delivery configuration is wired'
