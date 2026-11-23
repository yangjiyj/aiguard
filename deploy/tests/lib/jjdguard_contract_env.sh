#!/usr/bin/env bash
set -Eeuo pipefail

write_jjdguard_contract_env() {
  local env_file="$1"
  umask 077
  cat >"$env_file" <<'ENV'
POSTGRES_PASSWORD=contract-postgres
REDIS_PASSWORD=contract-redis
JJD_PROVIDER_SECRET_KEY=contract-provider
JJD_INTERNAL_API_SECRET=contract-internal
JJD_SEMANTIC_GATEWAY_ATTESTATION_KEY=contract-semantic-attestation
JJD_TIER1_INTERNAL_TOKEN=contract-tier1
JJD_RULE_PACK_ATTESTATION_TOKEN=contract-rule-pack
MCP_CONFIRMATION_SCOPE_SECRET=contract-mcp-confirmation
UAG_AUDIT_HMAC_KEY=contract-audit-hmac
BOOTSTRAP_ADMIN_PASSWORD=contract-admin
JJD_PORTAL_API_SECRET=contract-portal
AUTH_SECRET=contract-auth
CHAT_POSTGRES_PASSWORD=contract-chat-postgres
PORTAL_INTERNAL_TOKEN=contract-portal-internal
PORTAL_KEY_ENC_SECRET=contract-portal-enc
PORTAL_OIDC_CLIENT_SECRET=contract-portal-oidc
CHAT_PORTAL_UI_OIDC_SECRET=contract-ui-oidc
KEYCLOAK_ADMIN_PASSWORD=contract-identity-bootstrap
CHAT_OIDC_HOST=chat-edge
POSTGRES_PORT=45432
REDIS_PORT=46379
CHAT_UI_PORT=43100
CHAT_ADMIN_PORT=48280
GATEWAY_PUBLIC_URL=https://gateway.contract.test
BILLING_ENABLED=false
ENV
  chmod 600 "$env_file"
  test "$(stat -c %a "$env_file")" = 600
}
