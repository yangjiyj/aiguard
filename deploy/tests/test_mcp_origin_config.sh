#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
ENV_EXAMPLE="$ROOT/deploy/docker-compose/.env.example"
MAIN="$ROOT/apps/gateway-core/cmd/server/main.go"
ROUTES="$ROOT/apps/gateway-core/cmd/server/mcp_routes.go"

contract_line() {
  local file="$1" fragment="$2" matches count
  matches="$(grep -Fn -- "$fragment" "$file" || true)"
  count="$(printf '%s\n' "$matches" | awk 'NF {n++} END {print n+0}')"
  if [ "$count" -ne 1 ]; then
    echo "MCP origin contract requires one occurrence of: $fragment" >&2
    exit 1
  fi
  printf '%s\n' "${matches%%:*}"
}

grep -Fqx 'MCP_ALLOWED_ORIGINS=' "$ENV_EXAMPLE" || {
  echo "MCP_ALLOWED_ORIGINS missing from env example" >&2
  exit 1
}
for compose in "$ROOT/deploy/docker-compose/docker-compose.yml" "$ROOT/deploy/docker-compose/docker-compose.offline.yml"; do
  grep -Fq 'MCP_ALLOWED_ORIGINS=${MCP_ALLOWED_ORIGINS:-}' "$compose" || {
    echo "$compose does not pass the MCP origin allowlist to gateway-core" >&2
    exit 1
  }
done
grep -Fq 'mcpProxy.SetAllowedOrigins(cfg.MCPAllowedOrigins)' "$MAIN" || {
  echo "gateway does not load the validated MCP origin allowlist" >&2
  exit 1
}
auth_decl="$(contract_line "$MAIN" 'dataPlaneAuth := func(next http.Handler) http.Handler {')"
auth_chain="$(contract_line "$MAIN" 'return authMiddleware.Middleware(cfg)(integrationPolicies.Middleware(next))')"
mcp_register="$(contract_line "$MAIN" 'registerMCPRoutes(r, dataPlaneAuth, mcpProxy)')"
if ! (( auth_decl < auth_chain && auth_chain < mcp_register )); then
  echo "MCP authentication and integration policy chain is not wired in order" >&2
  exit 1
fi
route_function="$(contract_line "$ROUTES" 'func registerMCPRoutes(')"
route_scope="$(contract_line "$ROUTES" 'router.Route("/mcp", func(r chi.Router) {')"
origin="$(contract_line "$ROUTES" 'r.Use(proxy.OriginMiddleware)')"
preflight="$(contract_line "$ROUTES" 'r.Options("/{serverID}", func(w http.ResponseWriter, _ *http.Request) {')"
protected_group="$(contract_line "$ROUTES" 'r.Group(func(protected chi.Router) {')"
protected_auth="$(contract_line "$ROUTES" 'protected.Use(authMiddleware)')"
protected_routes="$(contract_line "$ROUTES" 'proxy.Register(protected)')"
if ! (( route_function < route_scope && route_scope < origin && origin < preflight &&
        preflight < protected_group && protected_group < protected_auth && protected_auth < protected_routes )); then
  echo "MCP Origin and preflight must precede the authenticated policy chain" >&2
  exit 1
fi
echo "[ok] MCP origin allowlist deployment contract"
