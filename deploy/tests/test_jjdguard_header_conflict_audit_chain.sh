#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
GO="${GO:-/usr/local/go/bin/go}"

(cd "$ROOT/packages/shared-go" && "$GO" test ./headercompat ./headeraudit ./agentdetect)
(cd "$ROOT/apps/control-plane" && "$GO" test ./internal/audit_chain ./internal/handler -run 'HeaderContract|Critical|Internal|EvalIntegration|PortalIntegration')
(cd "$ROOT/apps/gateway-core" && "$GO" test ./internal/auth ./internal/handler -run 'Header|Session|Workspace|Agent|ReverseProxy|CriticalAudit')
(cd "$ROOT/apps/proxy-server" && "$GO" test ./internal/handler -run 'Header|Agent|Audit|MITM|CriticalAudit')

if rg -n 'Header\.Get\("X-(NewAPI|JJDGuard)-(Session-Id|Workspace-Id|Agent-Type)' \
  "$ROOT/apps/gateway-core/internal/auth/auth.go" \
  "$ROOT/apps/gateway-core/internal/handler/reverse_proxy_audit.go" \
  "$ROOT/apps/proxy-server/internal/handler/audit.go"; then
  echo "direct scalar migration-header read remains" >&2
  exit 1
fi

gateway_clients="$(rg -c 'headeraudit.NewClient\(' "$ROOT/apps/gateway-core/cmd/server/main.go")"
proxy_clients="$(rg -c 'headeraudit.NewClient\(' "$ROOT/apps/proxy-server/cmd/server/main.go")"
[[ "$gateway_clients" == "1" && "$proxy_clients" == "1" ]]

echo "PASS: three product boundaries reject conflicts with one synchronous critical-audit client and no direct fallback reads"
