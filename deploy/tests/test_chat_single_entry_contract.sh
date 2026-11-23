#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEV_COMPOSE="$ROOT/docker-compose/docker-compose.yml"
OFFLINE_COMPOSE="$ROOT/docker-compose/docker-compose.offline.yml"
WEB_SERVER="$ROOT/../apps/web-console/server.js"
PORTAL_CONFIG="$ROOT/../enterprise-ai-portal/next.config.ts"
PORTAL_AUTH_ROUTE="$ROOT/../enterprise-ai-portal/src/app/api/auth/[...nextauth]/route.ts"
DEPLOY_SCRIPT="$ROOT/docker-compose/deploy-offline.sh"

fail() { echo "[fail] $*" >&2; exit 1; }
contains() { grep -Fq -- "$2" "$1" || fail "$1 缺少: $2"; }
rejects() { ! grep -Fq -- "$2" "$1" || fail "$1 不应包含: $2"; }

contains "$PORTAL_CONFIG" 'basePath: "/chat"'
contains "$PORTAL_AUTH_ROUTE" 'restoreExternalBasePath'
contains "$WEB_SERVER" "requestPath === '/chat' || requestPath.startsWith('/chat/')"
contains "$WEB_SERVER" "requestPath === '/sso' || requestPath.startsWith('/sso/')"
contains "$DEPLOY_SCRIPT" '_legacy_sso_public="http://${_chat_host}:${_chat_idp_port}"'
contains "$DEPLOY_SCRIPT" '"http://0.0.0.0:${_chat_idp_port}"'
contains "$DEPLOY_SCRIPT" '"http://[::]:${_chat_idp_port}"'
contains "$DEPLOY_SCRIPT" 'CHAT_URL=%s/chat'
contains "$DEPLOY_SCRIPT" 'SSO_URL=%s/sso'

for compose in "$DEV_COMPOSE" "$OFFLINE_COMPOSE"; do
  rejects "$compose" '${CHAT_UI_BIND:-0.0.0.0}:${CHAT_UI_PORT:-3100}:3100'
  rejects "$compose" '${CHAT_ADMIN_BIND:-0.0.0.0}:${CHAT_ADMIN_PORT:-8280}:8280'
  rejects "$compose" '${CHAT_IDP_BIND:-0.0.0.0}:${CHAT_IDP_PORT:-8180}:8180'
  contains "$compose" 'CHAT_EDGE_URL=http://chat-edge:3100'
  contains "$compose" 'SSO_EDGE_URL=http://chat-edge:8180'
  contains "$compose" 'PORTAL_ADMIN_EDGE_URL=http://chat-edge:8280'
  contains "$compose" 'expose:'
  contains "$compose" 'NEXTAUTH_URL=${JJD_SSO_PUBLIC_URL:-http://chat-edge:8180}/chat/api/auth'
  contains "$compose" 'AUTH_URL=${JJD_SSO_PUBLIC_URL:-http://chat-edge:8180}/chat/api/auth'
  contains "$compose" 'PORTAL_PUBLIC_URL=${JJD_SSO_PUBLIC_URL:-http://chat-edge:8180}/chat'
  contains "$compose" 'PORTAL_COOKIE_SECURE=${PORTAL_COOKIE_SECURE:-true}'
  contains "$compose" "fetch('http://127.0.0.1:3100/chat/api/me')"
  contains "$compose" 'PORTAL_UI_ACCOUNT_REDIRECT=${JJD_SSO_PUBLIC_URL:-http://chat-edge:8180}/chat/api/auth/callback/account-login'
done

echo '[ok] Chat 与 SSO 复用 Web 公开入口'
