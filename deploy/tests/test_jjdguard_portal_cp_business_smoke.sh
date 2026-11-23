#!/usr/bin/env bash
set -Eeuo pipefail
umask 077
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
COMPOSE="$ROOT/deploy/docker-compose/docker-compose.yml"
HELPER="$ROOT/deploy/docker-compose/ensure-jjdguard-portal-cp-network.sh"

need() { command -v "$1" >/dev/null 2>&1 || { echo "[error] missing command: $1" >&2; exit 1; }; }
compose() { docker compose --env-file "$CANARY_ENV_FILE" -f "$COMPOSE" "$@"; }

if [[ "${1:-}" == "--self-test" ]]; then
  need bash; need docker; need jq
  bash -n "$0"
  grep -q 'jjdguard-portal-control-plane' "$0"
  grep -q 'authjs.session-token' "$0"
  grep -q '/chat/api/models' "$0"
  grep -q '/chat/api/me/records' "$0"
  grep -q '/chat/api/upload' "$0"
  grep -q 'network disconnect' "$0"
  grep -q 'network connect' "$0"
  grep -q 'expect=502' "$0"
  forbidden_demo='/home/dev/new'"api-demo"
  if grep -q "$forbidden_demo" "$0"; then
    echo '[error] forbidden demo path reference' >&2
    exit 1
  fi
  printf 'portal_cp_business_smoke_self_test=ok routes=3 outage=502 reconnect=1 cleanup=scoped\n'
  exit 0
fi

: "${CANARY_CORE_PROJECT:?CANARY_CORE_PROJECT is required}"
: "${CANARY_PORTAL_PROJECT:?CANARY_PORTAL_PROJECT is required}"
: "${CANARY_ENV_FILE:?CANARY_ENV_FILE is required}"
: "${CANARY_NETWORK:?CANARY_NETWORK is required}"
: "${CANARY_CP_ALIAS:=jjdguard-portal-control-plane}"
[[ -f "$CANARY_ENV_FILE" ]] || { echo '[error] canary env missing' >&2; exit 1; }
case "$CANARY_CORE_PROJECT:$CANARY_PORTAL_PROJECT:$CANARY_NETWORK" in
  *[!a-z0-9_.:-]*) echo '[error] invalid canary name' >&2; exit 64 ;;
esac

cleanup_only=0
[[ "${1:-}" == "--cleanup-only" ]] && cleanup_only=1
cleanup() {
  COMPOSE_PROJECT_NAME="$CANARY_PORTAL_PROJECT" compose -p "$CANARY_PORTAL_PROJECT" --profile chat down --remove-orphans >/dev/null 2>&1 || true
  COMPOSE_PROJECT_NAME="$CANARY_CORE_PROJECT" compose -p "$CANARY_CORE_PROJECT" --profile full down --remove-orphans >/dev/null 2>&1 || true
  "$HELPER" --remove-if-owner contract-canary --name "$CANARY_NETWORK" >/dev/null 2>&1 || true
}
if ((cleanup_only)); then cleanup; exit 0; fi

need docker; need jq
trap cleanup EXIT
"$HELPER" --name "$CANARY_NETWORK" --owner contract-canary >/dev/null

COMPOSE_PROJECT_NAME="$CANARY_CORE_PROJECT" compose -p "$CANARY_CORE_PROJECT" --profile full up -d \
  postgres redis security-engine control-plane tier1-classifier
COMPOSE_PROJECT_NAME="$CANARY_PORTAL_PROJECT" compose -p "$CANARY_PORTAL_PROJECT" --profile chat up -d \
  chat-postgres chat-portal-proxy chat-portal-ui

container_for() {
  docker ps --filter "label=com.docker.compose.project=$1" --filter "label=com.docker.compose.service=$2" --format '{{.ID}}' | head -n1
}
cp_container="$(container_for "$CANARY_CORE_PROJECT" control-plane)"
ui_container="$(container_for "$CANARY_PORTAL_PROJECT" chat-portal-ui)"
[[ -n "$cp_container" && -n "$ui_container" ]]

for _ in $(seq 1 60); do
  health="$(docker inspect "$ui_container" --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}')"
  [[ "$health" == healthy ]] && break
  sleep 2
done
[[ "${health:-}" == healthy ]] || { echo '[error] Portal UI not healthy' >&2; exit 1; }

expected_ip="$(docker network inspect "$CANARY_NETWORK" --format "{{with index .Containers \"$cp_container\"}}{{.IPv4Address}}{{end}}" | cut -d/ -f1)"
resolved_ip="$(docker exec "$ui_container" node -e "require('dns').lookup('$CANARY_CP_ALIAS',(e,a)=>{if(e)process.exit(1);console.log(a)})")"
[[ -n "$expected_ip" && "$resolved_ip" == "$expected_ip" ]]

auth_secret="$(grep '^AUTH_SECRET=' "$CANARY_ENV_FILE" | tail -n1 | cut -d= -f2-)"
[[ -n "$auth_secret" ]]
cookie="$(docker exec -e AUTH_SECRET="$auth_secret" "$ui_container" node --input-type=module -e '
import { encode } from "next-auth/jwt";
const token = await encode({
  token: { sub: "canary-user", email: "canary@example.test", name: "Canary", department: "security", role: "employee" },
  secret: process.env.AUTH_SECRET,
  salt: "authjs.session-token",
  maxAge: 600,
});
process.stdout.write(token);
')"
[[ -n "$cookie" ]]

probe() {
  local expect="$1"
  docker exec -e COOKIE="$cookie" -e EXPECT="$expect" "$ui_container" node --input-type=module -e '
const headers={cookie:`authjs.session-token=${process.env.COOKIE}`};
const base="http://127.0.0.1:3100/chat";
const form=new FormData(); form.append("file",new File([new Uint8Array([0x78])],"canary.txt",{type:"text/plain"}));
const responses=await Promise.all([
  fetch(`${base}/api/models`,{headers,cache:"no-store"}),
  fetch(`${base}/api/me/records?limit=1`,{headers,cache:"no-store"}),
  fetch(`${base}/api/upload`,{method:"POST",headers,body:form}),
]);
const expected=Number(process.env.EXPECT);
if(responses.some(r=>r.status!==expected)) { console.error(responses.map(r=>r.status).join(",")); process.exit(1); }
' >/dev/null
}

probe 200
docker network disconnect "$CANARY_NETWORK" "$ui_container"
# expect=502: 三路都必须实时失败，不能返回cache或本地降级数据。
probe 502
docker network connect "$CANARY_NETWORK" "$ui_container"
probe 200

COMPOSE_PROJECT_NAME="$CANARY_CORE_PROJECT" compose -p "$CANARY_CORE_PROJECT" exec -T postgres \
  psql -U jjdguard -d jjdguard -tAc \
  "SELECT count(*) FROM audit_operations WHERE user_id='canary-user' OR payload::text LIKE '%canary-user%';" |
  awk '$1+0 > 0 {ok=1} END {exit !ok}'

printf 'portal_cp_business_smoke=ok routes=3 outage_failures=3 reconnect=3 attribution=1 alias=1\n'
