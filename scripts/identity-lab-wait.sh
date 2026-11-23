#!/usr/bin/env bash
# Wait for long-running identity-lab services and successful one-shot jobs.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
LAB_DIR="$REPO_ROOT/deploy/identity-lab"
COMPOSE_FILE="$LAB_DIR/docker-compose.identity-lab.yml"
ENV_FILE="${IDENTITY_LAB_ENV_FILE:-}"
if [ -z "$ENV_FILE" ]; then
  if [ -f "$LAB_DIR/.env" ]; then ENV_FILE="$LAB_DIR/.env"; else ENV_FILE="$LAB_DIR/.env.example"; fi
fi
[ -f "$ENV_FILE" ] || { echo "identity-lab wait failed: env file is missing" >&2; exit 1; }
TIMEOUT="${IDENTITY_LAB_WAIT_TIMEOUT:-300}"

compose() {
  docker compose -f "$COMPOSE_FILE" --env-file "$ENV_FILE" "$@"
}

container_state() {
  local service="$1" id
  id="$(compose ps -a -q "$service" 2>/dev/null)"
  if [ -z "$id" ]; then
    printf 'missing'
    return
  fi
  docker inspect -f '{{.State.Status}}|{{.State.ExitCode}}|{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' "$id"
}

for _ in $(seq 1 "$TIMEOUT"); do
  ready=1
  for service in openldap samba-ad enterprise-keycloak jjdguard-keycloak control-plane-postgres control-plane-redis control-plane portal-proxy identity-portal; do
    state="$(container_state "$service")"
    case "$state" in
      running\|0\|healthy) ;;
      running\|0\|unhealthy)
        echo "identity-lab wait failed: $service is unhealthy" >&2
        exit 1
        ;;
      exited\|*|dead\|*)
        echo "identity-lab wait failed: $service stopped before healthy" >&2
        exit 1
        ;;
      *) ready=0 ;;
    esac
  done

  for service in cert-init ldap-seed control-plane-migrate control-plane-seed portal-prisma; do
    state="$(container_state "$service")"
    case "$state" in
      exited\|0\|none) ;;
      exited\|*\|none|dead\|*)
        echo "identity-lab wait failed: $service did not complete successfully" >&2
        exit 1
        ;;
      *) ready=0 ;;
    esac
  done

  if [ "$ready" -eq 1 ]; then
    exit 0
  fi
  sleep 1
done
echo "identity-lab wait failed: services were not ready before timeout" >&2
exit 1
