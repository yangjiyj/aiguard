#!/usr/bin/env bash
# Real MCP closed-loop acceptance against isolated PostgreSQL and real services.
set -euo pipefail
# 临时容器：打测试标签、先回收被杀掉的测试进程留下的孤儿容器，清理用 docker rm -f -v（见该库说明）。
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/../lib/test-containers.sh"
jjd_test_reap_orphan_containers

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
# shellcheck source=deploy/tests/mcp_real_e2e/claude_output.sh
source "$SCRIPT_DIR/claude_output.sh"
# shellcheck source=deploy/tests/mcp_real_e2e/log_sanitize.sh
source "$SCRIPT_DIR/log_sanitize.sh"
ROOT="$(CDPATH= cd -- "$SCRIPT_DIR/../../.." && pwd)"
COMPOSE_FILE="$ROOT/deploy/docker-compose/docker-compose.yml"
RUN_ID="${MCP_E2E_RUN_ID:-$(date -u +%Y%m%d%H%M%S)-$RANDOM}"
PROJECT="jjdguard-mcp-e2e-${RUN_ID,,}"
PROJECT="${PROJECT//_/-}"
TEMP_DIR="$(mktemp -d)"
ARTIFACT_DIR="${MCP_E2E_ARTIFACT_DIR:-$ROOT/.artifacts/mcp-real-e2e/$RUN_ID}"
EVIDENCE="$ARTIFACT_DIR/evidence.json"
ENV_FILE="$TEMP_DIR/e2e.env"
OVERRIDE_FILE="$TEMP_DIR/compose.override.yml"
PSQL_BRIDGE="$TEMP_DIR/psql"
CLAUDE_HOME="$TEMP_DIR/claude-home"
mkdir -p "$ARTIFACT_DIR" "$CLAUDE_HOME"
chmod 700 "$TEMP_DIR" "$CLAUDE_HOME"

PRIMARY_CONTAINER="${PROJECT}-upstream-primary"
POISON_CONTAINER="${PROJECT}-upstream-poison"
SHADOW_CONTAINER="${PROJECT}-upstream-shadow"
KEEP="${MCP_E2E_KEEP:-0}"
# 保留现场排查时不带 owner_pid，回收不会碰；否则按测试进程打标签。
if [[ "$KEEP" == "1" ]]; then jjd_test_container_labels_kept mcp-real-e2e; else jjd_test_container_labels mcp-real-e2e; fi
COMPOSE=()

log() {
  printf '[mcp-e2e] %s\n' "$*"
}

cleanup() {
  local status=$?
  trap - EXIT INT TERM
  set +e
  if [[ "$KEEP" != "1" ]]; then
    docker rm -f -v "$PRIMARY_CONTAINER" "$POISON_CONTAINER" "$SHADOW_CONTAINER" \
      >/dev/null 2>&1 || true
    if (( ${#COMPOSE[@]} > 0 )); then
      "${COMPOSE[@]}" down -v --remove-orphans >/dev/null 2>&1 || true
    fi
    docker image rm \
      "${PROJECT}-gateway-core:latest" \
      "${PROJECT}-control-plane:latest" \
      "${PROJECT}-security-engine:latest" >/dev/null 2>&1 || true
  else
    log "keeping isolated project for diagnosis: $PROJECT"
  fi
  rm -rf "$TEMP_DIR"
  if [[ "$status" -ne 0 ]]; then
    log "FAILED; sanitized partial evidence: $EVIDENCE"
  fi
  exit "$status"
}
trap cleanup EXIT INT TERM

secret() {
  openssl rand -hex 32
}

read -r GATEWAY_PORT CONTROL_PORT SECURITY_PORT POSTGRES_PORT REDIS_PORT \
  PROXY_PORT PRIMARY_PORT POISON_PORT SHADOW_PORT < <(
  python3 - <<'PY'
import socket
sockets = []
ports = []
for _ in range(9):
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    sockets.append(s)
    ports.append(str(s.getsockname()[1]))
print(" ".join(ports))
for s in sockets:
    s.close()
PY
)

POSTGRES_PASSWORD="$(secret)"
REDIS_PASSWORD="$(secret)"
PROVIDER_SECRET="$(secret)"
INTERNAL_SECRET="$(secret)"
MCP_CONFIRMATION_SCOPE_SECRET="$(secret)"
SEMANTIC_GATEWAY_ATTESTATION_KEY="$(secret)"
RULE_ATTESTATION_SECRET="$(secret)"
AUDIT_HMAC_SECRET="$(secret)"
ADMIN_INITIAL_PASSWORD="Aa9_$(secret)"
ADMIN_NEW_PASSWORD="Bb8_$(secret)"
UPSTREAM_TOKEN="$(secret)"
CONTROL_TOKEN="$(secret)"
OTHER_TENANT_KEY="jjd_other_$(secret)"
CLAUDE_GATEWAY_KEY="jjd_claude_$(secret)"
CHAT_ONLY_KEY="jjd_chat_$(secret)"
EMPTY_SCOPE_KEY="jjd_empty_$(secret)"
DRIFT_TOKEN="$(secret)"

cat >"$ENV_FILE" <<EOF
POSTGRES_USER=jjdguard
POSTGRES_PASSWORD=$POSTGRES_PASSWORD
POSTGRES_DB=jjdguard
REDIS_PASSWORD=$REDIS_PASSWORD
JJD_PROVIDER_SECRET_KEY=$PROVIDER_SECRET
JJD_INTERNAL_API_SECRET=$INTERNAL_SECRET
MCP_CONFIRMATION_SCOPE_SECRET=$MCP_CONFIRMATION_SCOPE_SECRET
JJD_SEMANTIC_GATEWAY_ATTESTATION_KEY=$SEMANTIC_GATEWAY_ATTESTATION_KEY
JJD_RULE_PACK_ATTESTATION_TOKEN=$RULE_ATTESTATION_SECRET
JJD_RULE_PACK_ATTESTATION_TENANT=tenant_default
UAG_AUDIT_HMAC_KEY=$AUDIT_HMAC_SECRET
BOOTSTRAP_ADMIN_USERNAME=admin
BOOTSTRAP_ADMIN_EMAIL=admin@e2e.invalid
BOOTSTRAP_ADMIN_PASSWORD=$ADMIN_INITIAL_PASSWORD
SESSION_COOKIE_SECURE=false
JJD_LICENSE_ENFORCE=false
SECURITY_AUDIT_ONLY=false
MCP_GATEWAY_ENABLED=true
MCP_ALLOWED_ORIGINS=https://trusted.e2e.invalid
SECURITY_SEMANTIC_ENABLED=false
SECURITY_SEMANTIC_INPUT_ENABLED=false
SECURITY_SEMANTIC_AGENT_ENABLED=false
GATEWAY_BIND=127.0.0.1
GATEWAY_PORT=$GATEWAY_PORT
CONTROL_BIND=127.0.0.1
CONTROL_PORT=$CONTROL_PORT
SECURITY_BIND=127.0.0.1
SECURITY_PORT=$SECURITY_PORT
POSTGRES_BIND=127.0.0.1
POSTGRES_PORT=$POSTGRES_PORT
REDIS_BIND=127.0.0.1
REDIS_PORT=$REDIS_PORT
PROXY_BIND=127.0.0.1
PROXY_PORT=$PROXY_PORT
TLS_ENABLED=false
EOF
chmod 600 "$ENV_FILE"

cat >"$OVERRIDE_FILE" <<EOF
services:
  gateway-core:
    image: ${PROJECT}-gateway-core:latest
  control-plane:
    image: ${PROJECT}-control-plane:latest
  security-engine:
    image: ${PROJECT}-security-engine:latest
    environment:
      - SECURITY_AUDIT_ONLY=true
EOF

COMPOSE=(
  docker compose
  --env-file "$ENV_FILE"
  -p "$PROJECT"
  -f "$COMPOSE_FILE"
  -f "$OVERRIDE_FILE"
)

cat >"$PSQL_BRIDGE" <<'EOF'
#!/bin/sh
set -eu
exec docker compose \
  --env-file "$MCP_E2E_ENV_FILE" \
  -p "$MCP_E2E_PROJECT" \
  -f "$MCP_E2E_COMPOSE_FILE" \
  -f "$MCP_E2E_OVERRIDE_FILE" \
  exec -T postgres psql -U jjdguard -d jjdguard "$@"
EOF
chmod 700 "$PSQL_BRIDGE"
export MCP_E2E_ENV_FILE="$ENV_FILE"
export MCP_E2E_PROJECT="$PROJECT"
export MCP_E2E_COMPOSE_FILE="$COMPOSE_FILE"
export MCP_E2E_OVERRIDE_FILE="$OVERRIDE_FILE"

wait_http() {
  local url="$1"
  local label="$2"
  local attempt
  for attempt in $(seq 1 120); do
    if curl -fsS --max-time 2 "$url" >/dev/null 2>&1; then
      log "$label is ready"
      return 0
    fi
    sleep 1
  done
  log "$label did not become ready"
  return 1
}

wait_service_health() {
  local service="$1"
  local container status attempt
  container="$("${COMPOSE[@]}" ps -q "$service")"
  for attempt in $(seq 1 90); do
    status="$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' \
      "$container" 2>/dev/null || true)"
    if [[ "$status" == "healthy" || "$status" == "running" ]]; then
      log "$service is $status"
      return 0
    fi
    sleep 1
  done
  "${COMPOSE[@]}" logs --no-color --tail=80 "$service" >"$ARTIFACT_DIR/${service}.failure.log" 2>&1 || true
  return 1
}

log "running controlled MCP server contract tests"
python3 "$SCRIPT_DIR/test_mock_mcp_server.py"
"$SCRIPT_DIR/test_claude_output.sh"
"$SCRIPT_DIR/test_log_sanitize.sh"

log "starting isolated PostgreSQL and Redis"
"${COMPOSE[@]}" up -d postgres redis
wait_service_health postgres
wait_service_health redis

# pg_isready becomes true for the temporary postmaster while the official
# entrypoint is still applying initdb scripts. Wait for the explicit handoff to
# the final postmaster before invoking the production migration runner.
postgres_container="$("${COMPOSE[@]}" ps -q postgres)"
init_complete=false
for _ in $(seq 1 120); do
  if docker logs "$postgres_container" 2>&1 |
      grep -q 'PostgreSQL init process complete'; then
    init_complete=true
    break
  fi
  sleep 1
done
if [[ "$init_complete" != "true" ]]; then
  log "PostgreSQL initdb did not complete"
  exit 1
fi
wait_service_health postgres

log "applying all private migrations to real PostgreSQL"
MIGRATION_PSQL="$PSQL_BRIDGE" \
  bash "$ROOT/deploy/lib/migration-runner.sh" \
  --migrations-dir "$ROOT/deploy/migrations" \
  >"$ARTIFACT_DIR/migrations.log"

NETWORK="${PROJECT}_jjdguard-net"
run_upstream() {
  local container="$1"
  local alias="$2"
  local port="$3"
  docker run "${JJD_TEST_CONTAINER_LABELS[@]}" -d --rm \
    --name "$container" \
    --network "$NETWORK" \
    --network-alias "$alias" \
    -p "127.0.0.1:${port}:9808" \
    -v "$SCRIPT_DIR/mock_mcp_server.py:/app/mock_mcp_server.py:ro" \
    -e "MCP_E2E_UPSTREAM_TOKEN=$UPSTREAM_TOKEN" \
    -e "MCP_E2E_CALLER_TOKEN=$CLAUDE_GATEWAY_KEY" \
    -e "MCP_E2E_CONTROL_TOKEN=$CONTROL_TOKEN" \
    -e "MCP_E2E_SERVER_NAME=$alias" \
    python:3.12-alpine \
    python /app/mock_mcp_server.py --name "$alias" >/dev/null
}

log "starting three isolated MCP upstream fixtures"
run_upstream "$PRIMARY_CONTAINER" mcp-primary "$PRIMARY_PORT"
run_upstream "$POISON_CONTAINER" mcp-poison "$POISON_PORT"
run_upstream "$SHADOW_CONTAINER" mcp-shadow "$SHADOW_PORT"

wait_upstream() {
  local port="$1"
  local attempt
  for attempt in $(seq 1 60); do
    if curl -fsS --max-time 2 \
      -H "X-E2E-Control-Token: $CONTROL_TOKEN" \
      "http://127.0.0.1:${port}/__state" >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  return 1
}
wait_upstream "$PRIMARY_PORT"
wait_upstream "$POISON_PORT"
wait_upstream "$SHADOW_PORT"

log "building and starting real control-plane, security-engine, and gateway"
build_output="$TEMP_DIR/services-build.log"
if ! "${COMPOSE[@]}" up -d --build security-engine control-plane gateway-core \
    2>&1 | tee "$build_output"; then
  sanitize_mcp_e2e_log "$build_output" "$ARTIFACT_DIR/services-build.failure.log"
  for service in control-plane security-engine gateway-core; do
    "${COMPOSE[@]}" logs --no-color --tail=160 "$service" \
      >"$ARTIFACT_DIR/${service}.failure.log" 2>&1 || true
  done
  exit 1
fi
wait_service_health security-engine
wait_service_health control-plane
wait_service_health gateway-core
wait_http "http://127.0.0.1:${CONTROL_PORT}/health" control-plane
wait_http "http://127.0.0.1:${GATEWAY_PORT}/health" gateway-core

other_hash="$(printf '%s' "$OTHER_TENANT_KEY" | sha256sum | awk '{print $1}')"
other_prefix="${OTHER_TENANT_KEY:0:8}"
claude_hash="$(printf '%s' "$CLAUDE_GATEWAY_KEY" | sha256sum | awk '{print $1}')"
claude_prefix="${CLAUDE_GATEWAY_KEY:0:8}"
chat_hash="$(printf '%s' "$CHAT_ONLY_KEY" | sha256sum | awk '{print $1}')"
chat_prefix="${CHAT_ONLY_KEY:0:8}"
empty_hash="$(printf '%s' "$EMPTY_SCOPE_KEY" | sha256sum | awk '{print $1}')"
empty_prefix="${EMPTY_SCOPE_KEY:0:8}"
"$PSQL_BRIDGE" -v ON_ERROR_STOP=1 >/dev/null <<SQL
INSERT INTO tenants (id,name,edition,status)
VALUES ('tenant_mcp_e2e_other','MCP E2E Other','enterprise','active');
INSERT INTO projects (id,tenant_id,name,status)
VALUES ('project_mcp_e2e_other','tenant_mcp_e2e_other','MCP E2E Other','active');
INSERT INTO internal_keys
  (id,tenant_id,project_id,key_hash,key_prefix,scopes_json,status)
VALUES
  ('key_mcp_e2e_other','tenant_mcp_e2e_other','project_mcp_e2e_other',
   '$other_hash','$other_prefix','["mcp"]'::jsonb,'active');
INSERT INTO internal_keys
  (id,tenant_id,project_id,key_hash,key_prefix,scopes_json,status)
VALUES
  ('key_mcp_e2e_claude','tenant_default','project_default',
   '$claude_hash','$claude_prefix','["mcp"]'::jsonb,'active'),
  ('key_mcp_e2e_chat','tenant_default','project_default',
   '$chat_hash','$chat_prefix','["chat"]'::jsonb,'active'),
  ('key_mcp_e2e_empty','tenant_default','project_default',
   '$empty_hash','$empty_prefix','[]'::jsonb,'active');
SQL

log "running spec client through the public MCP gateway"
MCP_E2E_ADMIN_INITIAL_PASSWORD="$ADMIN_INITIAL_PASSWORD" \
MCP_E2E_ADMIN_NEW_PASSWORD="$ADMIN_NEW_PASSWORD" \
MCP_E2E_UPSTREAM_TOKEN="$UPSTREAM_TOKEN" \
MCP_E2E_CONTROL_TOKEN="$CONTROL_TOKEN" \
MCP_E2E_OTHER_TENANT_KEY="$OTHER_TENANT_KEY" \
MCP_E2E_CHAT_ONLY_KEY="$CHAT_ONLY_KEY" \
MCP_E2E_EMPTY_SCOPE_KEY="$EMPTY_SCOPE_KEY" \
MCP_E2E_GATEWAY_KEY="$CLAUDE_GATEWAY_KEY" \
MCP_E2E_DRIFT_TOKEN="$DRIFT_TOKEN" \
python3 "$SCRIPT_DIR/spec_client.py" \
  --gateway-url "http://127.0.0.1:$GATEWAY_PORT" \
  --control-url "http://127.0.0.1:$CONTROL_PORT" \
  --primary-upstream-url "http://mcp-primary:9808/mcp" \
  --poison-upstream-url "http://mcp-poison:9808/mcp" \
  --shadow-upstream-url "http://mcp-shadow:9808/mcp" \
  --primary-control-url "http://127.0.0.1:$PRIMARY_PORT" \
  --poison-control-url "http://127.0.0.1:$POISON_PORT" \
  --shadow-control-url "http://127.0.0.1:$SHADOW_PORT" \
  --evidence "$EVIDENCE"

log "checking Claude Code remote HTTP MCP transport"
claude_supported=false
claude_connected=false
claude_version=""
if command -v claude >/dev/null 2>&1; then
  claude_version="$(claude --version 2>/dev/null | head -1 | tr -cd '[:alnum:]._-')"
  if claude mcp add --help 2>&1 | grep -q -- '--transport <transport>'; then
    claude_supported=true
    primary_server_id="$(
      python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["objects"]["primary_server"])' \
      "$EVIDENCE"
    )"
    HOME="$CLAUDE_HOME" claude mcp add \
      --scope user \
      --transport http \
      jjdguard-real-e2e \
      "http://127.0.0.1:${GATEWAY_PORT}/mcp/${primary_server_id}" \
      --header 'Authorization: Bearer ${MCP_E2E_GATEWAY_KEY}' \
      --header 'X-JJDGuard-Session-Id: e2e-claude-code' \
      >/dev/null 2>&1
    if MCP_E2E_GATEWAY_KEY="$CLAUDE_GATEWAY_KEY" HOME="$CLAUDE_HOME" \
      timeout 20 claude mcp get jjdguard-real-e2e \
      >"$TEMP_DIR/claude-mcp.out" 2>&1; then
      if claude_mcp_output_connected "$TEMP_DIR/claude-mcp.out"; then
        claude_connected=true
      fi
    fi
  fi
fi
if [[ "$claude_supported" == "true" && "$claude_connected" != "true" ]]; then
  log "Claude Code supports remote HTTP MCP but the isolated connection smoke failed"
  exit 1
fi

log "collecting sanitized PostgreSQL evidence"
db_summary="$("$PSQL_BRIDGE" -tAc "
SELECT json_build_object(
  'database','postgresql',
  'migration_max',(SELECT max(version) FROM schema_migrations),
  'mcp_servers',(SELECT count(*) FROM mcp_servers),
  'mcp_tools',(SELECT count(*) FROM mcp_tools),
  'mcp_tool_logs',(SELECT count(*) FROM tool_call_logs WHERE tool_type='mcp'),
  'mcp_confirmations',(SELECT count(*) FROM agentguard_confirmations WHERE source='mcp'),
  'mcp_execution_rows',(SELECT count(*) FROM mcp_confirmation_executions),
  'executed_rows',(SELECT count(*) FROM mcp_confirmation_executions WHERE execution_status='executed'),
  'drift_failed_rows',(SELECT count(*) FROM mcp_confirmation_executions WHERE execution_status='failed' AND error_code='approval_context_drift'),
  'drift_execution_forwarded_rows',(SELECT count(*) FROM tool_call_logs WHERE tool_type='mcp' AND session_id='e2e-drift' AND event_kind='execution_forwarded' AND COALESCE(execution_observed,FALSE)),
  'drift_blocked_preflight_rows',(SELECT count(*) FROM tool_call_logs WHERE tool_type='mcp' AND session_id='e2e-drift' AND event_kind='invocation_proposed' AND effective_decision='block' AND NOT COALESCE(execution_observed,FALSE)),
  'plaintext_argument_rows',(SELECT count(*) FROM agentguard_confirmations WHERE source='mcp' AND COALESCE(tool_call_arguments,'')<>''),
  'encrypted_replay_rows',(SELECT count(*) FROM mcp_confirmation_executions WHERE replay_context_ciphertext LIKE 'enc:v1:%'),
  'encrypted_upstream_auth',(SELECT bool_and(auth_ciphertext LIKE 'enc:v1:%') FROM mcp_servers),
  'quarantined_servers',(SELECT count(*) FROM mcp_servers WHERE admission_status='quarantined'),
  'quarantined_tools',(SELECT count(*) FROM mcp_tools WHERE admission_status='quarantined')
);")"

MCP_E2E_DB_SUMMARY="$db_summary" \
MCP_E2E_CLAUDE_SUPPORTED="$claude_supported" \
MCP_E2E_CLAUDE_CONNECTED="$claude_connected" \
MCP_E2E_CLAUDE_VERSION="$claude_version" \
python3 - "$EVIDENCE" <<'PY'
import json
import os
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
evidence = json.loads(path.read_text())
evidence["database_evidence"] = json.loads(os.environ["MCP_E2E_DB_SUMMARY"])
evidence["claude_code"] = {
    "version": os.environ.get("MCP_E2E_CLAUDE_VERSION", ""),
    "remote_http_supported": os.environ["MCP_E2E_CLAUDE_SUPPORTED"] == "true",
    "connection_smoke_passed": os.environ["MCP_E2E_CLAUDE_CONNECTED"] == "true",
    "raw_output_retained": False,
}
db = evidence["database_evidence"]
required = (
    db["mcp_confirmations"] == 2
    and db["mcp_execution_rows"] == 2
    and db["executed_rows"] == 1
    and db["drift_failed_rows"] == 1
    and db["drift_execution_forwarded_rows"] == 0
    and db["drift_blocked_preflight_rows"] >= 1
    and db["plaintext_argument_rows"] == 0
    and db["encrypted_replay_rows"] == 2
    and db["encrypted_upstream_auth"] is True
)
evidence["checks"].append({
    "name": "postgres_evidence_invariants",
    "passed": required,
})
evidence["passed"] = bool(evidence["passed"] and required)
path.write_text(json.dumps(evidence, ensure_ascii=False, indent=2) + "\n")
if not evidence["passed"]:
    raise SystemExit(1)
PY

log "PASS; evidence: $EVIDENCE"
log "isolated containers, network, volumes, credentials, and test data will now be removed"
