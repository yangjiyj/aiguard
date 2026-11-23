#!/usr/bin/env bash
# W28-T16-isolated-e2e-vm-20260926: isolated T16 CP/GW real E2E on jjdguard-vm.
#
# Rewritten from the home-only version of this script (which required
# offline buildx named build-context inputs: release-go-cache /
# release-alpine-runtime / release-security-python-deps, none of which exist
# on this VM). This VM has normal outbound network access and no
# docker-buildx-driven offline image pipeline for this repo, so this version
# follows the VM's own proven T03 pattern instead:
#   - postgres + redis run as isolated, uniquely-named, loopback-only Docker
#     containers (bridge network, port-mapped, not host network).
#   - control-plane and gateway-core are built with `go build` and run as
#     plain background processes bound to 127.0.0.1 (same approach already
#     verified working for the T03 stack's start.sh on this VM).
#   - security-engine runs as a real Python/uvicorn process in a throwaway
#     venv (no Docker image), since T16's counter-example requires a live,
#     non-vacuous semantic Judge per the original script's own comment.
# No product verification logic (license issuer/signature checks, T13/T16
# authorization semantics) is touched by this rewrite.
set -euo pipefail
# 临时容器：打测试标签、先回收被杀掉的测试进程留下的孤儿容器，清理用 docker rm -f -v（见该库说明）。
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/../lib/test-containers.sh"
jjd_test_reap_orphan_containers
jjd_test_container_labels t16-real-e2e
SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
ROOT="$(CDPATH= cd -- "$SCRIPT_DIR/../../.." && pwd)"
RUN_ID="$(date -u +%Y%m%d%H%M%S)-$(openssl rand -hex 4)"
PREFIX="w28-t16"
WORKDIR_BASE="/home/dev/tmp/w28"
RUNDIR="$WORKDIR_BASE/run-$RUN_ID"
GO_LOCK="/home/dev/tmp/wave3-go.lock"
ARTIFACT_DIR="${T16_E2E_ARTIFACT_DIR:?T16_E2E_ARTIFACT_DIR must be set}"

if [[ -e "$ARTIFACT_DIR" ]]; then
  printf '[t16-e2e] refusing to overwrite existing artifact directory\n' >&2
  exit 2
fi
mkdir -p "$ARTIFACT_DIR"
mkdir -p "$RUNDIR"
chmod 700 "$RUNDIR"
RUN_LOG="$RUNDIR/fixture.log"
exec > >(tee -a "$RUN_LOG") 2>&1
log() { printf '[t16-e2e] %s\n' "$*"; }

# Fixed, contract-mandated port block (28390-28399), loopback-only.
GATEWAY_PORT=28390
PROXY_PORT=28391
CONTROL_PORT=28392
SECURITY_PORT=28393
POSTGRES_PORT=28394
REDIS_PORT=28395
for p in $GATEWAY_PORT $PROXY_PORT $CONTROL_PORT $SECURITY_PORT $POSTGRES_PORT $REDIS_PORT; do
  if [[ -n "$(ss -H -ltn "( sport = :$p )" 2>/dev/null)" ]]; then
    printf '[t16-e2e] REFUSE: port %s already occupied\n' "$p" >&2
    exit 75
  fi
done

PG_CONTAINER="$PREFIX-postgres-$RUN_ID"
REDIS_CONTAINER="$PREFIX-redis-$RUN_ID"
CP_PID_FILE="$RUNDIR/control-plane.pid"
GW_PID_FILE="$RUNDIR/gateway-core.pid"
SEC_PID_FILE="$RUNDIR/security-engine.pid"
CP_LOG="$RUNDIR/control-plane.log"
GW_LOG="$RUNDIR/gateway-core.log"
SEC_LOG="$RUNDIR/security-engine.log"
BIN_DIR="$RUNDIR/bin"
VENV_DIR="$RUNDIR/venv"
mkdir -p "$BIN_DIR"

CLEANUP_DONE=0
cleanup() {
  local status=$?
  trap - EXIT INT TERM
  set +e
  if [[ "$CLEANUP_DONE" == "0" ]]; then
    CLEANUP_DONE=1
    log "cleanup: stopping any running w28-t16 processes and containers"
    for pidfile in "$CP_PID_FILE" "$GW_PID_FILE" "$SEC_PID_FILE"; do
      if [[ -f "$pidfile" ]]; then
        pid="$(cat "$pidfile" 2>/dev/null || true)"
        if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
          kill "$pid" 2>/dev/null || true
          for _ in $(seq 1 20); do kill -0 "$pid" 2>/dev/null || break; sleep 0.5; done
          kill -9 "$pid" 2>/dev/null || true
        fi
      fi
    done
    docker rm -f -v "$PG_CONTAINER" "$REDIS_CONTAINER" >/dev/null 2>&1 || true
    docker volume rm -f "$PG_CONTAINER-data" >/dev/null 2>&1 || true
  fi
  exit "$status"
}
trap cleanup EXIT INT TERM

secret() { openssl rand -hex 32; }
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

log "generating one-run agent_security license fixture (test issuer=product-fixed value, trust=one-off test public key only, per T03 event136 precedent)"
LICENSE_FILE="$RUNDIR/license.json"
(cd "$ROOT/apps/control-plane" && flock "$GO_LOCK" env -u DATABASE_URL -u REDIS_URL PATH=/home/dev/.local/go/bin:/usr/bin:/bin GOWORK=off GOFLAGS=-buildvcs=false GOPROXY=https://goproxy.cn,direct /home/dev/.local/go/bin/go run -tags t16e2e ./internal/testtools/t16licensegen) >"$LICENSE_FILE"
chmod 600 "$LICENSE_FILE"
LICENSE_KEYS="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["public_keys"])' "$LICENSE_FILE")"
LICENSE_FIXTURE_KID="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["key_id"])' "$LICENSE_FILE")"
LICENSE_FIXTURE_ISSUER_CLAIM="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["issuer_claim"])' "$LICENSE_FILE")"
LICENSE_FIXTURE_PUBKEY_SHA256="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["public_key_sha256"])' "$LICENSE_FILE")"

log "starting isolated PostgreSQL 16 container ($PG_CONTAINER) on 127.0.0.1:$POSTGRES_PORT"
docker run "${JJD_TEST_CONTAINER_LABELS[@]}" -d --name "$PG_CONTAINER" \
  -p "127.0.0.1:$POSTGRES_PORT:5432" \
  -e "POSTGRES_USER=jjdguard" \
  -e "POSTGRES_PASSWORD=$POSTGRES_PASSWORD" \
  -e "POSTGRES_DB=jjdguard" \
  postgres:16-alpine >/dev/null

log "starting isolated Redis container ($REDIS_CONTAINER) on 127.0.0.1:$REDIS_PORT"
docker run "${JJD_TEST_CONTAINER_LABELS[@]}" -d --name "$REDIS_CONTAINER" \
  -p "127.0.0.1:$REDIS_PORT:6379" \
  redis:7-alpine redis-server --requirepass "$REDIS_PASSWORD" >/dev/null

PSQL_BRIDGE="$RUNDIR/psql.sh"
cat >"$PSQL_BRIDGE" <<EOF
#!/bin/sh
set -eu
exec docker exec -i -e PGPASSWORD="$POSTGRES_PASSWORD" "$PG_CONTAINER" psql -X -U jjdguard -d jjdguard "\$@"
EOF
chmod 700 "$PSQL_BRIDGE"

wait_pg() {
  for _ in $(seq 1 90); do
    if docker exec "$PG_CONTAINER" pg_isready -U jjdguard -d jjdguard >/dev/null 2>&1; then log "postgres ready"; return 0; fi
    sleep 1
  done
  log "postgres did not become ready"; return 1
}
wait_redis() {
  for _ in $(seq 1 90); do
    if docker exec "$REDIS_CONTAINER" redis-cli -a "$REDIS_PASSWORD" --no-auth-warning ping 2>/dev/null | grep -q PONG; then log "redis ready"; return 0; fi
    sleep 1
  done
  log "redis did not become ready"; return 1
}
wait_pg
wait_redis

log "applying baseline migrations and confirming the documented pre-seed stop at 003"
if MIGRATION_PSQL="$PSQL_BRIDGE" bash "$ROOT/deploy/lib/migration-runner.sh" --migrations-dir "$ROOT/deploy/migrations" >"$RUNDIR/migrations-first.log" 2>&1; then
  log "runner unexpectedly crossed the documented pre-seed stop"
  exit 1
fi
if ! grep -q "migration failed at 003_private_deployment.sql" "$RUNDIR/migrations-first.log" || ! grep -q "user_admin" "$RUNDIR/migrations-first.log"; then
  log "migration runner failed outside its documented pre-seed boundary"
  cat "$RUNDIR/migrations-first.log"
  exit 1
fi
log "applying checked-in 002 baseline seed, which the production runner excludes"
awk '/^[[:space:]]*--[[:space:]]*\+?goose[[:space:]]+Down([[:space:]]|$)/ { exit } { print }' "$ROOT/deploy/migrations/002_seed_data.sql" | "$PSQL_BRIDGE" -X -v ON_ERROR_STOP=1
log "re-running production migration runner from the pre-seed boundary"
if ! MIGRATION_PSQL="$PSQL_BRIDGE" bash "$ROOT/deploy/lib/migration-runner.sh" --migrations-dir "$ROOT/deploy/migrations" >"$RUNDIR/migrations.log" 2>&1; then
  log "source migration runner failed after baseline seed"
  cat "$RUNDIR/migrations.log"
  exit 1
fi
log "retiring the 002 demo ruleset_default/tenant_demo row so it cannot shadow migration 010's tenant_default row"
"$PSQL_BRIDGE" -X -v ON_ERROR_STOP=1 -c "
  DO \$\$
  BEGIN
    IF EXISTS (SELECT 1 FROM rule_sets WHERE id='ruleset_default' AND tenant_id='tenant_demo') THEN
      DELETE FROM rules WHERE rule_set_id='ruleset_default';
      DELETE FROM rule_sets WHERE id='ruleset_default' AND tenant_id='tenant_demo';
    END IF;
  END
  \$\$;
"

log "building control-plane and gateway-core from source (flock-serialized go build)"
build_go_binary() {
  local component="$1" pkg="$2"
  ( cd "$ROOT/apps/$component" && flock "$GO_LOCK" env -u DATABASE_URL -u REDIS_URL PATH=/home/dev/.local/go/bin:/usr/bin:/bin CGO_ENABLED=0 GOOS=linux GOWORK=off GOFLAGS=-buildvcs=false GOPROXY=https://goproxy.cn,direct /home/dev/.local/go/bin/go build -o "$BIN_DIR/$component" "$pkg" )
}
build_go_binary control-plane ./cmd/server
build_go_binary gateway-core ./cmd/server
log "go binaries built: $BIN_DIR/control-plane, $BIN_DIR/gateway-core"

log "provisioning security-engine venv and installing dependencies (network install, no docker image)"
python3 -m venv "$VENV_DIR"
"$VENV_DIR/bin/pip" install --quiet --upgrade pip >/dev/null
"$VENV_DIR/bin/pip" install --quiet 'fastapi>=0.115.0' 'uvicorn[standard]>=0.32.0' 'pydantic>=2.10.0' 'httpx>=0.28.0' 'regex>=2024.11.6,<2027.0.0' >"$RUNDIR/pip-install.log" 2>&1
log "security-engine core deps installed"

DATABASE_URL="postgres://jjdguard:$POSTGRES_PASSWORD@127.0.0.1:$POSTGRES_PORT/jjdguard?sslmode=disable"
REDIS_URL="redis://:$REDIS_PASSWORD@127.0.0.1:$REDIS_PORT/0"
SECURITY_ENGINE_URL="http://127.0.0.1:$SECURITY_PORT"
CONTROL_PLANE_URL="http://127.0.0.1:$CONTROL_PORT"
GATEWAY_CORE_URL="http://127.0.0.1:$GATEWAY_PORT"

log "starting security-engine (SECURITY_AUDIT_ONLY=true; never touches the production audit-only baseline)"
( cd "$ROOT/apps/security-engine" && exec env \
  SECURITY_AUDIT_ONLY=true SECURITY_FILE_CONTENT_DLP_ENABLED=false PYTHONPATH="$ROOT/apps/security-engine" \
  JJD_INTERNAL_API_SECRET="$INTERNAL_SECRET" \
  "$VENV_DIR/bin/python" -m uvicorn app.main:app --host 127.0.0.1 --port "$SECURITY_PORT" >"$SEC_LOG" 2>&1 ) &
echo $! >"$SEC_PID_FILE"
wait_http() {
  local url="$1" label="$2"
  for _ in $(seq 1 120); do
    if curl -fsS --max-time 2 "$url" >/dev/null 2>&1; then log "$label ready"; return 0; fi
    sleep 1
  done
  log "$label did not become ready"; return 1
}
wait_http "$SECURITY_ENGINE_URL/health" security-engine

log "starting control-plane and gateway-core as background processes bound to 127.0.0.1"
( cd "$ROOT/apps/control-plane" && exec env \
  DATABASE_URL="$DATABASE_URL" REDIS_URL="$REDIS_URL" SECURITY_ENGINE_URL="$SECURITY_ENGINE_URL" \
  LISTEN_ADDR="127.0.0.1:$CONTROL_PORT" GATEWAY_ENVIRONMENT_SCOPE=w28-t16-e2e \
  JJD_PROVIDER_SECRET_KEY="$PROVIDER_SECRET" JJD_INTERNAL_API_SECRET="$INTERNAL_SECRET" \
  MCP_CONFIRMATION_SCOPE_SECRET="$MCP_CONFIRMATION_SCOPE_SECRET" \
  JJD_SEMANTIC_GATEWAY_ATTESTATION_KEY="$SEMANTIC_GATEWAY_ATTESTATION_KEY" \
  JJD_RULE_PACK_ATTESTATION_TOKEN="$RULE_ATTESTATION_SECRET" JJD_RULE_PACK_ATTESTATION_TENANT=tenant_default \
  UAG_AUDIT_HMAC_KEY="$AUDIT_HMAC_SECRET" \
  BOOTSTRAP_ADMIN_USERNAME=admin BOOTSTRAP_ADMIN_EMAIL=admin@t16-e2e.invalid BOOTSTRAP_ADMIN_PASSWORD="$ADMIN_INITIAL_PASSWORD" \
  SESSION_COOKIE_SECURE=false JJD_LICENSE_ENFORCE=false JJD_LICENSE_PUBLIC_KEYS="$LICENSE_KEYS" \
  SECURITY_AUDIT_ONLY=false AGENT_ENDPOINT_ENABLED=true MCP_GATEWAY_ENABLED=false MCP_ALLOWED_ORIGINS=https://t16-e2e.invalid \
  SECURITY_SEMANTIC_ENABLED=true SECURITY_SEMANTIC_INPUT_ENABLED=true SECURITY_SEMANTIC_AGENT_ENABLED=true \
  TLS_ENABLED=false GOWORK=off GOFLAGS=-buildvcs=false \
  "$BIN_DIR/control-plane" >"$CP_LOG" 2>&1 ) &
echo $! >"$CP_PID_FILE"
wait_http "$CONTROL_PLANE_URL/health" control-plane

( cd "$ROOT/apps/gateway-core" && exec env \
  DATABASE_URL="$DATABASE_URL" REDIS_URL="$REDIS_URL" SECURITY_ENGINE_URL="$SECURITY_ENGINE_URL" \
  CONTROL_PLANE_URL="$CONTROL_PLANE_URL" \
  LISTEN_ADDR="127.0.0.1:$GATEWAY_PORT" PROXY_LISTEN_ADDR="127.0.0.1:$PROXY_PORT" GATEWAY_ENVIRONMENT_SCOPE=w28-t16-e2e \
  JJD_PROVIDER_SECRET_KEY="$PROVIDER_SECRET" JJD_INTERNAL_API_SECRET="$INTERNAL_SECRET" \
  MCP_CONFIRMATION_SCOPE_SECRET="$MCP_CONFIRMATION_SCOPE_SECRET" \
  JJD_SEMANTIC_GATEWAY_ATTESTATION_KEY="$SEMANTIC_GATEWAY_ATTESTATION_KEY" \
  JJD_RULE_PACK_ATTESTATION_TOKEN="$RULE_ATTESTATION_SECRET" JJD_RULE_PACK_ATTESTATION_TENANT=tenant_default \
  UAG_AUDIT_HMAC_KEY="$AUDIT_HMAC_SECRET" \
  SECURITY_AUDIT_ONLY=false AGENT_ENDPOINT_ENABLED=true MCP_GATEWAY_ENABLED=false MCP_ALLOWED_ORIGINS=https://t16-e2e.invalid \
  SECURITY_SEMANTIC_ENABLED=true SECURITY_SEMANTIC_INPUT_ENABLED=true SECURITY_SEMANTIC_AGENT_ENABLED=true \
  TLS_ENABLED=false GOWORK=off GOFLAGS=-buildvcs=false \
  "$BIN_DIR/gateway-core" >"$GW_LOG" 2>&1 ) &
echo $! >"$GW_PID_FILE"
wait_http "$GATEWAY_CORE_URL/health" gateway-core

log "running CP admin, endpoint, T13/T16 decide, T02 event, lineage, and revoke flow"
T16_E2E_ADMIN_INITIAL_PASSWORD="$ADMIN_INITIAL_PASSWORD" T16_E2E_ADMIN_NEW_PASSWORD="$ADMIN_NEW_PASSWORD" T16_E2E_LICENSE_FILE="$LICENSE_FILE" \
python3 "$SCRIPT_DIR/client.py" --control-url "$CONTROL_PLANE_URL" --gateway-url "$GATEWAY_CORE_URL" --run-id "$RUN_ID" --evidence "$ARTIFACT_DIR/evidence.json" --state "$RUNDIR/state.json"

task_id="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["task_id"])' "$RUNDIR/state.json")"
endpoint_id="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["endpoint_id"])' "$RUNDIR/state.json")"
adversarial_tool_id="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["fetch_adversarial_tool_id"])' "$RUNDIR/state.json")"
deviation_tool_id="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["fetch_undergranted_tool_id"])' "$RUNDIR/state.json")"
fetch_task_id="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["fetch_task_id"])' "$RUNDIR/state.json")"
adversarial_raw_http="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["adversarial_raw_decision"])' "$RUNDIR/state.json")"
adversarial_effective_http="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["adversarial_effective_decision"])' "$RUNDIR/state.json")"
deviation_raw_http="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["deviation_raw_decision"])' "$RUNDIR/state.json")"
deviation_effective_http="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["deviation_effective_decision"])' "$RUNDIR/state.json")"
log "asserting persisted migration, task revocation, endpoint activation, T13 authorize count, and DB-side tool_call_logs decisions match what client.py observed over HTTP"
# NOTE (W28): the previous version of this block asserted agent_intent_task_steps
# rows (step1_auth=="allowed", two_server_bound_steps==2, source_refs lineage,
# t13_allowed_count==6, history_ref_hash length 71). That block was written
# against an earlier client.py design and was never actually run (see this
# branch's prior commit "接入 license_fixture 声明字段（未跑通验证）"). The
# current client.py deliberately never reaches an "allowed" file-type decide()
# outcome: every type="file" decide() call structurally hits the builtin
# SSH-key PathGlob ambiguity and returns 503 AGENT_POLICY_UNAVAILABLE by design
# (see client.py's decide() docstring and
# apps/gateway-core/internal/endpointpolicy/bundle.go's compileGlob). No
# agent_intent_task_steps row is ever created by this fixture; asserting on
# that table here was asserting behavior the fixture cannot produce. This
# rewritten block instead: (a) fixes a real bug (schema_migrations.version is
# the full filename, not the numeric prefix, so the old
# WHERE version='873' could never match), and (b) cross-checks tool_call_logs
# directly against the same two WebFetch calls client.py already verified over
# HTTP (categories 2 and 3 in client.py), so a server that lied over HTTP
# without persisting would be caught. t13_allowed_count is exactly 11: three
# type=file authorize() calls (2 facets each) + three WebFetch
# authorize_webfetch() calls (2+2+1 facets for normal/adversarial/deviation).
"$PSQL_BRIDGE" -qAt -v task_id="$task_id" -v endpoint_id="$endpoint_id" -v adversarial_tool_id="$adversarial_tool_id" -v deviation_tool_id="$deviation_tool_id" -v fetch_task_id="$fetch_task_id" <<'SQL' >"$ARTIFACT_DIR/db-summary.json"
SELECT json_build_object(
 'postgres_version',version(),
 'migration_873',EXISTS(SELECT 1 FROM schema_migrations WHERE version='873_agent_intent_tasks.sql'),
 'task_state',(SELECT state FROM agent_intent_tasks WHERE id=:'task_id'::uuid),
 'task_grant_count',(SELECT count(*) FROM agent_intent_task_grants WHERE task_id=:'task_id'::uuid),
 'endpoint_active',EXISTS(SELECT 1 FROM agent_endpoints WHERE id=:'endpoint_id' AND status='active'),
 't13_allowed_count',(SELECT count(*) FROM agent_authorization_requests WHERE state='complete' AND decision_json->>'allowed'='true'),
 't13_denied_count',(SELECT count(*) FROM agent_authorization_requests WHERE state='complete' AND decision_json->>'allowed'='false'),
 'fetch_task_steps',(SELECT COALESCE(json_agg(json_build_object('seq',server_sequence,'tool',tool_name,'action',action,
   'auth',authorization_state,'lineage',lineage_state,'outcome',terminal_outcome,'result_hash_len',length(COALESCE(result_hash,'')),
   'source_refs',source_refs) ORDER BY server_sequence),'[]'::json) FROM agent_intent_task_steps WHERE task_id=:'fetch_task_id'::uuid),
 'adversarial_raw_decision_db',(SELECT raw_decision FROM tool_call_logs WHERE endpoint_id=:'endpoint_id' AND tool_call_id=:'adversarial_tool_id' ORDER BY created_at DESC,id DESC LIMIT 1),
 'adversarial_effective_decision_db',(SELECT effective_decision FROM tool_call_logs WHERE endpoint_id=:'endpoint_id' AND tool_call_id=:'adversarial_tool_id' ORDER BY created_at DESC,id DESC LIMIT 1),
 'deviation_raw_decision_db',(SELECT raw_decision FROM tool_call_logs WHERE endpoint_id=:'endpoint_id' AND tool_call_id=:'deviation_tool_id' ORDER BY created_at DESC,id DESC LIMIT 1),
 'deviation_effective_decision_db',(SELECT effective_decision FROM tool_call_logs WHERE endpoint_id=:'endpoint_id' AND tool_call_id=:'deviation_tool_id' ORDER BY created_at DESC,id DESC LIMIT 1)
)::text;
SQL
python3 - "$ARTIFACT_DIR/evidence.json" "$ARTIFACT_DIR/db-summary.json" "$adversarial_raw_http" "$adversarial_effective_http" "$deviation_raw_http" "$deviation_effective_http" <<'PY'
import json, pathlib, sys
evidence_path, summary_path = map(pathlib.Path, sys.argv[1:3])
adversarial_raw_http, adversarial_effective_http, deviation_raw_http, deviation_effective_http = sys.argv[3:7]
evidence, summary = json.loads(evidence_path.read_text()), json.loads(summary_path.read_text())
steps = summary["fetch_task_steps"]
checks = {
 "migration_873_applied": summary["migration_873"] is True,
 "endpoint_active": summary["endpoint_active"] is True,
 "task_revoked_via_cp": summary["task_state"] == "revoked",
 "both_task_grant_snapshots": summary["task_grant_count"] == 2,
 "eleven_exact_t13_calls_allowed": summary["t13_allowed_count"] == 11,
 "one_exact_t13_network_connect_denied": summary["t13_denied_count"] == 1,
 "three_server_ledger_steps_for_webfetch_task": [s["seq"] for s in steps] == [1, 2, 3],
 "step1_allowed_and_terminal_result_attached": len(steps) == 3 and steps[0]["auth"] == "allowed"
    and steps[0]["lineage"] == "server_task_record" and steps[0]["outcome"] == "succeeded" and steps[0]["result_hash_len"] == 64,
 "step2_cites_step1_accepted_result": len(steps) == 3 and len(steps[1]["source_refs"]) == 1
    and steps[1]["source_refs"][0].get("lineage_state") == "accepted_result_hash_match"
    and str(steps[1]["source_refs"][0].get("linked_step_sequence")) == "1",
 "step3_out_of_scope_egress_not_allowed_in_ledger": len(steps) == 3 and steps[2]["auth"] in ("denied", "scope_mismatch")
    and steps[2]["lineage"] == "uncertain",
 "adversarial_decision_persisted_matches_http": (summary["adversarial_raw_decision_db"] == adversarial_raw_http
    and summary["adversarial_effective_decision_db"] == adversarial_effective_http),
 "deviation_decision_persisted_matches_http": (summary["deviation_raw_decision_db"] == deviation_raw_http
    and summary["deviation_effective_decision_db"] == deviation_effective_http),
}
evidence["database_summary"] = summary
evidence["database_checks"] = [{"name": k, "passed": v} for k,v in checks.items()]
evidence["passed"] = bool(evidence["passed"]) and all(checks.values())
evidence_path.write_text(json.dumps(evidence, ensure_ascii=False, indent=2) + "\n")
if not evidence["passed"]:
    raise SystemExit("T16 CP/GW database invariant failed")
PY
log "stopping processes and containers, freezing exact identities and exit metadata"
: >"$ARTIFACT_DIR/container-exit.txt"
for pidfile_name in "control-plane:$CP_PID_FILE" "gateway-core:$GW_PID_FILE" "security-engine:$SEC_PID_FILE"; do
  name="${pidfile_name%%:*}"; pidfile="${pidfile_name#*:}"
  pid="$(cat "$pidfile" 2>/dev/null || true)"
  if [[ -n "$pid" ]]; then
    kill "$pid" 2>/dev/null || true
    for _ in $(seq 1 20); do kill -0 "$pid" 2>/dev/null || break; sleep 0.5; done
    still_running=1; kill -0 "$pid" 2>/dev/null || still_running=0
    if [[ "$still_running" == "1" ]]; then kill -9 "$pid" 2>/dev/null || true; fi
    printf '%s|pid:%s|killed\n' "$name" "$pid" >>"$ARTIFACT_DIR/container-exit.txt"
  fi
done
for c in "$PG_CONTAINER" "$REDIS_CONTAINER"; do
  docker inspect -f '{{.Name}}|{{.Id}}|{{.State.Status}}|{{.State.ExitCode}}|{{.State.OOMKilled}}' "$c" >>"$ARTIFACT_DIR/container-exit.txt" 2>/dev/null || true
done
cp "$RUN_LOG" "$ARTIFACT_DIR/fixture.log"
cp "$SCRIPT_DIR/run.sh" "$ARTIFACT_DIR/operator.sh"
cp "$SCRIPT_DIR/client.py" "$ARTIFACT_DIR/client.py"
cp "$ROOT/apps/control-plane/internal/testtools/t16licensegen/main.go" "$ARTIFACT_DIR/licensegen.go"
cp "$ROOT/deploy/migrations/873_agent_intent_tasks.sql" "$ARTIFACT_DIR/873_agent_intent_tasks.sql"
source_commit="$(git -C "$ROOT" rev-parse HEAD)"
source_tree="$(git -C "$ROOT" show -s --format=%T HEAD)"
migration_sha="$(sha256sum "$ROOT/deploy/migrations/873_agent_intent_tasks.sql" | awk '{print $1}')"
python3 - "$ARTIFACT_DIR/receipt.json" "$RUN_ID" "$source_commit" "$source_tree" "$migration_sha" "$LICENSE_FIXTURE_KID" "$LICENSE_FIXTURE_ISSUER_CLAIM" "$LICENSE_FIXTURE_PUBKEY_SHA256" <<'PY'
import json, pathlib, sys
path, run_id, commit, tree, migration_sha, fixture_kid, fixture_issuer_claim, fixture_pubkey_sha256 = sys.argv[1:]
data = {
 "acceptance_slice": "T16 isolated real E2E (VM-native processes: containerized postgres/redis + go-built CP/GW binaries + venv security-engine, no offline buildx images)",
 "attempt": 1, "run_id": run_id, "worker": "W28-T16-isolated-e2e-vm-20260926 (fixture updated by t16-dev-20260928)",
 "source_commit": commit, "source_tree": tree, "migration_873_sha256": migration_sha,
 "operator_exit_code": 0, "slice_result": "PASS", "overall_t16": "HOLD",
 "coverage": [
  "ephemeral signed agent_security license imported through CP API",
  "real CP enrollment, endpoint, principal/grant, T13 authorize, and approved-task APIs",
  "real GW decide calls CP's endpoint-authenticated T16 resolver for three ambiguous-path"
  " (type=file) calls, correctly yielding AGENT_POLICY_UNAVAILABLE by the builtin SSH-key"
  " PathGlob rule (both before and after task revocation)",
  "authenticated GW tool.post event accepted for the type=file flow",
  "three-step WebFetch chain on its own approved task: step 1 in-scope fetch (T13 matched, allow),"
  " accepted tool.post attaches its result hash; step 2 cites that attacker-controlled result"
  " (decision unchanged, no leakage, SemanticJudge observe-only); step 3 egress to an ungranted"
  " host: T13 persists an explicit network_connect denial, GW re-resolves it and floors raw"
  " decision at block (monitor -> effective audit), recorded as a deviation",
  "server-owned agent_intent_task_steps ledger: 3 ordered steps, step 1 terminal result,"
  " step 2 source ref accepted_result_hash_match linked to step 1, step 3 not allowed",
  "DB-side tool_call_logs.raw_decision/effective_decision for the adversarial and deviation"
  " WebFetch calls verified to match what client.py observed over HTTP (not just re-trusting"
  " the HTTP response)",
  "revocation removes task context; T13 authorization for the granted facets still resolves",
  "isolated PostgreSQL 16 (container) + isolated Redis 7 (container) + go-built CP/GW binaries + real security-engine process, direct sanitized row assertions"
 ],
 "limits": [
  "one isolated tenant, endpoint, principal, and synthetic file-read flow",
  "no shared VM or production database writes",
  "no live agent, MCP executor, multi-tenant matrix, load/concurrency stress, retention/pruning, or deployment acceptance",
  "this CP/GW slice does not accept full T16",
  "CP/GW run as VM-native go-built processes, not the product's offline-buildx Docker images (see run.sh header comment for why)",
  "type=file decide() calls remain structurally ambiguous by design (503) and create no step rows;"
  " the step ledger is exercised by the WebFetch chain only",
  "SemanticJudge is observe-only (Allow/Audit cap); its verdict is never an authorization input"
 ],
 "container_exit_metadata": "container-exit.txt has exact process/container identities and exit states",
 "license_fixture": {
  "kid": fixture_kid,
  "issuer_claim": fixture_issuer_claim,
  "trust_scope": "isolated-t16-e2e-only",
  "no_production_trust": True,
  "public_key_sha256": fixture_pubkey_sha256,
  "precedent_ref": "pskc:/home/dev/agent-platform-orchestration/run-20260924-115441/results/T03-dev/revocation-list-resume-event133/runtime-adoption-plan-event136/adoption-plan-event136.md (KID dev-t03-revocation-20260925)"
 }
}
pathlib.Path(path).write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n")
PY
(
 cd "$ARTIFACT_DIR"
 sha256sum operator.sh client.py licensegen.go 873_agent_intent_tasks.sql fixture.log evidence.json db-summary.json container-exit.txt receipt.json > SHA256SUMS
)
log "PASS; evidence sealed at $ARTIFACT_DIR"
