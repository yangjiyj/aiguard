#!/usr/bin/env bash
set -euo pipefail
# 临时容器：打测试标签、先回收被杀掉的测试进程留下的孤儿容器，清理用 docker rm -f -v（见该库说明）。
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib/test-containers.sh"
jjd_test_reap_orphan_containers
jjd_test_container_labels model-routing-e2e

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
if ! command -v docker >/dev/null 2>&1 || ! docker info >/dev/null 2>&1 || ! docker image inspect postgres:16-alpine >/dev/null 2>&1; then
  echo "SKIP: model routing cross-service E2E requires local postgres:16-alpine"
  exit 0
fi

container="jjdguard-model-routing-e2e-$$-$RANDOM"
cleanup() { docker rm -f -v "$container" >/dev/null 2>&1 || true; }
trap cleanup EXIT INT TERM
docker run "${JJD_TEST_CONTAINER_LABELS[@]}" --rm -d --name "$container" -p 127.0.0.1::5432 -e POSTGRES_PASSWORD=test -e POSTGRES_DB=test postgres:16-alpine >/dev/null
for _ in {1..30}; do
  [[ "$(docker exec "$container" psql -U postgres -d test -tAc 'SELECT 1' 2>/dev/null || true)" == "1" ]] && break
  sleep 1
done
[[ "$(docker exec "$container" psql -U postgres -d test -tAc 'SELECT 1')" == "1" ]]

port="$(docker port "$container" 5432/tcp | awk -F: '{print $NF}')"
set +e
first_migration_output="$(PGPASSWORD=test bash "$ROOT/deploy/migrate-private.sh" 127.0.0.1 "$port" test postgres 2>&1)"
first_migration_status=$?
set -e
if [[ "$first_migration_status" -eq 0 ]] || [[ "$first_migration_output" != *"user_admin"* ]]; then
	echo "$first_migration_output" >&2
	echo "expected the verified pre-seed migration stop at 003" >&2
	exit 1
fi
awk '/^[[:space:]]*--[[:space:]]*\+?goose[[:space:]]+Down([[:space:]]|$)/ { exit } { print }' "$ROOT/deploy/migrations/002_seed_data.sql" \
	| docker exec -i "$container" psql -v ON_ERROR_STOP=1 -U postgres -d test >/dev/null
set +e
second_migration_log="$(mktemp)"
PGPASSWORD=test bash "$ROOT/deploy/migrate-private.sh" 127.0.0.1 "$port" test postgres >"$second_migration_log" 2>&1
second_migration_status=$?
set -e
if [[ "$second_migration_status" -ne 0 ]]; then
	tail -80 "$second_migration_log" >&2
	echo "second migration pass failed with status $second_migration_status" >&2
	rm -f "$second_migration_log"
	exit "$second_migration_status"
fi
rm -f "$second_migration_log"

docker exec -i "$container" psql -v ON_ERROR_STOP=1 -U postgres -d test >/dev/null <<'SQL'
INSERT INTO tenants(id,name,status) VALUES
 ('mr_e2e_tenant_a','模型路由E2E甲','active'),('mr_e2e_tenant_b','模型路由E2E乙','active');
INSERT INTO users(id,tenant_id,username,password_hash,role,status) VALUES
 ('mr_e2e_user_a','mr_e2e_tenant_a','owner-a','x','tenant_owner','active'),
 ('mr_e2e_user_b','mr_e2e_tenant_b','owner-b','x','tenant_owner','active');
INSERT INTO projects(id,tenant_id,name,code,environment,owner_user_id,status) VALUES
 ('mr_e2e_project_a','mr_e2e_tenant_a','E2E项目','e2e','testing','mr_e2e_user_a','active');
INSERT INTO providers(id,tenant_id,name,provider_type,base_url,auth_mode,status) VALUES
 ('mr_e2e_provider_a','mr_e2e_tenant_a','主线路','openai','http://127.0.0.1.invalid','api_key','active'),
 ('mr_e2e_provider_b','mr_e2e_tenant_a','备用线路','anthropic','http://127.0.0.1.invalid','api_key','active');
INSERT INTO provider_credentials(id,provider_id,credential_name,secret_ciphertext,status) VALUES
 ('mr_e2e_cred_a','mr_e2e_provider_a','e2e','primary-secret','active'),
 ('mr_e2e_cred_b','mr_e2e_provider_b','e2e','fallback-secret','active');
INSERT INTO models(id,provider_id,model_name,model_label,upstream_model_id,capabilities_json,status) VALUES
 ('mr_e2e_model_a','mr_e2e_provider_a','logical/model','逻辑模型','primary-upstream','{"chat":true}','active'),
 ('mr_e2e_model_b','mr_e2e_provider_b','logical/model','逻辑模型','fallback-upstream','{"chat":true}','active');
SQL

export MODEL_ROUTING_E2E_DATABASE_URL="postgres://postgres:test@127.0.0.1:${port}/test?sslmode=disable"
export CONTENT_LOGS_TEST_DATABASE_URL="$MODEL_ROUTING_E2E_DATABASE_URL"
export PATH="/usr/local/go/bin:${PATH}"

(cd "$ROOT/apps/control-plane" && MODEL_ROUTING_E2E_PHASE=control-write go test ./internal/handler -run '^TestModelRoutingCrossServiceControlWritePhase$' -count=1)
(cd "$ROOT/apps/gateway-core" && MODEL_ROUTING_E2E_PHASE=gateway go test ./internal/handler -run '^TestModelRoutingCrossServiceGatewayPhase$' -count=1)
(cd "$ROOT/apps/control-plane" && MODEL_ROUTING_E2E_PHASE=control-read go test ./internal/handler -run '^TestModelRoutingCrossServiceControlReadPhase$' -count=1)

echo "PASS: model routing cross-service E2E"
