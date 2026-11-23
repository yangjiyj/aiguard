#!/usr/bin/env bash
set -Eeuo pipefail
# 临时容器：打测试标签、先回收被杀掉的测试进程留下的孤儿容器，清理用 docker rm -f -v（见该库说明）。
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib/test-containers.sh"
jjd_test_reap_orphan_containers
jjd_test_container_labels evidence-run-agent-projection-migration

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
MIGRATION="$ROOT/deploy/migrations/819_repair_evidence_run_agent_projection.sql"

[[ -f "$MIGRATION" ]] || {
  echo "missing migration: $MIGRATION" >&2
  exit 1
}

required_patterns=(
  "EXCLUDED.effective_agent_type = 'openai-codex'"
  "'main', 'default', 'agent', 'assistant', 'unknown', 'electron', 'vscode'"
  "'openai-codex', 'codex', 'codex-cli', 'openai codex'"
  "evidence_agent_projection_v1"
)
for required in "${required_patterns[@]}"; do
  grep -Fq "$required" "$MIGRATION" || {
    echo "migration missing projection guard: $required" >&2
    exit 1
  }
done

if ! command -v docker >/dev/null 2>&1 || ! docker info >/dev/null 2>&1 || ! docker image inspect postgres:16-alpine >/dev/null 2>&1; then
  echo "SKIP: evidence-run agent projection migration requires local postgres:16-alpine"
  exit 0
fi

container_name="jjdguard-evidence-agent-819-${RANDOM}-$$"
container_id=""
cleanup() {
  if [[ -n "$container_id" ]]; then
    docker rm -f -v "$container_id" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT INT TERM

container_id="$(docker run "${JJD_TEST_CONTAINER_LABELS[@]}" --rm -d --name "$container_name" -e POSTGRES_PASSWORD=test -e POSTGRES_DB=test postgres:16-alpine)"

ready=0
for _ in {1..60}; do
  if [[ "$(docker exec "$container_id" psql -U postgres -d test -tAc 'SELECT 1' 2>/dev/null)" == 1 ]]; then
    ready=1
    break
  fi
  sleep 1
done
[[ "$ready" == 1 ]] || {
  docker logs "$container_id" >&2 || true
  echo "temporary PostgreSQL readiness timeout" >&2
  exit 1
}

docker exec -i "$container_id" psql -v ON_ERROR_STOP=1 -U postgres -d test <<'SQL' >/dev/null
CREATE FUNCTION jjdguard_customer_content_text(value text)
RETURNS boolean
LANGUAGE sql
IMMUTABLE
AS $$ SELECT COALESCE(BTRIM(value), '') <> '' $$;

CREATE TABLE request_logs (
    id varchar(64) PRIMARY KEY,
    request_id varchar(64) NOT NULL UNIQUE,
    tenant_id varchar(64) NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    session_id varchar(128),
    agent_type varchar(64),
    agent_runtime varchar(64),
    agent_detection_source varchar(64),
    agent_detection_confidence real,
    evidence_run_id varchar(64),
    evidence_run_source varchar(64),
    client_id varchar(64),
    user_id varchar(64),
    proxy_source_ip varchar(64),
    source_ip varchar(64)
);

CREATE TABLE content_logs (
    id varchar(64) PRIMARY KEY,
    request_id varchar(64) NOT NULL,
    tenant_id varchar(64) NOT NULL,
    role varchar(32) NOT NULL,
    content text NOT NULL,
    session_id varchar(128),
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE access_content_logs (
    id varchar(64) PRIMARY KEY,
    request_id varchar(64) NOT NULL,
    tenant_id varchar(64) NOT NULL,
    conversation_id varchar(128),
    section_id varchar(128),
    request_content_redacted text,
    response_content_redacted text,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE evidence_run_request_index (
    tenant_id varchar(64) NOT NULL,
    request_log_id varchar(64) NOT NULL,
    request_id varchar(64) NOT NULL,
    created_at timestamptz NOT NULL,
    effective_agent_type varchar(64) NOT NULL DEFAULT '',
    effective_agent_runtime varchar(64) NOT NULL DEFAULT '',
    effective_detection_source varchar(64) NOT NULL DEFAULT '',
    effective_detection_confidence real NOT NULL DEFAULT 0,
    session_id varchar(128) NOT NULL DEFAULT '',
    evidence_run_id varchar(64) NOT NULL DEFAULT '',
    evidence_run_source varchar(64) NOT NULL DEFAULT '',
    conversation_id varchar(128) NOT NULL DEFAULT '',
    section_id varchar(128) NOT NULL DEFAULT '',
    chain_principal varchar(256) NOT NULL DEFAULT '',
    title_hash char(32) NOT NULL DEFAULT '',
    transcript_signature text NOT NULL DEFAULT '',
    derived_chain_root varchar(64) NOT NULL DEFAULT '',
    derived_chain_size integer NOT NULL DEFAULT 0,
    chain_dirty boolean NOT NULL DEFAULT false,
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, request_log_id)
);

CREATE FUNCTION sync_evidence_run_request_index()
RETURNS trigger
LANGUAGE plpgsql
AS $$ BEGIN RETURN NEW; END $$;

CREATE TRIGGER trg_request_logs_evidence_run_request_index
AFTER INSERT OR UPDATE OF request_id, tenant_id, created_at, session_id, agent_type,
    agent_runtime, agent_detection_source, agent_detection_confidence,
    evidence_run_id, evidence_run_source, user_id, client_id, proxy_source_ip, source_ip
ON request_logs
FOR EACH ROW EXECUTE FUNCTION sync_evidence_run_request_index();

CREATE TRIGGER trg_content_logs_evidence_run_request_index
AFTER INSERT OR UPDATE OF content, role, session_id
ON content_logs
FOR EACH ROW EXECUTE FUNCTION sync_evidence_run_request_index();

CREATE TRIGGER trg_access_content_logs_evidence_run_request_index
AFTER INSERT OR UPDATE OF request_id, conversation_id, section_id,
    request_content_redacted, response_content_redacted
ON access_content_logs
FOR EACH ROW EXECUTE FUNCTION sync_evidence_run_request_index();

INSERT INTO request_logs (
    id, request_id, tenant_id, session_id, agent_type, agent_runtime,
    agent_detection_source, agent_detection_confidence,
    evidence_run_id, evidence_run_source
) VALUES
    ('log-workbuddy', 'req-workbuddy', 'tenant-a', '', 'main', NULL,
     'client_header', NULL, NULL, NULL),
    ('log-stale-workbuddy', 'req-stale-workbuddy', 'tenant-a', '', 'workbuddy', NULL,
     'user_agent', 0.85, NULL, NULL),
    ('log-stale-codebuddy', 'req-stale-codebuddy', 'tenant-a', '', 'codebuddy', NULL,
     'message_protocol', 0.98, NULL, NULL),
    ('log-stale-cline', 'req-stale-cline', 'tenant-a', '', 'cline', 'vscode',
     'user_agent', 0.85, NULL, NULL),
    ('log-generic-default', 'req-generic-default', 'tenant-a', '', 'default', NULL,
     'client_header', 0.40, NULL, NULL),
    ('log-generic-empty', 'req-generic-empty', 'tenant-a', '', NULL, NULL,
     'user_agent_runtime', 0.35, NULL, NULL),
    ('log-generic-electron', 'req-generic-electron', 'tenant-a', '', 'electron', 'electron',
     'user_agent_runtime', 0.35, NULL, NULL),
    ('log-vscode', 'req-vscode', 'tenant-a', '', 'vscode', NULL,
     'client_header', 0.50, NULL, NULL),
    ('log-explicit-codex', 'req-explicit-codex', 'tenant-a', '', 'openai-codex', 'codex-cli',
     'explicit_header', 1.0, 'run-explicit-codex', 'responses_thread_id');

INSERT INTO content_logs (id, request_id, tenant_id, role, content, session_id) VALUES
    ('content-workbuddy', 'log-workbuddy', 'tenant-a', 'user',
     '<system-reminder data-role="user-context"><user_info>OpenAI Codex project notes</user_info></system-reminder>', ''),
    ('content-stale-workbuddy', 'log-stale-workbuddy', 'tenant-a', 'user',
     'OpenAI Codex appears in copied project notes', ''),
    ('content-vscode', 'log-vscode', 'tenant-a', 'user', 'ordinary VS Code request', ''),
    ('content-explicit-codex', 'log-explicit-codex', 'tenant-a', 'user', 'ordinary explicit Codex request', '');

INSERT INTO evidence_run_request_index (
    tenant_id, request_log_id, request_id, created_at,
    effective_agent_type, effective_agent_runtime,
    effective_detection_source, effective_detection_confidence,
    evidence_run_id, evidence_run_source
)
SELECT tenant_id, id, request_id, created_at,
       CASE WHEN id IN (
           'log-workbuddy', 'log-stale-workbuddy', 'log-stale-codebuddy', 'log-stale-cline',
           'log-generic-default', 'log-generic-empty', 'log-generic-electron'
       ) THEN 'openai-codex' ELSE COALESCE(agent_type, '') END,
       COALESCE(agent_runtime, CASE WHEN agent_type = 'vscode' THEN 'vscode' ELSE '' END),
       CASE WHEN id IN (
           'log-workbuddy', 'log-stale-workbuddy', 'log-stale-codebuddy', 'log-stale-cline',
           'log-generic-default', 'log-generic-empty', 'log-generic-electron'
       ) THEN 'content' ELSE COALESCE(agent_detection_source, '') END,
       CASE WHEN id IN (
           'log-workbuddy', 'log-stale-workbuddy', 'log-stale-codebuddy', 'log-stale-cline',
           'log-generic-default', 'log-generic-empty', 'log-generic-electron'
       ) THEN 0.98 ELSE COALESCE(agent_detection_confidence, 0) END,
       CASE WHEN id IN (
           'log-workbuddy', 'log-stale-workbuddy', 'log-stale-codebuddy', 'log-stale-cline',
           'log-generic-default', 'log-generic-empty', 'log-generic-electron'
       ) THEN '' ELSE COALESCE(evidence_run_id, '') END,
       CASE WHEN id IN (
           'log-workbuddy', 'log-stale-workbuddy', 'log-stale-codebuddy', 'log-stale-cline',
           'log-generic-default', 'log-generic-empty', 'log-generic-electron'
       ) THEN '' ELSE COALESCE(evidence_run_source, '') END
FROM request_logs;
SQL

apply_migration() {
  docker exec -i "$container_id" psql -v ON_ERROR_STOP=1 -U postgres -d test <"$MIGRATION" >/dev/null
}

assert_state() {
  local request_log_id="$1"
  local expected="$2"
  local actual
  actual="$(docker exec "$container_id" psql -U postgres -d test -At -F '|' -c "
    SELECT effective_agent_type,
           effective_agent_runtime,
           effective_detection_source,
           effective_detection_confidence,
           evidence_run_id,
           evidence_run_source
    FROM evidence_run_request_index
    WHERE tenant_id = 'tenant-a' AND request_log_id = '$request_log_id'
  ")"
  [[ "$actual" == "$expected" ]] || {
    echo "unexpected projection for $request_log_id: $actual" >&2
    exit 1
  }
}

apply_migration
assert_state "log-workbuddy" "openai-codex||content|0.98||"
assert_state "log-stale-workbuddy" "openai-codex||content|0.98||"
assert_state "log-stale-codebuddy" "openai-codex||content|0.98||"
assert_state "log-stale-cline" "openai-codex|vscode|content|0.98||"
assert_state "log-generic-default" "openai-codex||content|0.98||"
assert_state "log-generic-empty" "openai-codex||content|0.98||"
assert_state "log-generic-electron" "openai-codex|electron|content|0.98||"
assert_state "log-vscode" "vscode|vscode|client_header|0.5||"
assert_state "log-explicit-codex" "openai-codex|codex-cli|explicit_header|1|run-explicit-codex|responses_thread_id"

# A registry alias is canonicalized on a fresh trigger insert and stays
# canonical on later request-log updates.
docker exec "$container_id" psql -v ON_ERROR_STOP=1 -U postgres -d test -c "
  INSERT INTO request_logs (
      id, request_id, tenant_id, session_id, agent_type, agent_runtime,
      agent_detection_source, agent_detection_confidence
  ) VALUES (
      'log-codex-alias', 'req-codex-alias', 'tenant-a', '', 'codex-cli', 'codex-cli',
      'explicit_header', 1.0
  )
" >/dev/null
assert_state "log-codex-alias" "openai-codex|codex-cli|explicit_header|1||"
docker exec "$container_id" psql -v ON_ERROR_STOP=1 -U postgres -d test -c "
  UPDATE request_logs SET session_id = 'late-alias-update' WHERE id = 'log-codex-alias'
" >/dev/null
assert_state "log-codex-alias" "openai-codex|codex-cli|explicit_header|1||"

# Unrelated late updates must not destructively demote an uncertain historical
# Codex projection whose raw product identity is still generic.
docker exec "$container_id" psql -v ON_ERROR_STOP=1 -U postgres -d test -c "
  UPDATE request_logs
  SET session_id = 'late-generic-update'
  WHERE id IN ('log-generic-default', 'log-generic-empty', 'log-generic-electron')
" >/dev/null
assert_state "log-generic-default" "openai-codex||content|0.98||"
assert_state "log-generic-empty" "openai-codex||content|0.98||"
assert_state "log-generic-electron" "openai-codex|electron|content|0.98||"

# A later authoritative write is still projected immediately. Other historical
# rows remain untouched until evidence_agent_projection_v1 processes them.
docker exec "$container_id" psql -v ON_ERROR_STOP=1 -U postgres -d test -c "
  UPDATE request_logs
  SET agent_type = 'workbuddy',
      agent_detection_source = 'message_protocol',
      agent_detection_confidence = 0.98,
      evidence_run_id = 'run-workbuddy',
      evidence_run_source = 'workbuddy_workspace'
  WHERE id = 'log-workbuddy'
" >/dev/null
assert_state "log-workbuddy" "workbuddy||message_protocol|0.98|run-workbuddy|workbuddy_workspace"
assert_state "log-stale-workbuddy" "openai-codex||content|0.98||"
assert_state "log-stale-codebuddy" "openai-codex||content|0.98||"
assert_state "log-stale-cline" "openai-codex|vscode|content|0.98||"
assert_state "log-generic-default" "openai-codex||content|0.98||"
assert_state "log-generic-empty" "openai-codex||content|0.98||"
assert_state "log-generic-electron" "openai-codex|electron|content|0.98||"
assert_state "log-stale-workbuddy" "openai-codex||content|0.98||"

# A WorkBuddy-controlled envelope may legitimately mention Codex in project
# context. That text must not override the explicit WorkBuddy attribution.
docker exec "$container_id" psql -v ON_ERROR_STOP=1 -U postgres -d test -c "
  UPDATE content_logs
  SET content = content || ' OpenAI Codex'
  WHERE id = 'content-workbuddy'
" >/dev/null
assert_state "log-workbuddy" "workbuddy||message_protocol|0.98|run-workbuddy|workbuddy_workspace"

# A generic VS Code row is refined by positive Codex content, then retains that
# refinement when a later content update no longer repeats the product marker.
docker exec "$container_id" psql -v ON_ERROR_STOP=1 -U postgres -d test -c "
  UPDATE content_logs
  SET content = 'OpenAI Codex'
  WHERE id = 'content-vscode'
" >/dev/null
assert_state "log-vscode" "openai-codex|vscode|content|0.98||"

docker exec "$container_id" psql -v ON_ERROR_STOP=1 -U postgres -d test -c "
  UPDATE content_logs
  SET content = 'ordinary late VS Code content'
  WHERE id = 'content-vscode'
" >/dev/null
assert_state "log-vscode" "openai-codex|vscode|content|0.98||"

# An explicit Codex identity keeps its authoritative detection metadata even
# when content happens to contain the same marker used for VS Code refinement.
docker exec "$container_id" psql -v ON_ERROR_STOP=1 -U postgres -d test -c "
  UPDATE content_logs
  SET content = 'OpenAI Codex explicit request'
  WHERE id = 'content-explicit-codex'
" >/dev/null
assert_state "log-explicit-codex" "openai-codex|codex-cli|explicit_header|1|run-explicit-codex|responses_thread_id"
assert_state "log-codex-alias" "openai-codex|codex-cli|explicit_header|1||"

apply_migration
assert_state "log-workbuddy" "workbuddy||message_protocol|0.98|run-workbuddy|workbuddy_workspace"
assert_state "log-vscode" "openai-codex|vscode|content|0.98||"
assert_state "log-explicit-codex" "openai-codex|codex-cli|explicit_header|1|run-explicit-codex|responses_thread_id"

echo "[ok] migration 819 is expand-only, projects new writes, and is idempotent"
