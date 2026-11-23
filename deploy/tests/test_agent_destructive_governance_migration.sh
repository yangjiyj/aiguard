#!/usr/bin/env bash
set -euo pipefail
# 临时容器：打测试标签、先回收被杀掉的测试进程留下的孤儿容器，清理用 docker rm -f -v（见该库说明）。
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib/test-containers.sh"
jjd_test_reap_orphan_containers
jjd_test_container_labels agent-destructive-governance-migration

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
MIGRATION="$ROOT/deploy/migrations/140_agent_destructive_operation_governance.sql"
RUNNER="${MIGRATION_RUNNER_UNDER_TEST:-$ROOT/deploy/lib/migration-runner.sh}"

[[ -f "$MIGRATION" ]] || {
  echo "missing migration: $MIGRATION" >&2
  exit 1
}

for required in \
  agent_destructive_policies operation_id event_type risk_category risk_subcategory \
  reason_summary target_summary mode_default_action custom_action final_action \
  notification_required notification_status discardable_path_matched \
  discardable_path_reason execution_forwarded \
  application_id agent_type model protocol \
  tool_destructive_intent tool_attempt_blocked tool_execution_risk \
  uq_tool_call_logs_destructive_operation_event \
  agent_destructive_project_legacy_mode \
  initialize_agent_destructive_policies_from_legacy \
  agent_destructive_legacy_policy_initialized_v1 \
  node_modules dist build .cache tmp test-output; do
  grep -Fq "$required" "$MIGRATION" || {
    echo "missing destructive-governance contract: $required" >&2
    exit 1
  }
done

if grep -Eqi '^[[:space:]]*UPDATE[[:space:]]+tool_call_logs' "$MIGRATION"; then
  echo "migration must not rewrite historical tool_call_logs" >&2
  exit 1
fi
if grep -Fq 'SECURITY_AUDIT_ONLY' "$MIGRATION"; then
  echo "migration must use an explicit database setting, not read environment keys" >&2
  exit 1
fi

container_capture_line="$(grep -nE '^[[:space:]]+if ! container_id="[$][(]docker run' "$0" | cut -d: -f1 || true)"
trap_registration_line="$(grep -nE '^[[:space:]]+trap cleanup EXIT' "$0" | head -1 | cut -d: -f1 || true)"
[[ -n "$container_capture_line" ]] || {
  echo "default PostgreSQL fixture must capture docker run container ID" >&2
  exit 1
}
grep -Eq '^[[:space:]]+docker rm -f -v "[$]container_id"' "$0" || {
  echo "default PostgreSQL fixture cleanup must remove by container ID" >&2
  exit 1
}
if grep -Eq '^[[:space:]]+docker rm -f -v "[$]container_name"' "$0"; then
  echo "default PostgreSQL fixture must not remove by caller-chosen name" >&2
  exit 1
fi
[[ -n "$trap_registration_line" && "$trap_registration_line" -gt "$container_capture_line" ]] || {
  echo "cleanup trap must be registered only after docker run returns an ID" >&2
  exit 1
}

dsn="${1:-${TEST_DATABASE_URL:-}}"
container_id=""
schema="adg140_${RANDOM}_$$"
runner_dir=""
psql_wrapper=""

cleanup() {
  if [[ -n "$dsn" ]]; then
    psql "$dsn" -v ON_ERROR_STOP=1 \
      -c "DROP SCHEMA IF EXISTS $schema CASCADE" >/dev/null 2>&1 || true
  fi
  if [[ -n "$runner_dir" ]]; then
    rm -rf "$runner_dir"
  fi
  if [[ -n "$psql_wrapper" ]]; then
    rm -f "$psql_wrapper"
  fi
  if [[ -n "$container_id" ]]; then
    docker rm -f -v "$container_id" >/dev/null 2>&1 || true
  fi
}

if [[ -z "$dsn" ]]; then
  command -v docker >/dev/null 2>&1 || {
    echo "docker is required for the default isolated PostgreSQL migration test" >&2
    exit 1
  }
  command -v psql >/dev/null 2>&1 || {
    echo "psql is required for the migration test" >&2
    exit 1
  }
  docker info >/dev/null 2>&1 || {
    echo "docker daemon is unavailable; refusing a static-only false green" >&2
    exit 1
  }

  # The default path never reads /home/dev/jjdguard or any deployed database.
  container_name="adg140-postgres-${RANDOM}-$$"
  if ! container_id="$(docker run "${JJD_TEST_CONTAINER_LABELS[@]}" --rm -d --name "$container_name" \
    -e POSTGRES_HOST_AUTH_METHOD=trust \
    -p 127.0.0.1::5432 postgres:16-alpine)"; then
    echo "failed to start isolated postgres:16-alpine" >&2
    exit 1
  fi
  trap cleanup EXIT

  port=""
  for _ in $(seq 1 30); do
    port="$(docker port "$container_name" 5432/tcp 2>/dev/null | sed 's/.*://' || true)"
    [[ -n "$port" ]] && break
    sleep 1
  done
  [[ -n "$port" ]] || {
    echo "isolated PostgreSQL did not publish a loopback port" >&2
    docker logs "$container_name" >&2 || true
    exit 1
  }
  dsn="postgresql://postgres@127.0.0.1:$port/postgres"

  for _ in $(seq 1 30); do
    if psql "$dsn" -tAc "SELECT 1" >/dev/null 2>&1; then
      break
    fi
    sleep 1
  done
  psql "$dsn" -v ON_ERROR_STOP=1 -tAc "SELECT 1" >/dev/null 2>&1 || {
    echo "isolated PostgreSQL failed to become ready" >&2
    docker logs "$container_name" >&2 || true
    exit 1
  }
fi
if [[ -z "$container_id" ]]; then
  trap cleanup EXIT
fi

psql "$dsn" -v ON_ERROR_STOP=1 <<SQL >/dev/null
CREATE SCHEMA $schema;
SET search_path TO $schema;
CREATE TABLE tenants (
  id varchar(64) PRIMARY KEY
);
CREATE TABLE system_settings (
  key varchar(128) PRIMARY KEY,
  value text NOT NULL,
  updated_at timestamptz DEFAULT now()
);
CREATE TABLE tool_call_logs (
  id varchar(64) PRIMARY KEY,
  request_id varchar(64) NOT NULL,
  tenant_id varchar(64) NOT NULL,
  tool_name varchar(128) NOT NULL,
  tool_type varchar(32) NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);
INSERT INTO tenants(id) VALUES ('tenant-a'), ('tenant-b');
INSERT INTO system_settings(key, value)
VALUES ('security_audit_only', 'true');
INSERT INTO tool_call_logs(id, request_id, tenant_id, tool_name, tool_type)
VALUES ('legacy-row', 'legacy-request', 'tenant-a', 'Bash', 'system');
SQL

runner_dir="$(mktemp -d)"
psql_wrapper="$(mktemp)"
cp "$MIGRATION" "$runner_dir/140_agent_destructive_operation_governance.sql"
cat >"$runner_dir/139_runner_concurrency_probe.sql" <<'SQL'
CREATE TABLE runner_concurrency_probe(id integer PRIMARY KEY);
SQL
mkdir "$runner_dir/barrier"
cat >"$psql_wrapper" <<'WRAPPER'
#!/usr/bin/env bash
for argument in "$@"; do
  if [[ "$argument" == "MIGRATION_RUNNER_LOCK_HOLDER=1" ]]; then
    touch "$ADG140_TEST_BARRIER_DIR/lock-aware"
    continue
  fi
  if [[ ! -e "$ADG140_TEST_BARRIER_DIR/lock-aware" && "$argument" == *"SELECT COALESCE(NULLIF(checksum"* ]]; then
    touch "$ADG140_TEST_BARRIER_DIR/$PPID"
    for _ in $(seq 1 50); do
      [[ "$(find "$ADG140_TEST_BARRIER_DIR" -type f | wc -l)" -ge 2 ]] && break
      sleep 0.1
    done
    break
  fi
done
exec env PGOPTIONS="-c search_path=$ADG140_TEST_SCHEMA" \
  psql "$ADG140_TEST_DSN" "$@"
WRAPPER
chmod +x "$psql_wrapper"
export ADG140_TEST_SCHEMA="$schema"
export ADG140_TEST_DSN="$dsn"
export ADG140_TEST_BARRIER_DIR="$runner_dir/barrier"
set +e
MIGRATION_PSQL="$psql_wrapper" bash "$RUNNER" \
  --migrations-dir "$runner_dir" >"$runner_dir/runner-a.out" 2>&1 &
runner_a_pid=$!
MIGRATION_PSQL="$psql_wrapper" bash "$RUNNER" \
  --migrations-dir "$runner_dir" >"$runner_dir/runner-b.out" 2>&1 &
runner_b_pid=$!
wait "$runner_a_pid"
runner_a_status=$?
wait "$runner_b_pid"
runner_b_status=$?
set -e
if [[ "$runner_a_status" -ne 0 || "$runner_b_status" -ne 0 ]]; then
  echo "concurrent migration runners failed: A=$runner_a_status B=$runner_b_status" >&2
  sed 's/^/[runner-a] /' "$runner_dir/runner-a.out" >&2
  sed 's/^/[runner-b] /' "$runner_dir/runner-b.out" >&2
  exit 1
fi
expected_checksum="$(sha256sum "$MIGRATION" | awk '{print $1}')"
runner_record="$(PGOPTIONS="-c search_path=$schema" psql "$dsn" -tAc \
  "SELECT count(*)::text || ':' || bool_and(checksum = '$expected_checksum')::text FROM schema_migrations WHERE version = '140_agent_destructive_operation_governance.sql'")"
[[ "$runner_record" == "1:true" ]] || {
  echo "migration runner ledger/checksum mismatch: $runner_record" >&2
  exit 1
}
policy_record="$(PGOPTIONS="-c search_path=$schema" psql "$dsn" -tAc \
  "SELECT count(*)::text || ':' || count(DISTINCT tenant_id)::text FROM agent_destructive_policies")"
[[ "$policy_record" == "2:2" ]] || {
  echo "concurrent migration runners duplicated policies: $policy_record" >&2
  exit 1
}
echo "[ok] concurrent migration runners A=$runner_a_status B=$runner_b_status ledger=$runner_record policies=$policy_record"

column_count="$(psql "$dsn" -tAc "
SELECT count(*)
FROM information_schema.columns
WHERE table_schema = '$schema'
  AND table_name = 'tool_call_logs'
  AND column_name IN (
    'operation_id','event_type','risk_category','risk_subcategory',
    'reason_summary','target_summary','mode_default_action','custom_action',
    'final_action','notification_required','notification_status',
    'discardable_path_matched','discardable_path_reason','execution_forwarded'
  )")"
[[ "$column_count" == "14" ]] || {
  echo "expected 14 destructive event columns, got $column_count" >&2
  exit 1
}

legacy_untouched="$(PGOPTIONS="-c search_path=$schema" psql "$dsn" -tAc "
SELECT count(*) FROM tool_call_logs
WHERE id = 'legacy-row'
  AND operation_id IS NULL
  AND event_type IS NULL
  AND notification_status IS NULL
  AND execution_forwarded IS NULL")"
[[ "$legacy_untouched" == "1" ]] || {
  echo "historical tool-call row was rewritten" >&2
  exit 1
}

policy_shape="$(PGOPTIONS="-c search_path=$schema" psql "$dsn" -tAc "
SELECT mode || ':' || action || ':' || discardable_paths_json::text
FROM agent_destructive_policies
WHERE tenant_id = 'tenant-a' AND scope_type = 'tenant'")"
[[ "$policy_shape" == "audit:record:[\"dist\", \"tmp\", \"build\", \".cache\", \"node_modules\", \"test-output\"]" ]] || {
  echo "legacy audit-only setting did not initialize the expected policy: $policy_shape" >&2
  exit 1
}

legacy_projection="$(PGOPTIONS="-c search_path=$schema" psql "$dsn" -tAc "
SELECT agent_destructive_project_legacy_mode('observe')
       || ':' || agent_destructive_project_legacy_mode('strict')")"
[[ "$legacy_projection" == "audit:strict" ]] || {
  echo "legacy observe projection is wrong: $legacy_projection" >&2
  exit 1
}

token_projection="$(PGOPTIONS="-c search_path=$schema" psql "$dsn" -tAc "
SELECT string_agg(label || '=' || agent_destructive_legacy_audit_only(token)::text, ',' ORDER BY ord)
FROM (VALUES
  (1,'null',NULL::text),(2,'empty',''),(3,'blank','   '),(4,'garbage','unexpected'),
  (5,'true-upper','TRUE'),(6,'yes-mixed','YeS'),(7,'on-upper','ON'),(8,'one','1'),
  (9,'false-upper','FALSE'),(10,'no-mixed','nO'),(11,'off-upper','OFF'),(12,'zero','0')
) AS tokens(ord,label,token)")"
[[ "$token_projection" == "null=true,empty=true,blank=true,garbage=true,true-upper=true,yes-mixed=true,on-upper=true,one=true,false-upper=false,no-mixed=false,off-upper=false,zero=false" ]] || { echo "legacy audit-only token projection is unsafe: $token_projection" >&2; exit 1; }

PGOPTIONS="-c search_path=$schema" psql "$dsn" -v ON_ERROR_STOP=1 <<'SQL' >/dev/null
INSERT INTO tenants(id) VALUES ('tenant-custom'), ('tenant-legacy-missing');
INSERT INTO agent_destructive_policies(
  id, tenant_id, scope_type, scope_ref, mode, action,
  discardable_paths_json, notify_channel_ids_json, version, enabled, created_by, updated_by
) VALUES (
  'custom-policy', 'tenant-custom', 'tenant', '', 'light', 'alert_allow',
  '["custom-cache"]', '["channel-custom"]', 7, true, 'customer-admin', 'customer-admin'
);
SQL
custom_before="$(PGOPTIONS="-c search_path=$schema" psql "$dsn" -tAc "
SELECT md5(to_jsonb(p)::text)
FROM agent_destructive_policies AS p WHERE tenant_id = 'tenant-custom'")"
PGOPTIONS="-c search_path=$schema" psql "$dsn" -v ON_ERROR_STOP=1 <<'SQL' >/dev/null
SELECT initialize_agent_destructive_policies_from_legacy(false);
SQL
custom_after="$(PGOPTIONS="-c search_path=$schema" psql "$dsn" -tAc "
SELECT md5(to_jsonb(p)::text)
FROM agent_destructive_policies AS p WHERE tenant_id = 'tenant-custom'")"
custom_count="$(PGOPTIONS="-c search_path=$schema" psql "$dsn" -tAc "SELECT count(*) FROM agent_destructive_policies WHERE tenant_id = 'tenant-custom'")"
missing_shape="$(PGOPTIONS="-c search_path=$schema" psql "$dsn" -tAc "SELECT mode || ':' || action FROM agent_destructive_policies WHERE tenant_id = 'tenant-legacy-missing'")"
[[ "$custom_before" == "$custom_after" ]] || { echo "legacy initialization rewrote an existing customer policy" >&2; exit 1; }
[[ "$custom_count" == "1" ]] || { echo "legacy initialization added a tenant default over an existing policy: $custom_count" >&2; exit 1; }
[[ "$missing_shape" == "strict:block" ]] || { echo "explicit legacy initialization did not source the requested enforcement mode: $missing_shape" >&2; exit 1; }

PGOPTIONS="-c search_path=$schema" psql "$dsn" -v ON_ERROR_STOP=1 <<'SQL' >/dev/null
UPDATE system_settings SET value = 'false' WHERE key = 'security_audit_only';
INSERT INTO tenants(id) VALUES ('tenant-after-migration');
SQL
PGOPTIONS="-c search_path=$schema" \
  psql "$dsn" -v ON_ERROR_STOP=1 -f "$MIGRATION" >/dev/null

post_rerun="$(PGOPTIONS="-c search_path=$schema" psql "$dsn" -tAc "
SELECT
  (SELECT mode || ':' || action FROM agent_destructive_policies
   WHERE tenant_id = 'tenant-a' AND scope_type = 'tenant')
  || ':' ||
  (SELECT count(*) FROM agent_destructive_policies
   WHERE tenant_id = 'tenant-after-migration')")"
[[ "$post_rerun" == "audit:record:0" ]] || {
  echo "legacy switch continued to clamp policy after one-time initialization: $post_rerun" >&2
  exit 1
}

expect_rejected() {
  local sql="$1" label="$2"
  if PGOPTIONS="-c search_path=$schema" \
      psql "$dsn" -v ON_ERROR_STOP=1 -c "$sql" >/dev/null 2>&1; then
    echo "destructive-governance invariant accepted invalid row: $label" >&2
    exit 1
  fi
}

policy_columns="id,tenant_id,scope_type,scope_ref,mode,action,discardable_paths_json,notify_channel_ids_json"
expect_rejected \
  "INSERT INTO agent_destructive_policies($policy_columns) VALUES ('cross-tenant','missing-tenant','tenant','','audit','record','[]','[]')" \
  "unknown tenant"
expect_rejected \
  "INSERT INTO agent_destructive_policies($policy_columns) VALUES ('bad-scope','tenant-a','agent','','audit','record','[]','[]')" \
  "scoped policy without scope_ref"
expect_rejected \
  "INSERT INTO agent_destructive_policies($policy_columns) VALUES ('bad-mode','tenant-a','tenant','','observe','record','[]','[]')" \
  "legacy observe stored as a new mode"
expect_rejected \
  "INSERT INTO agent_destructive_policies($policy_columns) VALUES ('bad-action','tenant-a','tenant','','audit','delete','[]','[]')" \
  "unknown action"
expect_rejected \
  "INSERT INTO agent_destructive_policies($policy_columns) VALUES ('bad-json','tenant-a','tenant','','audit','record','{}','[]')" \
  "discardable paths object"
expect_rejected \
  "INSERT INTO agent_destructive_policies($policy_columns) VALUES ('bad-parent','tenant-a','tenant','','audit','record','[\"../secrets\"]','[]')" \
  "parent traversal path"
expect_rejected \
  "INSERT INTO agent_destructive_policies($policy_columns) VALUES ('bad-dot','tenant-a','agent','path-dot','audit','record','[\".\"]','[]')" \
  "current-directory path"
expect_rejected \
  "INSERT INTO agent_destructive_policies($policy_columns) VALUES ('bad-dot-slash','tenant-a','agent','path-dot-slash','audit','record','[\"./\"]','[]')" \
  "dot-slash path"
expect_rejected \
  "INSERT INTO agent_destructive_policies($policy_columns) VALUES ('bad-dot-backslash','tenant-a','agent','path-dot-backslash','audit','record','[\".\\\\\"]','[]')" \
  "dot-backslash path"
expect_rejected \
  "INSERT INTO agent_destructive_policies($policy_columns) VALUES ('bad-home-prefix','tenant-a','agent','path-home-prefix','audit','record','[\"~cache\"]','[]')" \
  "tilde-prefixed path"
expect_rejected \
  "INSERT INTO agent_destructive_policies($policy_columns) VALUES ('bad-channel','tenant-a','tenant','','audit','record','[]','[1]')" \
  "non-string notification channel"

PGOPTIONS="-c search_path=$schema" psql "$dsn" -v ON_ERROR_STOP=1 <<'SQL' >/dev/null
INSERT INTO tool_call_logs(
  id,request_id,tenant_id,tool_name,tool_type,operation_id,event_type
) VALUES
  ('intent-1','request-1','tenant-a','Bash','system','operation-1','tool_destructive_intent'),
  ('blocked-1','request-1','tenant-a','Bash','system','operation-1','tool_attempt_blocked');
SQL
expect_rejected \
  "INSERT INTO tool_call_logs(id,request_id,tenant_id,tool_name,tool_type,operation_id,event_type) VALUES ('intent-duplicate','request-2','tenant-a','Bash','system','operation-1','tool_destructive_intent')" \
  "duplicate operation event"
expect_rejected \
  "INSERT INTO tool_call_logs(id,request_id,tenant_id,tool_name,tool_type,operation_id,event_type) VALUES ('bad-event','request-2','tenant-a','Bash','system','operation-2','tool_deleted')" \
  "unknown destructive event type"

constraint_count="$(psql "$dsn" -tAc "
SELECT count(*)
FROM pg_constraint
WHERE conrelid = '$schema.agent_destructive_policies'::regclass
  AND conname IN (
    'agent_destructive_policies_tenant_fk',
    'agent_destructive_policies_tenant_id_id_key',
    'agent_destructive_policies_scope_check',
    'agent_destructive_policies_mode_check',
    'agent_destructive_policies_action_check',
    'agent_destructive_policies_paths_check'
  )")"
[[ "$constraint_count" == "6" ]] || {
  echo "expected tenant/composite/check constraints, got $constraint_count/6" >&2
  exit 1
}

index_shape="$(PGOPTIONS="-c search_path=$schema" psql "$dsn" -tAc "
SELECT i.indisvalid::text || ':' || i.indisunique::text || ':'
       || i.indnkeyatts::text || ':' || i.indnatts::text || ':'
       || lower(btrim(pg_get_indexdef(i.indexrelid, 1, true))) || ':'
       || lower(btrim(pg_get_indexdef(i.indexrelid, 2, true))) || ':'
       || lower(btrim(pg_get_indexdef(i.indexrelid, 3, true))) || ':'
       || regexp_replace(
            regexp_replace(lower(pg_get_expr(i.indpred, i.indrelid)),
                           '::(text|character varying)', '', 'g'),
            '[[:space:]()]', '', 'g'
          )
FROM pg_index i
JOIN pg_class c ON c.oid = i.indexrelid
JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE n.nspname = '$schema'
  AND c.relname = 'uq_tool_call_logs_destructive_operation_event'")"
[[ "$index_shape" == "true:true:3:3:tenant_id:operation_id:event_type:operation_idisnotnullandbtrimoperation_id<>''" ]] || {
  echo "destructive-operation event index has incompatible catalog shape: $index_shape" >&2
  exit 1
}

public_index_shape="$(PGOPTIONS="-c search_path=$schema" psql "$dsn" -tAc "
SELECT i.indisvalid::text || ':' || i.indisunique::text || ':'
       || i.indnkeyatts::text || ':' || i.indnatts::text || ':'
       || lower(btrim(pg_get_indexdef(i.indexrelid, 1, true))) || ':'
       || lower(btrim(pg_get_indexdef(i.indexrelid, 2, true))) || ':'
       || regexp_replace(
            regexp_replace(lower(pg_get_expr(i.indpred, i.indrelid)),
                           '::(text|character varying)', '', 'g'),
            '[[:space:]()]', '', 'g'
          )
FROM pg_index i
JOIN pg_class c ON c.oid = i.indexrelid
JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE n.nspname = '$schema'
  AND c.relname = 'uq_tool_call_logs_destructive_public_event'")"
[[ "$public_index_shape" == "true:true:2:2:tenant_id:public_event_id:public_event_idisnotnullandbtrimpublic_event_id<>''" ]] || {
  echo "destructive public-event index has incompatible catalog shape: $public_index_shape" >&2
  exit 1
}

PGOPTIONS="-c search_path=$schema" psql "$dsn" -v ON_ERROR_STOP=1 <<'SQL' >/dev/null
UPDATE pg_index
SET indisvalid = false, indisready = false
WHERE indexrelid = 'uq_tool_call_logs_destructive_public_event'::regclass;
SQL
PGOPTIONS="-c search_path=$schema" psql "$dsn" -v ON_ERROR_STOP=1 -f "$MIGRATION" >/dev/null
public_recovered="$(PGOPTIONS="-c search_path=$schema" psql "$dsn" -tAc "
SELECT i.indisvalid::text || ':' || i.indisready::text
FROM pg_index i
JOIN pg_class c ON c.oid = i.indexrelid
JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE n.nspname = '$schema'
  AND c.relname = 'uq_tool_call_logs_destructive_public_event'")"
[[ "$public_recovered" == "true:true" ]] || {
  echo "destructive public-event index did not recover: $public_recovered" >&2
  exit 1
}

PGOPTIONS="-c search_path=$schema" psql "$dsn" -v ON_ERROR_STOP=1 <<'SQL' >/dev/null
DROP INDEX uq_tool_call_logs_destructive_operation_event;
CREATE INDEX uq_tool_call_logs_destructive_operation_event
  ON tool_call_logs (tenant_id);
SQL
if poison_output="$(PGOPTIONS="-c search_path=$schema" \
    psql "$dsn" -v ON_ERROR_STOP=1 -f "$MIGRATION" 2>&1)"; then
  echo "migration accepted incompatible same-name destructive-operation index" >&2
  exit 1
fi
grep -Fq 'incompatible definition for index uq_tool_call_logs_destructive_operation_event' \
  <<<"$poison_output" || {
    echo "migration rejected poisoned index for an unexpected reason: $poison_output" >&2
    exit 1
  }
PGOPTIONS="-c search_path=$schema" psql "$dsn" -v ON_ERROR_STOP=1 <<'SQL' >/dev/null
DROP INDEX uq_tool_call_logs_destructive_operation_event;
CREATE FUNCTION btrim(varchar)
RETURNS text
LANGUAGE sql
IMMUTABLE
AS $$ SELECT 'not-blank'::text $$;
CREATE UNIQUE INDEX uq_tool_call_logs_destructive_operation_event
  ON tool_call_logs (tenant_id, operation_id, event_type)
  WHERE operation_id IS NOT NULL AND btrim(operation_id) <> '';
SQL
if overload_output="$(PGOPTIONS="-c search_path=$schema" \
    psql "$dsn" -v ON_ERROR_STOP=1 -f "$MIGRATION" 2>&1)"; then
  echo "migration accepted destructive-operation predicate with non-catalog btrim" >&2
  exit 1
fi
grep -Fq 'incompatible definition for index uq_tool_call_logs_destructive_operation_event' \
  <<<"$overload_output" || {
    echo "migration rejected overloaded predicate for an unexpected reason: $overload_output" >&2
    exit 1
  }

PGOPTIONS="-c search_path=$schema,pg_catalog" \
  psql "$dsn" -v ON_ERROR_STOP=1 <<'SQL' >/dev/null
DROP INDEX uq_tool_call_logs_destructive_operation_event;
CREATE FUNCTION text_ne_always(text, text)
RETURNS boolean
LANGUAGE sql
IMMUTABLE
AS $$ SELECT true $$;
CREATE OPERATOR <> (
  LEFTARG = text,
  RIGHTARG = text,
  FUNCTION = text_ne_always
);
CREATE UNIQUE INDEX uq_tool_call_logs_destructive_operation_event
  ON tool_call_logs (tenant_id, operation_id, event_type)
  WHERE operation_id IS NOT NULL
    AND pg_catalog.btrim(operation_id::text) <> ''::text;
SQL
if operator_output="$(PGOPTIONS="-c search_path=$schema,pg_catalog" \
    psql "$dsn" -v ON_ERROR_STOP=1 -f "$MIGRATION" 2>&1)"; then
  echo "migration accepted destructive-operation predicate with non-catalog operator" >&2
  exit 1
fi
grep -Fq 'incompatible definition for index uq_tool_call_logs_destructive_operation_event' \
  <<<"$operator_output" || {
    echo "migration rejected overloaded operator for an unexpected reason: $operator_output" >&2
    exit 1
  }

echo "[ok] agent destructive governance migration upgrade, idempotence, compatibility, and isolation"
