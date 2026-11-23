#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
MIGRATION="$ROOT/deploy/migrations/112_tool_event_runtime_truth.sql"

[[ -f "$MIGRATION" ]] || { echo "missing migration: $MIGRATION" >&2; exit 1; }

for column in event_kind execution_observed result_observed tool_call_id asset_id skill_invocation_id mcp_server_id mcp_tool_id definition_hash attribution_mode attribution_confidence; do
  grep -Eq "ADD COLUMN IF NOT EXISTS[[:space:]]+$column|ADD COLUMN[[:space:]]+$column" "$MIGRATION" || {
    echo "missing additive column: $column" >&2
    exit 1
  }
done
grep -Eq 'NOT VALID' "$MIGRATION" || { echo "runtime-truth checks must be NOT VALID" >&2; exit 1; }
grep -Eqi 'CREATE INDEX CONCURRENTLY' "$MIGRATION" || { echo "large-table indexes must be concurrent" >&2; exit 1; }
if grep -Eqi '^[[:space:]]*UPDATE[[:space:]]+tool_call_logs' "$MIGRATION"; then
  echo "migration must not rewrite historical tool_call_logs" >&2
  exit 1
fi

dsn="${1:-}"
if [[ -z "$dsn" ]]; then
  echo "[ok] runtime truth migration static contract"
  exit 0
fi

schema="rt112_${RANDOM}_$$"
runner_dir="$(mktemp -d)"
psql_wrapper="$(mktemp)"
cleanup() {
  psql "$dsn" -v ON_ERROR_STOP=1 -c "DROP SCHEMA IF EXISTS $schema CASCADE" >/dev/null 2>&1 || true
  rm -rf "$runner_dir" "$psql_wrapper"
}
trap cleanup EXIT

psql "$dsn" -v ON_ERROR_STOP=1 <<SQL >/dev/null
CREATE SCHEMA $schema;
SET search_path TO $schema;
CREATE TABLE tool_call_logs (
  id text PRIMARY KEY,
  request_id text NOT NULL,
  session_id text,
  tenant_id text NOT NULL,
  user_id text,
  tool_name text NOT NULL,
  tool_type text NOT NULL,
  risk_level text NOT NULL DEFAULT 'low',
  parameters jsonb DEFAULT '{}'::jsonb,
  result text,
  status text NOT NULL DEFAULT 'success',
  raw_decision text,
  effective_decision text,
  provenance text,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE agentguard_policies (
  id varchar(64) PRIMARY KEY,
  tenant_id varchar(64) NOT NULL
);
CREATE TABLE agentguard_policy_versions (
  id varchar(64) PRIMARY KEY,
  tenant_id varchar(64) NOT NULL,
  policy_id varchar(64) NOT NULL REFERENCES agentguard_policies(id) ON DELETE CASCADE
);
INSERT INTO tool_call_logs (id, request_id, tenant_id, tool_name, tool_type, result, status)
VALUES ('legacy-definition', 'req-def', 'tenant-1', 'Read', 'file', 'request tool passed policy check', 'success');
INSERT INTO tool_call_logs (id, request_id, tenant_id, tool_name, tool_type, raw_decision, effective_decision, status)
VALUES ('legacy-proposed', 'req-proposed', 'tenant-1', 'Bash', 'system', 'allow', 'allow', 'success');
INSERT INTO tool_call_logs (id, request_id, tenant_id, tool_name, tool_type, provenance, status)
VALUES ('legacy-mcp-status-only', 'req-mcp', 'tenant-1', 'demo__write', 'mcp', 'mcp_gateway', 'success');
SQL

for _ in 1 2; do
  PGOPTIONS="-c search_path=$schema" psql "$dsn" -v ON_ERROR_STOP=1 -f "$MIGRATION" >/dev/null
done

agentguard_tenant_constraints="$(psql "$dsn" -tAc "
SELECT count(*)
FROM pg_constraint c
WHERE c.conrelid IN (
  '$schema.agentguard_policies'::regclass,
  '$schema.agentguard_policy_versions'::regclass
)
  AND c.conname IN (
    'agentguard_policies_tenant_id_id_key',
    'agentguard_policy_versions_tenant_policy_fk'
  )")"
[[ "$agentguard_tenant_constraints" == "2" ]] || {
  echo "expected two AgentGuard tenant-integrity constraints, got $agentguard_tenant_constraints" >&2
  exit 1
}
agentguard_fk_shape="$(psql "$dsn" -tAc "
SELECT contype::text || ':' || confdeltype::text || ':' || convalidated::text
FROM pg_constraint
WHERE conrelid = '$schema.agentguard_policy_versions'::regclass
  AND conname = 'agentguard_policy_versions_tenant_policy_fk'")"
[[ "$agentguard_fk_shape" == "f:c:false" ]] || {
  echo "unexpected AgentGuard tenant FK shape: $agentguard_fk_shape" >&2
  exit 1
}

PGOPTIONS="-c search_path=$schema" psql "$dsn" -v ON_ERROR_STOP=1 <<SQL >/dev/null
INSERT INTO agentguard_policies (id, tenant_id) VALUES ('policy-shared', 'tenant-a');
INSERT INTO agentguard_policy_versions (id, tenant_id, policy_id)
VALUES ('version-same-tenant', 'tenant-a', 'policy-shared');
SQL
if PGOPTIONS="-c search_path=$schema" psql "$dsn" -v ON_ERROR_STOP=1 \
    -c "INSERT INTO agentguard_policy_versions (id, tenant_id, policy_id) VALUES ('version-cross-tenant', 'tenant-b', 'policy-shared')" >/dev/null 2>&1; then
  echo "AgentGuard policy version accepted a cross-tenant policy reference" >&2
  exit 1
fi
PGOPTIONS="-c search_path=$schema" psql "$dsn" -v ON_ERROR_STOP=1 \
  -c "DELETE FROM agentguard_policies WHERE id = 'policy-shared'" >/dev/null
cascade_survivors="$(PGOPTIONS="-c search_path=$schema" psql "$dsn" -tAc \
  "SELECT count(*) FROM agentguard_policy_versions WHERE policy_id = 'policy-shared'")"
[[ "$cascade_survivors" == "0" ]] || {
  echo "AgentGuard composite tenant FK did not cascade policy versions: $cascade_survivors" >&2
  exit 1
}

# A failed concurrent build leaves an INVALID relation with the target name.
# IF NOT EXISTS must not turn that poisoned catalog state into a successful migration.
PGOPTIONS="-c search_path=$schema" psql "$dsn" -v ON_ERROR_STOP=1 <<SQL >/dev/null
INSERT INTO tool_call_logs (id, request_id, tenant_id, tool_name, tool_type, event_kind, execution_observed, result_observed, effective_decision, tool_call_id, created_at)
VALUES
  ('index-poison-a', 'req-a', 'tenant-index', 'tool', 'mcp', 'invocation_proposed', false, false, 'allow', 'duplicate-call', '2026-01-01T00:00:00Z'),
  ('index-poison-b', 'req-b', 'tenant-index', 'tool', 'mcp', 'invocation_proposed', false, false, 'allow', 'duplicate-call', '2026-01-01T00:00:00Z');
DROP INDEX idx_tool_call_logs_tenant_event_created;
DROP INDEX idx_tool_call_logs_tenant_tool_call_id;
SQL

if PGOPTIONS="-c search_path=$schema" psql "$dsn" -v ON_ERROR_STOP=1 \
    -c "CREATE UNIQUE INDEX CONCURRENTLY idx_tool_call_logs_tenant_event_created ON tool_call_logs (tenant_id, event_kind, created_at DESC) WHERE event_kind IS NOT NULL" >/dev/null 2>&1; then
  echo "failed to seed INVALID event index" >&2
  exit 1
fi
if PGOPTIONS="-c search_path=$schema" psql "$dsn" -v ON_ERROR_STOP=1 \
    -c "CREATE UNIQUE INDEX CONCURRENTLY idx_tool_call_logs_tenant_tool_call_id ON tool_call_logs (tenant_id, tool_call_id) WHERE tool_call_id IS NOT NULL AND tool_call_id <> ''" >/dev/null 2>&1; then
  echo "failed to seed INVALID tool-call index" >&2
  exit 1
fi

invalid_runtime_indexes="$(psql "$dsn" -tAc "
SELECT count(*)
FROM pg_index i
JOIN pg_class index_rel ON index_rel.oid = i.indexrelid
JOIN pg_class table_rel ON table_rel.oid = i.indrelid
JOIN pg_namespace n ON n.oid = table_rel.relnamespace
WHERE n.nspname = '$schema'
  AND table_rel.relname = 'tool_call_logs'
  AND index_rel.relnamespace = table_rel.relnamespace
  AND index_rel.relname IN (
    'idx_tool_call_logs_tenant_event_created',
    'idx_tool_call_logs_tenant_tool_call_id'
  )
  AND NOT i.indisvalid")"
[[ "$invalid_runtime_indexes" == "2" ]] || {
  echo "failed to establish two INVALID runtime indexes: $invalid_runtime_indexes" >&2
  exit 1
}

# Exercise the exact migration runner path as well. Its no-outer-transaction
# detector must select plain execution for CREATE INDEX CONCURRENTLY, and the
# checksum record must make the second run a skip.
cp "$MIGRATION" "$runner_dir/112_tool_event_runtime_truth.sql"
cat >"$psql_wrapper" <<'WRAPPER'
#!/usr/bin/env bash
exec env PGOPTIONS="-c search_path=$RUNTIME_TRUTH_TEST_SCHEMA" \
  psql "$RUNTIME_TRUTH_TEST_DSN" "$@"
WRAPPER
chmod +x "$psql_wrapper"
export RUNTIME_TRUTH_TEST_SCHEMA="$schema"
export RUNTIME_TRUTH_TEST_DSN="$dsn"
for _ in 1 2; do
  MIGRATION_PSQL="$psql_wrapper" bash "$ROOT/deploy/lib/migration-runner.sh" \
    --migrations-dir "$runner_dir" >/dev/null
done
runner_records="$(PGOPTIONS="-c search_path=$schema" psql "$dsn" -tAc \
  "SELECT count(*) FROM schema_migrations WHERE version = '112_tool_event_runtime_truth.sql'")"
[[ "$runner_records" == "1" ]] || {
  echo "migration runner did not record exactly one 112 checksum: $runner_records" >&2
  exit 1
}

valid_runtime_indexes="$(psql "$dsn" -tAc "
SELECT count(*)
FROM pg_index i
JOIN pg_class index_rel ON index_rel.oid = i.indexrelid
JOIN pg_class table_rel ON table_rel.oid = i.indrelid
JOIN pg_namespace n ON n.oid = table_rel.relnamespace
WHERE n.nspname = '$schema'
  AND table_rel.relname = 'tool_call_logs'
  AND index_rel.relnamespace = table_rel.relnamespace
  AND index_rel.relname IN (
    'idx_tool_call_logs_tenant_event_created',
    'idx_tool_call_logs_tenant_tool_call_id'
  )
  AND i.indisvalid")"
[[ "$valid_runtime_indexes" == "2" ]] || {
  echo "migration runner left runtime indexes missing or INVALID: $valid_runtime_indexes/2 valid" >&2
  exit 1
}
PGOPTIONS="-c search_path=$schema" psql "$dsn" -v ON_ERROR_STOP=1 \
  -c "DELETE FROM tool_call_logs WHERE id IN ('index-poison-a', 'index-poison-b')" >/dev/null

legacy_marked="$(PGOPTIONS="-c search_path=$schema" psql "$dsn" -tAc \
  "SELECT count(*) FROM tool_call_logs WHERE event_kind IS NOT NULL OR execution_observed IS NOT NULL")"
[[ "$legacy_marked" == "0" ]] || {
  echo "historical rows were rewritten as runtime facts: $legacy_marked" >&2
  exit 1
}

invalid_checks="$(psql "$dsn" -tAc "
SELECT count(*)
FROM pg_constraint c
JOIN pg_namespace n ON n.oid = c.connamespace
WHERE n.nspname = '$schema'
  AND c.conname IN ('tool_call_logs_event_kind_check','tool_call_logs_attribution_mode_check','tool_call_logs_attribution_confidence_check','tool_call_logs_execution_fact_check','tool_call_logs_block_not_executed_check','tool_call_logs_result_fact_check')
  AND NOT c.convalidated")"
[[ "$invalid_checks" == "6" ]] || {
  echo "expected six NOT VALID runtime-truth checks, got $invalid_checks" >&2
  exit 1
}

expect_rejected() {
  local sql="$1" label="$2"
  if PGOPTIONS="-c search_path=$schema" psql "$dsn" -v ON_ERROR_STOP=1 -c "$sql" >/dev/null 2>&1; then
    echo "runtime-truth invariant accepted invalid row: $label" >&2
    exit 1
  fi
}

expect_accepted() {
  local sql="$1" label="$2"
  if ! PGOPTIONS="-c search_path=$schema" psql "$dsn" -v ON_ERROR_STOP=1 -c "$sql" >/dev/null 2>&1; then
    echo "runtime-truth invariant rejected valid row: $label" >&2
    exit 1
  fi
}

base="INSERT INTO tool_call_logs (id, request_id, tenant_id, tool_name, tool_type, event_kind, execution_observed, result_observed, effective_decision) VALUES"
expect_accepted \
  "$base ('good-legacy-null-tuple','req','tenant','tool','mcp',NULL,NULL,NULL,'allow')" \
  "legacy fact tuple is entirely unknown"
expect_accepted \
  "$base ('good-proposal','req','tenant','tool','mcp','invocation_proposed',false,false,'allow')" \
  "new proposal has explicit false facts"
expect_rejected \
  "$base ('bad-forward-false','req','tenant','tool','mcp','execution_forwarded',false,false,'allow')" \
  "execution_forwarded without execution_observed"
expect_rejected \
  "$base ('bad-execution-kind','req','tenant','tool','mcp','invocation_proposed',true,false,'allow')" \
  "execution_observed on non-forward event"
expect_rejected \
  "$base ('bad-execution-null-kind','req','tenant','tool','mcp',NULL,true,NULL,'allow')" \
  "execution_observed without event kind"
expect_rejected \
  "$base ('bad-new-execution-null','req','tenant','tool','mcp','invocation_proposed',NULL,false,'allow')" \
  "new event without explicit execution fact"
expect_rejected \
  "$base ('bad-new-result-null','req','tenant','tool','mcp','invocation_proposed',false,NULL,'allow')" \
  "new event without explicit result fact"
expect_rejected \
  "$base ('bad-block-executed','req','tenant','tool','mcp','execution_forwarded',true,false,'block')" \
  "blocked decision observed as execution"
expect_rejected \
  "$base ('bad-result-false','req','tenant','tool','mcp','result_observed',false,false,'allow')" \
  "result_observed event without result fact"
expect_rejected \
  "$base ('bad-result-kind','req','tenant','tool','mcp','invocation_proposed',false,true,'allow')" \
  "result fact on proposal event"
expect_rejected \
  "$base ('bad-result-null-kind','req','tenant','tool','mcp',NULL,NULL,true,'allow')" \
  "result fact without event kind"

attribution_base="INSERT INTO tool_call_logs (id, request_id, tenant_id, tool_name, tool_type, event_kind, execution_observed, result_observed, effective_decision, attribution_mode, attribution_confidence) VALUES"
expect_accepted \
  "$attribution_base ('good-attribution-none','req','tenant','tool','mcp','invocation_proposed',false,false,'allow',NULL,NULL)" \
  "attribution tuple is entirely absent"
expect_accepted \
  "$attribution_base ('good-attribution-linked','req','tenant','tool','mcp','invocation_proposed',false,false,'allow','linked',0.75)" \
  "attribution tuple is present and bounded"
expect_rejected \
  "$attribution_base ('bad-attribution-mode-only','req','tenant','tool','mcp','invocation_proposed',false,false,'allow','linked',NULL)" \
  "attribution mode without confidence"
expect_rejected \
  "$attribution_base ('bad-attribution-confidence-only','req','tenant','tool','mcp','invocation_proposed',false,false,'allow',NULL,0.75)" \
  "attribution confidence without mode"
expect_rejected \
  "$attribution_base ('bad-attribution-low','req','tenant','tool','mcp','invocation_proposed',false,false,'allow','linked',-0.01)" \
  "attribution confidence below zero"
expect_rejected \
  "$attribution_base ('bad-attribution-high','req','tenant','tool','mcp','invocation_proposed',false,false,'allow','linked',1.01)" \
  "attribution confidence above one"

echo "[ok] runtime truth migration repeated application and legacy safety"
