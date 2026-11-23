#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
MIGRATION="$ROOT/deploy/migrations/117_mcp_supply_chain_admission.sql"
for required in admission_status observed_manifest_snapshot approved_manifest_hash approved_manifest_snapshot observed_route_hash approved_route_hash compute_mcp_route_hash route_binding_changed approved_schema_hash approved_schema_snapshot quarantine_reason admission_reviewed_by admission_revision mcp_tools_tenant_server_fk rug_pull_manifest_changed rug_pull_schema_changed; do
  grep -Fq "$required" "$MIGRATION" || { echo "missing fact: $required" >&2; exit 1; }
done
dsn=""
if (( $# > 0 )); then dsn="$1"; fi
if [[ -z "$dsn" ]]; then echo "[ok] MCP supply-chain migration static contract"; exit 0; fi
schema="mcp117_$RANDOM"
cleanup() { psql "$dsn" -v ON_ERROR_STOP=1 -c "DROP SCHEMA IF EXISTS $schema CASCADE" >/dev/null 2>&1 || true; }
trap cleanup EXIT
psql "$dsn" -v ON_ERROR_STOP=1 -c "CREATE SCHEMA $schema" >/dev/null
PGOPTIONS="-c search_path=$schema" psql "$dsn" -v ON_ERROR_STOP=1 <<'SQL' >/dev/null
CREATE TABLE tenants(id TEXT PRIMARY KEY);
CREATE TABLE mcp_servers(id TEXT PRIMARY KEY,tenant_id TEXT NOT NULL REFERENCES tenants(id),name TEXT NOT NULL,server_url TEXT,transport TEXT NOT NULL DEFAULT 'streamable_http',allow_private_egress BOOLEAN NOT NULL DEFAULT FALSE,auth_key_ref TEXT NOT NULL DEFAULT '',auth_ciphertext TEXT NOT NULL DEFAULT '',manifest_hash TEXT NOT NULL DEFAULT '',capabilities_json JSONB DEFAULT '{}');
CREATE TABLE mcp_tools(id TEXT PRIMARY KEY,server_id TEXT NOT NULL REFERENCES mcp_servers(id) ON DELETE CASCADE,tenant_id TEXT NOT NULL,tool_name TEXT NOT NULL,description TEXT NOT NULL DEFAULT '',input_schema JSONB,schema_hash TEXT NOT NULL DEFAULT '',removed BOOLEAN NOT NULL DEFAULT FALSE,UNIQUE(server_id,tool_name));
INSERT INTO tenants VALUES('tenant-a'),('tenant-b');
SQL
for _ in 1 2; do PGOPTIONS="-c search_path=$schema" psql "$dsn" -v ON_ERROR_STOP=1 -f "$MIGRATION" >/dev/null; done
PGOPTIONS="-c search_path=$schema" psql "$dsn" -v ON_ERROR_STOP=1 <<'SQL' >/dev/null
INSERT INTO mcp_servers(id,tenant_id,name,manifest_hash,admission_status,observed_manifest_snapshot,approved_manifest_hash,approved_manifest_snapshot,admission_reviewed_by,admission_reviewed_at)
VALUES('server-a','tenant-a','a','manifest-v1','approved','[{"name":"safe"}]','manifest-v1','[{"name":"safe"}]','admin-a',now());
INSERT INTO mcp_servers(id,tenant_id,name,server_url,manifest_hash,admission_status,observed_manifest_snapshot,approved_manifest_hash,approved_manifest_snapshot,admission_reviewed_by,admission_reviewed_at)
VALUES('server-route','tenant-a','route','https://one.example/mcp','manifest-route','approved','[]','manifest-route','[]','admin-a',now());
UPDATE mcp_servers SET approved_route_hash=observed_route_hash WHERE id='server-route';
INSERT INTO mcp_tools(id,tenant_id,server_id,tool_name,description,input_schema,schema_hash,admission_status,approved_schema_hash,approved_schema_snapshot,admission_reviewed_by,admission_reviewed_at)
VALUES('tool-a','tenant-a','server-a','safe','safe','{}','schema-v1','approved','schema-v1','{"schema_hash":"schema-v1"}','admin-a',now());
SQL
if PGOPTIONS="-c search_path=$schema" psql "$dsn" -v ON_ERROR_STOP=1 -c "INSERT INTO mcp_tools(id,tenant_id,server_id,tool_name) VALUES('cross','tenant-b','server-a','x')" >/dev/null 2>&1; then
PGOPTIONS="-c search_path=$schema" psql "$dsn" -v ON_ERROR_STOP=1 -c "UPDATE mcp_servers SET server_url='https://two.example/mcp' WHERE id='server-route'" >/dev/null
route_state="$(PGOPTIONS="-c search_path=$schema" psql "$dsn" -tAc "SELECT admission_status||':'||quarantine_reason||':'||(observed_route_hash<>approved_route_hash)::text FROM mcp_servers WHERE id='server-route'")"
[[ "$route_state" == "quarantined:route_binding_changed:true" ]] || { echo "route binding trigger failed: $route_state" >&2; exit 1; }

  echo "cross-tenant relation accepted" >&2; exit 1
fi
PGOPTIONS="-c search_path=$schema" psql "$dsn" -v ON_ERROR_STOP=1 -c "UPDATE mcp_tools SET schema_hash='schema-v2',description='changed' WHERE id='tool-a'" >/dev/null
tool_state="$(PGOPTIONS="-c search_path=$schema" psql "$dsn" -tAc "SELECT admission_status||':'||quarantine_reason||':'||approved_schema_hash FROM mcp_tools WHERE id='tool-a'")"
[[ "$tool_state" == "quarantined:rug_pull_schema_changed:schema-v1" ]] || { echo "tool trigger failed: $tool_state" >&2; exit 1; }
PGOPTIONS="-c search_path=$schema" psql "$dsn" -v ON_ERROR_STOP=1 -c "UPDATE mcp_servers SET manifest_hash='manifest-v2',observed_manifest_snapshot='[{\"name\":\"changed\"}]' WHERE id='server-a'" >/dev/null
server_state="$(PGOPTIONS="-c search_path=$schema" psql "$dsn" -tAc "SELECT admission_status||':'||quarantine_reason||':'||approved_manifest_hash FROM mcp_servers WHERE id='server-a'")"
[[ "$server_state" == "quarantined:rug_pull_manifest_changed:manifest-v1" ]] || { echo "server trigger failed: $server_state" >&2; exit 1; }
echo "[ok] MCP supply-chain migration idempotence, tenant isolation, and rug-pull triggers"
