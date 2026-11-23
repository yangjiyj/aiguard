#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
MIGRATION="$ROOT/deploy/migrations/118_mcp_key_scope.sql"

[[ -f "$MIGRATION" ]] || { echo "missing migration: $MIGRATION" >&2; exit 1; }
for required in internal_keys scopes_json chat responses embeddings models; do
  grep -Fq "$required" "$MIGRATION" || { echo "missing scope migration fact: $required" >&2; exit 1; }
done
grep -Fq "ALTER COLUMN scopes_json" "$MIGRATION" &&
  grep -Fq "SET DEFAULT" "$MIGRATION" || {
  echo "new direct key rows need model-only default scopes" >&2
  exit 1
}
grep -Eq "scopes_json[[:space:]]*=[[:space:]]*'\[\]'::jsonb|scopes_json[[:space:]]*=[[:space:]]*'\[\]'" "$MIGRATION" || {
  echo "legacy empty scopes need conservative backfill" >&2
  exit 1
}
if grep -Eq "UPDATE[[:space:]]+internal_keys.*mcp" "$MIGRATION"; then
  echo "legacy keys must not receive MCP privilege" >&2
  exit 1
fi

expected_default='DEFAULT_KEY_SCOPES=["chat","responses","embeddings","models"]'
for file in deploy/docker-compose/.env.example deploy/docker-compose/deploy-oneclick.sh deploy/docker-compose/deploy-offline.sh; do
  grep -Fq "$expected_default" "$ROOT/$file" || {
    echo "$file still grants wildcard/default MCP privilege" >&2; exit 1;
  }
done

dsn="${1:-}"
if [[ -z "$dsn" ]]; then
  echo "[ok] MCP key scope migration static contract"
  exit 0
fi

schema="mcp118_${RANDOM}_$$"
cleanup() {
  psql "$dsn" -v ON_ERROR_STOP=1 -c "DROP SCHEMA IF EXISTS $schema CASCADE" >/dev/null 2>&1 || true
}
trap cleanup EXIT
psql "$dsn" -v ON_ERROR_STOP=1 -c "CREATE SCHEMA $schema" >/dev/null
PGOPTIONS="-c search_path=$schema" psql "$dsn" -v ON_ERROR_STOP=1 <<'SQL' >/dev/null
CREATE TABLE internal_keys (
  id TEXT PRIMARY KEY,
  scopes_json JSONB DEFAULT '[]'::jsonb
);
INSERT INTO internal_keys(id,scopes_json) VALUES
  ('legacy-empty','[]'::jsonb),
  ('wildcard','["*"]'::jsonb),
  ('mcp-explicit','["mcp"]'::jsonb);
SQL
for _ in 1 2; do
  PGOPTIONS="-c search_path=$schema" psql "$dsn" -v ON_ERROR_STOP=1 -f "$MIGRATION" >/dev/null
done
PGOPTIONS="-c search_path=$schema" psql "$dsn" -v ON_ERROR_STOP=1 -c "INSERT INTO internal_keys(id) VALUES ('new-default')" >/dev/null
legacy="$(PGOPTIONS="-c search_path=$schema" psql "$dsn" -tAc "SELECT (scopes_json ? 'chat')::text||'|'||(scopes_json ? 'mcp')::text||'|'||jsonb_array_length(scopes_json) FROM internal_keys WHERE id='legacy-empty'")"
new_default="$(PGOPTIONS="-c search_path=$schema" psql "$dsn" -tAc "SELECT (scopes_json ? 'chat')::text||'|'||(scopes_json ? 'mcp')::text||'|'||jsonb_array_length(scopes_json) FROM internal_keys WHERE id='new-default'")"
wildcard="$(PGOPTIONS="-c search_path=$schema" psql "$dsn" -tAc "SELECT scopes_json::text FROM internal_keys WHERE id='wildcard'")"
explicit="$(PGOPTIONS="-c search_path=$schema" psql "$dsn" -tAc "SELECT scopes_json::text FROM internal_keys WHERE id='mcp-explicit'")"
[[ "$legacy" == "true|false|4" && "$new_default" == "true|false|4" ]] || {
  echo "model-only scope backfill/default failed: legacy=$legacy new=$new_default" >&2
  exit 1
}
[[ "$wildcard" == '["*"]' && "$explicit" == '["mcp"]' ]] || {
  echo "explicit scopes changed: wildcard=$wildcard mcp=$explicit" >&2
  exit 1
}
echo "[ok] MCP key scope migration preserves explicit grants and removes legacy implicit MCP access"
