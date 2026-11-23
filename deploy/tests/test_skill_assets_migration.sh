#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
MIGRATION="$ROOT/deploy/migrations/115_skill_gateway_assets.sql"

[[ -f "$MIGRATION" ]] || { echo "missing migration: $MIGRATION" >&2; exit 1; }

for table in skill_assets skill_asset_versions skill_invocations; do
  grep -Eqi "CREATE TABLE IF NOT EXISTS[[:space:]]+$table" "$MIGRATION" || {
    echo "missing table: $table" >&2
    exit 1
  }
done
for required in tenant_id bundle_hash tree_hash findings_json admission_status scan_status attribution_mode attribution_confidence; do
  grep -Fq "$required" "$MIGRATION" || {
    echo "missing skill runtime fact: $required" >&2
    exit 1
  }
done
grep -Eqi "UNIQUE[[:space:]]*\([[:space:]]*tenant_id[[:space:]]*,[[:space:]]*asset_id[[:space:]]*,[[:space:]]*bundle_hash[[:space:]]*\)" "$MIGRATION" || {
  echo "skill versions need tenant-scoped bundle uniqueness" >&2
  exit 1
}
grep -Eqi "REFERENCES[[:space:]]+skill_assets[[:space:]]*\([[:space:]]*tenant_id[[:space:]]*,[[:space:]]*id[[:space:]]*\)" "$MIGRATION" || {
  echo "skill version/invocation references must preserve tenant identity" >&2
  exit 1
}
grep -Eqi "ON[[:space:]]+skill_invocations[[:space:]]*\([[:space:]]*tenant_id[[:space:]]*,[[:space:]]*session_id[[:space:]]*,[[:space:]]*tool_call_id[[:space:]]*\)" "$MIGRATION" || {
  echo "skill result linkage needs tenant/session/tool-call uniqueness" >&2
  exit 1
}
grep -Fq "skill_invocations_tenant_asset_version_fk" "$MIGRATION" || {
  echo "skill invocation asset and version must be bound as one identity" >&2
  exit 1
}
grep -Fq "reject_approved_skill_version_mutation" "$MIGRATION" || {
  echo "approved skill versions must be immutable" >&2
  exit 1
}

dsn="${1:-}"
if [[ -z "$dsn" ]]; then
  echo "[ok] skill asset migration static contract"
  exit 0
fi

schema="skill115_${RANDOM}_$$"
cleanup() {
  psql "$dsn" -v ON_ERROR_STOP=1 -c "DROP SCHEMA IF EXISTS $schema CASCADE" >/dev/null 2>&1 || true
}
trap cleanup EXIT

psql "$dsn" -v ON_ERROR_STOP=1 -c "CREATE SCHEMA $schema" >/dev/null
for _ in 1 2; do
  PGOPTIONS="-c search_path=$schema" psql "$dsn" -v ON_ERROR_STOP=1 -f "$MIGRATION" >/dev/null
done

PGOPTIONS="-c search_path=$schema" psql "$dsn" -v ON_ERROR_STOP=1 <<'SQL' >/dev/null
INSERT INTO skill_assets (id, tenant_id, canonical_name, source_type)
VALUES
  ('asset-a', 'tenant-a', 'pdf', 'uploaded'),
  ('asset-a2', 'tenant-a', 'pdf-alt', 'uploaded'),
  ('asset-b', 'tenant-b', 'pdf', 'uploaded');

INSERT INTO skill_asset_versions (
  id, tenant_id, asset_id, declared_version, bundle_hash, tree_hash,
  manifest_json, findings_json, risk_level, decision, scan_status
) VALUES
  ('version-a', 'tenant-a', 'asset-a', '1.0.0', repeat('a', 64), repeat('b', 64),
   '{}'::jsonb, '[]'::jsonb, 'low', 'allow', 'completed'),
  ('version-a2', 'tenant-a', 'asset-a2', '1.0.0', repeat('e', 64), repeat('f', 64),
   '{}'::jsonb, '[]'::jsonb, 'low', 'allow', 'completed');
SQL

if PGOPTIONS="-c search_path=$schema" psql "$dsn" -v ON_ERROR_STOP=1   -c "INSERT INTO skill_asset_versions (id, tenant_id, asset_id, bundle_hash, tree_hash, manifest_json, findings_json, risk_level, decision, scan_status) VALUES ('cross-version','tenant-b','asset-a',repeat('c',64),repeat('d',64),'{}','[]','low','allow','completed')" >/dev/null 2>&1; then
  echo "cross-tenant skill version reference was accepted" >&2
  exit 1
fi

if PGOPTIONS="-c search_path=$schema" psql "$dsn" -v ON_ERROR_STOP=1   -c "INSERT INTO skill_invocations (id,tenant_id,asset_id,request_id,session_id,tool_call_id,canonical_name,status,raw_decision,effective_decision,attribution_mode,attribution_confidence) VALUES ('cross-call','tenant-b','asset-a','r','s','tc','pdf','proposed','audit','audit','explicit',1)" >/dev/null 2>&1; then
  echo "cross-tenant invocation reference was accepted" >&2
  exit 1
fi
if PGOPTIONS="-c search_path=$schema" psql "$dsn" -v ON_ERROR_STOP=1   -c "INSERT INTO skill_invocations (id,tenant_id,asset_id,asset_version_id,request_id,session_id,tool_call_id,canonical_name,status,raw_decision,effective_decision,attribution_mode,attribution_confidence) VALUES ('mismatched-call','tenant-a','asset-a','version-a2','r2','s2','tc2','pdf','proposed','audit','audit','explicit',1)" >/dev/null 2>&1; then
  echo "mismatched Skill asset/version evidence was accepted" >&2
  exit 1
fi

PGOPTIONS="-c search_path=$schema" psql "$dsn" -v ON_ERROR_STOP=1 <<'SQL' >/dev/null
UPDATE skill_asset_versions
SET admission_status='approved', approved_by='admin', approved_at=now()
WHERE id='version-a';
SQL
if PGOPTIONS="-c search_path=$schema" psql "$dsn" -v ON_ERROR_STOP=1   -c "UPDATE skill_asset_versions SET findings_json='[{"type":"tampered"}]'::jsonb WHERE id='version-a'" >/dev/null 2>&1; then
  echo "approved skill version remained mutable" >&2
  exit 1
fi

same_name_count="$(PGOPTIONS="-c search_path=$schema" psql "$dsn" -tAc "SELECT count(*) FROM skill_assets WHERE canonical_name='pdf'")"
[[ "$same_name_count" == "2" ]] || {
  echo "cross-tenant same-name assets did not coexist: $same_name_count" >&2
  exit 1
}

echo "[ok] skill asset migration repeated application and tenant integrity"
