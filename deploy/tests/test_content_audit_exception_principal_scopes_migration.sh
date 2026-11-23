#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
MIGRATION="$ROOT/deploy/migrations/826_content_audit_exception_principal_scopes.sql"

[[ -f "$MIGRATION" ]]
grep -Fq 'ADD COLUMN IF NOT EXISTS include_children' "$MIGRATION"
grep -Fq 'key_v1' "$MIGRATION"
grep -Fq 'actor_department_v1' "$MIGRATION"
grep -Fq 'chk_content_audit_exception_scope_v1' "$MIGRATION"
grep -Fq 'NOT VALID' "$MIGRATION"

dsn="${1:-}"
if [[ -z "$dsn" ]]; then
  echo '[ok] content exception principal scope migration static contract'
  exit 0
fi

schema="contentexc826_${RANDOM}_$$"
cleanup() {
  psql "$dsn" -v ON_ERROR_STOP=1 -c "DROP SCHEMA IF EXISTS $schema CASCADE" >/dev/null 2>&1 || true
}
trap cleanup EXIT
psql "$dsn" -v ON_ERROR_STOP=1 -c "CREATE SCHEMA $schema" >/dev/null
PGOPTIONS="-c search_path=$schema" psql "$dsn" -v ON_ERROR_STOP=1 <<'SQL' >/dev/null
CREATE TABLE content_audit_exceptions (
  id varchar(64) PRIMARY KEY,
  tenant_id varchar(64) NOT NULL,
  scope_type varchar(32) NOT NULL DEFAULT 'tenant',
  scope_ref varchar(255) NOT NULL DEFAULT '',
  rule_id varchar(64),
  rule_ref text,
  decision varchar(16) NOT NULL DEFAULT 'audit',
  reason text NOT NULL,
  expires_at timestamptz,
  enabled boolean NOT NULL DEFAULT true
);
INSERT INTO content_audit_exceptions
  (id,tenant_id,scope_type,scope_ref,decision,reason)
VALUES
  ('legacy-unknown','tenant-a','legacy_future_scope','','audit','preserve but fail closed'),
  ('legacy-tenant','tenant-a','tenant','','audit','preserve legacy');
SQL

for _ in 1 2; do
  PGOPTIONS="-c search_path=$schema" psql "$dsn" -v ON_ERROR_STOP=1 -f "$MIGRATION" >/dev/null
done

legacy="$(PGOPTIONS="-c search_path=$schema" psql "$dsn" -tAc "
  SELECT string_agg(id||'='||include_children::text,',' ORDER BY id)
  FROM content_audit_exceptions
  WHERE id LIKE 'legacy-%'")"
[[ "$legacy" == 'legacy-tenant=false,legacy-unknown=false' ]] || {
  echo "unexpected legacy migration result: $legacy" >&2
  exit 1
}

constraint_validated="$(PGOPTIONS="-c search_path=$schema" psql "$dsn" -tAc "
  SELECT convalidated
  FROM pg_constraint
  WHERE conname='chk_content_audit_exception_scope_v1'
    AND conrelid='content_audit_exceptions'::regclass")"
[[ "$constraint_validated" == 'f' ]] || {
  echo "scope compatibility constraint must remain NOT VALID: $constraint_validated" >&2
  exit 1
}

assert_rejected() {
  local sql="$1"
  if PGOPTIONS="-c search_path=$schema" psql "$dsn" -v ON_ERROR_STOP=1 -c "$sql" >/dev/null 2>&1; then
    echo "unexpectedly accepted: $sql" >&2
    exit 1
  fi
}

assert_rejected "INSERT INTO content_audit_exceptions (id,tenant_id,scope_type,scope_ref,decision,reason) VALUES ('new-unknown','tenant-a','future_scope','','audit','reject')"
assert_rejected "INSERT INTO content_audit_exceptions (id,tenant_id,scope_type,scope_ref,include_children,decision,reason) VALUES ('key-children','tenant-a','key_v1','key-a',true,'audit','reject')"
assert_rejected "INSERT INTO content_audit_exceptions (id,tenant_id,scope_type,scope_ref,decision,reason) VALUES ('dept-empty','tenant-a','actor_department_v1','','audit','reject')"

PGOPTIONS="-c search_path=$schema" psql "$dsn" -v ON_ERROR_STOP=1 -c "
  INSERT INTO content_audit_exceptions
    (id,tenant_id,scope_type,scope_ref,include_children,decision,reason)
  VALUES
    ('key-valid','tenant-a','key_v1','key-a',false,'audit','valid'),
    ('dept-valid','tenant-a','actor_department_v1','dept-a',true,'audit','valid')
" >/dev/null

echo '[ok] content exception principal scope migration is idempotent and preserves legacy unknown rows'
