#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
MIGRATION="$ROOT/deploy/migrations/822_quota_policy_stable_key_id.sql"

[[ -f "$MIGRATION" ]]
grep -Fq 'ADD COLUMN IF NOT EXISTS key_id' "$MIGRATION"
grep -Fq 'fk_quota_policies_key_id' "$MIGRATION"
grep -Fq 'HAVING COUNT(*) = 1' "$MIGRATION"
grep -Fq 'uq_quota_policies_tenant_key_id' "$MIGRATION"
grep -Fq 'ON DELETE CASCADE' "$MIGRATION"

dsn="${1:-}"
if [[ -z "$dsn" ]]; then
  echo '[ok] stable key quota migration static contract'
  exit 0
fi

schema="keyquota822_${RANDOM}_$$"
cleanup() {
  psql "$dsn" -v ON_ERROR_STOP=1 -c "DROP SCHEMA IF EXISTS $schema CASCADE" >/dev/null 2>&1 || true
}
trap cleanup EXIT
psql "$dsn" -v ON_ERROR_STOP=1 -c "CREATE SCHEMA $schema" >/dev/null
PGOPTIONS="-c search_path=$schema" psql "$dsn" -v ON_ERROR_STOP=1 <<'SQL' >/dev/null
CREATE TABLE internal_keys (
  id varchar(64) PRIMARY KEY,
  tenant_id varchar(64) NOT NULL,
  key_prefix varchar(32) NOT NULL
);
CREATE TABLE quota_policies (
  id varchar(64) PRIMARY KEY,
  tenant_id varchar(64) NOT NULL,
  scope_type varchar(32) NOT NULL,
  key_prefix varchar(32)
);
INSERT INTO internal_keys VALUES
  ('key-unique','tenant-a','sk-unique'),
  ('key-ambiguous-a','tenant-a','sk-ambiguous'),
  ('key-ambiguous-b','tenant-a','sk-ambiguous'),
  ('key-duplicate-policy','tenant-a','sk-duplicate-policy'),
  ('key-other-tenant','tenant-b','sk-other');
INSERT INTO quota_policies VALUES
  ('policy-unique','tenant-a','key','sk-unique'),
  ('policy-ambiguous','tenant-a','key','sk-ambiguous'),
  ('policy-duplicate-a','tenant-a','key','sk-duplicate-policy'),
  ('policy-duplicate-b','tenant-a','key','sk-duplicate-policy');
SQL
for _ in 1 2; do
  PGOPTIONS="-c search_path=$schema" psql "$dsn" -v ON_ERROR_STOP=1 -f "$MIGRATION" >/dev/null
done
result="$(PGOPTIONS="-c search_path=$schema" psql "$dsn" -tAc "SELECT string_agg(id||'='||COALESCE(key_id,'NULL'),',' ORDER BY id) FROM quota_policies")"
expected='policy-ambiguous=NULL,policy-duplicate-a=NULL,policy-duplicate-b=NULL,policy-unique=key-unique'
[[ "$result" == "$expected" ]] || { echo "unexpected backfill: $result" >&2; exit 1; }

fk_columns="$(PGOPTIONS="-c search_path=$schema" psql "$dsn" -tAc "
SELECT string_agg(a.attname, ',' ORDER BY u.ord)
FROM pg_constraint c
CROSS JOIN LATERAL unnest(c.conkey) WITH ORDINALITY AS u(attnum, ord)
JOIN pg_attribute a ON a.attrelid = c.conrelid AND a.attnum = u.attnum
WHERE c.conname = 'fk_quota_policies_key_id'
  AND c.conrelid = 'quota_policies'::regclass
  AND c.confdeltype = 'c'")"
[[ "$fk_columns" == 'tenant_id,key_id' ]] || { echo "unexpected FK columns/action: $fk_columns" >&2; exit 1; }

if PGOPTIONS="-c search_path=$schema" psql "$dsn" -v ON_ERROR_STOP=1 -c \
  "INSERT INTO quota_policies (id,tenant_id,scope_type,key_prefix,key_id) VALUES ('policy-cross-tenant','tenant-a','key','sk-other','key-other-tenant')" \
  >/dev/null 2>&1; then
  echo 'cross-tenant key reference unexpectedly accepted' >&2
  exit 1
fi

PGOPTIONS="-c search_path=$schema" psql "$dsn" -v ON_ERROR_STOP=1 -c \
  "DELETE FROM internal_keys WHERE id='key-unique'" >/dev/null
cascade_count="$(PGOPTIONS="-c search_path=$schema" psql "$dsn" -tAc "SELECT COUNT(*) FROM quota_policies WHERE id='policy-unique'")"
[[ "$cascade_count" == '0' ]] || { echo "key policy was not deleted by cascade: $cascade_count" >&2; exit 1; }
echo '[ok] stable key quota migration is idempotent and preserves ambiguous rows'
