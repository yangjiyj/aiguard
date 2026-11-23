#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
MIGRATION="$ROOT/deploy/migrations/113_normalize_builtin_rule_types.sql"
SEED="$ROOT/deploy/migrations/068_industry_data_security_packs.sql"
EXPECTED_SEED_SHA256="401d33d04627135c0ccd99a5013b623d8311eb5c0c9804c4bf2e23b133a67956"

[[ -f "$MIGRATION" ]] || { echo "missing migration: $MIGRATION" >&2; exit 1; }
actual_seed_sha256="$(sha256sum "$SEED" | awk '{print $1}')"
[[ "$actual_seed_sha256" == "$EXPECTED_SEED_SHA256" ]] || {
  echo "immutable migration 068 checksum changed: $actual_seed_sha256" >&2
  exit 1
}
grep -Fq "ruleset_builtin_generic" "$MIGRATION" || { echo "migration must scope the generic builtin rule set" >&2; exit 1; }
grep -Eqi "rule_type[[:space:]]*=[[:space:]]*'pii'" "$MIGRATION" || { echo "migration must only rewrite legacy pii rows" >&2; exit 1; }
for id in rule_g_idcard rule_g_phone rule_g_bankcard rule_g_email rule_g_passport; do
  grep -Fq "$id" "$MIGRATION" || { echo "migration missing known builtin id: $id" >&2; exit 1; }
  grep -Eq "\('$id',[[:space:]]*'ruleset_builtin_generic',[[:space:]]*'pii'" "$SEED" || {
    echo "immutable migration 068 was rewritten for $id" >&2
    exit 1
  }
done

dsn="${1:-}"
if [[ -z "$dsn" ]]; then
  echo "[ok] rule runtime type migration static contract"
  exit 0
fi

schema="rule_type_113_${RANDOM}_$$"
cleanup() {
  psql "$dsn" -v ON_ERROR_STOP=1 -c "DROP SCHEMA IF EXISTS $schema CASCADE" >/dev/null 2>&1 || true
}
trap cleanup EXIT

psql "$dsn" -v ON_ERROR_STOP=1 <<SQL >/dev/null
CREATE SCHEMA $schema;
SET search_path TO $schema;
CREATE TABLE rules (id text PRIMARY KEY, rule_set_id text NOT NULL, rule_type text NOT NULL, match_config_json jsonb NOT NULL DEFAULT '{}');
INSERT INTO rules(id,rule_set_id,rule_type,match_config_json) VALUES
  ('rule_g_idcard','ruleset_builtin_generic','pii','{"regex":"id"}'),
  ('rule_g_phone','ruleset_builtin_generic','pii','{"regex":"phone"}'),
  ('rule_g_bankcard','ruleset_builtin_generic','pii','{"regex":"bank"}'),
  ('rule_g_email','ruleset_builtin_generic','pii','{"regex":"email"}'),
  ('rule_g_passport','ruleset_builtin_generic','pii','{"regex":"passport"}'),
  ('rule_g_other','ruleset_builtin_generic','pii','{"regex":"other"}'),
  ('tenant_rule','tenant_ruleset','pii','{"regex":"tenant"}');
SQL

for _ in 1 2; do
  PGOPTIONS="-c search_path=$schema" psql "$dsn" -v ON_ERROR_STOP=1 -f "$MIGRATION" >/dev/null
done

normalized="$(PGOPTIONS="-c search_path=$schema" psql "$dsn" -tAc "SELECT count(*) FROM rules WHERE id IN ('rule_g_idcard','rule_g_phone','rule_g_bankcard','rule_g_email','rule_g_passport') AND rule_type='regex'")"
[[ "$normalized" == "5" ]] || { echo "expected 5 normalized builtin rules, got $normalized" >&2; exit 1; }
untouched="$(PGOPTIONS="-c search_path=$schema" psql "$dsn" -tAc "SELECT count(*) FROM rules WHERE id IN ('rule_g_other','tenant_rule') AND rule_type='pii'")"
[[ "$untouched" == "2" ]] || { echo "migration changed out-of-scope rows: $untouched/2 untouched" >&2; exit 1; }

echo "[ok] rule runtime type migration database contract"
