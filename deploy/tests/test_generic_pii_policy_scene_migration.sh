#!/usr/bin/env bash
set -euo pipefail

dsn="${RULES_TEST_DATABASE_URL:-}"
if [[ -z "$dsn" ]]; then
  echo "SKIP: RULES_TEST_DATABASE_URL is not set"
  exit 0
fi

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
migration="$root_dir/deploy/migrations/128_generic_pii_policy_scene.sql"
schema="generic_pii_scene_$$_${RANDOM}"

cleanup() {
  psql "$dsn" -v ON_ERROR_STOP=1 -c "DROP SCHEMA IF EXISTS \"$schema\" CASCADE" >/dev/null
}
trap cleanup EXIT

psql "$dsn" -v ON_ERROR_STOP=1 <<SQL >/dev/null
CREATE SCHEMA "$schema";
SET search_path TO "$schema";
CREATE TABLE rule_sets (
  id text PRIMARY KEY,
  tenant_id text NOT NULL,
  source_type text NOT NULL
);
CREATE TABLE rules (
  id text PRIMARY KEY,
  rule_set_id text NOT NULL REFERENCES rule_sets(id),
  scope_json jsonb
);
INSERT INTO rule_sets(id,tenant_id,source_type) VALUES
  ('ruleset_builtin_generic','tenant_system','builtin'),
  ('tenant_rules','tenant_a','system');
INSERT INTO rules(id,rule_set_id,scope_json) VALUES
  ('rule_g_phone','ruleset_builtin_generic','{"data_level":"L3"}'),
  ('rule_g_idcard','ruleset_builtin_generic','{"data_level":"L4","scene":"old"}'),
  ('rule_g_bankcard','ruleset_builtin_generic','{}'),
  ('rule_g_email','ruleset_builtin_generic',NULL),
  ('rule_g_passport','ruleset_builtin_generic','{"data_level":"L4"}'),
  ('rule_g_unrelated','ruleset_builtin_generic','{"scene":"keep"}'),
  ('rule_g_phone_tenant','tenant_rules','{"scene":"keep"}');
SQL

for _ in 1 2; do
  PGOPTIONS="-c search_path=$schema" psql "$dsn" -v ON_ERROR_STOP=1 -f "$migration" >/dev/null
done

expected="5|5|3|keep|keep"
actual="$(PGOPTIONS="-c search_path=$schema" psql "$dsn" -Atc "
SELECT
  count(*) FILTER (WHERE id IN ('rule_g_phone','rule_g_idcard','rule_g_bankcard','rule_g_email','rule_g_passport')),
  count(*) FILTER (WHERE id IN ('rule_g_phone','rule_g_idcard','rule_g_bankcard','rule_g_email','rule_g_passport') AND scope_json->>'scene'='data_leak'),
  count(*) FILTER (WHERE scope_json ? 'data_level'),
  max(scope_json->>'scene') FILTER (WHERE id='rule_g_unrelated'),
  max(scope_json->>'scene') FILTER (WHERE id='rule_g_phone_tenant')
FROM rules;")"

if [[ "$actual" != "$expected" ]]; then
  echo "generic PII scene migration mismatch: got $actual want $expected" >&2
  exit 1
fi

echo "PASS: generic PII policies are idempotently assigned to data_leak"
