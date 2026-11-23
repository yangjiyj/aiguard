#!/usr/bin/env bash
set -Eeuo pipefail
# 临时容器：打测试标签、先回收被杀掉的测试进程留下的孤儿容器，清理用 docker rm -f -v（见该库说明）。
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib/test-containers.sh"
jjd_test_reap_orphan_containers
jjd_test_container_labels jjdguard-neutral-baseline
umask 077
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
MIGRATOR="$ROOT/deploy/migrations/prepare-jjdguard-neutral-baseline.sh"
MANIFEST="$ROOT/deploy/migrations/jjdguard-neutral-baseline-manifest.tsv"
[[ -x "$MIGRATOR" ]] || { echo '[neutral-test] migrator missing' >&2; exit 1; }
[[ -f "$MANIFEST" ]] || { echo '[neutral-test] manifest missing' >&2; exit 1; }

token="$(od -An -N6 -tx1 /dev/urandom | tr -d ' \n')"
case "$token" in (*[!0-9a-f]*|'') exit 1;; esac
name="jjdguard-neutral-$token"
tmp="$(mktemp -d)"
cleanup() {
  docker rm -f -v "$name" >/dev/null 2>&1 || true
  rm -rf "$tmp"
}
trap cleanup EXIT

docker run "${JJD_TEST_CONTAINER_LABELS[@]}" -d --name "$name" \
  --label com.jjdguard.fixture=neutral-baseline \
  -e POSTGRES_PASSWORD=fixture-password \
  -e POSTGRES_USER=fixture \
  -e POSTGRES_DB=fixture \
  -p 127.0.0.1::5432 postgres:16-alpine >/dev/null
for _ in $(seq 1 60); do
  docker exec "$name" pg_isready -U fixture -d fixture >/dev/null 2>&1 && break
  sleep 1
done
docker exec "$name" pg_isready -U fixture -d fixture >/dev/null
port="$(docker inspect "$name" --format '{{(index (index .NetworkSettings.Ports "5432/tcp") 0).HostPort}}')"
case "$port" in (*[!0-9]*|'') exit 1;; esac
base_dsn="postgresql://fixture:fixture-password@127.0.0.1:$port"
dsn="$base_dsn/fixture"
psqlq() { psql "$dsn" -v ON_ERROR_STOP=1 -X -q "$@"; }
scalar() { psql "$dsn" -v ON_ERROR_STOP=1 -X -tAc "$1" | tr -d '[:space:]'; }

migrations="$tmp/migrations"
install -d -m 0700 "$migrations"
printf '%s\n' 'SELECT 1;' >"$migrations/001_fixture.sql"
printf '%s\n' 'SELECT 3;' >"$migrations/003_fixture.sql"
# 四位编号（2.9.22 起新迁移从 1000 起）必须进账本比对，按 migration-version.sh 的规则识别。
printf '%s\n' 'SELECT 1010;' >"$migrations/1010_fixture.sql"
m1="$(sha256sum "$migrations/001_fixture.sql" | awk '{print $1}')"
m3="$(sha256sum "$migrations/003_fixture.sql" | awk '{print $1}')"
m1010="$(sha256sum "$migrations/1010_fixture.sql" | awk '{print $1}')"
manifest_sha="$(sha256sum "$MANIFEST" | awk '{print $1}')"
inventory_sha="$(printf 'fixture-inventory-v1' | sha256sum | awk '{print $1}')"
payload_sha="$(printf 'fixture-compat-payload-v1' | sha256sum | awk '{print $1}')"
trust="$tmp/handoff.tsv"
write_trust() {
  printf '%s\t%s\n' \
    schema jjdguard-compat-handoff/v1 \
    manifest_sha256 "$manifest_sha" \
    inventory_sha256 "$inventory_sha" \
    payload_sha256 "$payload_sha" >"$trust"
  chmod 0400 "$trust"
}
write_trust

psqlq <<SQL
CREATE TABLE schema_migrations (
  version text PRIMARY KEY,
  checksum text NOT NULL,
  applied_at timestamptz NOT NULL DEFAULT now()
);
INSERT INTO schema_migrations(version, checksum) VALUES
  ('001_fixture.sql', '$m1'),
  ('003_fixture.sql', '$m3'),
  ('1010_fixture.sql', '$m1010');
CREATE TABLE jjdguard_compat_inventory (
  singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
  inventory_sha256 text NOT NULL,
  payload_sha256 text NOT NULL
);
INSERT INTO jjdguard_compat_inventory(singleton, inventory_sha256, payload_sha256)
VALUES (true, '$inventory_sha', '$payload_sha');

CREATE SCHEMA compat_brand_fixture;
CREATE TYPE compat_brand_fixture.newapi_state AS ENUM ('newapi_pending', 'ready');
CREATE TABLE compat_brand_fixture.newapi_system_settings (
  id integer PRIMARY KEY,
  kind text NOT NULL,
  newapi_code text NOT NULL DEFAULT 'newapi-system',
  customer_text text NOT NULL,
  newapi_generated text GENERATED ALWAYS AS (newapi_code || '-generated') STORED,
  state compat_brand_fixture.newapi_state NOT NULL DEFAULT 'newapi_pending'
);
ALTER TABLE compat_brand_fixture.newapi_system_settings ENABLE ROW LEVEL SECURITY;
CREATE POLICY newapi_policy ON compat_brand_fixture.newapi_system_settings USING (true);
CREATE VIEW compat_brand_fixture.newapi_view AS
  SELECT id, newapi_code FROM compat_brand_fixture.newapi_system_settings;
CREATE MATERIALIZED VIEW compat_brand_fixture.newapi_matview AS
  SELECT count(*) AS total FROM compat_brand_fixture.newapi_system_settings;
CREATE FUNCTION compat_brand_fixture.newapi_fn() RETURNS text
  LANGUAGE sql IMMUTABLE AS \$\$ SELECT 'newapi-system'::text \$\$;
CREATE PROCEDURE compat_brand_fixture.newapi_proc()
  LANGUAGE sql AS \$\$ SELECT 1 \$\$;
CREATE FUNCTION compat_brand_fixture.fixture_trigger_fn() RETURNS trigger
  LANGUAGE plpgsql AS \$\$ BEGIN RETURN NEW; END \$\$;
CREATE TRIGGER newapi_trigger BEFORE UPDATE ON compat_brand_fixture.newapi_system_settings
  FOR EACH ROW EXECUTE FUNCTION compat_brand_fixture.fixture_trigger_fn();
COMMENT ON TABLE compat_brand_fixture.newapi_system_settings IS 'newapi system table';
COMMENT ON COLUMN compat_brand_fixture.newapi_system_settings.newapi_code IS 'newapi system code';
COMMENT ON EXTENSION plpgsql IS 'newapi fixture extension comment';
INSERT INTO compat_brand_fixture.newapi_system_settings(id, kind, customer_text) VALUES
  (1, 'system', 'customer free text says NewAPI and must stay byte-identical'),
  (2, 'customer', 'customer-owned NewAPI wording must never be rewritten');
SQL

customer_before="$(psql "$dsn" -X -tAc "SELECT string_agg(customer_text, E'\\n' ORDER BY id) FROM compat_brand_fixture.newapi_system_settings")"
count_before="$(scalar "SELECT count(*) FROM compat_brand_fixture.newapi_system_settings")"
types_before="$(psql "$dsn" -X -Atc "SELECT kind||'|'||replace(name,'newapi','jjdguard') FROM (VALUES ('table','newapi_system_settings'),('view','newapi_view'),('matview','newapi_matview'),('function','newapi_fn'),('procedure','newapi_proc'),('type','newapi_state'),('policy','newapi_policy'),('trigger','newapi_trigger')) v(kind,name) ORDER BY kind,name")"

result="$tmp/result.tsv"
run_migrator() {
  "$MIGRATOR" \
    --dsn "$dsn" \
    --manifest "$MANIFEST" \
    --migrations-dir "$migrations" \
    --trust-file "$trust" \
    --result "$result"
}

if JJDGUARD_NEUTRAL_TEST_CRASH_BEFORE_COMMIT=1 run_migrator >/dev/null 2>&1; then
  echo '[neutral-test] injected crash unexpectedly committed' >&2
  exit 1
fi
test "$(scalar "SELECT to_regclass('compat_brand_fixture.newapi_system_settings') IS NOT NULL")" = t
test "$(scalar 'SELECT count(*) FROM schema_migrations')" = 3
test ! -e "$result"

run_migrator
test "$(scalar "SELECT to_regclass('compat_brand_fixture.jjdguard_system_settings') IS NOT NULL")" = t
test "$(scalar "SELECT to_regclass('compat_brand_fixture.newapi_system_settings') IS NULL")" = t
test "$(scalar "SELECT to_regclass('compat_brand_fixture.jjdguard_view') IS NOT NULL")" = t
test "$(scalar "SELECT to_regclass('compat_brand_fixture.jjdguard_matview') IS NOT NULL")" = t
test "$(scalar "SELECT to_regprocedure('compat_brand_fixture.jjdguard_fn()') IS NOT NULL")" = t
test "$(scalar "SELECT to_regprocedure('compat_brand_fixture.jjdguard_proc()') IS NOT NULL")" = t
test "$(scalar "SELECT EXISTS(SELECT 1 FROM pg_type t JOIN pg_namespace n ON n.oid=t.typnamespace WHERE n.nspname='compat_brand_fixture' AND t.typname='jjdguard_state')")" = t
test "$(scalar "SELECT EXISTS(SELECT 1 FROM pg_enum e JOIN pg_type t ON t.oid=e.enumtypid JOIN pg_namespace n ON n.oid=t.typnamespace WHERE n.nspname='compat_brand_fixture' AND t.typname='jjdguard_state' AND e.enumlabel='jjdguard_pending')")" = t
test "$(scalar "SELECT EXISTS(SELECT 1 FROM pg_policy WHERE polname='jjdguard_policy')")" = t
test "$(scalar "SELECT EXISTS(SELECT 1 FROM pg_trigger WHERE tgname='jjdguard_trigger' AND NOT tgisinternal)")" = t
test "$(scalar "SELECT position('jjdguard-system' in column_default)>0 FROM information_schema.columns WHERE table_schema='compat_brand_fixture' AND table_name='jjdguard_system_settings' AND column_name='jjdguard_code'")" = t
test "$(scalar "SELECT is_generated='ALWAYS' FROM information_schema.columns WHERE table_schema='compat_brand_fixture' AND table_name='jjdguard_system_settings' AND column_name='jjdguard_generated'")" = t
test "$(scalar "SELECT obj_description('compat_brand_fixture.jjdguard_system_settings'::regclass)='JJDGuard system table'")" = t
test "$(scalar "SELECT col_description('compat_brand_fixture.jjdguard_system_settings'::regclass, (SELECT attnum FROM pg_attribute WHERE attrelid='compat_brand_fixture.jjdguard_system_settings'::regclass AND attname='jjdguard_code'))='JJDGuard system code'")" = t
test "$(scalar "SELECT obj_description((SELECT oid FROM pg_extension WHERE extname='plpgsql'),'pg_extension')='JJDGuard fixture extension comment'")" = t
test "$(scalar "SELECT jjdguard_code='jjdguard-system' FROM compat_brand_fixture.jjdguard_system_settings WHERE kind='system'")" = t
customer_after="$(psql "$dsn" -X -tAc "SELECT string_agg(customer_text, E'\\n' ORDER BY id) FROM compat_brand_fixture.jjdguard_system_settings")"
test "$customer_after" = "$customer_before"
test "$(scalar 'SELECT count(*) FROM compat_brand_fixture.jjdguard_system_settings')" = "$count_before"
types_after="$(psql "$dsn" -X -Atc "SELECT kind||'|'||name FROM (VALUES ('table','jjdguard_system_settings'),('view','jjdguard_view'),('matview','jjdguard_matview'),('function','jjdguard_fn'),('procedure','jjdguard_proc'),('type','jjdguard_state'),('policy','jjdguard_policy'),('trigger','jjdguard_trigger')) v(kind,name) ORDER BY kind,name")"
test "$types_after" = "$types_before"
test "$(scalar 'SELECT count(*) FROM schema_migrations')" = 1
test "$(scalar "SELECT version='jjdguard-neutral-baseline-v1' AND checksum='$manifest_sha' FROM schema_migrations")" = t

expected_fields=$'schema\nstatus\nneutral_marker\nmanifest_sha256\ninventory_sha256\npayload_sha256\ncatalog_sha256\nobject_count\nrow_count\nstarted_at\nfinished_at'
test "$(cut -f1 "$result")" = "$expected_fields"
grep -Fqx $'schema\tjjdguard-neutral-result/v1' "$result"
grep -Fqx $'neutral_marker\tjjdguard-neutral-baseline-v1' "$result"
grep -Eq $'^catalog_sha256\t[0-9a-f]{64}$' "$result"
grep -Eq $'^object_count\t[0-9]+$' "$result"
grep -Eq $'^row_count\t[0-9]+$' "$result"
! grep -Fq 'customer free text' "$result"

first_catalog="$(awk -F '\t' '$1=="catalog_sha256" {print $2}' "$result")"
run_migrator
test "$(awk -F '\t' '$1=="status" {print $2}' "$result")" = already-applied
test "$(awk -F '\t' '$1=="catalog_sha256" {print $2}' "$result")" = "$first_catalog"

psqlq -c "INSERT INTO schema_migrations(version,checksum) VALUES ('unknown.sql','deadbeef')"
if run_migrator >/dev/null 2>&1; then echo '[neutral-test] extra ledger row accepted' >&2; exit 1; fi
psqlq -c "DELETE FROM schema_migrations WHERE version='unknown.sql'"
psqlq -c "UPDATE schema_migrations SET checksum='deadbeef'"
if run_migrator >/dev/null 2>&1; then echo '[neutral-test] marker checksum drift accepted' >&2; exit 1; fi
psqlq -c "UPDATE schema_migrations SET checksum='$manifest_sha'"

create_ledger_db() {
  local db=$1
  psql "$base_dsn/postgres" -X -v ON_ERROR_STOP=1 -q -c "CREATE DATABASE $db"
  psql "$base_dsn/$db" -X -v ON_ERROR_STOP=1 -q <<SQL
CREATE TABLE schema_migrations(version text PRIMARY KEY, checksum text NOT NULL, applied_at timestamptz DEFAULT now());
CREATE TABLE jjdguard_compat_inventory(singleton boolean PRIMARY KEY, inventory_sha256 text NOT NULL, payload_sha256 text NOT NULL);
INSERT INTO jjdguard_compat_inventory VALUES (true, '$inventory_sha', '$payload_sha');
SQL
}
create_ledger_db ledgercheck
ledger_dsn="$base_dsn/ledgercheck"
for mode in missing missing_four_digit extra checksum unknown; do
  psql "$ledger_dsn" -X -v ON_ERROR_STOP=1 -q -c 'TRUNCATE schema_migrations'
  case "$mode" in
    missing) psql "$ledger_dsn" -X -q -c "INSERT INTO schema_migrations(version,checksum) VALUES ('001_fixture.sql','$m1')" ;;
    missing_four_digit) psql "$ledger_dsn" -X -q -c "INSERT INTO schema_migrations(version,checksum) VALUES ('001_fixture.sql','$m1'),('003_fixture.sql','$m3')" ;;
    extra) psql "$ledger_dsn" -X -q -c "INSERT INTO schema_migrations(version,checksum) VALUES ('001_fixture.sql','$m1'),('003_fixture.sql','$m3'),('1010_fixture.sql','$m1010'),('004_extra.sql','deadbeef')" ;;
    checksum) psql "$ledger_dsn" -X -q -c "INSERT INTO schema_migrations(version,checksum) VALUES ('001_fixture.sql','deadbeef'),('003_fixture.sql','$m3'),('1010_fixture.sql','$m1010')" ;;
    unknown) psql "$ledger_dsn" -X -q -c "INSERT INTO schema_migrations(version,checksum) VALUES ('mystery.sql','deadbeef')" ;;
  esac
  if "$MIGRATOR" --dsn "$ledger_dsn" --manifest "$MANIFEST" --migrations-dir "$migrations" --trust-file "$trust" --result "$tmp/reject.tsv" >/dev/null 2>&1; then
    echo "[neutral-test] ledger mode accepted: $mode" >&2; exit 1
  fi
done

psql "$base_dsn/postgres" -X -v ON_ERROR_STOP=1 -q -c 'CREATE DATABASE zerodb'
zero_result="$tmp/zero.tsv"
"$MIGRATOR" --dsn "$base_dsn/zerodb" --manifest "$MANIFEST" --migrations-dir "$migrations" --trust-file "$trust" --result "$zero_result"
grep -Fqx $'status\tnot-present/zero' "$zero_result"
grep -Fqx $'neutral_marker\tnot-present/zero' "$zero_result"

chmod 0600 "$trust"
printf '\n' >>"$trust"
if run_migrator >/dev/null 2>&1; then echo '[neutral-test] trust drift accepted' >&2; exit 1; fi
printf 'neutral_baseline=ok catalog_types=8 ledger_rejections=6 crash_rollback=1 idempotent=1 zero_ledger=1 customer_text_unchanged=1\n'
