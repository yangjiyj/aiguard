#!/usr/bin/env bash
set -Eeuo pipefail
umask 077
# 迁移文件按 migration-version.sh 的规则识别（三位以上数字编号，与 migration-runner 一致）。
# shellcheck source=../lib/migration-version.sh
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/../lib/migration-version.sh"

MARKER='jjdguard-neutral-baseline-v1'
RESULT_SCHEMA='jjdguard-neutral-result/v1'

die() {
  printf '[neutral-baseline] %s\n' "$*" >&2
  exit 1
}

usage() {
  printf '%s\n' \
    'Usage: prepare-jjdguard-neutral-baseline.sh --dsn DSN --manifest FILE' \
    '       --migrations-dir DIR --trust-file FILE --result FILE'
}

for tool in psql awk cmp find sort mktemp stat od; do
  command -v "$tool" >/dev/null 2>&1 || die "required command is missing: $tool"
done

sha256_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | awk '{print $1}'
  else
    die 'required SHA-256 command is missing'
  fi
}

dsn=''
manifest=''
migrations_dir=''
trust_file=''
result=''
declare -A seen=()
set_option() {
  local name="$1" value="$2"
  [[ -z "${seen[$name]+x}" ]] || die "duplicate option: $name"
  [[ -n "$value" ]] || die "empty option: $name"
  seen[$name]=1
  printf -v "$name" '%s' "$value"
}

while (($#)); do
  case "$1" in
    --dsn|--manifest|--migrations-dir|--trust-file|--result)
      (($# >= 2)) || die "missing value for $1"
      case "$1" in
        --dsn) set_option dsn "$2" ;;
        --manifest) set_option manifest "$2" ;;
        --migrations-dir) set_option migrations_dir "$2" ;;
        --trust-file) set_option trust_file "$2" ;;
        --result) set_option result "$2" ;;
      esac
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      die "unknown argument: $1"
      ;;
  esac
done

for required in dsn manifest migrations_dir trust_file result; do
  [[ -n "${!required}" ]] || die "missing required option: $required"
done
[[ -f "$manifest" && ! -L "$manifest" ]] || die 'manifest must be a regular non-symlink file'
[[ -d "$migrations_dir" ]] || die 'migrations directory is missing'
[[ -f "$trust_file" && ! -L "$trust_file" ]] || die 'trust file must be a regular non-symlink file'
[[ ! -L "$result" ]] || die 'result path must not be a symlink'
[[ -d "$(dirname "$result")" ]] || die 'result parent directory is missing'
[[ "$result" != "$manifest" && "$result" != "$trust_file" ]] || die 'result must not replace an input file'

tmp_dir="$(mktemp -d)"
cleanup() {
  rm -rf "$tmp_dir"
}
trap cleanup EXIT

expected_manifest="$tmp_dir/manifest.expected"
cat >"$expected_manifest" <<'MANIFEST'
schema	jjdguard-neutral-manifest/v1
marker	jjdguard-neutral-baseline-v1
rename	table	compat_brand_fixture	newapi_system_settings	jjdguard_system_settings
rename	column	compat_brand_fixture	newapi_system_settings	newapi_code	jjdguard_code
rename	column	compat_brand_fixture	newapi_system_settings	newapi_generated	jjdguard_generated
rename	view	compat_brand_fixture	newapi_view	jjdguard_view
rename	materialized_view	compat_brand_fixture	newapi_matview	jjdguard_matview
rename	function	compat_brand_fixture	newapi_fn()	jjdguard_fn
rename	procedure	compat_brand_fixture	newapi_proc()	jjdguard_proc
rename	type	compat_brand_fixture	newapi_state	jjdguard_state
rename	enum_value	compat_brand_fixture	newapi_state	newapi_pending	jjdguard_pending
rename	policy	compat_brand_fixture	newapi_system_settings	newapi_policy	jjdguard_policy
rename	trigger	compat_brand_fixture	newapi_system_settings	newapi_trigger	jjdguard_trigger
rewrite	default	compat_brand_fixture	newapi_system_settings	newapi_code	newapi-system	jjdguard-system
rewrite	function_result	compat_brand_fixture	newapi_fn()	newapi-system	jjdguard-system
rewrite	comment_table	compat_brand_fixture	newapi_system_settings	newapi system table	JJDGuard system table
rewrite	comment_column	compat_brand_fixture	newapi_system_settings	newapi_code	newapi system code	JJDGuard system code
rewrite	comment_extension	plpgsql	newapi fixture extension comment	JJDGuard fixture extension comment
rewrite	system_value	compat_brand_fixture	newapi_system_settings	kind	system	newapi_code	newapi-system	jjdguard-system
MANIFEST
cmp -s "$expected_manifest" "$manifest" || die 'manifest does not match the reviewed neutralization recipe'

trust_mode="$(stat -c '%a' "$trust_file")"
trust_owner="$(stat -c '%u' "$trust_file")"
[[ "$trust_mode" == 400 ]] || die 'trust file mode must be 0400'
[[ "$trust_owner" == "$(id -u)" ]] || die 'trust file owner must be the invoking user'
mapfile -t trust_lines <"$trust_file"
[[ "${#trust_lines[@]}" -eq 4 ]] || die 'trust file must contain exactly four canonical fields'
[[ "${trust_lines[0]}" == $'schema\tjjdguard-compat-handoff/v1' ]] || die 'trust schema mismatch'
[[ "${trust_lines[1]}" =~ ^manifest_sha256$'\t'([0-9a-f]{64})$ ]] || die 'invalid manifest hash in trust file'
manifest_sha="${BASH_REMATCH[1]}"
[[ "${trust_lines[2]}" =~ ^inventory_sha256$'\t'([0-9a-f]{64})$ ]] || die 'invalid inventory hash in trust file'
inventory_sha="${BASH_REMATCH[1]}"
[[ "${trust_lines[3]}" =~ ^payload_sha256$'\t'([0-9a-f]{64})$ ]] || die 'invalid payload hash in trust file'
payload_sha="${BASH_REMATCH[1]}"
[[ "$(sha256_file "$manifest")" == "$manifest_sha" ]] || die 'manifest hash does not match the trusted handoff'

psql_scalar() {
  psql "$dsn" -X -v ON_ERROR_STOP=1 -Atc "$1"
}

write_result() {
  local status="$1" marker="$2" catalog_sha="$3" object_count="$4" row_count="$5" started="$6"
  local finished result_tmp
  finished="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  result_tmp="$(mktemp "$(dirname "$result")/.jjdguard-neutral-result.XXXXXX")"
  printf '%s\n' \
    "schema	$RESULT_SCHEMA" \
    "status	$status" \
    "neutral_marker	$marker" \
    "manifest_sha256	$manifest_sha" \
    "inventory_sha256	$inventory_sha" \
    "payload_sha256	$payload_sha" \
    "catalog_sha256	$catalog_sha" \
    "object_count	$object_count" \
    "row_count	$row_count" \
    "started_at	$started" \
    "finished_at	$finished" >"$result_tmp"
  chmod 0400 "$result_tmp"
  mv -f "$result_tmp" "$result"
}

started_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
ledger_state="$(psql_scalar "SELECT CASE WHEN to_regclass('public.schema_migrations') IS NULL THEN 'missing' ELSE 'present' END")"
if [[ "$ledger_state" == missing ]]; then
  empty_file="$tmp_dir/empty"
  : >"$empty_file"
  write_result 'not-present/zero' 'not-present/zero' "$(sha256_file "$empty_file")" 0 0 "$started_at"
  exit 0
fi
ledger_count="$(psql_scalar 'SELECT count(*) FROM public.schema_migrations')"
[[ "$ledger_count" =~ ^[0-9]+$ ]] || die 'could not read migration ledger count'
if [[ "$ledger_count" == 0 ]]; then
  empty_file="$tmp_dir/empty"
  : >"$empty_file"
  write_result 'not-present/zero' 'not-present/zero' "$(sha256_file "$empty_file")" 0 0 "$started_at"
  exit 0
fi

inventory_state="$(psql_scalar "SELECT CASE WHEN to_regclass('public.jjdguard_compat_inventory') IS NULL THEN 'missing' ELSE 'present' END")"
[[ "$inventory_state" == present ]] || die 'trusted compatibility inventory table is missing'
inventory_record="$(psql "$dsn" -X -v ON_ERROR_STOP=1 -AtF $'\t' -c 'SELECT inventory_sha256, payload_sha256 FROM public.jjdguard_compat_inventory WHERE singleton IS TRUE ORDER BY inventory_sha256, payload_sha256')"
[[ "$inventory_record" == "$inventory_sha"$'\t'"$payload_sha" ]] || die 'database compatibility inventory does not match the trusted handoff'

verify_neutral_state() {
  local ok
  ok="$(psql_scalar "
SELECT
  to_regclass('compat_brand_fixture.jjdguard_system_settings') IS NOT NULL
  AND to_regclass('compat_brand_fixture.newapi_system_settings') IS NULL
  AND to_regclass('compat_brand_fixture.jjdguard_view') IS NOT NULL
  AND to_regclass('compat_brand_fixture.jjdguard_matview') IS NOT NULL
  AND to_regprocedure('compat_brand_fixture.jjdguard_fn()') IS NOT NULL
  AND to_regprocedure('compat_brand_fixture.jjdguard_proc()') IS NOT NULL
  AND EXISTS (SELECT 1 FROM pg_type t JOIN pg_namespace n ON n.oid=t.typnamespace WHERE n.nspname='compat_brand_fixture' AND t.typname='jjdguard_state')
  AND NOT EXISTS (SELECT 1 FROM pg_type t JOIN pg_namespace n ON n.oid=t.typnamespace WHERE n.nspname='compat_brand_fixture' AND t.typname='newapi_state')
  AND EXISTS (SELECT 1 FROM pg_enum e JOIN pg_type t ON t.oid=e.enumtypid JOIN pg_namespace n ON n.oid=t.typnamespace WHERE n.nspname='compat_brand_fixture' AND t.typname='jjdguard_state' AND e.enumlabel='jjdguard_pending')
  AND NOT EXISTS (SELECT 1 FROM pg_enum e JOIN pg_type t ON t.oid=e.enumtypid JOIN pg_namespace n ON n.oid=t.typnamespace WHERE n.nspname='compat_brand_fixture' AND e.enumlabel='newapi_pending')
  AND EXISTS (SELECT 1 FROM pg_policy WHERE polname='jjdguard_policy' AND polrelid='compat_brand_fixture.jjdguard_system_settings'::regclass)
  AND NOT EXISTS (SELECT 1 FROM pg_policy WHERE polname='newapi_policy')
  AND EXISTS (SELECT 1 FROM pg_trigger WHERE tgname='jjdguard_trigger' AND tgrelid='compat_brand_fixture.jjdguard_system_settings'::regclass AND NOT tgisinternal)
  AND NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname='newapi_trigger' AND NOT tgisinternal)
  AND EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema='compat_brand_fixture' AND table_name='jjdguard_system_settings' AND column_name='jjdguard_code' AND position('jjdguard-system' in column_default)>0)
  AND EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema='compat_brand_fixture' AND table_name='jjdguard_system_settings' AND column_name='jjdguard_generated' AND is_generated='ALWAYS' AND position('jjdguard_code' in generation_expression)>0)
  AND obj_description('compat_brand_fixture.jjdguard_system_settings'::regclass)='JJDGuard system table'
  AND col_description('compat_brand_fixture.jjdguard_system_settings'::regclass, (SELECT attnum FROM pg_attribute WHERE attrelid='compat_brand_fixture.jjdguard_system_settings'::regclass AND attname='jjdguard_code'))='JJDGuard system code'
  AND obj_description((SELECT oid FROM pg_extension WHERE extname='plpgsql'),'pg_extension')='JJDGuard fixture extension comment'
  AND position('jjdguard-system' in pg_get_functiondef('compat_brand_fixture.jjdguard_fn()'::regprocedure))>0
  AND EXISTS (SELECT 1 FROM compat_brand_fixture.jjdguard_system_settings WHERE kind='system' AND jjdguard_code='jjdguard-system')
")"
  [[ "$ok" == t ]] || die 'neutral catalog verification failed'
}

catalog_receipt() {
  local catalog_file="$tmp_dir/catalog.tsv"
  psql "$dsn" -X -v ON_ERROR_STOP=1 -AtF $'\t' >"$catalog_file" <<'SQL'
SELECT kind, name, detail
FROM (
  SELECT 'table'::text AS kind, c.relname::text AS name, c.relkind::text AS detail
    FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
   WHERE n.nspname='compat_brand_fixture' AND c.relname='jjdguard_system_settings'
  UNION ALL
  SELECT 'view', c.relname, encode(convert_to(pg_get_viewdef(c.oid, true),'UTF8'),'hex')
    FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
   WHERE n.nspname='compat_brand_fixture' AND c.relname='jjdguard_view'
  UNION ALL
  SELECT 'materialized_view', c.relname, encode(convert_to(pg_get_viewdef(c.oid, true),'UTF8'),'hex')
    FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
   WHERE n.nspname='compat_brand_fixture' AND c.relname='jjdguard_matview'
  UNION ALL
  SELECT CASE p.prokind WHEN 'p' THEN 'procedure' ELSE 'function' END, p.proname, encode(convert_to(pg_get_functiondef(p.oid),'UTF8'),'hex')
    FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
   WHERE n.nspname='compat_brand_fixture' AND p.proname IN ('jjdguard_fn','jjdguard_proc')
  UNION ALL
  SELECT 'type', t.typname, string_agg(e.enumlabel, ',' ORDER BY e.enumsortorder)
    FROM pg_type t JOIN pg_namespace n ON n.oid=t.typnamespace JOIN pg_enum e ON e.enumtypid=t.oid
   WHERE n.nspname='compat_brand_fixture' AND t.typname='jjdguard_state' GROUP BY t.typname
  UNION ALL
  SELECT 'policy', polname, encode(convert_to(pg_get_expr(polqual, polrelid),'UTF8'),'hex') FROM pg_policy WHERE polname='jjdguard_policy'
  UNION ALL
  SELECT 'trigger', tgname, encode(convert_to(pg_get_triggerdef(oid, true),'UTF8'),'hex') FROM pg_trigger WHERE tgname='jjdguard_trigger' AND NOT tgisinternal
  UNION ALL
  SELECT 'column', column_name, encode(convert_to(COALESCE(column_default,'') || '|' || COALESCE(generation_expression,''),'UTF8'),'hex')
    FROM information_schema.columns
   WHERE table_schema='compat_brand_fixture' AND table_name='jjdguard_system_settings' AND column_name IN ('jjdguard_code','jjdguard_generated')
  UNION ALL
  SELECT 'comment', 'table/column/extension', encode(convert_to(
    obj_description('compat_brand_fixture.jjdguard_system_settings'::regclass) || '|' ||
    col_description('compat_brand_fixture.jjdguard_system_settings'::regclass, (SELECT attnum FROM pg_attribute WHERE attrelid='compat_brand_fixture.jjdguard_system_settings'::regclass AND attname='jjdguard_code')) || '|' ||
    obj_description((SELECT oid FROM pg_extension WHERE extname='plpgsql'),'pg_extension'), 'UTF8'),'hex')
) AS catalog
ORDER BY kind, name, detail;
SQL
  catalog_sha="$(sha256_file "$catalog_file")"
  object_count="$(wc -l <"$catalog_file" | tr -d '[:space:]')"
  row_count="$(psql_scalar 'SELECT count(*) FROM compat_brand_fixture.jjdguard_system_settings')"
  [[ "$catalog_sha" =~ ^[0-9a-f]{64}$ && "$object_count" =~ ^[0-9]+$ && "$row_count" =~ ^[0-9]+$ ]] || die 'could not build neutral catalog receipt'
}

marker_present="$(psql_scalar "SELECT count(*) FROM public.schema_migrations WHERE version='$MARKER'")"
if [[ "$marker_present" != 0 ]]; then
  [[ "$ledger_count" == 1 && "$marker_present" == 1 ]] || die 'neutral marker must be the only migration ledger row'
  marker_checksum="$(psql_scalar "SELECT checksum FROM public.schema_migrations WHERE version='$MARKER'")"
  [[ "$marker_checksum" == "$manifest_sha" ]] || die 'neutral marker checksum drift detected'
  verify_neutral_state
  catalog_receipt
  write_result 'already-applied' "$MARKER" "$catalog_sha" "$object_count" "$row_count" "$started_at"
  exit 0
fi

expected_ledger="$tmp_dir/ledger.expected"
actual_ledger="$tmp_dir/ledger.actual"
# 账本按 migration-version.sh 的规则取文件（三位以上数字编号，去掉 002_seed_data.sql 和 *_verify.sql）。
while IFS= read -r -d '' migration; do
  name="$(basename "$migration")"
  printf '%s\t%s\n' "$name" "$(sha256_file "$migration")"
done < <(migration_versioned_files "$migrations_dir") >"$expected_ledger"
[[ -s "$expected_ledger" ]] || die 'no versioned migration files were found'
psql "$dsn" -X -v ON_ERROR_STOP=1 -AtF $'\t' -c 'SELECT version, checksum FROM public.schema_migrations ORDER BY version' >"$actual_ledger"
cmp -s "$expected_ledger" "$actual_ledger" || die 'migration ledger is not an exact checksum match for the supplied migration directory'

preflight_ok="$(psql_scalar "
SELECT
  to_regclass('compat_brand_fixture.newapi_system_settings') IS NOT NULL
  AND to_regclass('compat_brand_fixture.jjdguard_system_settings') IS NULL
  AND to_regclass('compat_brand_fixture.newapi_view') IS NOT NULL
  AND to_regclass('compat_brand_fixture.newapi_matview') IS NOT NULL
  AND to_regprocedure('compat_brand_fixture.newapi_fn()') IS NOT NULL
  AND to_regprocedure('compat_brand_fixture.newapi_proc()') IS NOT NULL
  AND EXISTS (SELECT 1 FROM pg_type t JOIN pg_namespace n ON n.oid=t.typnamespace WHERE n.nspname='compat_brand_fixture' AND t.typname='newapi_state')
  AND EXISTS (SELECT 1 FROM pg_policy WHERE polname='newapi_policy' AND polrelid='compat_brand_fixture.newapi_system_settings'::regclass)
  AND EXISTS (SELECT 1 FROM pg_trigger WHERE tgname='newapi_trigger' AND tgrelid='compat_brand_fixture.newapi_system_settings'::regclass AND NOT tgisinternal)
")"
[[ "$preflight_ok" == t ]] || die 'database does not match the reviewed compatibility pre-state'

{
  cat <<'SQL'
BEGIN;
SELECT pg_advisory_xact_lock(hashtextextended(current_database() || ':jjdguard-neutral-baseline-v1', 0));
CREATE TEMP TABLE _jjdguard_expected_inventory(inventory_sha256 text, payload_sha256 text) ON COMMIT DROP;
SQL
  printf "INSERT INTO _jjdguard_expected_inventory VALUES ('%s', '%s');\n" "$inventory_sha" "$payload_sha"
  cat <<'SQL'
DO $inventory_guard$
BEGIN
  IF NOT EXISTS (
    SELECT 1
      FROM public.jjdguard_compat_inventory actual
      JOIN _jjdguard_expected_inventory expected
        ON actual.inventory_sha256=expected.inventory_sha256
       AND actual.payload_sha256=expected.payload_sha256
     WHERE actual.singleton IS TRUE
  ) OR (SELECT count(*) FROM public.jjdguard_compat_inventory) <> 1 THEN
    RAISE EXCEPTION 'trusted compatibility inventory changed while acquiring the migration lock';
  END IF;
END
$inventory_guard$;
CREATE TEMP TABLE _jjdguard_customer_snapshot ON COMMIT DROP AS
  SELECT id, customer_text FROM compat_brand_fixture.newapi_system_settings;
ALTER TABLE compat_brand_fixture.newapi_system_settings RENAME TO jjdguard_system_settings;
ALTER TABLE compat_brand_fixture.jjdguard_system_settings RENAME COLUMN newapi_code TO jjdguard_code;
ALTER TABLE compat_brand_fixture.jjdguard_system_settings RENAME COLUMN newapi_generated TO jjdguard_generated;
ALTER VIEW compat_brand_fixture.newapi_view RENAME TO jjdguard_view;
ALTER MATERIALIZED VIEW compat_brand_fixture.newapi_matview RENAME TO jjdguard_matview;
ALTER FUNCTION compat_brand_fixture.newapi_fn() RENAME TO jjdguard_fn;
ALTER PROCEDURE compat_brand_fixture.newapi_proc() RENAME TO jjdguard_proc;
ALTER TYPE compat_brand_fixture.newapi_state RENAME TO jjdguard_state;
ALTER TYPE compat_brand_fixture.jjdguard_state RENAME VALUE 'newapi_pending' TO 'jjdguard_pending';
ALTER POLICY newapi_policy ON compat_brand_fixture.jjdguard_system_settings RENAME TO jjdguard_policy;
ALTER TRIGGER newapi_trigger ON compat_brand_fixture.jjdguard_system_settings RENAME TO jjdguard_trigger;
ALTER TABLE compat_brand_fixture.jjdguard_system_settings ALTER COLUMN jjdguard_code SET DEFAULT 'jjdguard-system';
UPDATE compat_brand_fixture.jjdguard_system_settings SET jjdguard_code='jjdguard-system' WHERE kind='system' AND jjdguard_code='newapi-system';
CREATE OR REPLACE FUNCTION compat_brand_fixture.jjdguard_fn() RETURNS text
  LANGUAGE sql IMMUTABLE AS $$ SELECT 'jjdguard-system'::text $$;
COMMENT ON TABLE compat_brand_fixture.jjdguard_system_settings IS 'JJDGuard system table';
COMMENT ON COLUMN compat_brand_fixture.jjdguard_system_settings.jjdguard_code IS 'JJDGuard system code';
COMMENT ON EXTENSION plpgsql IS 'JJDGuard fixture extension comment';
DO $customer_guard$
BEGIN
  IF EXISTS (
    SELECT 1
      FROM _jjdguard_customer_snapshot before
      FULL JOIN compat_brand_fixture.jjdguard_system_settings after USING (id)
     WHERE before.id IS NULL OR after.id IS NULL OR before.customer_text IS DISTINCT FROM after.customer_text
  ) THEN
    RAISE EXCEPTION 'customer-owned text changed during neutralization';
  END IF;
END
$customer_guard$;
SQL
  if [[ "${JJDGUARD_NEUTRAL_TEST_CRASH_BEFORE_COMMIT:-0}" == 1 ]]; then
    cat <<'SQL'
DO $injected_failure$ BEGIN RAISE EXCEPTION 'injected failure before neutral ledger commit'; END $injected_failure$;
SQL
  fi
  printf "DELETE FROM public.schema_migrations;\nINSERT INTO public.schema_migrations(version, checksum, applied_at) VALUES ('%s', '%s', now());\n" "$MARKER" "$manifest_sha"
  printf '%s\n' 'COMMIT;'
} | psql "$dsn" -X -v ON_ERROR_STOP=1 -q

verify_neutral_state
catalog_receipt
write_result 'applied' "$MARKER" "$catalog_sha" "$object_count" "$row_count" "$started_at"
printf '[neutral-baseline] status=applied objects=%s rows=%s\n' "$object_count" "$row_count"
