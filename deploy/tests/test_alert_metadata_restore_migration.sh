#!/usr/bin/env bash
set -euo pipefail
# 临时容器：打测试标签、先回收被杀掉的测试进程留下的孤儿容器，清理用 docker rm -f -v（见该库说明）。
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib/test-containers.sh"
jjd_test_reap_orphan_containers
jjd_test_container_labels alert-metadata-restore-migration

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
MIGRATION="${ALERT_METADATA_MIGRATION_UNDER_TEST:-$ROOT/deploy/migrations/876_restore_safe_alert_metadata_search_path.sql}"
scratch="$(mktemp -d)"
container_id=""
cleanup() {
  if [[ -n "$container_id" ]]; then
    docker rm -f -v "$container_id" >/dev/null 2>&1 || true
  fi
  rm -rf "$scratch"
}
# No published ports, host mounts, or caller-provided database are used.
if ! container_id="$(docker run "${JJD_TEST_CONTAINER_LABELS[@]}" --rm -d --network none \
  -e POSTGRES_HOST_AUTH_METHOD=trust postgres:16-alpine)"; then
  rm -rf "$scratch"
  exit 1
fi
trap cleanup EXIT
ready=false
for _ in $(seq 1 30); do
  if docker exec "$container_id" pg_isready -h 127.0.0.1 -U postgres >/dev/null 2>&1; then
    ready=true
    break
  fi
  sleep 1
done
[[ "$ready" == true ]] || {
  docker logs "$container_id" >&2
  exit 1
}
sql() {
  local database="$1"
  shift
  docker exec -i "$container_id" psql -X -qAt -v ON_ERROR_STOP=1 \
    -U postgres -d "$database" "$@"
}
for database in metadata_source metadata_old_restore metadata_fixed_restore; do
  sql postgres -c "CREATE DATABASE $database" >/dev/null
done
sql metadata_source <<'SQL' >/dev/null
CREATE TABLE public.security_events(id integer PRIMARY KEY, matched_summary jsonb NOT NULL);
SQL
sql metadata_source <"$ROOT/deploy/migrations/850_alert_read_metadata.sql" >/dev/null
sql metadata_source <"$ROOT/deploy/migrations/851_compact_nonfinding_read_metadata.sql" >/dev/null
sql metadata_source <<'SQL' >/dev/null
ALTER FUNCTION public.jjd_alert_read_metadata_v1(jsonb) SET statement_timeout TO '5s';
ALTER FUNCTION public.jjd_alert_read_metadata_v2(jsonb) SET lock_timeout TO '1s';
ALTER FUNCTION public.jjd_alert_finding_metadata_v1(jsonb) SET work_mem TO '8MB';
INSERT INTO public.security_events VALUES
  (1, '{"type":"semantic_attack","raw_evidence":"root-secret","evidence_context":"root-context","_jjd_evidence_identity":"forged","findings":[{"type":"pii","raw_evidence":"finding-secret"},{"type":"heuristic","counts_as_security_finding":false,"raw_evidence":"observation-secret"}],"observations":[{"raw_evidence":"retain-original"}],"triage":{"review_state":"pending","extra":"drop-derived"}}'),
  (2, '{"findings":[],"observations":[]}'),
  (3, '[]');
SQL

if sql metadata_source >"$scratch/old-copy.log" 2>&1 <<'SQL'
SET search_path TO '';
COPY public.security_events(id, matched_summary) FROM STDIN;
4	{"type":"pii","raw_evidence":"copy-secret"}
\.
SQL
then
  echo 'old-schema empty-search-path COPY unexpectedly succeeded' >&2
  exit 1
fi
grep -Fm1 'jjd_alert_finding_metadata_v1(jsonb) does not exist' "$scratch/old-copy.log"
docker exec "$container_id" pg_dump -U postgres -Fc -d metadata_source >"$scratch/old.dump"
if docker exec -i "$container_id" pg_restore -U postgres -d metadata_old_restore \
    --exit-on-error <"$scratch/old.dump" >"$scratch/old-restore.log" 2>&1; then
  echo 'old-schema custom-format pg_restore unexpectedly succeeded' >&2
  exit 1
fi
grep -Fm1 'jjd_alert_finding_metadata_v1(jsonb) does not exist' "$scratch/old-restore.log"
echo '[ok] old schema reproduces generated-column COPY and pg_restore failures'

contract_sql="SELECT jsonb_object_agg(p.proname, jsonb_build_object(
  'settings', COALESCE((SELECT jsonb_agg(setting ORDER BY ord)
    FROM unnest(p.proconfig) WITH ORDINALITY AS config(setting, ord)
    WHERE split_part(setting, '=', 1) <> 'search_path'), '[]'::jsonb),
  'source', p.prosrc, 'volatility', p.provolatile, 'parallel', p.proparallel,
  'strict', p.proisstrict, 'security_definer', p.prosecdef))
  FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
  WHERE n.nspname='public' AND p.proname IN (
    'jjd_alert_finding_metadata_v1','jjd_alert_read_metadata_v1','jjd_alert_read_metadata_v2');"
before_contract="$(sql metadata_source -c "$contract_sql")"
sql metadata_source <"$MIGRATION" >/dev/null
[[ "$(sql metadata_source -c "$contract_sql")" == "$before_contract" ]] || {
  echo 'migration changed existing function bodies, attributes, or other proconfig keys' >&2
  exit 1
}
path_count="$(sql metadata_source -c "SELECT count(*) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='public' AND p.proname IN ('jjd_alert_read_metadata_v1','jjd_alert_read_metadata_v2') AND p.proconfig @> ARRAY['search_path=pg_catalog, public, pg_temp'];")"
[[ "$path_count" == 2 ]] || {
  echo "both generated metadata functions require a fixed safe search_path: $path_count/2" >&2
  exit 1
}
all_config_sql="SELECT jsonb_object_agg(p.proname, to_jsonb(p.proconfig)) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='public' AND p.proname IN ('jjd_alert_finding_metadata_v1','jjd_alert_read_metadata_v1','jjd_alert_read_metadata_v2');"
first_config="$(sql metadata_source -c "$all_config_sql")"
sql metadata_source <"$MIGRATION" >/dev/null
[[ "$(sql metadata_source -c "$all_config_sql")" == "$first_config" ]] || {
  echo 'repeating the migration changed function configuration' >&2
  exit 1
}
echo '[ok] both paths are fixed; repeat execution and other function settings remain stable'

sql metadata_source <<'SQL' >/dev/null
CREATE TABLE public.legacy_security_events(
  id integer PRIMARY KEY, matched_summary jsonb NOT NULL,
  alert_read_metadata_v1 jsonb GENERATED ALWAYS AS (public.jjd_alert_read_metadata_v1(matched_summary)) STORED
);
INSERT INTO public.legacy_security_events(id, matched_summary)
  SELECT id, matched_summary FROM public.security_events;
SET search_path TO '';
COPY public.security_events(id, matched_summary) FROM STDIN;
4	{"type":"pii","raw_evidence":"copy-secret"}
\.
SELECT public.jjd_alert_read_metadata_v1('{"findings":[{"type":"pii"}]}'::jsonb);
SELECT public.jjd_alert_read_metadata_v2('{"findings":[{"counts_as_security_finding":false}]}'::jsonb);
SQL
rows_sql="SELECT jsonb_build_object(
  'current', (SELECT jsonb_agg(to_jsonb(e) ORDER BY id) FROM public.security_events e),
  'legacy', (SELECT jsonb_agg(to_jsonb(e) ORDER BY id) FROM public.legacy_security_events e));"
before_rows="$(sql metadata_source -c "$rows_sql")"
docker exec "$container_id" pg_dump -U postgres -Fc -d metadata_source >"$scratch/fixed.dump"
docker exec -i "$container_id" pg_restore -U postgres -d metadata_fixed_restore \
  --exit-on-error <"$scratch/fixed.dump" >"$scratch/fixed-restore.log" 2>&1 || {
  cat "$scratch/fixed-restore.log" >&2
  exit 1
}
[[ "$(sql metadata_fixed_restore -c "$rows_sql")" == "$before_rows" ]] || {
  echo 'restored original data or generated metadata differs' >&2
  exit 1
}
[[ "$(sql metadata_fixed_restore -c "$all_config_sql")" == "$first_config" ]] || {
  echo 'pg_dump/pg_restore changed function configurations' >&2
  exit 1
}
[[ "$(sql metadata_fixed_restore -c "SELECT count(*) FROM pg_attribute WHERE attrelid IN ('public.security_events'::regclass, 'public.legacy_security_events'::regclass) AND attname='alert_read_metadata_v1' AND attgenerated='s';")" == 2 ]]
[[ "$(sql metadata_fixed_restore -c "SELECT (matched_summary->>'raw_evidence'='root-secret' AND alert_read_metadata_v1->>'raw_evidence'='present' AND alert_read_metadata_v1#>'{findings,1}'='null'::jsonb AND alert_read_metadata_v1->>'_jjd_evidence_identity'=encode(sha256(convert_to('root-context','UTF8')),'hex'))::text FROM public.security_events WHERE id=1;")" == true ]]
echo '[ok] custom-format restore preserves v1/v2 stored generated columns, evidence, derived metadata, and proconfig'
