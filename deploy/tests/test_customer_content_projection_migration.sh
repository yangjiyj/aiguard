#!/usr/bin/env bash
set -Eeuo pipefail
# 临时容器：打测试标签、先回收被杀掉的测试进程留下的孤儿容器，清理用 docker rm -f -v（见该库说明）。
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib/test-containers.sh"
jjd_test_reap_orphan_containers
jjd_test_container_labels customer-content-projection-migration

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
MIGRATION="$ROOT/deploy/migrations/820_customer_content_projection_triggers.sql"
REPAIR_MIGRATION="$ROOT/deploy/migrations/821_serialize_customer_content_projection.sql"

[[ -f "$MIGRATION" ]] || {
  echo "missing migration: $MIGRATION" >&2
  exit 1
}

for column in has_customer_content has_customer_request_body has_customer_response_body; do
  grep -Fq "ALTER COLUMN $column SET DEFAULT false" "$MIGRATION"
  grep -Fq "$column =" "$MIGRATION"
done
grep -Fq 'CREATE OR REPLACE FUNCTION refresh_request_customer_content_projection' "$MIGRATION"
grep -Fq 'CREATE TRIGGER trg_content_logs_customer_content_projection' "$MIGRATION"
grep -Fq 'CREATE TRIGGER trg_access_content_logs_customer_content_projection' "$MIGRATION"
grep -Fq "TG_OP = 'DELETE'" "$MIGRATION"
grep -Fq 'jjdguard_customer_content_text(acl.request_content_redacted)' "$MIGRATION"
grep -Fq 'jjdguard_customer_content_text(acl.response_content_redacted)' "$MIGRATION"
grep -Fq "COALESCE(rl.proxy_mode, '') <> 'forward'" "$MIGRATION"

[[ -f "$REPAIR_MIGRATION" ]]
grep -Fq 'FOR NO KEY UPDATE' "$REPAIR_MIGRATION"
grep -Fq 'VOLATILE' "$REPAIR_MIGRATION"
! grep -Eiq 'WITH[[:space:]].*MATERIALIZED|SELECT[[:space:]]+jjdguard_refresh_request_customer_content_projection' "$MIGRATION"
! grep -Eiq 'WITH[[:space:]].*MATERIALIZED|SELECT[[:space:]]+jjdguard_refresh_request_customer_content_projection' "$REPAIR_MIGRATION"

if ! command -v docker >/dev/null 2>&1 || ! docker info >/dev/null 2>&1 || ! docker image inspect postgres:16-alpine >/dev/null 2>&1; then
  echo 'SKIP: live projection trigger fixture requires local postgres:16-alpine'
  printf 'customer_content_projection_migration=ok\n'
  exit 0
fi

container_name="jjdguard-customer-projection-820-${RANDOM}-$$"
container_id=""
cleanup() {
  [[ -z "$container_id" ]] || docker rm -f -v "$container_id" >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM
container_id="$(docker run "${JJD_TEST_CONTAINER_LABELS[@]}" --rm -d --name "$container_name" -e POSTGRES_PASSWORD=test -e POSTGRES_DB=test postgres:16-alpine)"
for _ in {1..60}; do
  [[ "$(docker exec "$container_id" psql -U postgres -d test -tAc 'SELECT 1' 2>/dev/null)" == 1 ]] && break
  sleep 1
done
[[ "$(docker exec "$container_id" psql -U postgres -d test -tAc 'SELECT 1' 2>/dev/null)" == 1 ]] || {
  docker logs "$container_id" >&2 || true
  echo 'temporary PostgreSQL readiness timeout' >&2
  exit 1
}

docker exec -i "$container_id" psql -v ON_ERROR_STOP=1 -U postgres -d test <<'SQL' >/dev/null
CREATE FUNCTION jjdguard_customer_content_text(value text)
RETURNS boolean LANGUAGE sql IMMUTABLE
AS $$ SELECT COALESCE(BTRIM(value), '') <> '' AND value NOT LIKE '<system>%' $$;
CREATE TABLE request_logs (
  id varchar(64) PRIMARY KEY,
  request_id varchar(64) NOT NULL UNIQUE,
  tenant_id varchar(64) NOT NULL,
  proxy_mode varchar(32),
  has_customer_content boolean,
  has_customer_request_body boolean,
  has_customer_response_body boolean,
  customer_content_rule_version smallint NOT NULL DEFAULT 1
);
CREATE TABLE content_logs (
  id varchar(64) PRIMARY KEY,
  request_id varchar(64) NOT NULL REFERENCES request_logs(id) ON DELETE CASCADE,
  tenant_id varchar(64) NOT NULL,
  role varchar(32) NOT NULL,
  content text NOT NULL
);
CREATE TABLE access_content_logs (
  id varchar(64) PRIMARY KEY,
  request_id varchar(64) NOT NULL REFERENCES request_logs(request_id) ON DELETE CASCADE,
  tenant_id varchar(64) NOT NULL,
  request_content_redacted text,
  response_content_redacted text,
  file_metadata_json jsonb NOT NULL DEFAULT '[]'::jsonb
);
INSERT INTO request_logs(
  id,request_id,tenant_id,proxy_mode,
  has_customer_content,has_customer_request_body,has_customer_response_body
)
VALUES ('log-old','req-old','tenant-a','api',false,false,false);
INSERT INTO content_logs(id,request_id,tenant_id,role,content)
VALUES ('cl-old','log-old','tenant-a','user','old customer prompt');
SQL
docker exec -i "$container_id" psql -v ON_ERROR_STOP=1 -U postgres -d test <"$MIGRATION" >/dev/null
docker exec -i "$container_id" psql -v ON_ERROR_STOP=1 -U postgres -d test <<'SQL' >/dev/null
DO $$
DECLARE shape text;
BEGIN
  SELECT has_customer_content||'|'||has_customer_request_body||'|'||has_customer_response_body
  INTO shape FROM request_logs WHERE request_id='req-old';
  IF shape IS DISTINCT FROM 'false|false|false' THEN RAISE EXCEPTION 'expand migration rewrote history: %', shape; END IF;

  INSERT INTO request_logs(id,request_id,tenant_id,proxy_mode)
  VALUES ('log-new','req-new','tenant-a','api');
  SELECT has_customer_content||'|'||has_customer_request_body||'|'||has_customer_response_body
  INTO shape FROM request_logs WHERE request_id='req-new';
  IF shape IS DISTINCT FROM 'false|false|false' THEN RAISE EXCEPTION 'fresh defaults shape=%', shape; END IF;

  INSERT INTO content_logs(id,request_id,tenant_id,role,content)
  VALUES ('cl-user','log-new','tenant-a','user','new prompt'),
         ('cl-assistant','log-new','tenant-a','assistant','new answer');
  SELECT has_customer_content||'|'||has_customer_request_body||'|'||has_customer_response_body
  INTO shape FROM request_logs WHERE request_id='req-new';
  IF shape IS DISTINCT FROM 'true|true|true' THEN RAISE EXCEPTION 'content trigger shape=%', shape; END IF;

  DELETE FROM content_logs WHERE id='cl-user';
  SELECT has_customer_content||'|'||has_customer_request_body||'|'||has_customer_response_body
  INTO shape FROM request_logs WHERE request_id='req-new';
  IF shape IS DISTINCT FROM 'true|false|true' THEN RAISE EXCEPTION 'delete trigger shape=%', shape; END IF;

  INSERT INTO request_logs(id,request_id,tenant_id,proxy_mode)
  VALUES ('log-forward','req-forward','tenant-a','forward');
  INSERT INTO content_logs(id,request_id,tenant_id,role,content)
  VALUES ('cl-forward','log-forward','tenant-a','user','ignored duplicate body');
  SELECT has_customer_content||'|'||has_customer_request_body||'|'||has_customer_response_body
  INTO shape FROM request_logs WHERE request_id='req-forward';
  IF shape IS DISTINCT FROM 'false|false|false' THEN RAISE EXCEPTION 'forward content shape=%', shape; END IF;

  INSERT INTO access_content_logs(id,request_id,tenant_id,request_content_redacted)
  VALUES ('acl-forward','req-forward','tenant-a','forward prompt');
  SELECT has_customer_content||'|'||has_customer_request_body||'|'||has_customer_response_body
  INTO shape FROM request_logs WHERE request_id='req-forward';
  IF shape IS DISTINCT FROM 'true|true|false' THEN RAISE EXCEPTION 'access trigger shape=%', shape; END IF;
END $$;
SQL


# Upgrade from the already-deployed 820. The synchronous successor must not
# repair history; migration 834 schedules the background task.
docker exec -i "$container_id" psql -v ON_ERROR_STOP=1 -U postgres -d test -c "UPDATE request_logs SET has_customer_request_body=false WHERE request_id='req-old'" >/dev/null
docker exec -i "$container_id" psql -v ON_ERROR_STOP=1 -U postgres -d test <"$REPAIR_MIGRATION" >/dev/null
# Reapplying the successor against populated tables must remain idempotent.
docker exec -i "$container_id" psql -v ON_ERROR_STOP=1 -U postgres -d test <"$REPAIR_MIGRATION" >/dev/null
docker exec -i "$container_id" psql -v ON_ERROR_STOP=1 -U postgres -d test <<'SQL' >/dev/null
CREATE FUNCTION fixture_assert_projection(request text, expected text)
RETURNS void LANGUAGE plpgsql AS $$
DECLARE shape text;
BEGIN
  SELECT has_customer_content||'|'||has_customer_request_body||'|'||has_customer_response_body
  INTO shape FROM request_logs WHERE request_id=request;
  IF shape IS DISTINCT FROM expected THEN
    RAISE EXCEPTION 'request % projection % expected %', request, shape, expected;
  END IF;
END $$;
SELECT fixture_assert_projection('req-old', 'false|false|false');
SELECT fixture_assert_projection('req-new', 'true|false|true');
SELECT fixture_assert_projection('req-forward', 'true|true|false');
DO $$ BEGIN
  IF (SELECT count(*) FROM pg_trigger WHERE tgname IN (
      'trg_content_logs_customer_content_projection',
      'trg_access_content_logs_customer_content_projection',
      'trg_request_logs_customer_content_projection')) <> 3 THEN
    RAISE EXCEPTION 'migration reapplication duplicated triggers';
  END IF;
END $$;
-- Same-parent UPDATE must refresh content, role and redacted evidence changes.
UPDATE content_logs SET content='<system> no body' WHERE id='cl-assistant';
SELECT fixture_assert_projection('req-new', 'false|false|false');
UPDATE content_logs SET content='updated prompt', role='user' WHERE id='cl-assistant';
SELECT fixture_assert_projection('req-new', 'true|true|false');
-- Moving a child must refresh both parents, including its new tenant identity.
INSERT INTO request_logs(id,request_id,tenant_id,proxy_mode)
VALUES ('log-moved','req-moved','tenant-b','api');
UPDATE content_logs SET request_id='log-moved', tenant_id='tenant-b', role='assistant' WHERE id='cl-assistant';
SELECT fixture_assert_projection('req-new', 'false|false|false');
SELECT fixture_assert_projection('req-moved', 'true|false|true');
-- Changing proxy mode must stop/start counting duplicate content_logs bodies.
UPDATE request_logs SET proxy_mode='forward' WHERE request_id='req-moved';
SELECT fixture_assert_projection('req-moved', 'false|false|false');
UPDATE request_logs SET proxy_mode='api' WHERE request_id='req-moved';
SELECT fixture_assert_projection('req-moved', 'true|false|true');
UPDATE access_content_logs SET request_content_redacted='', file_metadata_json='[{"name":"fixture.txt"}]'::jsonb WHERE id='acl-forward';
SELECT fixture_assert_projection('req-forward', 'true|false|false');
UPDATE access_content_logs SET request_id='req-new', response_content_redacted='updated answer', file_metadata_json='[]'::jsonb WHERE id='acl-forward';
SELECT fixture_assert_projection('req-forward', 'false|false|false');
SELECT fixture_assert_projection('req-new', 'true|false|true');
DELETE FROM access_content_logs WHERE id='acl-forward';
SELECT fixture_assert_projection('req-new', 'false|false|false');
-- Cascaded deletion must not recurse or fail on the now-absent parent.
DELETE FROM request_logs WHERE request_id='req-moved';
SQL

# Two connections deliberately overlap after the first trigger has updated the
# parent. Waiting for pg_stat_activity makes the race deterministic without a
# fixed sleep or relying on the scheduler to hit a narrow timing window.
python3 - "$container_id" <<'PY'
import subprocess
import sys
import time

command = ['docker', 'exec', '-i', sys.argv[1], 'psql', '-X', '-v', 'ON_ERROR_STOP=1', '-U', 'postgres', '-d', 'test', '-At']

def sql(statement):
    return subprocess.check_output(command, input=statement, text=True, timeout=15).strip()

def wait_activity(name, predicate):
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        if sql("SELECT count(*) FROM pg_stat_activity WHERE application_name='" + name + "' AND " + predicate) == '1':
            return
        time.sleep(0.02)
    raise AssertionError('fixture connection did not reach expected activity: ' + name)

def insert(table, identifier, role):
    if table == 'content_logs':
        return ("INSERT INTO content_logs(id,request_id,tenant_id,role,content) VALUES "
                "('%s','log-race','tenant-a','%s','synthetic body');" % (identifier, role))
    column = 'request_content_redacted' if role == 'user' else 'response_content_redacted'
    return ("INSERT INTO access_content_logs(id,request_id,tenant_id,%s) VALUES "
            "('%s','req-race','tenant-a','synthetic body');" % (column, identifier))

for first_table, second_table in [
    ('content_logs', 'content_logs'),
    ('content_logs', 'access_content_logs'),
    ('access_content_logs', 'content_logs'),
    ('access_content_logs', 'access_content_logs'),
]:
    sql("INSERT INTO request_logs(id,request_id,tenant_id,proxy_mode) VALUES ('log-race','req-race','tenant-a','api');")
    first = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
    second = None
    try:
        first.stdin.write("BEGIN; SET statement_timeout='10s'; SET application_name='projection-fixture-first'; " + insert(first_table, 'race-first', 'user') + '\n')
        first.stdin.flush()
        wait_activity('projection-fixture-first', "state='idle in transaction'")
        second = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
        second.stdin.write("BEGIN; SET statement_timeout='10s'; SET application_name='projection-fixture-second'; " + insert(second_table, 'race-second', 'assistant') + " COMMIT;\n")
        second.stdin.close()
        wait_activity('projection-fixture-second', "wait_event_type='Lock'")
        first.stdin.write('COMMIT;\n')
        first.stdin.close()
        for writer in [first, second]:
            assert writer.wait(timeout=15) == 0, writer.stderr.read()
        sql("SELECT fixture_assert_projection('req-race', 'true|true|true');")
    finally:
        for writer in [first, second]:
            if writer is not None and writer.poll() is None:
                writer.kill()
                writer.wait(timeout=5)
    sql("DELETE FROM request_logs WHERE request_id='req-race';")
print('projection_concurrent_writers=ok cases=4')
PY

printf 'customer_content_projection_migration=ok\n'
