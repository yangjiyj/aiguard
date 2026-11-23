#!/usr/bin/env bash
set -euo pipefail
# 临时容器：打测试标签、先回收被杀掉的测试进程留下的孤儿容器，清理用 docker rm -f -v（见该库说明）。
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib/test-containers.sh"
jjd_test_reap_orphan_containers
jjd_test_container_labels agent-intent-tasks-migration

ROOT="$(cd "${T16_SOURCE_ROOT:-$(dirname "$0")/../..}" && pwd)"
MIGRATION="$ROOT/deploy/migrations/873_agent_intent_tasks.sql"
container_name="jjdguard-t16-intent-pg16-$(date -u +%Y%m%d%H%M%S)-$$-$RANDOM"
tmpdir="$(mktemp -d "/tmp/t16-intent-fixture.XXXXXX")"
owner_pid=""
resolver_pid=""

fail() {
  echo "FAIL: $*" >&2
  exit 1
}

cleanup() {
  if [[ -n "$resolver_pid" ]]; then
    kill "$resolver_pid" >/dev/null 2>&1 || true
    wait "$resolver_pid" >/dev/null 2>&1 || true
  fi
  if [[ -n "$owner_pid" ]]; then
    kill "$owner_pid" >/dev/null 2>&1 || true
    wait "$owner_pid" >/dev/null 2>&1 || true
  fi
  docker rm -f -v "$container_name" >/dev/null 2>&1 || true
  rm -rf -- "$tmpdir"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

[[ -f "$MIGRATION" ]] || fail "missing migration 873"
command -v docker >/dev/null 2>&1 || fail "docker is required"
docker info >/dev/null 2>&1 || fail "docker daemon is unavailable"
docker image inspect postgres:16-alpine >/dev/null 2>&1 || fail "postgres:16-alpine must already be present"

migration_sha256="$(sha256sum "$MIGRATION" | awk '{print $1}')"
container_id="$(docker run "${JJD_TEST_CONTAINER_LABELS[@]}" --pull=never --rm -d \
  --name "$container_name" \
  --publish 127.0.0.1::5432 \
  --tmpfs /var/lib/postgresql/data:rw,noexec,nosuid,size=512m \
  --cpus 1 --memory 768m \
  --env POSTGRES_PASSWORD=t16-fixture-only \
  --env POSTGRES_DB=t16_fixture \
  postgres:16-alpine)"

published="$(docker port "$container_name" 5432/tcp | head -n 1)"
[[ "$published" =~ ^127\.0\.0\.1:[0-9]+$ ]] || fail "PostgreSQL is not bound to a loopback ephemeral port"

psql_fixture() {
  docker exec -i "$container_name" psql -X -v ON_ERROR_STOP=1 -U postgres -d t16_fixture "$@"
}

ready=false
for _ in $(seq 1 120); do
  if psql_fixture -tAc 'SELECT 1' 2>/dev/null | grep -qx '1'; then
    ready=true
    break
  fi
  sleep 0.25
done
[[ "$ready" == true ]] || {
  docker logs "$container_name" >&2 || true
  fail "temporary PostgreSQL did not become ready"
}

# Apply and reapply the exact source migration to an empty throwaway PostgreSQL 16.
psql_fixture -q <"$MIGRATION" >/dev/null
psql_fixture -q <"$MIGRATION" >/dev/null
psql_fixture -q >/dev/null <<'SQL'
DO $$
BEGIN
  IF (SELECT count(*) FROM information_schema.tables
      WHERE table_schema='public'
        AND table_name IN ('agent_intent_tasks','agent_intent_task_grants','agent_intent_task_steps')) <> 3 THEN
    RAISE EXCEPTION 'T16 migration did not create all three tables';
  END IF;
  IF (SELECT count(*) FROM pg_trigger
      WHERE tgname IN ('trg_agent_intent_task_snapshot_immutable',
                       'trg_agent_intent_task_grant_snapshot_immutable')) <> 2 THEN
    RAISE EXCEPTION 'T16 immutable snapshot triggers are missing or duplicated';
  END IF;
END
$$;

INSERT INTO agent_intent_tasks (
  id, tenant_id, endpoint_id, product, principal_id, state,
  purpose, purpose_sha256, source_scope, source_scope_sha256, scope_sha256,
  approved_by, expires_at
) VALUES (
  '00000000-0000-4000-8000-000000000001', 'tenant-fixture', 'endpoint-fixture',
  'openclaw', '00000000-0000-4000-8000-000000000002', 'approved',
  'read approved fixture inputs', repeat('a',64),
  '{"allowed_kinds":["web"]}'::jsonb, repeat('b',64), repeat('c',64),
  'fixture-admin', clock_timestamp() + interval '1 hour'
);
INSERT INTO agent_intent_task_grants (
  tenant_id, task_id, grant_id, action, resource_type, resource_ref_hash, grant_expires_at
) VALUES (
  'tenant-fixture', '00000000-0000-4000-8000-000000000001',
  '00000000-0000-4000-8000-000000000003', 'file_read', 'file',
  repeat('d',64), clock_timestamp() + interval '1 hour'
);
INSERT INTO agent_intent_task_steps (
  id, tenant_id, task_id, server_sequence, endpoint_id, product,
  session_ref_hash, prompt_ref_hash, tool_use_ref_hash, tool_call_log_id,
  arguments_hash, tool_name, tool_type, action, resource_type, resource_ref_hash,
  authorization_state, authorization_bindings_hash, principal_ref_hash, grant_ref_hash,
  source_refs, lineage_state
) VALUES (
  '00000000-0000-4000-8000-000000000004', 'tenant-fixture',
  '00000000-0000-4000-8000-000000000001', 1, 'endpoint-fixture', 'openclaw',
  repeat('1',64), repeat('2',64), repeat('3',64), 'fixture-tool-call',
  'sha256:' || repeat('4',64), 'mcp__files__read_file', 'mcp', 'mcp_invoke', 'mcp_server',
  repeat('5',64), 'allowed', repeat('6',64), repeat('7',64), repeat('8',64),
  '[]'::jsonb, 'server_task_record'
);
SQL
printf 'PASS migration apply/reapply sha256=%s\n' "$migration_sha256"

expect_rejection() {
  local label="$1"
  local expected="$2"
  local sql="$3"
  local log="$tmpdir/$label.log"
  if psql_fixture -q -c "$sql" >"$log" 2>&1; then
    fail "$label unexpectedly succeeded"
  fi
  grep -Fq "$expected" "$log" || {
    sed -n '1,80p' "$log" >&2
    fail "$label failed for an unexpected reason"
  }
  printf 'PASS %s rejected\n' "$label"
}

expect_rejection task_snapshot_mutation \
  'approved intent task snapshot is immutable' \
  "UPDATE agent_intent_tasks SET purpose='tampered' WHERE id='00000000-0000-4000-8000-000000000001'"
expect_rejection task_grant_snapshot_mutation \
  'approved intent task grant snapshot is immutable' \
  "UPDATE agent_intent_task_grants SET resource_ref_hash=repeat('9',64) WHERE task_id='00000000-0000-4000-8000-000000000001'"

psql_fixture -q -c "DELETE FROM agent_intent_tasks WHERE id='00000000-0000-4000-8000-000000000001'" >/dev/null
deleted_children="$(psql_fixture -tAc "
  SELECT
    (SELECT count(*) FROM agent_intent_task_grants WHERE task_id='00000000-0000-4000-8000-000000000001') ||
    '|' ||
    (SELECT count(*) FROM agent_intent_task_steps WHERE task_id='00000000-0000-4000-8000-000000000001')
")"
[[ "$deleted_children" == '0|0' ]] || fail "task delete did not cascade to T16 grant/step snapshots: $deleted_children"
printf 'PASS tenant task delete cascades to T16 grant and step snapshots\n'

psql_fixture -q >/dev/null <<'SQL'
INSERT INTO agent_intent_tasks (
  id, tenant_id, endpoint_id, product, principal_id, purpose,
  purpose_sha256, source_scope, source_scope_sha256, scope_sha256,
  approved_by, expires_at
) VALUES (
  '00000000-0000-4000-8000-000000000005', 'tenant-fixture', 'endpoint-fixture',
  'openclaw', '00000000-0000-4000-8000-000000000002',
  'exercise serialized revocation lookup', repeat('a',64),
  '{"allowed_kinds":["web"]}'::jsonb, repeat('b',64), repeat('c',64),
  'fixture-admin', clock_timestamp() + interval '1 hour'
);
SQL

# Model the production lock order: one transaction revokes while holding the task
# row; the concurrent resolver uses SELECT ... FOR UPDATE and must observe revoked.
docker exec -e PGAPPNAME=t16_fixture_revocation_owner -i "$container_name" \
  psql -X -qAt -v ON_ERROR_STOP=1 -U postgres -d t16_fixture >"$tmpdir/owner.log" 2>&1 <<'SQL' &
BEGIN;
SELECT state FROM agent_intent_tasks
WHERE id='00000000-0000-4000-8000-000000000005'
FOR UPDATE;
SELECT pg_sleep(2);
UPDATE agent_intent_tasks
SET state='revoked', revoked_by='fixture-admin', revoked_at=clock_timestamp()
WHERE id='00000000-0000-4000-8000-000000000005';
COMMIT;
SQL
owner_pid="$!"

locked=false
for _ in $(seq 1 100); do
  owner_wait="$(psql_fixture -tAc "
    SELECT count(*) FROM pg_stat_activity
    WHERE application_name='t16_fixture_revocation_owner'
      AND state='active' AND wait_event='PgSleep'
  " 2>/dev/null || true)"
  if [[ "$owner_wait" == '1' ]]; then
    locked=true
    break
  fi
  sleep 0.05
done
[[ "$locked" == true ]] || {
  cat "$tmpdir/owner.log" >&2 || true
  fail "revocation owner never reached the held-row-lock interval"
}

resolver_started_ns="$(python3 -c 'import time; print(time.monotonic_ns())')"
docker exec -e PGAPPNAME=t16_fixture_resolver -i "$container_name" \
  psql -X -qAt -v ON_ERROR_STOP=1 -U postgres -d t16_fixture >"$tmpdir/resolver.log" 2>&1 <<'SQL' &
BEGIN;
SELECT state FROM agent_intent_tasks
WHERE id='00000000-0000-4000-8000-000000000005'
FOR UPDATE;
COMMIT;
SQL
resolver_pid="$!"

if ! wait "$resolver_pid"; then
  cat "$tmpdir/resolver.log" >&2 || true
  fail "concurrent resolver query failed"
fi
resolver_pid=""
resolver_finished_ns="$(python3 -c 'import time; print(time.monotonic_ns())')"
lock_wait_ms="$(((resolver_finished_ns - resolver_started_ns) / 1000000))"
if [[ "$lock_wait_ms" -lt 500 ]]; then
  cat "$tmpdir/resolver.log" >&2 || true
  fail "resolver did not wait for revocation row lock: $lock_wait_ms ms"
fi
grep -Fqx 'revoked' "$tmpdir/resolver.log" || {
  cat "$tmpdir/resolver.log" >&2 || true
  fail "resolver did not observe the committed revoked state"
}
if ! wait "$owner_pid"; then
  cat "$tmpdir/owner.log" >&2 || true
  fail "revocation owner transaction failed"
fi
owner_pid=""
printf 'PASS row-lock revocation/resolution ordering wait_ms=%s observed=revoked\n' "$lock_wait_ms"

task_state="$(psql_fixture -tAc "SELECT state FROM agent_intent_tasks WHERE id='00000000-0000-4000-8000-000000000005'")"
[[ "$task_state" == 'revoked' ]] || fail "final task state=$task_state expected=revoked"
printf 'PASS final T16 DB state=revoked; postgres=%s; bind=loopback-ephemeral; storage=tmpfs\n' \
  "$(psql_fixture -tAc 'SHOW server_version')"
