#!/usr/bin/env bash
# W2.2: migration 870 must revoke keys of users who were already disabled or
# deleted before the upgrade (backfill), audit it, leave project-level keys and
# active users' keys alone, and be safe to re-run.
set -euo pipefail
# 临时容器：打测试标签、先回收被杀掉的测试进程留下的孤儿容器，清理用 docker rm -f -v（见该库说明）。
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib/test-containers.sh"
jjd_test_reap_orphan_containers
jjd_test_container_labels revoke-user-keys-migration-870

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
MIGRATION="$ROOT/deploy/migrations/870_revoke_user_keys_on_disable.sql"
container="jjdguard-870-$RANDOM-$$"

fail() { echo "FAIL: $*" >&2; exit 1; }
cleanup() { docker rm -f -v "$container" >/dev/null 2>&1 || true; }
trap cleanup EXIT

command -v docker >/dev/null 2>&1 || fail "docker is required"
docker image inspect postgres:16-alpine >/dev/null 2>&1 || fail "postgres:16-alpine must already exist"
docker run "${JJD_TEST_CONTAINER_LABELS[@]}" --pull=never --rm -d --name "$container" -e POSTGRES_PASSWORD=test -e POSTGRES_DB=test postgres:16-alpine >/dev/null
for _ in $(seq 1 300); do
  docker logs "$container" 2>&1 | grep -Fq "PostgreSQL init process complete" && break
  sleep 0.1
done
for _ in $(seq 1 300); do
  docker exec "$container" psql -X -U postgres -d test -tAc "SELECT 1" 2>/dev/null | grep -qx 1 && break
  sleep 0.1
done

psql_db() { docker exec -i "$container" psql -X -q -v ON_ERROR_STOP=1 -U postgres -d test "$@"; }
scalar() { psql_db -tAc "$1"; }

# Minimal pre-870 shape of the three tables the migration touches.
psql_db <<'SQL'
CREATE TABLE users (id varchar(64) PRIMARY KEY, tenant_id varchar(64) NOT NULL, status varchar(32) NOT NULL);
CREATE TABLE internal_keys (id varchar(64) PRIMARY KEY, user_id varchar(64) REFERENCES users(id), status varchar(32) NOT NULL);
CREATE TABLE audit_operations (
  id varchar(64) PRIMARY KEY, tenant_id varchar(64), user_id varchar(64), action_type varchar(64) NOT NULL,
  action_detail jsonb, target_type varchar(64), target_id varchar(64), ip_address varchar(64),
  created_at timestamptz DEFAULT now());
INSERT INTO users VALUES ('u_active','t1','active'), ('u_disabled','t1','disabled'), ('u_deleted','t1','deleted');
INSERT INTO internal_keys VALUES
  ('k_active','u_active','active'),
  ('k_disabled_1','u_disabled','active'),
  ('k_disabled_2','u_disabled','active'),
  ('k_disabled_old','u_disabled','revoked'),
  ('k_deleted','u_deleted','active'),
  ('k_project',NULL,'active');
SQL

psql_db < "$MIGRATION"

[[ "$(scalar "SELECT string_agg(id||'='||status, ',' ORDER BY id) FROM internal_keys")" == \
  "k_active=active,k_deleted=revoked,k_disabled_1=revoked,k_disabled_2=revoked,k_disabled_old=revoked,k_project=active" ]] \
  || fail "backfill key states: $(scalar "SELECT string_agg(id||'='||status, ',' ORDER BY id) FROM internal_keys")"

[[ "$(scalar "SELECT count(*) FROM audit_operations WHERE action_type='user.keys.revoke'")" == 2 ]] \
  || fail "expected one audit row per affected user"
[[ "$(scalar "SELECT action_detail->>'revoked_count' FROM audit_operations WHERE target_id='u_disabled'")" == 2 ]] \
  || fail "u_disabled audit must list only the two newly revoked keys"
[[ "$(scalar "SELECT action_detail->>'reason' FROM audit_operations WHERE target_id='u_deleted'")" == migration_870_backfill ]] \
  || fail "backfill audit reason"

# Re-run is a no-op (no duplicate audit, no error).
psql_db < "$MIGRATION"
[[ "$(scalar "SELECT count(*) FROM audit_operations")" == 2 ]] || fail "re-run must not add audit rows"

# Trigger is live after the migration.
psql_db -c "UPDATE users SET status='disabled' WHERE id='u_active'"
[[ "$(scalar "SELECT status FROM internal_keys WHERE id='k_active'")" == revoked ]] || fail "trigger did not revoke on disable"
[[ "$(scalar "SELECT status FROM internal_keys WHERE id='k_project'")" == active ]] || fail "project-level key must stay active"

# Status changes that are not a deactivation do nothing.
psql_db -c "INSERT INTO users VALUES ('u_recon','t1','active')" -c "INSERT INTO internal_keys VALUES ('k_recon','u_recon','active')" \
  -c "UPDATE users SET status='reconciliation_required' WHERE id='u_recon'"
[[ "$(scalar "SELECT status FROM internal_keys WHERE id='k_recon'")" == active ]] || fail "non-deactivating status change must not revoke"

printf 'revoke_user_keys_migration_870=ok\n'
