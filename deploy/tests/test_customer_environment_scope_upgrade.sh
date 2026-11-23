#!/usr/bin/env bash
set -Eeuo pipefail
# 临时容器：打测试标签、先回收被杀掉的测试进程留下的孤儿容器，清理用 docker rm -f -v（见该库说明）。
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib/test-containers.sh"
jjd_test_reap_orphan_containers
jjd_test_container_labels customer-environment-scope-upgrade

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

# shellcheck source=../docker-compose/customer-environment-scope-repair-lib.sh
. deploy/docker-compose/customer-environment-scope-repair-lib.sh

unset GATEWAY_ENVIRONMENT_SCOPE
if customer_environment_scope_repair_enabled; then
  echo 'customer scope repair must be disabled without an explicit deployment scope' >&2
  exit 1
fi
GATEWAY_ENVIRONMENT_SCOPE=home
if customer_environment_scope_repair_enabled; then
  echo 'customer scope repair must not touch a home deployment' >&2
  exit 1
fi
GATEWAY_ENVIRONMENT_SCOPE=' CUSTOMER '
if customer_environment_scope_repair_enabled; then
  echo 'customer scope repair requires the exact trusted value customer' >&2
  exit 1
fi
GATEWAY_ENVIRONMENT_SCOPE=customer
customer_environment_scope_repair_enabled

for installer in deploy/docker-compose/deploy-oneclick.sh deploy/docker-compose/deploy-offline.sh; do
  grep -q '^GATEWAY_ENVIRONMENT_SCOPE=customer$' "$installer"
done
grep -q 'UPGRADE_OFFLINE_MODE=1' deploy/offline-installer/installer.sh
grep -q -- '--customer-deployment' deploy/offline-installer/installer.sh
grep -q 'persist_trusted_customer_environment_scope' deploy/docker-compose/upgrade.sh
grep -q 'JJD_VERIFIED_INSTALLER_CUSTOMER_SCOPE=1 bash ./upgrade-bundle.sh' deploy/offline-installer/installer.sh
grep -q 'persist_trusted_customer_environment_scope' deploy/docker-compose/upgrade-bundle.sh
grep -q 'GATEWAY_ENVIRONMENT_SCOPE=customer' deploy/docker-compose/upgrade-bundle.sh

for upgrader in deploy/docker-compose/upgrade.sh deploy/docker-compose/upgrade-bundle.sh; do
  grep -q 'repair_customer_environment_scope' "$upgrader"
done
grep -q 'apply-customer-environment-scope-repair.sh' deploy/docker-compose/upgrade-bundle.sh
for asset in customer-environment-scope-repair-lib.sh customer-environment-scope-repair.sql apply-customer-environment-scope-repair.sh; do
  grep -Fq "deploy/docker-compose\"/$asset" deploy/docker-compose/package-offline-bundle.sh
done

sql=deploy/docker-compose/customer-environment-scope-repair.sql
for table in request_logs access_content_logs content_logs retained_artifacts access_content_artifact_links; do
  grep -Eq "UPDATE[[:space:]]+${table}([[:space:]]|$)" "$sql"
done
grep -q "environment_scope = 'legacy-unclassified'" "$sql"
grep -q 'has_customer_content' "$sql"
grep -q 'has_customer_request_body' "$sql"
grep -q 'has_customer_response_body' "$sql"

repair_line="$(grep -n -E '^[[:space:]]+repair_customer_environment_scope$' deploy/docker-compose/upgrade-bundle.sh | cut -d: -f1)"
guard_line="$(grep -n -E '^[[:space:]]+UPGRADE_EXIT_GUARD_ACTIVE=1$' deploy/docker-compose/upgrade-bundle.sh | cut -d: -f1)"
switch_line="$(grep -n -E '^[[:space:]]+IMAGE_SWITCH_STARTED=1$' deploy/docker-compose/upgrade-bundle.sh | tail -1 | cut -d: -f1)"
[[ -n "$repair_line" && -n "$guard_line" && -n "$switch_line" && "$guard_line" -lt "$repair_line" && "$repair_line" -lt "$switch_line" ]] || {
  echo 'bundle repair must run inside the rollback guard before image switch' >&2
  exit 1
}
grep -q 'DATABASE_MUTATION_STARTED.*== 1' deploy/docker-compose/upgrade-bundle.sh

scope_fixture="$(mktemp -d)"
scope_upgrader="$scope_fixture/upgrade-bundle.sh"
cp deploy/docker-compose/upgrade-bundle.sh "$scope_upgrader"

printf 'POSTGRES_USER=jjdguard\nSECURITY_AUDIT_ONLY=true\n' >"$scope_fixture/.env"
JJD_VERIFIED_INSTALLER_CUSTOMER_SCOPE=1 bash -c '. "$1"; persist_trusted_customer_environment_scope; load_inherited_env' _ "$scope_upgrader"
[[ "$(grep -c '^GATEWAY_ENVIRONMENT_SCOPE=customer$' "$scope_fixture/.env")" == 1 ]]
[[ "$(grep -c '^SECURITY_AUDIT_ONLY=true$' "$scope_fixture/.env")" == 1 ]]

for existing_scope in customer home claude codex legacy-unclassified; do
  printf 'GATEWAY_ENVIRONMENT_SCOPE=%s\n' "$existing_scope" >"$scope_fixture/.env"
  JJD_VERIFIED_INSTALLER_CUSTOMER_SCOPE=1 bash -c '. "$1"; persist_trusted_customer_environment_scope; load_inherited_env; [[ "$GATEWAY_ENVIRONMENT_SCOPE" == "$2" ]]' _ "$scope_upgrader" "$existing_scope"
  [[ "$(grep -c '^GATEWAY_ENVIRONMENT_SCOPE=' "$scope_fixture/.env")" == 1 ]]
done

printf 'GATEWAY_ENVIRONMENT_SCOPE=invalid-scope\n' >"$scope_fixture/.env"
if JJD_VERIFIED_INSTALLER_CUSTOMER_SCOPE=1 bash -c '. "$1"; persist_trusted_customer_environment_scope' _ "$scope_upgrader" >/dev/null 2>&1; then
  echo 'invalid existing deployment scope must fail closed' >&2
  exit 1
fi

marker="$scope_fixture/command-substitution-ran"
printf 'EVIL=$(touch %s)\nGATEWAY_ENVIRONMENT_SCOPE=customer\n' "$marker" >"$scope_fixture/.env"
JJD_VERIFIED_INSTALLER_CUSTOMER_SCOPE=1 bash -c '. "$1"; persist_trusted_customer_environment_scope; load_inherited_env' _ "$scope_upgrader"
[[ ! -e "$marker" ]] || { echo 'inherited dotenv command substitution executed' >&2; exit 1; }
rm -rf "$scope_fixture"

# A previously interrupted 2.6.5 repair can leave a customer-scoped parent with
# legacy children or NULL projections. Those partial states must still enter the
# affected set before the idempotent updates run.
grep -q 'rl.has_customer_content IS NULL' "$sql"
grep -q 'rl.has_customer_request_body IS NULL' "$sql"
grep -q 'rl.has_customer_response_body IS NULL' "$sql"
grep -Eq 'JOIN[[:space:]]+access_content_logs[[:space:]]+acl' "$sql"
grep -Eq 'JOIN[[:space:]]+content_logs[[:space:]]+cl' "$sql"
grep -Eq 'JOIN[[:space:]]+retained_artifacts[[:space:]]+artifact' "$sql"
grep -Eq 'JOIN[[:space:]]+access_content_artifact_links[[:space:]]+artifact_link' "$sql"
if [[ $(grep -c "WHERE .*environment_scope = 'legacy-unclassified'" "$sql") -lt 5 ]]; then
  echo 'repair affected set does not cover every legacy child table' >&2
  exit 1
fi

if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1 && docker image inspect postgres:16-alpine >/dev/null 2>&1; then
  container_name="jjdguard-customer-scope-repair-${RANDOM}-$$"
  container_id="$(docker run "${JJD_TEST_CONTAINER_LABELS[@]}" --rm -d --name "$container_name" -e POSTGRES_PASSWORD=test -e POSTGRES_DB=test postgres:16-alpine)"
  cleanup_scope_fixture() { docker rm -f -v "$container_id" >/dev/null 2>&1 || true; }
  trap cleanup_scope_fixture EXIT INT TERM
  for _ in {1..60}; do
    [[ "$(docker exec "$container_id" psql -U postgres -d test -tAc 'SELECT 1' 2>/dev/null)" == 1 ]] && break
    sleep 1
  done
  [[ "$(docker exec "$container_id" psql -U postgres -d test -tAc 'SELECT 1' 2>/dev/null)" == 1 ]]
  docker exec -i "$container_id" psql -v ON_ERROR_STOP=1 -U postgres -d test <<'SQL' >/dev/null
CREATE FUNCTION jjdguard_customer_content_text(value text)
RETURNS boolean LANGUAGE sql IMMUTABLE
AS $$ SELECT COALESCE(BTRIM(value), '') <> '' $$;
CREATE TABLE request_logs (
  id varchar(64) PRIMARY KEY, request_id varchar(64) UNIQUE NOT NULL, tenant_id varchar(64) NOT NULL,
  environment_scope varchar(32) NOT NULL, proxy_mode varchar(32),
  has_customer_content boolean, has_customer_request_body boolean, has_customer_response_body boolean,
  customer_content_rule_version smallint NOT NULL DEFAULT 0
);
CREATE TABLE access_content_logs (
  id varchar(64) PRIMARY KEY, request_id varchar(64) NOT NULL, tenant_id varchar(64) NOT NULL,
  environment_scope varchar(32) NOT NULL, request_content_redacted text, response_content_redacted text,
  file_metadata_json jsonb NOT NULL DEFAULT '[]'::jsonb
);
CREATE TABLE content_logs (
  id varchar(64) PRIMARY KEY, request_id varchar(64) NOT NULL, tenant_id varchar(64) NOT NULL,
  environment_scope varchar(32) NOT NULL, role varchar(32) NOT NULL, content text NOT NULL
);
CREATE TABLE retained_artifacts (
  id varchar(64) PRIMARY KEY, source_request_id varchar(64), tenant_id varchar(64) NOT NULL,
  environment_scope varchar(32) NOT NULL
);
CREATE TABLE access_content_artifact_links (
  id varchar(64) PRIMARY KEY, request_id varchar(64) NOT NULL, tenant_id varchar(64) NOT NULL,
  environment_scope varchar(32) NOT NULL
);
INSERT INTO request_logs VALUES
 ('log-partial','req-partial','tenant-a','customer','api',NULL,NULL,NULL,0),
 ('log-content','req-content','tenant-a','customer','api',false,false,false,0),
 ('log-stale','req-stale','tenant-a','customer','api',false,false,false,0),
 ('log-empty','req-empty','tenant-a','customer','api',NULL,NULL,NULL,0);
INSERT INTO access_content_logs(id,request_id,tenant_id,environment_scope,request_content_redacted)
VALUES ('acl-partial','req-partial','tenant-a','legacy-unclassified','customer prompt');
INSERT INTO content_logs VALUES
 ('cl-partial','log-partial','tenant-a','customer','assistant','customer answer'),
 ('cl-content','log-content','tenant-a','legacy-unclassified','assistant','legacy child answer'),
 ('cl-stale','log-stale','tenant-a','customer','user','already-classified child prompt');
INSERT INTO retained_artifacts VALUES ('artifact-partial','req-partial','tenant-a','legacy-unclassified');
INSERT INTO access_content_artifact_links VALUES ('link-partial','req-partial','tenant-a','legacy-unclassified');
SQL
  docker exec -i "$container_id" psql -v ON_ERROR_STOP=1 -U postgres -d test <"$sql" >/dev/null
  docker exec -i "$container_id" psql -v ON_ERROR_STOP=1 -U postgres -d test <<'SQL' >/dev/null
DO $$
DECLARE shape text;
BEGIN
  SELECT has_customer_content||'|'||has_customer_request_body||'|'||has_customer_response_body
  INTO shape FROM request_logs WHERE request_id='req-partial';
  IF shape <> 'true|true|true' THEN RAISE EXCEPTION 'partial child projection=%', shape; END IF;
  SELECT has_customer_content||'|'||has_customer_request_body||'|'||has_customer_response_body
  INTO shape FROM request_logs WHERE request_id='req-content';
  IF shape <> 'true|false|true' THEN RAISE EXCEPTION 'legacy content projection=%', shape; END IF;
  SELECT has_customer_content||'|'||has_customer_request_body||'|'||has_customer_response_body
  INTO shape FROM request_logs WHERE request_id='req-stale';
  IF shape <> 'true|true|false' THEN RAISE EXCEPTION 'stale non-null projection=%', shape; END IF;
  SELECT has_customer_content||'|'||has_customer_request_body||'|'||has_customer_response_body
  INTO shape FROM request_logs WHERE request_id='req-empty';
  IF shape <> 'false|false|false' THEN RAISE EXCEPTION 'null-only projection=%', shape; END IF;
  IF EXISTS (
    SELECT 1 FROM access_content_logs WHERE environment_scope <> 'customer'
    UNION ALL SELECT 1 FROM content_logs WHERE environment_scope <> 'customer'
    UNION ALL SELECT 1 FROM retained_artifacts WHERE environment_scope <> 'customer'
    UNION ALL SELECT 1 FROM access_content_artifact_links WHERE environment_scope <> 'customer'
  ) THEN RAISE EXCEPTION 'legacy child scope survived repair'; END IF;
END $$;
SQL
  cleanup_scope_fixture
  trap - EXIT INT TERM
else
  echo 'SKIP: live partial-state repair fixture requires local postgres:16-alpine'
fi

printf 'customer_environment_scope_upgrade=ok\n'
