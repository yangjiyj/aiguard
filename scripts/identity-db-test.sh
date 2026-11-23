#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CONTAINER_PREFIX="jjdguard-identity-db-test-pg"
OWNER_LABEL="com.jjdguard.identity-db-test.owner"
OWNER_NONCE="${JJD_IDENTITY_DB_TEST_OWNER_NONCE:-$$-$RANDOM-$RANDOM}"
CONTAINER="$CONTAINER_PREFIX-$OWNER_NONCE"
RESULT_JSON="$(mktemp /tmp/jjdguard-identity-db-test.XXXXXX.json)"
DB_USER="jjd_identity_test"
DB_PASSWORD="jjd_identity_test"
DB_NAME="jjd_identity_test"
created=0
attempted=0

cleanup() {
  if [ "$attempted" -eq 1 ] || [ "$created" -eq 1 ]; then
    actual_owner="$(docker inspect --format "{{ index .Config.Labels \"$OWNER_LABEL\" }}" "$CONTAINER" 2>/dev/null || true)"
    if [ "$actual_owner" = "$OWNER_NONCE" ]; then
      docker rm -f -v "$CONTAINER" >/dev/null 2>&1 || true
    fi
  fi
  rm -f "$RESULT_JSON"
}
trap cleanup EXIT INT TERM

if ! [[ "$OWNER_NONCE" =~ ^[a-z0-9][a-z0-9-]{0,47}$ ]]; then
  echo "[error] invalid identity DB test owner nonce" >&2
  exit 2
fi

if docker ps -a --format '{{.Names}}' | grep -Fxq "$CONTAINER"; then
  echo "[error] refusing to reuse existing container: $CONTAINER" >&2
  exit 2
fi

attempted=1
docker run -d --name "$CONTAINER" --label "$OWNER_LABEL=$OWNER_NONCE" -e POSTGRES_USER="$DB_USER" -e POSTGRES_PASSWORD="$DB_PASSWORD" -e POSTGRES_DB="$DB_NAME" -p 127.0.0.1::5432 -v "$ROOT/deploy/migrations:/migrations:ro" -v "$ROOT/deploy/docker-compose/initdb/001_init_enterprise.sql:/docker-entrypoint-initdb.d/001_init_enterprise.sql:ro" -v "$ROOT/deploy/lib/migration-runner.sh:/migration-runner.sh:ro" postgres:16 >/dev/null
created=1

ready=0
for _ in $(seq 1 120); do
  if docker exec "$CONTAINER" pg_isready -U "$DB_USER" -d "$DB_NAME" >/dev/null 2>&1 &&
     docker exec "$CONTAINER" psql -U "$DB_USER" -d "$DB_NAME" -Atc "SELECT to_regclass('public.audit_dispositions') IS NOT NULL" 2>/dev/null | grep -qx t; then
    ready=1
    break
  fi
  sleep 1
done
if [ "$ready" -ne 1 ]; then
  docker logs --tail 100 "$CONTAINER" >&2
  echo "[error] identity DB initdb did not become ready" >&2
  exit 3
fi

docker exec -e PGHOST=127.0.0.1 -e PGPORT=5432 -e PGUSER="$DB_USER" -e PGPASSWORD="$DB_PASSWORD" -e PGDATABASE="$DB_NAME" -e MIGRATION_PSQL=/usr/bin/psql "$CONTAINER" /bin/bash /migration-runner.sh --migrations-dir /migrations

HOST_PORT="$(docker port "$CONTAINER" 5432/tcp | awk -F: 'END { print $NF }')"
if ! [[ "$HOST_PORT" =~ ^[0-9]+$ ]]; then
  echo "[error] failed to resolve identity DB host port" >&2
  exit 4
fi

TEST_PATTERN='^(TestDirectorySourceRuntimeReconciliationStateUsesStableReasonAndClears|TestDirectoryActivationClaimRejectsDraftMutationUntilIdempotentRelease|TestDirectoryActivationClaimCanceledReleaseClosesSessionAndIsIdempotent|TestActivateDirectorySourceClaimConflictStopsBeforeRuntime|TestActivateDirectorySourceClaimRejectsConcurrentDraftMutation|TestActivateDirectorySourceClaimRejectsConcurrentDisableThenReleases|TestDisableDirectorySourceClaimRejectsConcurrentActivationThenReleases|TestDirectoryActivationRestoreFailureMarksReconciliationWithoutRawError|TestDirectoryActivationMarkFailureReturnsStableSanitizedError|TestDirectoryActivationAtomicRollbackOnFinalizeFailure|TestDirectoryActivationKeepsSeenUserOnInvalidIdentity|TestDirectoryActivationFailsOnUnclassifiedBindError|TestIdentityOverviewDirectoryReconciliationIsAbnormalAndCounted|TestEnsurePortalUserDepartmentMoveInvalidatesOldTeamMembership|TestPortalUserAuthorizationContextBehavior|TestPortalUserAuthorizationContextHidesStorageError)$'
DSN="postgres://$DB_USER:$DB_PASSWORD@127.0.0.1:$HOST_PORT/$DB_NAME?sslmode=disable"

set +e
(
  cd "$ROOT/apps/control-plane"
  CONTENT_LOGS_TEST_DATABASE_URL="$DSN" JJD_REQUIRE_IDENTITY_DB_TESTS=1 /usr/local/go/bin/go test -json ./internal/repository ./internal/handler -run "$TEST_PATTERN" -count=1
) | tee "$RESULT_JSON"
test_status=$?
set -e

python3 - "$RESULT_JSON" <<'PY'
import json
import sys

expected = {
    "TestDirectorySourceRuntimeReconciliationStateUsesStableReasonAndClears",
    "TestDirectoryActivationClaimRejectsDraftMutationUntilIdempotentRelease",
    "TestDirectoryActivationClaimCanceledReleaseClosesSessionAndIsIdempotent",
    "TestActivateDirectorySourceClaimConflictStopsBeforeRuntime",
    "TestActivateDirectorySourceClaimRejectsConcurrentDraftMutation",
    "TestActivateDirectorySourceClaimRejectsConcurrentDisableThenReleases",
    "TestDisableDirectorySourceClaimRejectsConcurrentActivationThenReleases",
    "TestDirectoryActivationRestoreFailureMarksReconciliationWithoutRawError",
    "TestDirectoryActivationMarkFailureReturnsStableSanitizedError",
    "TestDirectoryActivationAtomicRollbackOnFinalizeFailure",
    "TestIdentityOverviewDirectoryReconciliationIsAbnormalAndCounted",
    "TestDirectoryActivationKeepsSeenUserOnInvalidIdentity",
    "TestDirectoryActivationFailsOnUnclassifiedBindError",
    "TestEnsurePortalUserDepartmentMoveInvalidatesOldTeamMembership",
    "TestPortalUserAuthorizationContextBehavior",
    "TestPortalUserAuthorizationContextHidesStorageError",
}
passed = set()
skipped = []
with open(sys.argv[1], encoding="utf-8") as stream:
    for line in stream:
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        test = event.get("Test")
        action = event.get("Action")
        if action == "skip":
            skipped.append(test or event.get("Package", "unknown"))
        elif action == "pass" and test:
            passed.add(test)
if skipped:
    raise SystemExit(f"identity DB tests skipped unexpectedly: {skipped}")
missing = sorted(expected - passed)
if missing:
    raise SystemExit(f"identity DB tests did not pass: {missing}")
print(f"PASS: identity DB exact tests={len(expected)} skipped=0")
PY

if [ "$test_status" -ne 0 ]; then
  echo "[error] identity DB go tests failed with status $test_status" >&2
  exit "$test_status"
fi
