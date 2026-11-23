#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
command -v docker >/dev/null 2>&1 || { echo 'SKIP: docker is unavailable'; exit 0; }
docker info >/dev/null 2>&1 || { echo 'SKIP: docker engine is unavailable'; exit 0; }
docker compose version >/dev/null 2>&1 || { echo 'SKIP: docker compose is unavailable'; exit 0; }
docker image inspect postgres:16-alpine >/dev/null 2>&1 || { echo 'SKIP: postgres:16-alpine is unavailable'; exit 0; }

fixture="$(mktemp -d)"
project="jjdguard_backfill_${RANDOM}_$$"
test_image="jjdguard-backfill-test:${RANDOM}-$$"
cleanup() {
  docker compose -p "$project" -f "$fixture/compose.yml" down -v --remove-orphans >/dev/null 2>&1 || true
  docker image rm "$test_image" >/dev/null 2>&1 || true
  rm -rf "$fixture"
}
trap cleanup EXIT INT TERM

cat >"$fixture/compose.yml" <<'YAML'
services:
  postgres:
    image: postgres:16-alpine
    environment:
      POSTGRES_PASSWORD: fixture
      POSTGRES_DB: backfill
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U postgres -d backfill"]
      interval: 1s
      timeout: 2s
      retries: 30
    volumes:
      - backfill-db:/var/lib/postgresql/data
volumes:
  backfill-db: {}
YAML

docker compose -p "$project" -f "$fixture/compose.yml" up -d --wait --wait-timeout 60

docker_arch="$(docker info --format '{{.Architecture}}')"
case "$docker_arch" in
  x86_64|amd64) go_arch=amd64 ;;
  aarch64|arm64) go_arch=arm64 ;;
  *) echo "unsupported Docker engine architecture for integration runner: $docker_arch" >&2; exit 1 ;;
esac

(
  cd "$ROOT/apps/worker"
  PATH="/usr/local/go/bin:$PATH" GOWORK=off GOOS=linux GOARCH="$go_arch" CGO_ENABLED=0 \
    go test -c -o "$fixture/backfill.test" ./internal/backfill
)

runner="$fixture/runner"
mkdir -p "$runner/app/apps/worker/internal/backfill" "$runner/app/deploy/migrations" "$runner/app/deploy/docker-compose"
install -m 0555 "$fixture/backfill.test" "$runner/app/apps/worker/internal/backfill/backfill.test"
for migration in \
  151_customer_content_noise_boundary.sql \
  813_workbuddy_workspace_evidence_runs.sql \
  816_security_event_delivery_disposition.sql \
  820_customer_content_projection_triggers.sql \
  821_serialize_customer_content_projection.sql \
  831_workbuddy_product_identity_tasks.sql \
  832_migration_backfill_framework.sql \
  834_customer_content_projection_backfill.sql \
  835_request_log_compatibility_backfill.sql \
  836_customer_environment_scope_backfill.sql \
  838_evidence_agent_projection_backfill.sql \
  839_security_event_delivery_backfill_index.sql \
  840_security_event_delivery_backfill.sql \
  841_evidence_title_noise_backfill_index.sql \
  842_evidence_title_noise_backfill.sql \
  843_workbuddy_identity_backfill.sql \
  844_usage_rollup_dimensions_backfill.sql \
  845_security_event_delivery_reconcile.sql; do
  cp "$ROOT/deploy/migrations/$migration" "$runner/app/deploy/migrations/$migration"
done
cp "$ROOT/deploy/docker-compose/customer-environment-scope-repair.sql" "$runner/app/deploy/docker-compose/"
cat >"$runner/Dockerfile" <<'DOCKERFILE'
FROM scratch
COPY app /app
WORKDIR /app/apps/worker/internal/backfill
ENTRYPOINT ["/app/apps/worker/internal/backfill/backfill.test"]
DOCKERFILE

docker build --platform "linux/$go_arch" -t "$test_image" "$runner"
docker run --rm --network "${project}_default" \
  -e JJD_BACKFILL_TEST_DATABASE_URL='postgres://postgres:fixture@postgres:5432/backfill?sslmode=disable' \
  "$test_image" -test.run TestPostgresCustomerProjectionCrashAndLockRecovery -test.count=1

container="$(docker compose -p "$project" -f "$fixture/compose.yml" ps -q postgres)"
UPGRADE_PREFLIGHT_POSTGRES_CONTAINER="$container" POSTGRES_USER=postgres POSTGRES_DB=backfill \
  UPGRADE_FROM_VERSION=fixture-old UPGRADE_TO_VERSION=fixture-new \
  UPGRADE_BACKUP_ROOT="$fixture" \
  bash "$ROOT/deploy/docker-compose/upgrade-preflight.sh" --output "$fixture/preflight.json" >"$fixture/preflight.stdout"
python3 -m json.tool "$fixture/preflight.json" >/dev/null
python3 - "$fixture/preflight.json" <<'CHECK'
import json,sys
report=json.load(open(sys.argv[1]))
# The crash-recovery fixture intentionally initializes only a projection
# schema. Per-file migration accounting must not infer a completed historical
# identity bridge merely from its higher numeric waterline.
assert report["risk"]=="MAINTENANCE_REQUIRED", report
assert report["reason"]=="historical bridge requires a quiesced writer window", report
assert report["bridge_target_version"] in report["pending_migrations"], report
assert report["current_data_version"]=="834_customer_content_projection_backfill.sql", report
CHECK
printf 'backfill_framework=ok project=%s engine_arch=%s\n' "$project" "$docker_arch"
