#!/usr/bin/env bash
set -Eeuo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
rows="${1:-100000}"
output="${2:-}"
[[ "$rows" =~ ^[1-9][0-9]*$ && "$rows" -le 10000000 ]] || {
  echo 'usage: run_backfill_scale.sh ROWS [OUTPUT.json]' >&2; exit 64;
}
if [[ "$rows" -ge 10000000 && "${JJD_ALLOW_10M_CAPACITY:-0}" != 1 ]]; then
  echo '[error] 10m capacity run requires JJD_ALLOW_10M_CAPACITY=1 and a dedicated resource window' >&2
  exit 75
fi
command -v docker >/dev/null
docker info >/dev/null
docker compose version >/dev/null
docker image inspect postgres:16-alpine >/dev/null

fixture="$(mktemp -d)"
project="jjdguard_scale_${rows}_${RANDOM}_$$"
cleanup() {
  docker compose -p "$project" -f "$fixture/compose.yml" down -v --remove-orphans >/dev/null 2>&1 || true
  rm -rf "$fixture"
}
trap cleanup EXIT INT TERM
cat >"$fixture/compose.yml" <<'YAML'
services:
  postgres:
    image: postgres:16-alpine
    environment:
      POSTGRES_PASSWORD: scale
      POSTGRES_DB: scale
    ports: ["127.0.0.1::5432"]
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U postgres -d scale"]
      interval: 1s
      timeout: 2s
      retries: 60
    volumes: [scale-db:/var/lib/postgresql/data]
volumes:
  scale-db: {}
YAML
docker compose -p "$project" -f "$fixture/compose.yml" up -d --wait --wait-timeout 90
port="$(docker compose -p "$project" -f "$fixture/compose.yml" port postgres 5432 | sed 's/.*://')"
(
  cd "$ROOT/apps/worker"
  JJD_BACKFILL_SCALE_DATABASE_URL="postgres://postgres:scale@127.0.0.1:$port/scale?sslmode=disable" \
    JJD_BACKFILL_SCALE_ROWS="$rows" PATH="/usr/local/go/bin:$PATH" GOWORK=off \
    go test ./internal/backfill -run TestPostgresCustomerProjectionScale -count=1 -timeout 4h -v
) | tee "$fixture/test.log"
metrics="$(sed -n 's/^BACKFILL_METRICS=//p' "$fixture/test.log" | tail -1)"
[[ -n "$metrics" ]] || { echo '[error] scale metrics missing' >&2; exit 1; }
python3 -m json.tool <<<"$metrics"
if [[ -n "$output" ]]; then
  mkdir -p "$(dirname "$output")"
  printf '%s\n' "$metrics" >"$output"
fi
printf 'backfill_scale=ok rows=%s project=%s\n' "$rows" "$project"
