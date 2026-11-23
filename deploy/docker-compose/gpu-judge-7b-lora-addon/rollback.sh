#!/bin/bash
set -Eeuo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="$ROOT/runtime.env"
PROJECT="${GPU_JUDGE_COMPOSE_PROJECT:-jjdguard-gpu-judge}"
[[ -f "$ENV_FILE" ]] || { echo '[error] runtime.env is missing' >&2; exit 1; }
docker compose -p "$PROJECT" --env-file "$ENV_FILE" -f "$ROOT/compose.yml" down
echo '[ok] GPU Judge container stopped; model, image, and runtime.env were retained'
echo '[next] point JJDGuard back to its previous Judge URL if gateway cutover was completed'
