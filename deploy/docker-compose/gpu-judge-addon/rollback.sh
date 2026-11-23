#!/bin/bash
set -Eeuo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="$ROOT/runtime.env"
PROJECT="${GPU_JUDGE_COMPOSE_PROJECT:-jjdguard-gpu-judge}"
[[ -f "$ENV_FILE" ]] || { echo '[error] runtime.env is missing' >&2; exit 1; }
files=(-f "$ROOT/compose.yml")
[[ -f "$ROOT/compose.instances.yml" ]] && files+=(-f "$ROOT/compose.instances.yml")
# --remove-orphans 同时清掉 1.x 单实例容器（llm-judge-gpu），不删卷、镜像、模型。
docker compose -p "$PROJECT" --env-file "$ENV_FILE" "${files[@]}" down --remove-orphans
echo '[ok] GPU Judge load balancer and instances stopped; model, images, TLS, and runtime.env were retained'
echo '[next] point JJDGuard back to its previous Judge URL if gateway cutover was completed'
