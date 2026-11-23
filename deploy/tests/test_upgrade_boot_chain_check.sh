#!/usr/bin/env bash
# verify_boot_chain_matches_running 的行为测试：用真实 docker 起小容器，覆盖
# 「开机链与运行一致→通过」「运行时不符→失败」「服务不在开机链→失败」，
# 以及 env_file 场景（compose 的 config --hash 不解析 env_file，容器标签含其内容）。
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
WORK="$(mktemp -d)"; PROJECT="bootchk$$"
cleanup() {
  docker ps -aq --filter "label=com.docker.compose.project=$PROJECT" 2>/dev/null | xargs -r docker rm -f -v >/dev/null 2>&1 || true
  docker ps -aq --filter 'name=bootchk-' 2>/dev/null | xargs -r docker rm -f -v >/dev/null 2>&1 || true
  docker volume ls -q --filter "label=com.docker.compose.project=$PROJECT" 2>/dev/null | xargs -r docker volume rm >/dev/null 2>&1 || true
  docker network ls -q --filter "label=com.docker.compose.project=$PROJECT" 2>/dev/null | xargs -r docker network rm >/dev/null 2>&1 || true
  docker volume ls -q --filter 'name=bootchk-' 2>/dev/null | xargs -r docker volume rm >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
trap cleanup EXIT
IMAGE="$(docker image ls --format '{{.Repository}}:{{.Tag}}' | grep -m1 -E '^(postgres|valkey/valkey|docker\.1ms\.run/library/caddy|nginx|alpine|busybox)')" || true
[[ -n "$IMAGE" ]] || { echo "[skip] 本机没有可用的小镜像"; exit 0; }
mkdir -p "$WORK/.upgrade"
# web 无 env_file；apienv 声明 env_file（复现 control-plane 的结构）
cat >"$WORK/docker-compose.offline.yml" <<YML
services:
  web:
    image: ${IMAGE}
    command: ["sh", "-c", "sleep 600"]
    environment:
      - MARKER=base
  apienv:
    image: ${IMAGE}
    command: ["sh", "-c", "sleep 600"]
    env_file: ./runtime.env
    volumes:
      - probevol:/probevol
volumes:
  probevol:
YML
printf 'TOKEN=boot\n' >"$WORK/runtime.env"
cat >"$WORK/override.yml" <<YML
services:
  web:
    environment:
      - MARKER=boot
YML
printf '%s\n' "$WORK/override.yml" >"$WORK/.upgrade/compose-files"
: >"$WORK/.env"
compose() { docker compose --project-name "$PROJECT" --project-directory "$WORK" --env-file "$WORK/.env" "$@"; }
fresh_stack() {
  docker ps -aq --filter "label=com.docker.compose.project=$PROJECT" 2>/dev/null | xargs -r docker rm -f -v >/dev/null 2>&1 || true
  compose -f "$WORK/docker-compose.offline.yml" -f "$WORK/override.yml" up -d --pull never >/dev/null 2>&1
}
# 只取被测函数及其依赖，不执行 upgrade-bundle.sh 的 main
fn_src="$(mktemp)"
{
  echo 'fail(){ echo "FAIL: $*"; return 1; }'
  echo 'log(){ echo "$*"; }'
  sed -n '/^project_container() {/,/^}/p' "$ROOT/deploy/docker-compose/upgrade-bundle.sh"
  sed -n '/^boot_chain_probe_hash() {/,/^}/p' "$ROOT/deploy/docker-compose/upgrade-bundle.sh"
  sed -n '/^boot_chain_probe_cleanup() {/,/^}/p' "$ROOT/deploy/docker-compose/upgrade-bundle.sh"
  sed -n '/^verify_boot_chain_matches_running() {/,/^}/p' "$ROOT/deploy/docker-compose/upgrade-bundle.sh"
} >"$fn_src"
if ! grep -q 'boot_chain_probe_hash()' "$fn_src"; then
  echo "[warn] 实现里没有 boot_chain_probe_hash（旧版本）：env_file 场景应当失败"
fi
# 被测函数把 "$COMPOSE_WRAPPER" 当可执行文件用：提供一个包装脚本
printf '#!/bin/sh\nexec docker compose "$@"\n' >"$WORK/compose-wrapper.sh"; chmod +x "$WORK/compose-wrapper.sh"
run_check_services() {
  local svcs="$1"
  ( SCRIPT_DIR="$WORK"; EXISTING_PROJECT_NAME="$PROJECT"; COMPOSE_WRAPPER="$WORK/compose-wrapper.sh"
    IFS=',' read -ra OLD_RUNNING_SERVICES <<<"$svcs"
    # shellcheck disable=SC1090
    source "$fn_src"; verify_boot_chain_matches_running )
}

# 1) 一致（含 env_file 服务）→ 通过，且必须走探针口径
fresh_stack
out="$(run_check_services 'web,apienv' 2>&1)" || { echo "$out"; echo "[fail] 一致时应通过"; exit 1; }
echo "$out" | grep -q "开机启动链与当前运行配置一致" || { echo "$out"; echo "[fail] 缺少通过日志"; exit 1; }
echo "$out" | grep -q "apienv" || { echo "$out"; echo "[fail] env_file 服务应走探针容器确认（回归：config --hash 不含 env_file）"; exit 1; }
echo "[ok] 一致时通过（env_file 服务经探针容器确认；探针建卷告警不得污染哈希）"
# 探针容器与临时卷不得残留
leftover="$(docker ps -aq --filter 'name=bootchk-' 2>/dev/null | wc -l)"
[[ "$leftover" -eq 0 ]] || { echo "[fail] 探针容器残留 $leftover 个"; exit 1; }
echo "[ok] 探针容器已清理"

# 2) 无 env_file 的服务漂移 → 失败并指出 web
fresh_stack
cat >"$WORK/live-only.yml" <<YML
services:
  web:
    environment:
      - MARKER=live-only
YML
docker ps -aq --filter "label=com.docker.compose.project=$PROJECT" 2>/dev/null | xargs -r docker rm -f -v >/dev/null 2>&1 || true
compose -f "$WORK/docker-compose.offline.yml" -f "$WORK/override.yml" -f "$WORK/live-only.yml" up -d --pull never >/dev/null 2>&1
if out="$(run_check_services 'web,apienv' 2>&1)"; then echo "$out"; echo "[fail] 开机链与运行不一致时必须失败"; exit 1; fi
echo "$out" | grep -q "web" || { echo "$out"; echo "[fail] 失败信息应指出不一致的服务"; exit 1; }
echo "[ok] 不一致时失败并指出服务 web"

# 3) env_file 服务漂移（运行时环境与开机链解析值不同）→ 失败并指出 apienv
cat >"$WORK/live-env.yml" <<YML
services:
  apienv:
    environment:
      - TOKEN=live-only
YML
docker ps -aq --filter "label=com.docker.compose.project=$PROJECT" 2>/dev/null | xargs -r docker rm -f -v >/dev/null 2>&1 || true
compose -f "$WORK/docker-compose.offline.yml" -f "$WORK/override.yml" -f "$WORK/live-env.yml" up -d --pull never >/dev/null 2>&1
if out="$(run_check_services 'apienv' 2>&1)"; then echo "$out"; echo "[fail] env_file 服务运行时漂移必须失败"; exit 1; fi
echo "$out" | grep -q "apienv" || { echo "$out"; echo "[fail] 失败信息应指出不一致的服务 apienv"; exit 1; }
echo "[ok] env_file 服务漂移时失败并指出服务 apienv"

# 4) 服务不在开机启动链里（现场只在链外文件里新增了服务）也必须失败
fresh_stack
run_check_ghost() {
  ( SCRIPT_DIR="$WORK"; EXISTING_PROJECT_NAME="$PROJECT"; COMPOSE_WRAPPER="$WORK/compose-wrapper.sh"
    OLD_RUNNING_SERVICES=(ghost)
    # shellcheck disable=SC1090
    source "$fn_src"
    # 用真实在跑的容器顶替 ghost 的位置，逼近「链外文件新增服务」的现场
    project_container(){ printf '%s' "${PROJECT}-web-1"; }
    verify_boot_chain_matches_running )
}
if out="$(run_check_ghost 2>&1)"; then echo "$out"; echo "[fail] 服务不在开机链里时必须失败"; exit 1; fi
echo "$out" | grep -q "ghost" || { echo "$out"; echo "[fail] 失败信息应指出缺失的服务"; exit 1; }
echo "[ok] 服务不在开机链里时失败"
rm -f "$fn_src"
