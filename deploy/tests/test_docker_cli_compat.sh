#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
DEPLOY_SCRIPT="$ROOT_DIR/deploy/docker-compose/deploy-offline.sh"
# 兼容层与灌卷逻辑在安装与升级共用的 deploy/lib/judge-model-load.sh 里。
JUDGE_MODEL_LIB="$ROOT_DIR/deploy/lib/judge-model-load.sh"

fail() { echo "[fail] $*" >&2; exit 1; }

# Extract only the compatibility layer so the fixture never runs deployment code.
HELPER="$(sed -n '/^OFFLINE_DOCKER_RUN_PULL_MODE=unknown$/,/^load_judge_model() {/p' "$JUDGE_MODEL_LIB" | sed '$d')"
[[ -n "$HELPER" ]] || fail 'offline Docker CLI compatibility layer is missing'
grep -Fqx '. "$SCRIPT_DIR/../lib/judge-model-load.sh"' "$DEPLOY_SCRIPT" ||
  fail 'offline installer must load the shared Docker CLI compatibility layer'

run_case() {
  local mode="$1" image_state="$2"
  (
    set -Eeuo pipefail
    docker() {
      case "$1" in
        run)
          if [ "$2" = '--help' ]; then
            if [ "$mode" = supported ]; then
              printf '%s\n' '      --pull string   Pull image before running ("always", "missing", "never")'
            fi
            return 0
          fi
          printf 'unexpected docker run: %s\n' "$*" >&2
          return 91
          ;;
        image)
          [ "$2" = inspect ] && [ "$image_state" = present ] || return 92
          return 0
          ;;
        *)
          printf 'unexpected docker command: %s\n' "$*" >&2
          return 93
          ;;
      esac
    }
    eval "$HELPER"
    prepare_offline_docker_run_pull
    printf 'mode=%s\n' "$OFFLINE_DOCKER_RUN_PULL_MODE"
  )
}

[[ "$(run_case supported missing | tail -n1)" == 'mode=supported' ]] ||
  fail 'new Docker CLI did not keep --pull=never mode'
[[ "$(run_case legacy present | tail -n1)" == 'mode=legacy' ]] ||
  fail 'legacy Docker CLI did not use verified local-image fallback'

set +e
missing_output="$(run_case legacy missing 2>&1)"
missing_status=$?
set -e
[[ "$missing_status" -ne 0 && "$missing_output" == *'local image postgres:16-alpine is missing'* ]] ||
  fail 'legacy Docker CLI must fail when the helper image is absent'

echo '[ok] offline deployment tolerates legacy Docker CLI without weakening local-image checks'
