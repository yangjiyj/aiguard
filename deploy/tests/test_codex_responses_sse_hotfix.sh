#!/bin/sh
set -eu

ROOT="$(CDPATH= cd -- "$(dirname "$0")/../.." && pwd)"
HOTFIX="$ROOT/deploy/hotfix/codex-responses-sse"
for file in hotfix-lib.sh install.sh rollback.sh verify.sh package.sh RELEASE_NOTES.md; do
  [ -f "$HOTFIX/$file" ] || { echo "missing $file" >&2; exit 1; }
done
for file in install.sh rollback.sh verify.sh package.sh; do
  sh -n "$HOTFIX/$file"
done
grep -q '1.6.0' "$HOTFIX/install.sh"
grep -q 'x86_64|amd64' "$HOTFIX/install.sh"
grep -q -- '--no-deps --force-recreate gateway-core' "$HOTFIX/install.sh"
grep -q 'rollback.sh' "$HOTFIX/install.sh"
grep -q 'sha256sum -c SHA256SUMS' "$HOTFIX/install.sh"
grep -q 'com.docker.compose.project.working_dir' "$HOTFIX/install.sh"
grep -q 'rollback_image=' "$HOTFIX/install.sh"
grep -q '恢复健康' "$HOTFIX/rollback.sh"
grep -q 'response.output_text.delta' "$HOTFIX/verify.sh"
grep -q 'response.function_call_arguments.delta' "$HOTFIX/verify.sh"
grep -q 'text/event-stream' "$HOTFIX/verify.sh"
grep -q 'sequence_number' "$HOTFIX/verify.sh"
grep -q 'response.completed' "$HOTFIX/verify.sh"
grep -q '"usage":' "$HOTFIX/verify.sh"

# shellcheck disable=SC1090
. "$HOTFIX/hotfix-lib.sh"
for version in 1.4.0 1.5.0 1.6.0; do
  supported_hotfix_version "$version" || {
    echo "supported version rejected: $version" >&2
    exit 1
  }
  [ "$(hotfix_image_relpath "$version")" = "images/$version/gateway-core-image.tar.gz" ] || {
    echo "wrong image path for $version" >&2
    exit 1
  }
done
if supported_hotfix_version 1.3.0; then
  echo "unknown version accepted" >&2
  exit 1
fi
if supported_hotfix_version 1.6.1; then
  echo "unlisted patch version accepted" >&2
  exit 1
fi

grep -q 'hotfix_image_relpath' "$HOTFIX/install.sh"
grep -q -- '--preflight-only' "$HOTFIX/install.sh"
grep -q 'saved_patch_image_id' "$HOTFIX/install.sh"
grep -q '当前运行镜像已偏离补丁状态' "$HOTFIX/install.sh"
grep -q 'CURRENT_VERSION' "$HOTFIX/rollback.sh"
grep -q 'current_image_id' "$HOTFIX/rollback.sh"
grep -q '当前运行镜像与补丁状态不一致' "$HOTFIX/rollback.sh"
grep -q 'docker ps -a' "$HOTFIX/rollback.sh"
grep -q '未发现旧容器，将按状态记录恢复' "$HOTFIX/rollback.sh"
grep -q 'target_ref_image_id' "$HOTFIX/rollback.sh"
grep -q 'images/' "$HOTFIX/package.sh"
grep -q 'assert_gateway_tree' "$HOTFIX/package.sh"
grep -q 'packages/shared-go' "$HOTFIX/package.sh"
grep -q -- '--platform linux/amd64' "$HOTFIX/package.sh"
grep -q '.Architecture' "$HOTFIX/package.sh"
grep -q '1.4.0' "$HOTFIX/RELEASE_NOTES.md"
grep -q '1.5.0' "$HOTFIX/RELEASE_NOTES.md"
grep -q '1.6.0' "$HOTFIX/RELEASE_NOTES.md"
echo "[ok] Codex SSE 热补丁脚本契约通过"
