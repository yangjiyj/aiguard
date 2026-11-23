#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BUILDER="$ROOT_DIR/deploy/docker-compose/build-offline-images-for-arch.sh"
LLM_DOCKERFILE="$ROOT_DIR/deploy/docker-compose/llm-judge/Dockerfile"
TOOLCHAIN_CACHE_DIR="$ROOT_DIR/deploy/docker-compose/release-toolchain-cache-dir.sh"

fail() { echo "[fail] $*" >&2; exit 1; }
assert_contains() {
  local text="$1" needle="$2"
  grep -Fq -- "$needle" <<<"$text" || fail "expected output to contain: $needle"
}
assert_not_contains() {
  local text="$1" needle="$2"
  if grep -Fq -- "$needle" <<<"$text"; then
    fail "expected output not to contain: $needle"
  fi
}

[[ -x "$BUILDER" ]] || fail "missing executable architecture builder: $BUILDER"
[[ -x "$TOOLCHAIN_CACHE_DIR" ]] || fail "missing executable toolchain cache locator: $TOOLCHAIN_CACHE_DIR"

grep -Fq -- '-DLLAMA_BUILD_UI=OFF' "$LLM_DOCKERFILE" || fail 'llama server build must not download or embed the unused web UI'
grep -Fq -- '-DLLAMA_USE_PREBUILT_UI=OFF' "$LLM_DOCKERFILE" || fail 'llama server build must not download prebuilt UI assets'

amd64_plan="$(OFFLINE_ARCH_BUILDER_DRY_RUN=1 "$BUILDER" amd64)"
amd64_toolchain_dir="$("$TOOLCHAIN_CACHE_DIR" amd64)"
assert_contains "$amd64_plan" 'platform=linux/amd64'
assert_contains "$amd64_plan" 'gateway-core control-plane security-engine proxy-server web-console worker'
assert_contains "$amd64_plan" 'docker-compose-llm-judge:latest'
assert_contains "$amd64_plan" 'docker-compose-tier1-classifier:latest'
assert_contains "$amd64_plan" 'enterprise-ai-portal:0.2.0-slim'
assert_contains "$amd64_plan" 'chat-portal/portal-proxy:0.1.0'
assert_contains "$amd64_plan" 'keycloak/keycloak:26.3'
assert_contains "$amd64_plan" 'library/caddy:2-alpine'
assert_contains "$amd64_plan" 'reuse cached fixed third-party image postgres:16-alpine'
assert_contains "$amd64_plan" 'reuse cached fixed third-party image valkey/valkey:8.1.10-alpine'
assert_not_contains "$amd64_plan" 'pull --platform linux/amd64'
assert_contains "$amd64_plan" "$amd64_toolchain_dir/docker-static.tgz"
assert_contains "$amd64_plan" 'docker-compose-linux-x86_64'
assert_contains "$amd64_plan" 'locked-compose'

arm64_plan="$(OFFLINE_ARCH_BUILDER_DRY_RUN=1 "$BUILDER" arm64)"
arm64_toolchain_dir="$("$TOOLCHAIN_CACHE_DIR" arm64)"
assert_contains "$arm64_plan" 'platform=linux/arm64'
assert_contains "$arm64_plan" 'gateway-core control-plane security-engine proxy-server web-console worker'
assert_contains "$arm64_plan" 'docker-compose-llm-judge:latest'
assert_contains "$arm64_plan" 'docker-compose-tier1-classifier:latest'
assert_contains "$arm64_plan" 'enterprise-ai-portal:0.2.0-slim'
assert_contains "$arm64_plan" 'chat-portal/portal-proxy:0.1.0'
assert_contains "$arm64_plan" 'keycloak/keycloak:26.3'
assert_contains "$arm64_plan" 'library/caddy:2-alpine'
assert_contains "$arm64_plan" 'reuse cached fixed third-party image postgres:16-alpine'
assert_contains "$arm64_plan" 'reuse cached fixed third-party image valkey/valkey:8.1.10-alpine'
assert_not_contains "$arm64_plan" 'pull --platform linux/arm64'
assert_contains "$arm64_plan" "$arm64_toolchain_dir/docker-static.tgz"
assert_contains "$arm64_plan" 'docker-compose-linux-aarch64'

lite_nochat_plan="$(BUNDLE_PROFILE=lite INCLUDE_CHAT=0 OFFLINE_ARCH_BUILDER_DRY_RUN=1 \
  "$BUILDER" amd64)"
assert_not_contains "$lite_nochat_plan" 'docker-compose-tier1-classifier:latest'
assert_not_contains "$lite_nochat_plan" 'enterprise-ai-portal:0.2.0-slim'

full_nochat_plan="$(BUNDLE_PROFILE=full INCLUDE_CHAT=0 OFFLINE_ARCH_BUILDER_DRY_RUN=1 \
  "$BUILDER" amd64)"
assert_contains "$full_nochat_plan" 'docker-compose-tier1-classifier:latest'
assert_not_contains "$full_nochat_plan" 'enterprise-ai-portal:0.2.0-slim'

lite_chat_plan="$(BUNDLE_PROFILE=lite INCLUDE_CHAT=1 OFFLINE_ARCH_BUILDER_DRY_RUN=1 \
  "$BUILDER" amd64)"
assert_not_contains "$lite_chat_plan" 'docker-compose-tier1-classifier:latest'
assert_contains "$lite_chat_plan" 'enterprise-ai-portal:0.2.0-slim'

full_chat_plan="$(BUNDLE_PROFILE=full INCLUDE_CHAT=1 OFFLINE_ARCH_BUILDER_DRY_RUN=1 \
  "$BUILDER" amd64)"
assert_contains "$full_chat_plan" 'docker-compose-tier1-classifier:latest'
assert_contains "$full_chat_plan" 'enterprise-ai-portal:0.2.0-slim'

prepare_plan="$(OFFLINE_RELEASE_THIRD_PARTY_INPUT_MODE=prepare \
  OFFLINE_ARCH_BUILDER_DRY_RUN=1 "$BUILDER" amd64)"
assert_contains "$prepare_plan" 'pull --platform linux/amd64 postgres:16-alpine'
assert_contains "$prepare_plan" 'pull --platform linux/amd64 valkey/valkey:8.1.10-alpine'

if OFFLINE_ARCH_BUILDER_DRY_RUN=1 "$BUILDER" armv7 >/dev/null 2>&1; then
  fail 'builder must reject unsupported armv7'
fi

for image in \
  docker-compose-gateway-core:latest \
  docker-compose-control-plane:latest \
  docker-compose-security-engine:latest \
  docker-compose-proxy-server:latest \
  docker-compose-web-console:latest \
  docker-compose-worker:latest \
  postgres:16-alpine valkey/valkey:8.1.10-alpine; do
  assert_contains "$arm64_plan" "inspect-architecture arm64 $image"
done

echo '[ok] offline architecture builder contract passed'
