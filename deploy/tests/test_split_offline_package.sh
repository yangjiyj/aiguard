#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
ARCH_LIB="$ROOT_DIR/deploy/docker-compose/lib-arch.sh"
PACKAGE_SCRIPT="$ROOT_DIR/deploy/docker-compose/package-offline-bundle.sh"
DOCKER_INSTALLER="$ROOT_DIR/deploy/docker-compose/install-docker.sh"
OFFLINE_COMPOSE="$ROOT_DIR/deploy/docker-compose/docker-compose.offline.yml"
CADDYFILE="$ROOT_DIR/deploy/docker-compose/chat/Caddyfile"
ACCEPTANCE_GATE="$ROOT_DIR/deploy/lib/acceptance-gate.sh"

fail() { echo "[fail] $*" >&2; exit 1; }
assert_eq() {
  local want="$1" got="$2" label="$3"
  [[ "$got" == "$want" ]] || fail "$label: want=$want got=$got"
}
assert_file_contains() {
  local file="$1" needle="$2"
  grep -Fq -- "$needle" "$file" || fail "expected $file to contain: $needle"
}

[[ -f "$ARCH_LIB" ]] || fail "missing architecture library: $ARCH_LIB"
# shellcheck disable=SC1090
source "$ARCH_LIB"

assert_eq amd64 "$(normalize_offline_arch x86_64)" "x86_64 alias"
assert_eq amd64 "$(normalize_offline_arch amd64)" "amd64 alias"
assert_eq arm64 "$(normalize_offline_arch aarch64)" "aarch64 alias"
assert_eq arm64 "$(normalize_offline_arch arm64)" "arm64 alias"
if normalize_offline_arch armv7l >/dev/null 2>&1; then
  fail "armv7 must not be accepted by the customer package contract"
fi

assert_eq x86_64 "$(docker_static_arch_dir amd64)" "amd64 Docker directory"
assert_eq aarch64 "$(docker_static_arch_dir arm64)" "arm64 Docker directory"
assert_eq x86_64 "$(compose_asset_arch amd64)" "amd64 Compose asset"
assert_eq aarch64 "$(compose_asset_arch arm64)" "arm64 Compose asset"

assert_eq 'jjdguard-1.4.0-offline-lite-amd64-20260713' \
  "$(offline_bundle_name 1.4.0 lite '' amd64 20260713)" "amd64 bundle name"
assert_eq 'jjdguard-1.4.0-offline-lite-arm64-20260713' \
  "$(offline_bundle_name 1.4.0 lite '' arm64 20260713)" "arm64 bundle name"

OFFLINE_TEST_UNAME_M=x86_64 assert_host_arch amd64
if OFFLINE_TEST_UNAME_M=x86_64 assert_host_arch arm64 >/dev/null 2>&1; then
  fail "arm64 package must reject an amd64 host"
fi
OFFLINE_TEST_UNAME_M=aarch64 assert_host_arch arm64

assert_file_contains "$PACKAGE_SCRIPT" '. "$SCRIPT_DIR/lib-arch.sh"'
assert_file_contains "$PACKAGE_SCRIPT" 'release-toolchain-cache-dir.sh'
assert_file_contains "$PACKAGE_SCRIPT" 'DOCKER_STATIC_TGZ="$TOOLCHAIN_ASSET_DIR/docker-static.tgz"'
assert_file_contains "$PACKAGE_SCRIPT" 'DOCKER_COMPOSE_BINARY="$TOOLCHAIN_ASSET_DIR/docker-compose"'
assert_file_contains "$PACKAGE_SCRIPT" 'offline_bundle_name'
assert_file_contains "$PACKAGE_SCRIPT" 'run_candidate_static_gates'
assert_file_contains "$PACKAGE_SCRIPT" 'test_release_toolchain_cache.sh'
assert_file_contains "$PACKAGE_SCRIPT" 'test_release_third_party_cache_only.sh'
assert_file_contains "$PACKAGE_SCRIPT" 'test_offline_release_hardening.sh'
assert_file_contains "$PACKAGE_SCRIPT" 'test_self_extracting_installer.sh'
assert_file_contains "$PACKAGE_SCRIPT" 'TMPDIR=/tmp bash "$PROJECT_ROOT/deploy/tests/$gate_test"'
if grep -Fq -- 'acceptance-gate.sh' "$PACKAGE_SCRIPT"; then
  fail 'candidate packaging must not treat a build-host runtime gate as formal acceptance'
fi
if grep -Fq -- 'OFFLINE_ALLOW_ARCH_MISMATCH' "$PACKAGE_SCRIPT"; then
  fail 'candidate packaging must not retain the removed local acceptance override'
fi
assert_file_contains "$OFFLINE_COMPOSE" 'REDIS_EXTRA_ARGS'
assert_file_contains "$OFFLINE_COMPOSE" 'http://127.0.0.1:8180/healthz'
assert_file_contains "$CADDYFILE" '@edge_health path /healthz'
assert_file_contains "$CADDYFILE" 'handle @edge_health {'
assert_file_contains "$CADDYFILE" 'respond "ok" 200'
assert_file_contains "$ACCEPTANCE_GATE" "REDIS_EXTRA_ARGS='--ignore-warnings ARM64-COW-BUG'"
assert_file_contains "$DOCKER_INSTALLER" '. "$SCRIPT_DIR/lib-arch.sh"'
assert_file_contains "$DOCKER_INSTALLER" 'assert_host_arch "$EXPECTED_ARCH"'

echo '[ok] split offline package architecture contract passed'
