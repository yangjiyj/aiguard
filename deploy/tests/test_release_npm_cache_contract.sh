#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
ARCH_BUILDER="$ROOT_DIR/deploy/docker-compose/build-offline-images-for-arch.sh"
TASK4_BUILDER="$ROOT_DIR/deploy/tests/build_jjdguard_task4_images.sh"
PORTAL_DOCKERFILE="$ROOT_DIR/enterprise-ai-portal/Dockerfile"
WEB_DOCKERFILE="$ROOT_DIR/apps/web-console/Dockerfile"

fail() {
  printf '[release-npm-cache] %s\n' "$*" >&2
  exit 1
}

assert_file_contains() {
  local file="$1" needle="$2"
  grep -Fq -- "$needle" "$file" || fail "missing $needle in $file"
}

assert_first_line() {
  local file="$1" expected="$2" actual
  IFS= read -r actual <"$file" || fail "cannot read first line: $file"
  [[ "$actual" == "$expected" ]] || fail "first line must be $expected in $file"
}

assert_task4_cache_context_rejected_before_docker() {
  local context="$1" expected="$2" output
  output="$TMP/output"
  if JJD_TASK4_TESTING=1 JJD_TASK4_DOCKER="$DOCKER_STUB" "$TASK4_BUILDER" \
    --candidate-revision "$(printf 'a%.0s' {1..40})" \
    --candidate-tree "$(printf 'b%.0s' {1..40})" \
    --receipt-dir "$TMP/receipts" \
    --portal-image portal:test \
    --npm-cache-context "$context" \
    --npm-cache-sha256 "$(printf 'd%.0s' {1..64})" \
    --source-root "$TMP/source" \
    --source-archive-sha256 "$(printf 'c%.0s' {1..64})" >"$output" 2>&1; then
    fail "unsafe cache context unexpectedly reached Task4 build: $context"
  fi
  grep -Fq -- "$expected" "$output" || fail "missing cache rejection: $expected"
  [[ ! -e "$DOCKER_MARKER" ]] || fail "Docker was called before cache rejection"
}

TMP="$(mktemp -d)"
trap 'rm -rf -- "$TMP"' EXIT
install -d -m 0700 "$TMP/source" "$TMP/cache-context"
DOCKER_STUB="$TMP/docker-stub"
DOCKER_MARKER="$TMP/docker-called"
printf '%s\n' '#!/bin/sh' ": >'$DOCKER_MARKER'" 'exit 99' >"$DOCKER_STUB"
chmod 0700 "$DOCKER_STUB"

for file in "$ARCH_BUILDER" "$TASK4_BUILDER" "$PORTAL_DOCKERFILE" "$WEB_DOCKERFILE"; do
  [[ -f "$file" && ! -L "$file" ]] || fail "required file is unsafe: $file"
done

assert_file_contains "$ARCH_BUILDER" 'OFFLINE_RELEASE_NPM_CACHE_INPUT'
assert_file_contains "$ARCH_BUILDER" 'prepare_release_npm_cache_context'
assert_file_contains "$ARCH_BUILDER" 'NPM_CACHE_ARCHIVE_SHA256'
assert_file_contains "$ARCH_BUILDER" 'release-npm-cache=$NPM_CACHE_CONTEXT'
assert_file_contains "$ARCH_BUILDER" '--npm-cache-context "$NPM_CACHE_CONTEXT"'
assert_file_contains "$ARCH_BUILDER" '--npm-cache-sha256 "$NPM_CACHE_ARCHIVE_SHA256"'
assert_file_contains "$TASK4_BUILDER" '--npm-cache-context'
assert_file_contains "$TASK4_BUILDER" '--npm-cache-sha256'
assert_file_contains "$TASK4_BUILDER" 'release-npm-cache=$npm_cache_context'

if grep -Fq -- 'release-npm-cache=$NPM_CACHE_INPUT' "$ARCH_BUILDER"; then
  fail 'arch builder must not stream the NPM cache directory as a Buildx context'
fi
if grep -Fq -- 'release-npm-cache=$npm_cache_context/npm-cache.tar' "$TASK4_BUILDER"; then
  fail 'Task4 must not stream the NPM cache directory as a Docker context'
fi
if grep -Fq -- 'docker-image://$NPM_CACHE_IMAGE' "$ARCH_BUILDER" ||
   grep -Fq -- 'docker-image://$npm_cache_image' "$TASK4_BUILDER"; then
  fail 'NPM cache context must not use a mutable Docker image tag'
fi
if grep -Fq -- 'docker image rm "$NPM_CACHE_IMAGE"' "$ARCH_BUILDER"; then
  fail 'NPM cache context must not leave a temporary Docker image cleanup path'
fi

for dockerfile in "$PORTAL_DOCKERFILE" "$WEB_DOCKERFILE"; do
  assert_first_line "$dockerfile" '# syntax=docker/dockerfile:1.7'
  assert_file_contains "$dockerfile" '# syntax=docker/dockerfile:1.7'
  assert_file_contains "$dockerfile" '--mount=type=bind,from=release-npm-cache'
  assert_file_contains "$dockerfile" 'npm-cache.tar'
  assert_file_contains "$dockerfile" 'tar -xf /tmp/npm-cache-input/npm-cache.tar'
  assert_file_contains "$dockerfile" 'npm ci --offline --legacy-peer-deps'
done

cd "$ROOT_DIR"
assert_task4_cache_context_rejected_before_docker "$TMP/missing-cache-context" \
  '--npm-cache-context must be an absolute real directory when --portal-image is set'
ln -s "$TMP/cache-context" "$TMP/cache-context-link"
assert_task4_cache_context_rejected_before_docker "$TMP/cache-context-link" \
  '--npm-cache-context must be an absolute real directory when --portal-image is set'

printf '[release-npm-cache] PASS\n'
