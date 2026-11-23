#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
ARCH_BUILDER="$ROOT_DIR/deploy/docker-compose/build-offline-images-for-arch.sh"
TASK4_BUILDER="$ROOT_DIR/deploy/tests/build_jjdguard_task4_images.sh"
PORTAL_DOCKERFILE="$ROOT_DIR/enterprise-ai-portal/Dockerfile"
BUNDLE_PACKAGER="$ROOT_DIR/deploy/docker-compose/package-offline-bundle.sh"
LOCK="$ROOT_DIR/deploy/docker-compose/release-prisma-engines.lock.json"
VERIFIER="$ROOT_DIR/deploy/docker-compose/verify-release-prisma-engines.py"

fail() {
  printf '[release-prisma-engines] %s\n' "$*" >&2
  exit 1
}

assert_file() {
  [[ -f "$1" && ! -L "$1" ]] || fail "required source file is missing or unsafe: $1"
}

assert_contains() {
  local file=$1 needle=$2
  grep -Fq -- "$needle" "$file" || fail "missing $needle in $file"
}

TMP="$(mktemp -d)"
IMAGE_TAG=
cleanup() {
  if [[ -n "$IMAGE_TAG" ]]; then
    docker image rm "$IMAGE_TAG" >/dev/null 2>&1 || true
  fi
  rm -rf -- "$TMP"
}
trap cleanup EXIT
INPUT="$TMP/prisma-engines"
install -d -m 0700 "$INPUT"
printf 'schema engine fixture\n' >"$INPUT/schema-engine-linux-musl-openssl-3.0.x"
printf 'query engine fixture\n' >"$INPUT/libquery_engine-linux-musl-openssl-3.0.x.so.node"
chmod 0500 "$INPUT"/*

schema_sha="$(sha256sum "$INPUT/schema-engine-linux-musl-openssl-3.0.x" | awk '{print $1}')"
query_sha="$(sha256sum "$INPUT/libquery_engine-linux-musl-openssl-3.0.x.so.node" | awk '{print $1}')"
jq -n \
  --arg schema_sha "$schema_sha" \
  --arg query_sha "$query_sha" \
  --argjson schema_size "$(stat -c %s "$INPUT/schema-engine-linux-musl-openssl-3.0.x")" \
  --argjson query_size "$(stat -c %s "$INPUT/libquery_engine-linux-musl-openssl-3.0.x.so.node")" \
  '{schema:"jjdguard-release-prisma-engines-lock/v1",prisma_version:"6.19.3",
    platform:"linux-musl-openssl-3.0.x",origin:"home-local-portal-runtime",
    source_image:"enterprise-ai-portal:0.2.0-slim",
    source_image_id:"sha256:e28bd38e70cb8623542e8b37b24e14ccd9aecff610c903dcd86df3fd215433b5",manifest:[
      {path:"libquery_engine-linux-musl-openssl-3.0.x.so.node",size:$query_size,sha256:$query_sha},
      {path:"schema-engine-linux-musl-openssl-3.0.x",size:$schema_size,sha256:$schema_sha}
    ]}' >"$TMP/fixture-lock.json"

assert_file "$LOCK"
assert_file "$VERIFIER"
assert_file "$ARCH_BUILDER"
assert_file "$TASK4_BUILDER"
assert_file "$PORTAL_DOCKERFILE"
assert_file "$BUNDLE_PACKAGER"

jq -e '
  (keys | sort) == ["manifest","origin","platform","prisma_version","schema","source_image","source_image_id"] and
  .schema == "jjdguard-release-prisma-engines-lock/v1" and
  .prisma_version == "6.19.3" and
  .platform == "linux-musl-openssl-3.0.x" and
  .origin == "home-local-portal-runtime" and
  .source_image == "enterprise-ai-portal:0.2.0-slim" and
  .source_image_id == "sha256:e28bd38e70cb8623542e8b37b24e14ccd9aecff610c903dcd86df3fd215433b5" and
  (.manifest | type == "array" and length == 2)
' "$LOCK" >/dev/null || fail 'source Prisma engine lock shape is invalid'

"$VERIFIER" --lock "$TMP/fixture-lock.json" --input "$INPUT" >"$TMP/receipt.json"
jq -e '
  (keys | sort) == ["approved_lock_sha256","content_sha256","manifest","origin","schema","source_image","source_image_id"] and
  .schema == "jjdguard-release-prisma-engines/v1" and
  .origin == "home-local-portal-runtime" and
  .source_image == "enterprise-ai-portal:0.2.0-slim" and
  .source_image_id == "sha256:e28bd38e70cb8623542e8b37b24e14ccd9aecff610c903dcd86df3fd215433b5" and
  (.approved_lock_sha256 | test("^[0-9a-f]{64}$")) and
  (.content_sha256 | test("^[0-9a-f]{64}$")) and
  ([.manifest[].path] | sort) == [
    "libquery_engine-linux-musl-openssl-3.0.x.so.node",
    "schema-engine-linux-musl-openssl-3.0.x"
  ]
' "$TMP/receipt.json" >/dev/null || fail 'Prisma engine receipt shape is invalid'

runtime_manifest="$TMP/runtime-manifest.tsv"
jq -r '.manifest[] | [.path, (.size | tostring), .sha256] | @tsv' \
  "$TMP/receipt.json" >"$runtime_manifest"
"$VERIFIER" --lock "$TMP/fixture-lock.json" --input "$INPUT" \
  --runtime-manifest "$runtime_manifest" >"$TMP/runtime-receipt.json"
cmp -s "$TMP/receipt.json" "$TMP/runtime-receipt.json" || \
  fail 'matching runtime Prisma manifest changed the signed receipt'

runtime_image_id="sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
"$VERIFIER" --lock "$TMP/fixture-lock.json" \
  --runtime-manifest "$runtime_manifest" \
  --runtime-image 'chat-portal/portal-proxy:0.1.0' \
  --runtime-image-id "$runtime_image_id" >"$TMP/runtime-image-receipt.json"
jq -e '
  (keys | sort) == [
    "approved_lock_sha256","content_sha256","expected_source_image",
    "expected_source_image_id","manifest","origin","runtime_image",
    "runtime_image_id","schema"
  ] and
  .schema == "jjdguard-release-prisma-runtime/v1" and
  .origin == "home-local-portal-runtime" and
  .expected_source_image == "enterprise-ai-portal:0.2.0-slim" and
  .expected_source_image_id == "sha256:e28bd38e70cb8623542e8b37b24e14ccd9aecff610c903dcd86df3fd215433b5" and
  .runtime_image == "chat-portal/portal-proxy:0.1.0" and
  .runtime_image_id == $runtime_image_id and
  (.manifest | type == "array" and length == 2)
' --arg runtime_image_id "$runtime_image_id" "$TMP/runtime-image-receipt.json" >/dev/null ||
  fail 'runtime Prisma engine receipt is not bound to the inspected runtime image'

tampered_runtime_manifest="$TMP/tampered-runtime-manifest.tsv"
awk -F $'\t' 'BEGIN { OFS = FS } NR == 1 { $3 = "0000000000000000000000000000000000000000000000000000000000000000" } { print }' \
  "$runtime_manifest" >"$tampered_runtime_manifest"
if output=$("$VERIFIER" --lock "$TMP/fixture-lock.json" --input "$INPUT" \
  --runtime-manifest "$tampered_runtime_manifest" 2>&1); then
  fail 'tampered runtime Prisma engine manifest was accepted'
fi
[[ "$output" == *'runtime engine manifest does not match verified receipt'* ]] || \
  fail "unexpected runtime Prisma manifest rejection: $output"

if output=$("$VERIFIER" --lock "$TMP/fixture-lock.json" \
  --runtime-manifest "$tampered_runtime_manifest" \
  --runtime-image 'chat-portal/portal-proxy:0.1.0' \
  --runtime-image-id "$runtime_image_id" 2>&1); then
  fail 'tampered runtime-only Prisma engine manifest was accepted'
fi
[[ "$output" == *'runtime engine manifest does not match reviewed lock'* ]] || \
  fail "unexpected runtime-only Prisma manifest rejection: $output"

ARM_INPUT="$TMP/prisma-engines-arm64"
ARM_LOCK="$TMP/fixture-lock-arm64.json"
install -d -m 0700 "$ARM_INPUT"
printf 'arm schema engine fixture\n' >"$ARM_INPUT/schema-engine-linux-musl-arm64-openssl-3.0.x"
printf 'arm query engine fixture\n' >"$ARM_INPUT/libquery_engine-linux-musl-arm64-openssl-3.0.x.so.node"
chmod 0500 "$ARM_INPUT"/*
arm_schema_sha="$(sha256sum "$ARM_INPUT/schema-engine-linux-musl-arm64-openssl-3.0.x" | awk '{print $1}')"
arm_query_sha="$(sha256sum "$ARM_INPUT/libquery_engine-linux-musl-arm64-openssl-3.0.x.so.node" | awk '{print $1}')"
jq -n \
  --arg schema_sha "$arm_schema_sha" \
  --arg query_sha "$arm_query_sha" \
  --argjson schema_size "$(stat -c %s "$ARM_INPUT/schema-engine-linux-musl-arm64-openssl-3.0.x")" \
  --argjson query_size "$(stat -c %s "$ARM_INPUT/libquery_engine-linux-musl-arm64-openssl-3.0.x.so.node")" \
  '{schema:"jjdguard-release-prisma-engines-lock/v1",prisma_version:"6.19.3",
    platform:"linux-musl-arm64-openssl-3.0.x",origin:"home-local-portal-runtime",
    source_image:"chat-portal/portal-proxy:0.1.0",
    source_image_id:"sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
    manifest:[
      {path:"libquery_engine-linux-musl-arm64-openssl-3.0.x.so.node",size:$query_size,sha256:$query_sha},
      {path:"schema-engine-linux-musl-arm64-openssl-3.0.x",size:$schema_size,sha256:$schema_sha}
    ]}' >"$ARM_LOCK"
"$VERIFIER" --target-arch arm64 --lock "$ARM_LOCK" --input "$ARM_INPUT" >"$TMP/arm-receipt.json"
jq -e '
  .source_image == "chat-portal/portal-proxy:0.1.0" and
  ([.manifest[].path] | sort) == [
    "libquery_engine-linux-musl-arm64-openssl-3.0.x.so.node",
    "schema-engine-linux-musl-arm64-openssl-3.0.x"
  ]
' "$TMP/arm-receipt.json" >/dev/null || fail 'ARM64 Prisma engine receipt shape is invalid'

chmod u+w "$INPUT/schema-engine-linux-musl-openssl-3.0.x"
printf 'tamper\n' >>"$INPUT/schema-engine-linux-musl-openssl-3.0.x"
if output=$("$VERIFIER" --lock "$TMP/fixture-lock.json" --input "$INPUT" 2>&1); then
  fail 'tampered Prisma engine input was accepted'
fi
[[ "$output" == *'does not match the approved lock'* ]] ||
  fail "unexpected Prisma engine tamper rejection: $output"

assert_contains "$ARCH_BUILDER" 'OFFLINE_RELEASE_PRISMA_ENGINE_INPUT'
assert_contains "$ARCH_BUILDER" '--prisma-engine-input "$PRISMA_ENGINE_INPUT"'
assert_contains "$ARCH_BUILDER" '--runtime-manifest "$runtime_engine_manifest"'
assert_contains "$ARCH_BUILDER" '--runtime-image "$PORTAL_PROXY_RUNTIME_INPUT"'
assert_contains "$ARCH_BUILDER" '--runtime-image-id "$PORTAL_PROXY_RUNTIME_IMAGE_ID"'
assert_contains "$ARCH_BUILDER" 'TASK4_BUILD_NETWORK_MODE=none'
assert_contains "$ARCH_BUILDER" '--network-mode "$TASK4_BUILD_NETWORK_MODE"'
assert_contains "$TASK4_BUILDER" '--prisma-engine-input'
assert_contains "$TASK4_BUILDER" 'prisma_engine_context="$tmp/prisma-engines"'
assert_contains "$TASK4_BUILDER" '--build-context "release-prisma-engine=$prisma_engine_context"'
assert_contains "$PORTAL_DOCKERFILE" 'COPY --from=release-prisma-engine . /tmp/release-prisma-engine/'
assert_contains "$PORTAL_DOCKERFILE" 'arm64) query_engine=libquery_engine-linux-musl-arm64-openssl-3.0.x.so.node'
assert_contains "$PORTAL_DOCKERFILE" 'schema_engine=schema-engine-linux-musl-arm64-openssl-3.0.x'
assert_contains "$PORTAL_DOCKERFILE" 'PRISMA_ENGINES_CHECKSUM_IGNORE_MISSING=1'
assert_contains "$PORTAL_DOCKERFILE" 'install -m 0555 "/tmp/release-prisma-engine/$query_engine"'
assert_contains "$PORTAL_DOCKERFILE" 'install -m 0555 "/tmp/release-prisma-engine/$schema_engine"'
assert_contains "$ARCH_BUILDER" '--target-arch "$TARGET_ARCH"'
assert_contains "$TASK4_BUILDER" '--target-arch "$target_arch"'
assert_contains "$BUNDLE_PACKAGER" 'PORTAL_IMAGE_MAX_BYTES=524288000'
if grep -Fq 'PORTAL_IMAGE_MAX_BYTES="${PORTAL_IMAGE_MAX_BYTES:-' "$BUNDLE_PACKAGER"; then
  fail 'formal Portal image size gate must not be relaxable through the environment'
fi

if [[ "${JJD_RELEASE_PRISMA_DOCKER_INTEGRATION:-0}" == 1 ]]; then
  NPM_CACHE_INPUT="${OFFLINE_RELEASE_NPM_CACHE_INPUT:-}"
  NPM_CACHE_CONTEXT="$TMP/npm-cache-context"
  PRISMA_ENGINE_INPUT="${OFFLINE_RELEASE_PRISMA_ENGINE_INPUT:-}"
  [[ "$NPM_CACHE_INPUT" == /* && -d "$NPM_CACHE_INPUT/_cacache" && ! -L "$NPM_CACHE_INPUT" ]] ||
    fail 'integration requires a real OFFLINE_RELEASE_NPM_CACHE_INPUT'
  [[ "$PRISMA_ENGINE_INPUT" == /* && -d "$PRISMA_ENGINE_INPUT" && ! -L "$PRISMA_ENGINE_INPUT" ]] ||
    fail 'integration requires a real OFFLINE_RELEASE_PRISMA_ENGINE_INPUT'
  "$VERIFIER" --lock "$LOCK" --input "$PRISMA_ENGINE_INPUT" >/dev/null

  install -d -m 0700 "$NPM_CACHE_CONTEXT"
  tar -C "$NPM_CACHE_INPUT" --sort=name --mtime='@0' --owner=0 --group=0 \
    --numeric-owner -cf "$NPM_CACHE_CONTEXT/npm-cache.tar" .
  chmod 0400 "$NPM_CACHE_CONTEXT/npm-cache.tar"
  IMAGE_TAG="jjdguard-prisma-contract-$$:test"
  docker buildx build --load --network none \
    --build-context "release-npm-cache=$NPM_CACHE_CONTEXT" \
    --build-context "release-prisma-engine=$PRISMA_ENGINE_INPUT" \
    --tag "$IMAGE_TAG" "$ROOT_DIR/enterprise-ai-portal" >"$TMP/docker-build.log" 2>&1 || {
      tail -n 100 "$TMP/docker-build.log" >&2
      fail 'real offline Portal build failed'
    }
  ! grep -Fq 'binaries.prisma.sh' "$TMP/docker-build.log" ||
    fail 'real offline Portal build attempted a Prisma download'

  PORTAL_IMAGE_MAX_BYTES=524288000
  portal_image_size="$(docker image inspect "$IMAGE_TAG" --format '{{.Size}}')"
  [[ "$portal_image_size" =~ ^[0-9]+$ ]] ||
    fail 'real offline Portal build did not report a numeric image size'
  (( portal_image_size <= PORTAL_IMAGE_MAX_BYTES )) ||
    fail "real offline Portal image is ${portal_image_size} bytes; limit is ${PORTAL_IMAGE_MAX_BYTES}"

  if docker run --rm --network none --entrypoint /bin/sh \
    -e 'DATABASE_URL=postgresql://offline:offline@127.0.0.1:5432/offline?schema=public' \
    "$IMAGE_TAG" -c 'cd /app && ./node_modules/.bin/prisma db push --skip-generate' \
    >"$TMP/prisma-runtime.log" 2>&1; then
    fail 'runtime Prisma probe unexpectedly connected to a database'
  fi
  ! grep -Fq 'binaries.prisma.sh' "$TMP/prisma-runtime.log" ||
    fail 'runtime Prisma probe attempted a Prisma download'
  grep -Eq 'P1001|Can.t reach database server' "$TMP/prisma-runtime.log" || {
    tail -n 100 "$TMP/prisma-runtime.log" >&2
    fail 'runtime Prisma probe did not reach the expected offline database boundary'
  }
fi

printf '[release-prisma-engines] PASS\n'
