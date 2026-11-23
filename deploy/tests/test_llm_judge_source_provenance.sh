#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PREPARE="$ROOT_DIR/deploy/docker-compose/prepare-upstream-sources.sh"
BUILDER="$ROOT_DIR/deploy/docker-compose/build-offline-images-for-arch.sh"
IMAGES_LST="$ROOT_DIR/deploy/docker-compose/images.lst"
DOCKERFILE="$ROOT_DIR/deploy/docker-compose/llm-judge/Dockerfile"
FIXTURE_ROOT="$(mktemp -d)"
trap 'rm -rf "$FIXTURE_ROOT"' EXIT

fail() {
  echo "[fail] $*" >&2
  exit 1
}

expect_failure() {
  local label="$1"
  shift
  if "$@" >"$FIXTURE_ROOT/$label.stdout" 2>"$FIXTURE_ROOT/$label.stderr"; then
    fail "$label was accepted"
  fi
}

run_prepare() {
  local mode="$1" remote="$2" revision="$3" cache="$4"
  JJDGUARD_UPSTREAM_SOURCE_TESTING=1 \
    "$PREPARE" "$mode" \
      --remote "$remote" \
      --revision "$revision" \
      --cache "$cache"
}

mutate_receipt() {
  local receipt="$1" key="$2" value="$3"
  python3 - "$receipt" "$key" "$value" <<'PY'
import json
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
data = json.loads(path.read_text(encoding="utf-8"))
key, value = sys.argv[2:]
data[key] = int(value) if key == "commit_count" else value
path.chmod(0o600)
path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
path.chmod(0o444)
PY
}

[[ -x "$PREPARE" ]] || fail "upstream source preparer is missing or not executable: $PREPARE"
awk '
  $4 == "llm-judge" {
    count++
    valid = ($3 == "upstream-source" &&
      $6 == "deploy/docker-compose/llm-judge/Dockerfile.offline" &&
      $7 == "deploy/docker-compose/llm-judge")
  }
  END { exit !(count == 1 && valid) }
' "$IMAGES_LST" ||
  fail 'llm-judge catalog entry does not pin the upstream-source Dockerfile/context'

if grep -Eq 'LLAMA_CPP_SRC|rsync[[:space:]]+-a|cat[[:space:]]+>.*Dockerfile' "$BUILDER"; then
  fail 'llm-judge builder still consumes unversioned host source or a dynamic Dockerfile'
fi
grep -Fq '"$SCRIPT_DIR/prepare-upstream-sources.sh" verify' "$BUILDER" ||
  fail 'builder does not verify the offline upstream cache'
LLM_FUNCTION="$FIXTURE_ROOT/build-llm-judge.txt"
awk '
  /^build_llm_judge\(\) \{/ { inside = 1 }
  inside { print }
  inside && /^}$/ { exit }
' "$BUILDER" >"$LLM_FUNCTION"
[[ -s "$LLM_FUNCTION" ]] || fail 'build_llm_judge function is missing'
grep -Fq 'cache="/home/dev/tool-cache/llama.cpp-$revision"' "$LLM_FUNCTION" ||
  fail 'llm-judge builder does not use the revision-scoped upstream cache'
grep -Fq -- '-t "$image" -f "$SOURCE_ROOT/$context/Dockerfile.offline" "$SOURCE_ROOT/$context"' "$LLM_FUNCTION" ||
  fail 'llm-judge build does not bind the fixed offline wrapper Dockerfile to its source context'
awk '
  index($0, "version_output=\"$(docker run") &&
    index($0, "--pull=never") &&
    index($0, "--network=none") &&
    index($0, "--rm --entrypoint /opt/llama/llama-server") {
    if (getline > 0 && index($0, "\"$image\" --version 2>&1)")) {
      found = 1
    }
  }
  END { exit !found }
' "$LLM_FUNCTION" ||
  fail 'builder does not probe the just-built llama-server image with --version'

for option in \
  '-DGGML_NATIVE=OFF' \
  '-DCMAKE_BUILD_TYPE=Release' \
  '-DGGML_BACKEND_DL=ON' \
  '-DGGML_CPU_ALL_VARIANTS=ON' \
  '-DGGML_CPU_ALL_VARIANTS=OFF' \
  '-DGGML_CPU_KLEIDIAI=OFF' \
  '-DGGML_CPU_ARM_ARCH=armv8-a' \
  '-DLLAMA_CURL=OFF' \
  '-DLLAMA_BUILD_TESTS=OFF' \
  '-DLLAMA_BUILD_UI=OFF'; do
  grep -Fq -- "$option" "$DOCKERFILE" || fail "llm-judge Dockerfile is missing: $option"
done
grep -Fq '[ "$TARGETARCH" = amd64 ]' "$DOCKERFILE" ||
  fail 'llm-judge Dockerfile does not select x86 flags by target architecture'
grep -Fq '[ "$TARGETARCH" = arm64 ]' "$DOCKERFILE" ||
  fail 'llm-judge Dockerfile does not select ARM flags by target architecture'
grep -Fq -- '-DLLAMA_BUILD_COMMIT=' "$DOCKERFILE" ||
  fail 'Dockerfile does not bind LLAMA_BUILD_COMMIT'
grep -Fq -- '-DLLAMA_BUILD_NUMBER=' "$DOCKERFILE" ||
  fail 'Dockerfile does not bind LLAMA_BUILD_NUMBER'

REMOTE="$FIXTURE_ROOT/origin.git"
SEED="$FIXTURE_ROOT/seed"
git init -q --bare "$REMOTE"
git init -q "$SEED"
git -C "$SEED" config user.name 'Upstream Fixture'
git -C "$SEED" config user.email upstream-fixture@example.invalid
mkdir -p "$SEED/src" "$SEED/include"
printf '%s\n' 'cmake_minimum_required(VERSION 3.16)' >"$SEED/CMakeLists.txt"
printf '%s\n' 'int main(void) { return 0; }' >"$SEED/src/server.cpp"
printf '%s\n' '#define FIXTURE 1' >"$SEED/include/fixture.h"
git -C "$SEED" add .
git -C "$SEED" commit -q -m initial
printf '%s\n' 'fixture-readme' >"$SEED/README.md"
git -C "$SEED" add README.md
git -C "$SEED" commit -q -m second
git -C "$SEED" branch -M main
git -C "$SEED" remote add origin "$REMOTE"
git -C "$SEED" push -q -u origin main
git -C "$REMOTE" symbolic-ref HEAD refs/heads/main
REVISION="$(git -C "$SEED" rev-parse HEAD)"

CACHE_ONE="$FIXTURE_ROOT/cache-one"
CACHE_TWO="$FIXTURE_ROOT/cache-two"
run_prepare prepare "$REMOTE" "$REVISION" "$CACHE_ONE"
run_prepare verify "$REMOTE" "$REVISION" "$CACHE_ONE"
run_prepare prepare "$REMOTE" "$REVISION" "$CACHE_TWO"
run_prepare verify "$REMOTE" "$REVISION" "$CACHE_TWO"

hash_one="$(sha256sum "$CACHE_ONE/llama.cpp.tar" | awk '{print $1}')"
hash_two="$(sha256sum "$CACHE_TWO/llama.cpp.tar" | awk '{print $1}')"
[[ "$hash_one" == "$hash_two" ]] || fail 'two preparations produced different source archives'
tar -tf "$CACHE_ONE/llama.cpp.tar" | grep -Fqx 'llama.cpp/src/server.cpp' ||
  fail 'source archive is missing tracked source'
if tar -tf "$CACHE_ONE/llama.cpp.tar" | grep -Eq '(^|/)\.git(/|$)'; then
  fail 'source archive contains Git metadata'
fi

archive_bad="$FIXTURE_ROOT/archive-bad"
cp -a "$CACHE_ONE" "$archive_bad"
chmod 0600 "$archive_bad/llama.cpp.tar"
printf '%s\n' tampered >>"$archive_bad/llama.cpp.tar"
expect_failure archive-hash run_prepare verify "$REMOTE" "$REVISION" "$archive_bad"

revision_bad="$FIXTURE_ROOT/revision-bad"
cp -a "$CACHE_ONE" "$revision_bad"
mutate_receipt "$revision_bad/receipt.json" revision 1111111111111111111111111111111111111111
expect_failure revision-mismatch run_prepare verify "$REMOTE" "$REVISION" "$revision_bad"

tree_bad="$FIXTURE_ROOT/tree-bad"
cp -a "$CACHE_ONE" "$tree_bad"
mutate_receipt "$tree_bad/receipt.json" tree 2222222222222222222222222222222222222222
expect_failure tree-mismatch run_prepare verify "$REMOTE" "$REVISION" "$tree_bad"

count_bad="$FIXTURE_ROOT/count-bad"
cp -a "$CACHE_ONE" "$count_bad"
mutate_receipt "$count_bad/receipt.json" commit_count 999999
expect_failure commit-count-mismatch run_prepare verify "$REMOTE" "$REVISION" "$count_bad"

ln -s "$CACHE_ONE" "$FIXTURE_ROOT/cache-link"
expect_failure cache-symlink run_prepare verify "$REMOTE" "$REVISION" "$FIXTURE_ROOT/cache-link"

RECORD_FUNCTION="$FIXTURE_ROOT/record-source-image.sh"
awk '
  /^record_source_image\(\) \{/ { inside = 1 }
  inside { print }
  inside && /^}$/ { exit }
' "$BUILDER" >"$RECORD_FUNCTION"
[[ -s "$RECORD_FUNCTION" ]] || fail 'record_source_image function is missing'

(
  PROJECT_ROOT="$ROOT_DIR"
  SOURCE_ROOT="$ROOT_DIR"
  SOURCE_REVISION="$(git -C "$ROOT_DIR" rev-parse HEAD)"
  RECORD_DIR="$FIXTURE_ROOT/records"
  PLATFORM=linux/amd64
  TARGET_ARCH=amd64
  SOURCE_ATTESTATION_FILE="$FIXTURE_ROOT/source-attestation.json"
  SOURCE_ARCHIVE_SHA256=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
  BUILDX_BUILD_ENGINE='{"builder":"fixture","kind":"buildx","nodes":[{"buildkit_version":"v1","endpoint":"fixture","name":"fixture","status":"running"}]}'
  image_id_for() { printf '%s\n' 'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'; }
  write_source_image_provenance_record() { :; }
  inspect_architecture() { :; }
  die() { exit 1; }
  # shellcheck disable=SC1090
  source "$RECORD_FUNCTION"
  record_source_image fixture/judge:1 full upstream-source judge \
    deploy/docker-compose/llm-judge/Dockerfile deploy/docker-compose/llm-judge \
    '{}' '{"upstream":{"component":"llama.cpp"},"wrapper_blobs":{"deploy/docker-compose/llm-judge/entrypoint.sh":"fixture"}}'
  record_source_image fixture/gateway:1 common first-party gateway-core \
    apps/gateway-core/Dockerfile apps/gateway-core '{}'
) || fail 'record_source_image corrupts a supplied provenance extension'

echo '[ok] llm-judge source archive is pinned to a verified upstream revision'
