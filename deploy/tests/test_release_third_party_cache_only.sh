#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BUILDER="$ROOT/deploy/docker-compose/build-offline-images-for-arch.sh"
PROVENANCE_LIB="$ROOT/deploy/docker-compose/lib-image-provenance.sh"

fail() {
  echo "[fail] $*" >&2
  exit 1
}

[[ -f "$BUILDER" ]] || fail "builder is missing: $BUILDER"
[[ -f "$PROVENANCE_LIB" ]] || fail "provenance helper is missing: $PROVENANCE_LIB"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

function_file="$tmp/pull-third-party.sh"
awk '
  /^pull_third_party_image\(\) \{/ { inside = 1 }
  inside { print }
  inside && /^}$/ { exit }
' "$BUILDER" >"$function_file"
[[ -s "$function_file" ]] || fail 'third-party image function is missing'

first_party_function_file="$tmp/build-first-party.sh"
awk '
  /^build_first_party_image\(\) \{/ { inside = 1 }
  inside { print }
  inside && /^}$/ { exit }
' "$BUILDER" >"$first_party_function_file"
[[ -s "$first_party_function_file" ]] || fail 'first-party image function is missing'

mkdir -p "$tmp/bin"
cat >"$tmp/bin/docker" <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail

printf '%s\n' "$*" >>"$FAKE_DOCKER_LOG"
case "${1:-}:${2:-}" in
  image:inspect)
    if [[ " $* " == *' {{json .RepoDigests}} '* ]]; then
      printf '%s\n' "$FAKE_REPO_DIGESTS"
    else
      printf '%s\n' '[{}]'
    fi
    ;;
  pull:*|tag:*|buildx:build)
    ;;
  *)
    echo "unexpected docker invocation: $*" >&2
    exit 99
    ;;
esac
EOF
chmod 700 "$tmp/bin/docker"

# shellcheck disable=SC1090
source "$PROVENANCE_LIB"

image='registry.example/dependency:1'
expected_digest="sha256:$(printf 'b%.0s' {1..64})"
correct_repo_digests="[\"registry.example/dependency@${expected_digest}\"]"
wrong_repo_digests="[\"registry.example/dependency@sha256:$(printf 'a%.0s' {1..64})\"]"

run_cache_only() {
  local repo_digests="$1"
  local log_file="$2"
  (
    PATH="$tmp/bin:$PATH"
    export PATH
    FAKE_DOCKER_LOG="$log_file"
    FAKE_REPO_DIGESTS="$repo_digests"
    export FAKE_DOCKER_LOG FAKE_REPO_DIGESTS
    PLATFORM='linux/amd64'
    TARGET_ARCH='amd64'
    THIRD_PARTY_INPUT_MODE='cache-only'
    BUILD_TOOLCHAIN='{}'
    RECORD_DIR="$tmp/records"
    mkdir -p "$RECORD_DIR"
    log() { :; }
    die() { exit 1; }
    assert_build_identity_unchanged() { :; }
    image_id_for() { printf 'sha256:%064d\n' 0; }
    write_third_party_image_provenance_record() { :; }
    inspect_architecture() { :; }
    # shellcheck disable=SC1090
    source "$function_file"
    pull_third_party_image "$image" common dependency "$expected_digest"
  )
}

run_cache_only_first_party() {
  local log_file="$1"
  (
    PATH="$tmp/bin:$PATH"
    export PATH
    FAKE_DOCKER_LOG="$log_file"
    export FAKE_DOCKER_LOG
    SOURCE_ROOT="$tmp/source"
    GO_BUILD_CACHE_INPUT="$tmp/go-cache"
    ALPINE_RUNTIME_INPUT="$tmp/alpine-runtime"
    PLATFORM='linux/amd64'
    BUILD_NETWORK_MODE=none
    BUILD_TOOLCHAIN='{}'
    SOURCE_LABELS=()
    mkdir -p "$SOURCE_ROOT/context" "$GO_BUILD_CACHE_INPUT/pkg/mod" "$ALPINE_RUNTIME_INPUT"
    printf 'FROM scratch\n' >"$SOURCE_ROOT/Dockerfile"
    log() { :; }
    die() { exit 1; }
    assert_build_identity_unchanged() { :; }
    record_source_image() { :; }
    # shellcheck disable=SC1090
    source "$first_party_function_file"
    build_first_party_image fixture:test common fixture Dockerfile context
  )
}

correct_log="$tmp/correct.log"
: >"$correct_log"
run_cache_only "$correct_repo_digests" "$correct_log" ||
  fail 'cache-only mode rejected the locally cached matching image'
if grep -Eq '^pull ' "$correct_log"; then
  fail 'cache-only mode issued docker pull'
fi

wrong_log="$tmp/wrong.log"
: >"$wrong_log"
if run_cache_only "$wrong_repo_digests" "$wrong_log"; then
  fail 'cache-only mode accepted a locally cached image with the wrong digest'
fi
if grep -Eq '^pull ' "$wrong_log"; then
  fail 'cache-only digest rejection issued docker pull'
fi

first_party_log="$tmp/first-party.log"
: >"$first_party_log"
run_cache_only_first_party "$first_party_log" ||
  fail 'cache-only first-party image build failed in the fixture'
if ! grep -Eq '^buildx build .*--network(=| )none( |$)' "$first_party_log"; then
  fail 'cache-only first-party image build did not disable build networking'
fi

echo '[ok] cache-only third-party release inputs reject network and digest drift'
