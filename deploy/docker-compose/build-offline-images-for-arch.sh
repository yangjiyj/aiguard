#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
# shellcheck disable=SC1091
source "$SCRIPT_DIR/lib-arch.sh"
# shellcheck disable=SC1091
source "$SCRIPT_DIR/lib-images.sh"
# shellcheck disable=SC1091
source "$SCRIPT_DIR/lib-image-provenance.sh"
# shellcheck disable=SC1091
source "$SCRIPT_DIR/lib-build-identity.sh"

TARGET_ARCH="$(normalize_offline_arch "${1:-}")"
PLATFORM="linux/$TARGET_ARCH"
BUNDLE_PROFILE="${BUNDLE_PROFILE:-full}"
INCLUDE_CHAT="${INCLUDE_CHAT:-1}"
THIRD_PARTY_INPUT_MODE="${OFFLINE_RELEASE_THIRD_PARTY_INPUT_MODE:-cache-only}"
TIER1_OWNED_MODEL_INPUT="${TIER1_OWNED_MODEL_INPUT:-}"
TIER1_PYTHON_DEPS_INPUT="${TIER1_PYTHON_DEPS_INPUT:-}"
SECURITY_ENGINE_PYTHON_DEPS_INPUT="${OFFLINE_RELEASE_SECURITY_ENGINE_PYTHON_DEPS_INPUT:-}"
LLM_JUDGE_RUNTIME_INPUT="${OFFLINE_RELEASE_LLM_JUDGE_RUNTIME_INPUT:-}"
JUDGE_OWNED_MODEL_INPUT="${JUDGE_OWNED_MODEL_INPUT:-}"
NPM_CACHE_INPUT="${OFFLINE_RELEASE_NPM_CACHE_INPUT:-}"
PRISMA_ENGINE_INPUT="${OFFLINE_RELEASE_PRISMA_ENGINE_INPUT:-}"
PORTAL_PROXY_RUNTIME_INPUT="${OFFLINE_RELEASE_PORTAL_PROXY_RUNTIME_INPUT:-}"
GO_BUILD_CACHE_INPUT="${OFFLINE_RELEASE_GO_CACHE_INPUT:-}"
ALPINE_RUNTIME_INPUT="${OFFLINE_RELEASE_ALPINE_RUNTIME_INPUT:-}"
SECURITY_ENGINE_PYTHON_DEPS_RECEIPT=
LLM_JUDGE_RUNTIME_IMAGE_ID=
LLM_JUDGE_RUNTIME_ALIAS=
LLM_JUDGE_RUNTIME_ENTRYPOINT_SHA256=
PORTAL_PROXY_RUNTIME_IMAGE_ID=
PORTAL_PROXY_RUNTIME_ALIAS=
PORTAL_PROXY_RUNTIME_SOURCE_REVISION=
PORTAL_PROXY_RUNTIME_SOURCE_TREE=
PORTAL_PROXY_PNPM_VERSION=
SERVICES="gateway-core control-plane security-engine proxy-server web-console worker"
IMAGES_LST="$SCRIPT_DIR/images.lst"
SOURCE_GATE="$SCRIPT_DIR/release-source-gate.sh"
CANDIDATE_SOURCE_GATE="$SCRIPT_DIR/release-candidate-source-gate.sh"
SOURCE_MODE="$(printenv OFFLINE_RELEASE_SOURCE_MODE 2>/dev/null || printf release)"
SOURCE_GATE_EXPECTED_REMOTE='git@github.com:yangjiyj/aiguard.git'
PRISMA_ENGINE_LOCK='deploy/docker-compose/release-prisma-engines.lock.json'
PRISMA_ENGINE_ARM64_LOCK='deploy/docker-compose/release-prisma-engines.arm64.lock.json'
COMPOSE_ARCH="$(compose_asset_arch "$TARGET_ARCH")"
TOOLCHAIN_ASSET_DIR="$("$SCRIPT_DIR/release-toolchain-cache-dir.sh" "$TARGET_ARCH")"
DOCKER_TGZ="$TOOLCHAIN_ASSET_DIR/docker-static.tgz"
COMPOSE_BIN="$TOOLCHAIN_ASSET_DIR/docker-compose"
TEMP_ROOT=
NPM_CACHE_CONTEXT=
NPM_CACHE_ARCHIVE=
NPM_CACHE_ARCHIVE_SHA256=

export IMAGES_LST INCLUDE_CHAT

log() { printf '[arch-builder] %s\n' "$*"; }
die() { printf '[arch-builder][error] %s\n' "$*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || die "missing command: $1"; }

require_npm_cache_input() {
  [[ "$NPM_CACHE_INPUT" == /* && -d "$NPM_CACHE_INPUT" && ! -L "$NPM_CACHE_INPUT" ]] ||
    die 'OFFLINE_RELEASE_NPM_CACHE_INPUT must be an absolute real directory'
  [[ "$(realpath -e "$NPM_CACHE_INPUT")" == "$NPM_CACHE_INPUT" ]] ||
    die 'OFFLINE_RELEASE_NPM_CACHE_INPUT must be canonical'
  [[ -d "$NPM_CACHE_INPUT/_cacache" && ! -L "$NPM_CACHE_INPUT/_cacache" ]] ||
    die 'OFFLINE_RELEASE_NPM_CACHE_INPUT is missing a real _cacache directory'
}

prepare_release_npm_cache_context() {
  [[ -n "$TEMP_ROOT" && -z "$NPM_CACHE_CONTEXT" && -z "$NPM_CACHE_ARCHIVE" && \
        -z "$NPM_CACHE_ARCHIVE_SHA256" ]] ||
    die 'NPM cache context preparation state is invalid'
  NPM_CACHE_CONTEXT="$TEMP_ROOT/npm-cache-context"
  NPM_CACHE_ARCHIVE="$NPM_CACHE_CONTEXT/npm-cache.tar"
  install -d -m 0700 "$NPM_CACHE_CONTEXT"
  tar -C "$NPM_CACHE_INPUT" --sort=name --mtime='@0' --owner=0 --group=0 \
    --numeric-owner -cf "$NPM_CACHE_ARCHIVE" . ||
    die 'unable to archive the local NPM cache'
  chmod 0400 "$NPM_CACHE_ARCHIVE"
  NPM_CACHE_ARCHIVE_SHA256="$(sha256sum "$NPM_CACHE_ARCHIVE" | awk '{print $1}')" ||
    die 'unable to hash the local NPM cache archive'
  [[ "$NPM_CACHE_ARCHIVE_SHA256" =~ ^[0-9a-f]{64}$ ]] ||
    die 'local NPM cache archive hash is invalid'
}

assert_npm_cache_context_unchanged() {
  local actual
  [[ -n "$NPM_CACHE_CONTEXT" && -n "$NPM_CACHE_ARCHIVE" && \
        -n "$NPM_CACHE_ARCHIVE_SHA256" ]] ||
    die 'local NPM cache context was not prepared'
  [[ -d "$NPM_CACHE_CONTEXT" && ! -L "$NPM_CACHE_CONTEXT" && \
     "$(realpath -e "$NPM_CACHE_CONTEXT")" == "$NPM_CACHE_CONTEXT" && \
     "$(stat -c %a "$NPM_CACHE_CONTEXT")" == 700 ]] ||
    die 'local NPM cache context is unsafe'
  [[ -f "$NPM_CACHE_ARCHIVE" && ! -L "$NPM_CACHE_ARCHIVE" && \
     "$(realpath -e "$NPM_CACHE_ARCHIVE")" == "$NPM_CACHE_ARCHIVE" && \
     "$(stat -c %a "$NPM_CACHE_ARCHIVE")" == 400 ]] ||
    die 'local NPM cache archive is unsafe'
  [[ "$(find -P "$NPM_CACHE_CONTEXT" -mindepth 1 -maxdepth 1 -printf '%f\n' | LC_ALL=C sort)" == npm-cache.tar ]] ||
    die 'local NPM cache context must contain only npm-cache.tar'
  actual="$(sha256sum "$NPM_CACHE_ARCHIVE" | awk '{print $1}')" ||
    die 'unable to hash the local NPM cache archive during the build'
  [[ "$actual" == "$NPM_CACHE_ARCHIVE_SHA256" ]] ||
    die 'local NPM cache archive changed during the build'
}

prisma_engine_lock_for_arch() {
  if [[ "$TARGET_ARCH" == arm64 ]]; then
    printf '%s\n' "$PRISMA_ENGINE_ARM64_LOCK"
  else
    printf '%s\n' "$PRISMA_ENGINE_LOCK"
  fi
}

require_prisma_engine_input() {
  [[ "$PRISMA_ENGINE_INPUT" == /* && -d "$PRISMA_ENGINE_INPUT" && ! -L "$PRISMA_ENGINE_INPUT" ]] ||
    die 'OFFLINE_RELEASE_PRISMA_ENGINE_INPUT must be an absolute real directory'
  [[ "$(realpath -e "$PRISMA_ENGINE_INPUT")" == "$PRISMA_ENGINE_INPUT" ]] ||
    die 'OFFLINE_RELEASE_PRISMA_ENGINE_INPUT must be canonical'
}

require_portal_proxy_runtime_input() {
  local actual_architecture runtime_source canonical_source_tree legacy_source_tree
  local query_engine_name schema_engine_name
  [[ "$PORTAL_PROXY_RUNTIME_INPUT" == 'chat-portal/portal-proxy:0.1.0' ]] ||
    die 'OFFLINE_RELEASE_PORTAL_PROXY_RUNTIME_INPUT must select chat-portal/portal-proxy:0.1.0'
  PORTAL_PROXY_RUNTIME_IMAGE_ID="$(docker image inspect --platform "$PLATFORM" "$PORTAL_PROXY_RUNTIME_INPUT" --format '{{.Id}}')" ||
    die 'local Portal Proxy runtime image is unavailable'
  [[ "$PORTAL_PROXY_RUNTIME_IMAGE_ID" =~ ^sha256:[0-9a-f]{64}$ ]] ||
    die 'local Portal Proxy runtime image ID is invalid'
  actual_architecture="$(docker image inspect --platform "$PLATFORM" "$PORTAL_PROXY_RUNTIME_INPUT" --format '{{.Architecture}}')" ||
    die 'unable to inspect local Portal Proxy runtime architecture'
  actual_architecture="$(normalize_offline_arch "$actual_architecture" 2>/dev/null || true)"
  [[ "$actual_architecture" == "$TARGET_ARCH" ]] ||
    die "local Portal Proxy runtime architecture mismatch: expected=$TARGET_ARCH actual=${actual_architecture:-missing}"
  runtime_source="$(docker image inspect "$PORTAL_PROXY_RUNTIME_INPUT" \
    --format '{{ index .Config.Labels "org.opencontainers.image.source" }}')"
  PORTAL_PROXY_RUNTIME_SOURCE_REVISION="$(docker image inspect "$PORTAL_PROXY_RUNTIME_INPUT" \
    --format '{{ index .Config.Labels "org.opencontainers.image.revision" }}')"
  canonical_source_tree="$(docker image inspect "$PORTAL_PROXY_RUNTIME_INPUT" \
    --format '{{with index .Config.Labels "com.jjdguard.source.tree"}}{{.}}{{end}}')"
  legacy_source_tree="$(docker image inspect "$PORTAL_PROXY_RUNTIME_INPUT" \
    --format '{{with index .Config.Labels "io.jjdguard.source-tree"}}{{.}}{{end}}')"
  if [[ -n "$canonical_source_tree" && -n "$legacy_source_tree" && \
        "$canonical_source_tree" != "$legacy_source_tree" ]]; then
    die 'Portal Proxy source tree labels disagree'
  fi
  PORTAL_PROXY_RUNTIME_SOURCE_TREE="${canonical_source_tree:-$legacy_source_tree}"
  [[ "$runtime_source" == "$SOURCE_GATE_EXPECTED_REMOTE" ]] ||
    die 'local Portal Proxy runtime source label is not the approved Gitee repository'
  [[ "$PORTAL_PROXY_RUNTIME_SOURCE_REVISION" =~ ^[0-9a-f]{40}$ &&
     "$PORTAL_PROXY_RUNTIME_SOURCE_TREE" =~ ^[0-9a-f]{40}$ ]] ||
    die 'local Portal Proxy runtime source labels are invalid'
  [[ "$(git -C "$PROJECT_ROOT" rev-parse "$PORTAL_PROXY_RUNTIME_SOURCE_REVISION^{tree}")" == \
     "$PORTAL_PROXY_RUNTIME_SOURCE_TREE" ]] ||
    die 'local Portal Proxy runtime source labels do not describe a known Gitee revision'
  if [[ "$TARGET_ARCH" == arm64 ]]; then
    query_engine_name=libquery_engine-linux-musl-arm64-openssl-3.0.x.so.node
    schema_engine_name=schema-engine-linux-musl-arm64-openssl-3.0.x
  else
    query_engine_name=libquery_engine-linux-musl-openssl-3.0.x.so.node
    schema_engine_name=schema-engine-linux-musl-openssl-3.0.x
  fi
  PORTAL_PROXY_PNPM_VERSION="$(docker run --platform "$PLATFORM" --pull=never --network=none --rm \
    --entrypoint pnpm "$PORTAL_PROXY_RUNTIME_INPUT" --version)" ||
    die 'local Portal Proxy runtime does not provide pnpm'
  [[ "$PORTAL_PROXY_PNPM_VERSION" == 10.10.0 ]] ||
    die "local Portal Proxy runtime pnpm version is unsupported: $PORTAL_PROXY_PNPM_VERSION"
}

require_portal_proxy_runtime_application_source() {
  "$SOURCE_ROOT/deploy/docker-compose/verify-portal-proxy-runtime-source.sh" \
    --repo "$PROJECT_ROOT" \
    --runtime-revision "$PORTAL_PROXY_RUNTIME_SOURCE_REVISION" \
    --release-revision "$SOURCE_REVISION" ||
    die 'Portal Proxy runtime application source differs from release source'
}

require_tier1_python_deps_input() {
  [[ "$TIER1_PYTHON_DEPS_INPUT" == /* && -d "$TIER1_PYTHON_DEPS_INPUT" && ! -L "$TIER1_PYTHON_DEPS_INPUT" ]] ||
    die 'TIER1_PYTHON_DEPS_INPUT must be an absolute real directory'
  [[ "$(realpath -e "$TIER1_PYTHON_DEPS_INPUT")" == "$TIER1_PYTHON_DEPS_INPUT" ]] ||
    die 'TIER1_PYTHON_DEPS_INPUT must be canonical'
  [[ "$(stat -c %a "$TIER1_PYTHON_DEPS_INPUT")" == 700 ]] ||
    die 'TIER1_PYTHON_DEPS_INPUT must be mode 0700'
}

require_security_engine_python_deps_input() {
  [[ "$SECURITY_ENGINE_PYTHON_DEPS_INPUT" == /* && -d "$SECURITY_ENGINE_PYTHON_DEPS_INPUT" && ! -L "$SECURITY_ENGINE_PYTHON_DEPS_INPUT" ]] ||
    die 'OFFLINE_RELEASE_SECURITY_ENGINE_PYTHON_DEPS_INPUT must be an absolute real directory'
  [[ "$(realpath -e "$SECURITY_ENGINE_PYTHON_DEPS_INPUT")" == "$SECURITY_ENGINE_PYTHON_DEPS_INPUT" ]] ||
    die 'OFFLINE_RELEASE_SECURITY_ENGINE_PYTHON_DEPS_INPUT must be canonical'
  [[ "$(stat -c %a "$SECURITY_ENGINE_PYTHON_DEPS_INPUT")" == 700 ]] ||
    die 'OFFLINE_RELEASE_SECURITY_ENGINE_PYTHON_DEPS_INPUT must be mode 0700'
}

require_llm_judge_runtime_input() {
  local actual_architecture
  [[ -n "$LLM_JUDGE_RUNTIME_INPUT" ]] ||
    die 'OFFLINE_RELEASE_LLM_JUDGE_RUNTIME_INPUT is required for llm-judge'
  LLM_JUDGE_RUNTIME_IMAGE_ID="$(docker image inspect --platform "$PLATFORM" "$LLM_JUDGE_RUNTIME_INPUT" --format '{{.Id}}')" ||
    die 'local Judge runtime image is unavailable'
  [[ "$LLM_JUDGE_RUNTIME_IMAGE_ID" =~ ^sha256:[0-9a-f]{64}$ ]] ||
    die 'local Judge runtime image ID is invalid'
  actual_architecture="$(docker image inspect --platform "$PLATFORM" "$LLM_JUDGE_RUNTIME_INPUT" --format '{{.Architecture}}')" ||
    die 'unable to inspect local Judge runtime architecture'
  actual_architecture="$(normalize_offline_arch "$actual_architecture" 2>/dev/null || true)"
  [[ "$actual_architecture" == "$TARGET_ARCH" ]] ||
    die "local Judge runtime architecture mismatch: expected=$TARGET_ARCH actual=${actual_architecture:-missing}"
}

require_go_build_cache_input() {
  [[ "$GO_BUILD_CACHE_INPUT" == /* && -d "$GO_BUILD_CACHE_INPUT" && ! -L "$GO_BUILD_CACHE_INPUT" ]] ||
    die 'OFFLINE_RELEASE_GO_CACHE_INPUT must be an absolute real directory'
  [[ "$(realpath -e "$GO_BUILD_CACHE_INPUT")" == "$GO_BUILD_CACHE_INPUT" ]] ||
    die 'OFFLINE_RELEASE_GO_CACHE_INPUT must be canonical'
  [[ -d "$GO_BUILD_CACHE_INPUT/pkg/mod" && ! -L "$GO_BUILD_CACHE_INPUT/pkg/mod" ]] ||
    die 'OFFLINE_RELEASE_GO_CACHE_INPUT is missing a real pkg/mod directory'
}

require_alpine_runtime_input() {
  [[ "$ALPINE_RUNTIME_INPUT" == /* && -d "$ALPINE_RUNTIME_INPUT" && ! -L "$ALPINE_RUNTIME_INPUT" ]] ||
    die 'OFFLINE_RELEASE_ALPINE_RUNTIME_INPUT must be an absolute real directory'
  [[ "$(realpath -e "$ALPINE_RUNTIME_INPUT")" == "$ALPINE_RUNTIME_INPUT" ]] ||
    die 'OFFLINE_RELEASE_ALPINE_RUNTIME_INPUT must be canonical'
  [[ "$(stat -c %a "$ALPINE_RUNTIME_INPUT")" == 700 ]] ||
    die 'OFFLINE_RELEASE_ALPINE_RUNTIME_INPUT must be mode 0700'
  [[ -f "$ALPINE_RUNTIME_INPUT/source.json" && ! -L "$ALPINE_RUNTIME_INPUT/source.json" ]] ||
    die 'OFFLINE_RELEASE_ALPINE_RUNTIME_INPUT is missing source metadata'
  [[ -d "$ALPINE_RUNTIME_INPUT/etc/ssl/certs" ]] ||
    die 'OFFLINE_RELEASE_ALPINE_RUNTIME_INPUT is missing CA certificates'
  [[ -f "$ALPINE_RUNTIME_INPUT/etc/ssl/cert.pem" ]] ||
    die 'OFFLINE_RELEASE_ALPINE_RUNTIME_INPUT is missing the CA bundle'
  [[ -f "$ALPINE_RUNTIME_INPUT/etc/ca-certificates.conf" ]] ||
    die 'OFFLINE_RELEASE_ALPINE_RUNTIME_INPUT is missing CA configuration'
  [[ -d "$ALPINE_RUNTIME_INPUT/usr/share/zoneinfo" ]] ||
    die 'OFFLINE_RELEASE_ALPINE_RUNTIME_INPUT is missing timezone data'
}

cleanup() {
  if [[ -n "$TEMP_ROOT" ]]; then
    rm -rf -- "$TEMP_ROOT"
  fi
}
trap cleanup EXIT HUP INT TERM

case "$BUNDLE_PROFILE" in lite|full) ;; *) die "unsupported BUNDLE_PROFILE: $BUNDLE_PROFILE" ;; esac
case "$INCLUDE_CHAT" in 0|1) ;; *) die "INCLUDE_CHAT must be 0 or 1" ;; esac
case "$THIRD_PARTY_INPUT_MODE" in
  cache-only | prepare) ;;
  *) die 'OFFLINE_RELEASE_THIRD_PARTY_INPUT_MODE must be cache-only or prepare' ;;
esac
BUILD_NETWORK_MODE=default
TASK4_BUILD_NETWORK_MODE=none
if [[ "$THIRD_PARTY_INPUT_MODE" == cache-only ]]; then
  BUILD_NETWORK_MODE=none
fi

print_plan() {
  local image profile kind component digest dockerfile context rows
  rows="$(read_image_catalog_for_profile "$BUNDLE_PROFILE")" ||
    die 'unable to read the release image catalog'
  log "platform=$PLATFORM"
  log "build services: $SERVICES"
  while read -r image profile kind component digest dockerfile context; do
    case "$kind" in
      third-party)
        case "$THIRD_PARTY_INPUT_MODE" in
          cache-only) log "reuse cached fixed third-party image $image@$digest for $PLATFORM" ;;
          prepare) log "pull --platform $PLATFORM $image@$digest" ;;
        esac
        ;;
      *) log "build --platform $PLATFORM $image source=$kind component=$component dockerfile=$dockerfile context=$context" ;;
    esac
    log "inspect-architecture $TARGET_ARCH $image"
  done <<<"$rows"
  log "runtime $DOCKER_TGZ"
  log "compose docker-compose-linux-$COMPOSE_ARCH"
  log "locked-compose $COMPOSE_BIN"
}

if [[ "${OFFLINE_ARCH_BUILDER_DRY_RUN:-0}" == 1 ]]; then
  print_plan
  exit 0
fi

[[ "$TARGET_ARCH" == amd64 || "$TARGET_ARCH" == arm64 ]] || die 'formal image builds support linux/amd64 and linux/arm64 only'
need docker
need file
need git
need python3
need sha256sum
need tar
docker buildx version >/dev/null 2>&1 || die 'Docker Buildx is required'
require_npm_cache_input
require_go_build_cache_input
require_alpine_runtime_input
require_security_engine_python_deps_input
if [[ "$THIRD_PARTY_INPUT_MODE" == prepare ]]; then
  OFFLINE_TARGET_ARCH="$TARGET_ARCH" "$SCRIPT_DIR/prepare-release-toolchain.sh" prepare
else
  OFFLINE_TARGET_ARCH="$TARGET_ARCH" "$SCRIPT_DIR/prepare-release-toolchain.sh" verify
fi
"$SCRIPT_DIR/verify-release-toolchain.sh" "$TARGET_ARCH"
[[ -n "$JUDGE_OWNED_MODEL_INPUT" ]] ||
  die 'JUDGE_OWNED_MODEL_INPUT is required to build a formal release'
python3 "$SCRIPT_DIR/verify-owned-judge-model.py" \
  --lock "$SCRIPT_DIR/owned-judge-model.lock.json" \
  --input "$JUDGE_OWNED_MODEL_INPUT" ||
  die 'owned Judge model input does not match the reviewed model lock'
if [[ "$BUNDLE_PROFILE" == full ]]; then
  "$SCRIPT_DIR/prepare-upstream-sources.sh" verify
  LLAMA_CPP_REVISION="$(sed -n 's/^llama_cpp_revision=//p' "$SCRIPT_DIR/release-toolchain.lock")"
  LLAMA_UPSTREAM_RECEIPT="/home/dev/tool-cache/llama.cpp-$LLAMA_CPP_REVISION/receipt.json"
fi

RELEASE_EVIDENCE="${RELEASE_EVIDENCE:-}"
[[ "$RELEASE_EVIDENCE" == /* ]] || die 'RELEASE_EVIDENCE must be an explicit absolute directory'
install -d -m 0700 "$RELEASE_EVIDENCE"
[[ -d "$RELEASE_EVIDENCE" && ! -L "$RELEASE_EVIDENCE" ]] || die 'RELEASE_EVIDENCE is not a real directory'
SOURCE_ATTESTATION_FILE="$RELEASE_EVIDENCE/release-source.json"
IMAGE_PROVENANCE_FILE="$RELEASE_EVIDENCE/image-provenance.json"
[[ ! -L "$SOURCE_ATTESTATION_FILE" && ! -L "$IMAGE_PROVENANCE_FILE" ]] ||
  die 'release evidence output must not be a symbolic link'

case "$SOURCE_MODE" in
  release)
    sh "$SOURCE_GATE" "$PROJECT_ROOT" "$SOURCE_ATTESTATION_FILE" "$SOURCE_GATE_EXPECTED_REMOTE"
    ;;
  candidate)
    sh "$CANDIDATE_SOURCE_GATE" "$PROJECT_ROOT" "$SOURCE_ATTESTATION_FILE" "$SOURCE_GATE_EXPECTED_REMOTE"
    ;;
  *) die 'OFFLINE_RELEASE_SOURCE_MODE must be release or candidate' ;;
esac
source_identity="$(read_release_source_identity "$SOURCE_ATTESTATION_FILE")" ||
  die 'unable to read release source identity'
SOURCE_REMOTE="$(printf '%s\n' "$source_identity" | sed -n '1p')"
SOURCE_REVISION="$(printf '%s\n' "$source_identity" | sed -n '2p')"
SOURCE_TREE="$(printf '%s\n' "$source_identity" | sed -n '3p')"

TEMP_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/jjdguard-release-images.XXXXXX")"
chmod 0700 "$TEMP_ROOT"
prepare_release_npm_cache_context
SOURCE_ARCHIVE_SHA256="$(prepare_release_git_context \
  "$PROJECT_ROOT" "$SOURCE_ATTESTATION_FILE" "$TEMP_ROOT/git-context")" ||
  die 'unable to prepare the release Git archive context'
SOURCE_ROOT="$TEMP_ROOT/git-context/source"
SECURITY_ENGINE_PYTHON_DEPS_RECEIPT="$(python3 "$SOURCE_ROOT/deploy/docker-compose/verify-security-engine-python-deps.py" \
  --requirements-lock "$SOURCE_ROOT/apps/security-engine/requirements.offline.lock" \
  --target-arch "$TARGET_ARCH" \
  --input "$SECURITY_ENGINE_PYTHON_DEPS_INPUT")" ||
  die 'local security-engine dependency input does not match the reviewed offline lock'
printf '%s\n' "$SECURITY_ENGINE_PYTHON_DEPS_RECEIPT" >"$RELEASE_EVIDENCE/security-engine-python-deps.json"
chmod 0444 "$RELEASE_EVIDENCE/security-engine-python-deps.json"
python3 "$SOURCE_ROOT/deploy/docker-compose/verify-portal-proxy-source.py" \
  --source-root "$SOURCE_ROOT" \
  --source-remote "$SOURCE_REMOTE" ||
  die 'Portal Proxy authority is absent or does not match the release source archive'
RECORD_DIR="$TEMP_ROOT/records"
install -d -m 0700 "$RECORD_DIR"
catalog_rows="$(read_image_catalog_for_profile "$BUNDLE_PROFILE")"

SOURCE_LABELS=(
  --label "org.opencontainers.image.revision=$SOURCE_REVISION"
  --label "org.opencontainers.image.source=$SOURCE_REMOTE"
  --label "com.jjdguard.source.tree=$SOURCE_TREE"
)

# Capture identity before Task4 or any regular Buildx construction begins.
BUILD_TOOLCHAIN="$(build_identity_json docker)" || die 'unable to capture build identity before construction'
BUILDX_BUILD_ENGINE="$(buildx_engine_json "$BUILD_TOOLCHAIN")" ||
  die 'unable to derive Buildx build engine identity'

prepare_compose() {
  [[ -x "$COMPOSE_BIN" ]] || die "locked Compose binary is unavailable: $COMPOSE_BIN"
  local compose_desc
  compose_desc="$(file -Lb "$COMPOSE_BIN")"
  case "$TARGET_ARCH:$compose_desc" in
    amd64:*x86-64*|amd64:*x86_64*|arm64:*ARM\ aarch64*|arm64:*AArch64*) ;;
    *) die "Compose binary architecture mismatch for $TARGET_ARCH: $compose_desc" ;;
  esac
  log "reuse verified locked Compose binary: $COMPOSE_BIN"
}

prepare_docker() {
  local verify_dir
  [[ -f "$DOCKER_TGZ" && ! -L "$DOCKER_TGZ" ]] ||
    die "locked Docker archive is unavailable: $DOCKER_TGZ"
  verify_dir="$TEMP_ROOT/docker-static"
  install -d -m 0700 "$verify_dir"
  tar -xzf "$DOCKER_TGZ" -C "$verify_dir" docker/docker
  local docker_desc
  docker_desc="$(file -Lb "$verify_dir/docker/docker")"
  case "$TARGET_ARCH:$docker_desc" in
    amd64:*x86-64*|amd64:*x86_64*|arm64:*ARM\ aarch64*|arm64:*AArch64*) ;;
    *) die "Docker static archive architecture mismatch for $TARGET_ARCH: $docker_desc" ;;
  esac
  log "reuse verified locked Docker archive: $DOCKER_TGZ"
}

catalog_field() {
  local component="$1" field="$2"
  awk -v component="$component" -v field="$field" \
    '!/^[[:space:]]*#/ && NF && $4 == component { print $field }' "$IMAGES_LST"
}

component_selected() {
  local component="$1"
  awk -v component="$component" '$4 == component { found=1 } END { exit !found }' <<<"$catalog_rows"
}

if component_selected enterprise-ai-portal; then
  require_prisma_engine_input
  python3 "$SOURCE_ROOT/deploy/docker-compose/verify-release-prisma-engines.py" \
    --lock "$SOURCE_ROOT/$(prisma_engine_lock_for_arch)" \
    --target-arch "$TARGET_ARCH" \
    --input "$PRISMA_ENGINE_INPUT" >/dev/null ||
    die 'local Prisma engine input does not match the reviewed release lock'
fi
if component_selected portal-proxy; then
  require_portal_proxy_runtime_input
  require_portal_proxy_runtime_application_source
fi

inspect_architecture() {
  local expected="$1" image="$2" actual
  actual="$(docker image inspect --platform "linux/$expected" "$image" --format '{{.Architecture}}' 2>/dev/null || true)"
  actual="$(normalize_offline_arch "$actual" 2>/dev/null || true)"
  [[ "$actual" == "$expected" ]] ||
    die "image architecture mismatch: $image expected=$expected actual=${actual:-missing}"
  log "inspect-architecture $expected $image"
}

image_id_for() {
  local image="$1" image_id
  image_id="$(docker image inspect --platform "$PLATFORM" "$image" --format '{{.Id}}')" || die "unable to inspect image: $image"
  [[ "$image_id" =~ ^sha256:[0-9a-f]{64}$ ]] || die "invalid image ID for $image"
  printf '%s\n' "$image_id"
}

record_source_image() {
  local image="$1" profile="$2" kind="$3" component="$4" dockerfile="$5" context="$6"
  local build_args_json="$7" extra_json base_images_override image_id dockerfile_blob base_images_json
  extra_json="${8:-}"
  base_images_override="${9:-}"
  [[ -n "$extra_json" ]] || extra_json='{}'
  local record_extra_json
  record_extra_json="$(python3 - "$extra_json" "$BUILDX_BUILD_ENGINE" <<'PY'
import json
import sys

extra = json.loads(sys.argv[1])
engine = json.loads(sys.argv[2])
if not isinstance(extra, dict):
    raise SystemExit("source record extension is not an object")
if "build_engine" in extra:
    if not isinstance(extra["build_engine"], dict):
        raise SystemExit("source record build engine is not an object")
else:
    extra["build_engine"] = engine
print(json.dumps(extra, sort_keys=True, separators=(",", ":")))
PY
  )" || die "unable to bind build engine for $component"
  image_id="$(image_id_for "$image")"
  dockerfile_blob="$(git -C "$PROJECT_ROOT" rev-parse "$SOURCE_REVISION:$dockerfile")" ||
    die "unable to resolve Dockerfile blob: $dockerfile"
  if [[ -n "$base_images_override" ]]; then
    base_images_json="$base_images_override"
  else
    base_images_json="$(python3 \
      "$SOURCE_ROOT/deploy/docker-compose/dockerfile-base-images.py" \
      --dockerfile "$SOURCE_ROOT/$dockerfile")" ||
      die "unable to parse pinned base images: $dockerfile"
  fi
  write_source_image_provenance_record \
    "$RECORD_DIR/$component.json" "$image" "$profile" "$kind" "$component" \
    "$dockerfile" "$context" "$PLATFORM" "$image_id" "$SOURCE_ATTESTATION_FILE" \
    "$SOURCE_ARCHIVE_SHA256" "$dockerfile_blob" "$base_images_json" \
    "$build_args_json" "$record_extra_json"
  inspect_architecture "$TARGET_ARCH" "$image"
}

build_first_party_image() {
  local image="$1" profile="$2" component="$3" dockerfile="$4" context="$5"
  local context_path="$SOURCE_ROOT/$context" build_args_json='{}' record_extra_json='{}'
  local -a build_args=() build_context_args=(
    --build-context "release-go-cache=$GO_BUILD_CACHE_INPUT"
    --build-context "release-alpine-runtime=$ALPINE_RUNTIME_INPUT"
  )
  [[ -f "$SOURCE_ROOT/$dockerfile" ]] || die "Dockerfile is absent from source archive: $dockerfile"
  [[ -d "$context_path" ]] || die "build context is absent from source archive: $context"
  case "$component" in
    security-engine)
      build_args=(--build-arg "SECURITY_ENGINE_BUILD=$SOURCE_REVISION")
      build_args_json="$(jq -cn --arg revision "$SOURCE_REVISION" '{SECURITY_ENGINE_BUILD:$revision}')"
      build_context_args+=(--build-context "release-security-python-deps=$SECURITY_ENGINE_PYTHON_DEPS_INPUT")
      record_extra_json="$(python3 - "$SECURITY_ENGINE_PYTHON_DEPS_RECEIPT" <<'PY'
import json
import sys

print(json.dumps({"security_engine_python_deps": json.loads(sys.argv[1])}, sort_keys=True, separators=(",", ":")))
PY
      )" || die 'unable to bind security-engine dependency receipt'
      ;;
    web-console)
      case "${BILLING_ENABLED:-false}" in true|false) ;; *) die 'BILLING_ENABLED must be true or false' ;; esac
      build_args=(--build-arg "VITE_BILLING_ENABLED=${BILLING_ENABLED:-false}")
      assert_npm_cache_context_unchanged
      build_context_args+=(--build-context "release-npm-cache=$NPM_CACHE_CONTEXT")
      build_args_json="{\"VITE_BILLING_ENABLED\":\"${BILLING_ENABLED:-false}\"}"
      ;;
  esac
  log "build $image from source archive for $PLATFORM"
  docker buildx build --platform "$PLATFORM" --no-cache --load --pull=false --network "$BUILD_NETWORK_MODE" \
    "${SOURCE_LABELS[@]}" "${build_args[@]}" "${build_context_args[@]}" -t "$image" \
    -f "$SOURCE_ROOT/$dockerfile" "$context_path"
  if [[ "$component" == web-console ]]; then
    assert_npm_cache_context_unchanged
  fi
  assert_build_identity_unchanged "$BUILD_TOOLCHAIN" docker ||
    die "Buildx identity drifted during build: $component"
  record_source_image "$image" "$profile" first-party "$component" \
    "$dockerfile" "$context" "$build_args_json" "$record_extra_json"
}

build_llm_judge() {
  local image="$1" profile="$2" component="$3" dockerfile="$4" context="$5"
  local revision cache receipt commit_count version_output source_entrypoint_sha runtime_entrypoint_sha
  local entrypoint_blob build_args_json extra_json base_images_json runtime_short
  revision="$(sed -n 's/^llama_cpp_revision=//p' "$SOURCE_ROOT/deploy/docker-compose/release-toolchain.lock")"
  cache="/home/dev/tool-cache/llama.cpp-$revision"
  receipt="$cache/receipt.json"
  commit_count="$(python3 - "$receipt" "$revision" <<'PY'
import json
import pathlib
import sys

data = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
if data.get("revision") != sys.argv[2] or not isinstance(data.get("commit_count"), int):
    raise SystemExit("invalid verified llama.cpp receipt")
print(data["commit_count"])
PY
  )" || die 'unable to read the verified llama.cpp receipt'
  require_llm_judge_runtime_input
  runtime_short="${LLM_JUDGE_RUNTIME_IMAGE_ID#sha256:}"
  LLM_JUDGE_RUNTIME_ALIAS="jjdguard-release-input/llm-judge:${SOURCE_REVISION:0:12}-${runtime_short:0:12}"
  docker image tag "$LLM_JUDGE_RUNTIME_INPUT" "$LLM_JUDGE_RUNTIME_ALIAS"
  [[ "$(image_id_for "$LLM_JUDGE_RUNTIME_ALIAS")" == "$LLM_JUDGE_RUNTIME_IMAGE_ID" ]] ||
    die 'local Judge runtime alias does not bind the inspected image ID'
  source_entrypoint_sha="$(sha256sum "$SOURCE_ROOT/$context/entrypoint.sh" | awk '{print $1}')"
  [[ "$source_entrypoint_sha" =~ ^[0-9a-f]{64}$ ]] ||
    die 'source Judge entrypoint hash is invalid'
  runtime_entrypoint_sha="$(docker run --platform "$PLATFORM" --pull=never --network=none --rm --user 0 \
    --entrypoint sha256sum "$LLM_JUDGE_RUNTIME_ALIAS" /usr/local/bin/entrypoint.sh | awk '{print $1}')" ||
    die 'unable to read local Judge runtime entrypoint hash'
  [[ "$runtime_entrypoint_sha" == "$source_entrypoint_sha" ]] ||
    die 'local Judge runtime entrypoint differs from the release source'
  LLM_JUDGE_RUNTIME_ENTRYPOINT_SHA256="$runtime_entrypoint_sha"
  entrypoint_blob="$(git -C "$PROJECT_ROOT" rev-parse \
    "$SOURCE_REVISION:$context/entrypoint.sh")"
  version_output="$(docker run --platform "$PLATFORM" --pull=never --network=none --rm --entrypoint /opt/llama/llama-server \
    "$LLM_JUDGE_RUNTIME_ALIAS" --version 2>&1)" || die 'local Judge runtime did not return version information'
  [[ "$version_output" == *"${revision:0:7}"* ]] ||
    die "local Judge runtime version does not contain fixed revision ${revision:0:7}"
  build_args_json="$(python3 - "$LLM_JUDGE_RUNTIME_ALIAS" <<'PY'
import json
import sys

print(json.dumps({"LOCAL_RUNTIME_IMAGE": sys.argv[1]}, sort_keys=True, separators=(",", ":")))
PY
  )"
  extra_json="$(python3 - "$receipt" "$context/entrypoint.sh" "$entrypoint_blob" \
    "$LLM_JUDGE_RUNTIME_INPUT" "$LLM_JUDGE_RUNTIME_IMAGE_ID" "$LLM_JUDGE_RUNTIME_ENTRYPOINT_SHA256" <<'PY'
import json
import pathlib
import sys

receipt = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
print(json.dumps({
    "build_mode": "home-runtime-reuse",
    "home_runtime": {
        "source_image": sys.argv[4],
        "source_image_id": sys.argv[5],
        "entrypoint_sha256": sys.argv[6],
    },
    "upstream": receipt,
    "wrapper_blobs": {sys.argv[2]: sys.argv[3]},
}, sort_keys=True, separators=(",", ":")))
PY
  )"
  base_images_json="$(python3 - "$LLM_JUDGE_RUNTIME_IMAGE_ID" <<'PY'
import json
import sys

image_id = sys.argv[1]
print(json.dumps([{
    "from_index": 0,
    "stage": None,
    "reference": f"home-runtime@{image_id}",
    "digest": image_id,
}], sort_keys=True, separators=(",", ":")))
PY
  )"
  log "rebuild $image from verified home Judge runtime $LLM_JUDGE_RUNTIME_IMAGE_ID"
  docker buildx build --platform "$PLATFORM" --no-cache --load --pull=false --network "$BUILD_NETWORK_MODE" \
    "${SOURCE_LABELS[@]}" \
    --build-arg "LOCAL_RUNTIME_IMAGE=$LLM_JUDGE_RUNTIME_ALIAS" \
    -t "$image" -f "$SOURCE_ROOT/$context/Dockerfile.offline" "$SOURCE_ROOT/$context"
  [[ "$(image_id_for "$LLM_JUDGE_RUNTIME_ALIAS")" == "$LLM_JUDGE_RUNTIME_IMAGE_ID" ]] ||
    die 'local Judge runtime alias changed during the release build'
  assert_build_identity_unchanged "$BUILD_TOOLCHAIN" docker ||
    die 'Buildx identity drifted during llm-judge build'
  version_output="$(docker run --platform "$PLATFORM" --pull=never --network=none --rm --entrypoint /opt/llama/llama-server \
    "$image" --version 2>&1)" || die 'built llama-server did not return version information'
  [[ "$version_output" == *"${revision:0:7}"* ]] ||
    die "built llama-server version does not contain fixed revision ${revision:0:7}"
  assert_build_identity_unchanged "$BUILD_TOOLCHAIN" docker ||
    die 'Buildx identity drifted during llm-judge verification'
  record_source_image "$image" "$profile" upstream-source "$component" \
    "$context/Dockerfile.offline" "$context" "$build_args_json" "$extra_json" "$base_images_json"
}

build_portal_proxy() {
  local image="$1" profile="$2" component="$3" dockerfile="$4" context="$5"
  local runtime_short lock_path lock_sha lock_blob source_lock_sha
  local engine_receipt runtime_engine_manifest build_args_json extra_json base_images_json
  local query_engine_name schema_engine_name
  if [[ "$TARGET_ARCH" == arm64 ]]; then
    query_engine_name=libquery_engine-linux-musl-arm64-openssl-3.0.x.so.node
    schema_engine_name=schema-engine-linux-musl-arm64-openssl-3.0.x
  else
    query_engine_name=libquery_engine-linux-musl-openssl-3.0.x.so.node
    schema_engine_name=schema-engine-linux-musl-openssl-3.0.x
  fi
  runtime_short="${PORTAL_PROXY_RUNTIME_IMAGE_ID#sha256:}"
  PORTAL_PROXY_RUNTIME_ALIAS="jjdguard-release-input/portal-proxy:${SOURCE_REVISION:0:12}-${runtime_short:0:12}"
  docker image tag "$PORTAL_PROXY_RUNTIME_INPUT" "$PORTAL_PROXY_RUNTIME_ALIAS"
  [[ "$(image_id_for "$PORTAL_PROXY_RUNTIME_ALIAS")" == "$PORTAL_PROXY_RUNTIME_IMAGE_ID" ]] ||
    die 'local Portal Proxy runtime alias does not bind the inspected image ID'

  lock_path="$context/pnpm-lock.yaml"
  [[ -f "$SOURCE_ROOT/$lock_path" && ! -L "$SOURCE_ROOT/$lock_path" ]] ||
    die 'Portal Proxy pnpm lock is unavailable in the release source archive'
  lock_sha="$(sha256sum "$SOURCE_ROOT/$lock_path" | awk '{print $1}')"
  source_lock_sha="$(git -C "$PROJECT_ROOT" cat-file blob "$SOURCE_REVISION:$lock_path" | sha256sum | awk '{print $1}')"
  [[ "$lock_sha" == "$source_lock_sha" ]] ||
    die 'Portal Proxy pnpm lock differs from the reviewed release source'
  lock_blob="$(git -C "$PROJECT_ROOT" rev-parse "$SOURCE_REVISION:$lock_path")"

  runtime_engine_manifest="$TEMP_ROOT/portal-proxy-runtime-prisma-manifest.tsv"
  docker run --platform "$PLATFORM" --pull=never --network=none --rm --user 0 --entrypoint sh \
    "$PORTAL_PROXY_RUNTIME_ALIAS" -ec '
set -eu
engine_dir="$(find /app/node_modules -type d -path "*/@prisma/engines" -print)"
[ -n "$engine_dir" ]
[ "$(printf "%s\n" "$engine_dir" | wc -l | tr -d "[:space:]")" = 1 ]
[ -d "$engine_dir" ] && [ ! -L "$engine_dir" ]
for engine in "$@"; do
  path="$engine_dir/$engine"
  [ -f "$path" ] && [ ! -L "$path" ]
  printf "%s\t%s\t%s\n" "$engine" \
    "$(wc -c < "$path" | tr -d "[:space:]")" \
    "$(sha256sum "$path" | awk '"'"'{print $1}'"'"')"
done
' sh "$query_engine_name" "$schema_engine_name" \
    >"$runtime_engine_manifest" || die 'unable to read Prisma engines from local Portal Proxy runtime'
  [[ -f "$runtime_engine_manifest" && ! -L "$runtime_engine_manifest" ]] || \
    die 'Portal Proxy runtime Prisma engine manifest is unsafe'
  chmod 0600 "$runtime_engine_manifest"
  engine_receipt="$(python3 "$SOURCE_ROOT/deploy/docker-compose/verify-release-prisma-engines.py" \
    --lock "$SOURCE_ROOT/$(prisma_engine_lock_for_arch)" \
    --target-arch "$TARGET_ARCH" \
    --runtime-manifest "$runtime_engine_manifest" \
    --runtime-image "$PORTAL_PROXY_RUNTIME_INPUT" \
    --runtime-image-id "$PORTAL_PROXY_RUNTIME_IMAGE_ID")" || \
    die 'Portal Proxy runtime Prisma engines do not match the reviewed release lock'
  build_args_json="$(python3 - "$PORTAL_PROXY_RUNTIME_ALIAS" <<'PY'
import json
import sys

print(json.dumps({"LOCAL_RUNTIME_IMAGE": sys.argv[1]}, sort_keys=True, separators=(",", ":")))
PY
  )" || die 'unable to bind Portal Proxy local runtime build argument'
  extra_json="$(python3 - "$PORTAL_PROXY_RUNTIME_INPUT" "$PORTAL_PROXY_RUNTIME_IMAGE_ID" \
    "$PORTAL_PROXY_RUNTIME_SOURCE_REVISION" "$PORTAL_PROXY_RUNTIME_SOURCE_TREE" \
    "$PORTAL_PROXY_PNPM_VERSION" "$lock_path" "$lock_sha" "$lock_blob" \
    "$engine_receipt" <<'PY'
import json
import sys

(source_image, source_image_id, source_revision, source_tree, pnpm_version,
 lock_path, lock_sha, lock_blob, engines) = sys.argv[1:]
print(json.dumps({
    "home_runtime": {
        "source_image": source_image,
        "source_image_id": source_image_id,
        "source_revision": source_revision,
        "source_tree": source_tree,
        "pnpm_version": pnpm_version,
        "pnpm_lock": {"path": lock_path, "sha256": lock_sha, "blob": lock_blob},
        "prisma_engines": json.loads(engines),
    },
}, sort_keys=True, separators=(",", ":")))
PY
  )" || die 'unable to bind Portal Proxy home runtime provenance'
  base_images_json="$(python3 - "$SOURCE_ROOT/$dockerfile" "$PORTAL_PROXY_RUNTIME_IMAGE_ID" <<'PY'
import json
import pathlib
import re
import shlex
import sys

dockerfile_path = pathlib.Path(sys.argv[1])
image_id = sys.argv[2]
text = dockerfile_path.read_text(encoding="utf-8")
if not re.fullmatch(r"sha256:[0-9a-f]{64}", image_id):
    raise SystemExit("invalid Portal Proxy runtime image ID")

stages = set()
bases = []
for from_index, match in enumerate(re.finditer(r"^FROM[ \t]+(.+?)\s*$", text, re.MULTILINE | re.IGNORECASE)):
    try:
        fields = shlex.split(match.group(1), posix=True)
    except ValueError as error:
        raise SystemExit(f"invalid Portal Proxy home runtime Dockerfile: {error}")
    while fields and fields[0].startswith("--"):
        fields.pop(0)
    if len(fields) not in {1, 3} or (len(fields) == 3 and fields[1].upper() != "AS"):
        raise SystemExit("invalid Portal Proxy home runtime Dockerfile")
    reference = fields[0]
    stage = fields[2] if len(fields) == 3 else None
    if reference == "${LOCAL_RUNTIME_IMAGE}":
        bases.append({
            "from_index": from_index,
            "stage": stage,
            "reference": f"home-runtime@{image_id}",
            "digest": image_id,
        })
    elif reference.lower() not in stages:
        raise SystemExit("Portal Proxy home runtime Dockerfile has an external base")
    if stage is not None and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", stage):
        stages.add(stage.lower())
    elif stage is not None:
        raise SystemExit("invalid Portal Proxy home runtime stage")

if not bases:
    raise SystemExit("Portal Proxy home runtime Dockerfile has no local base")
print(json.dumps(bases, sort_keys=True, separators=(",", ":")))
PY
  )" || die 'unable to record Portal Proxy local runtime base images'
  log "wrap verified home Portal Proxy runtime $PORTAL_PROXY_RUNTIME_IMAGE_ID"
  docker buildx build --platform "$PLATFORM" --no-cache --load --pull=false --network none \
    "${SOURCE_LABELS[@]}" \
    --label "io.jjdguard.source-tree=$SOURCE_TREE" \
    --build-arg "LOCAL_RUNTIME_IMAGE=$PORTAL_PROXY_RUNTIME_ALIAS" \
    -t "$image" -f "$SOURCE_ROOT/$dockerfile" "$SOURCE_ROOT/$context"
  [[ "$(image_id_for "$PORTAL_PROXY_RUNTIME_ALIAS")" == "$PORTAL_PROXY_RUNTIME_IMAGE_ID" ]] ||
    die 'local Portal Proxy runtime alias changed during the release build'
  assert_build_identity_unchanged "$BUILD_TOOLCHAIN" docker ||
    die 'Buildx identity drifted during Portal Proxy build'
  record_source_image "$image" "$profile" home-runtime "$component" \
    "$dockerfile" "$context" "$build_args_json" "$extra_json" "$base_images_json"
}

pull_third_party_image() {
  local image="$1" profile="$2" component="$3" expected_digest="$4"
  local image_id repo_digests_json actual_digest
  case "$THIRD_PARTY_INPUT_MODE" in
    cache-only)
      log "reuse cached fixed third-party image $image@$expected_digest for $PLATFORM"
      ;;
    prepare)
      log "pull fixed third-party image $image@$expected_digest for $PLATFORM"
      docker pull --platform "$PLATFORM" "$image@$expected_digest"
      docker tag "$image@$expected_digest" "$image"
      ;;
  esac
  assert_build_identity_unchanged "$BUILD_TOOLCHAIN" docker ||
    die "Buildx identity drifted during fixed image acquisition: $component"
  image_id="$(image_id_for "$image")"
  repo_digests_json="$(docker image inspect "$image" --format '{{json .RepoDigests}}')" ||
    die "unable to inspect RepoDigests for $image"
  actual_digest="$(image_provenance_repo_digest "$image" "$repo_digests_json" "$expected_digest")" ||
    die "unable to resolve the observed repository digest for $image"
  [[ "$actual_digest" == "$expected_digest" ]] ||
    die "third-party digest mismatch: $image expected=$expected_digest actual=$actual_digest"
  write_third_party_image_provenance_record \
    "$RECORD_DIR/$component.json" "$image" "$profile" "$component" \
    "$expected_digest" "$actual_digest" "$PLATFORM" "$image_id"
  inspect_architecture "$TARGET_ARCH" "$image"
}

if component_selected enterprise-ai-portal || component_selected tier1-classifier; then
  TASK4_RECEIPT_DIR="$RELEASE_EVIDENCE/task4"
  [[ ! -e "$TASK4_RECEIPT_DIR" && ! -L "$TASK4_RECEIPT_DIR" ]] ||
    die "Task4 evidence path already exists: $TASK4_RECEIPT_DIR"
  task4_components=()
  task4_args=(
    --target-arch "$TARGET_ARCH"
    --candidate-revision "$SOURCE_REVISION"
    --candidate-tree "$SOURCE_TREE"
    --receipt-dir "$TASK4_RECEIPT_DIR"
    --source-root "$SOURCE_ROOT"
    --source-archive-sha256 "$SOURCE_ARCHIVE_SHA256"
    --repo "$PROJECT_ROOT"
  )
  if component_selected enterprise-ai-portal; then
    task4_components+=(portal)
    task4_args+=(
      --portal-image "$(catalog_field enterprise-ai-portal 1)"
      --npm-cache-context "$NPM_CACHE_CONTEXT"
      --npm-cache-sha256 "$NPM_CACHE_ARCHIVE_SHA256"
      --prisma-engine-input "$PRISMA_ENGINE_INPUT"
    )
  fi
  if component_selected tier1-classifier; then
    [[ -n "$TIER1_OWNED_MODEL_INPUT" ]] ||
      die 'TIER1_OWNED_MODEL_INPUT is required to build tier1-classifier'
    require_tier1_python_deps_input
    task4_components+=(tier1)
    task4_args+=(
      --tier1-image "$(catalog_field tier1-classifier 1)"
      --tier1-model-input "$TIER1_OWNED_MODEL_INPUT"
      --tier1-python-deps-input "$TIER1_PYTHON_DEPS_INPUT"
    )
  fi
  task4_args+=(--network-mode "$TASK4_BUILD_NETWORK_MODE")
  task4_components_csv="$(IFS=,; printf '%s' "${task4_components[*]}")"
  if component_selected enterprise-ai-portal; then
    assert_npm_cache_context_unchanged
  fi
  env -u JJD_TASK4_DOCKER -u JJD_TASK4_TESTING \
    "$SOURCE_ROOT/deploy/tests/build_jjdguard_task4_images.sh" \
    "${task4_args[@]}"
  env -u JJD_TASK4_DOCKER -u JJD_TASK4_TESTING \
    "$SOURCE_ROOT/deploy/tests/test_jjdguard_task4_image_provenance.sh" \
    --candidate-revision "$SOURCE_REVISION" \
    --candidate-tree "$SOURCE_TREE" \
    --receipt-dir "$TASK4_RECEIPT_DIR" \
    --expected-components "$task4_components_csv" \
    --target-arch "$TARGET_ARCH" \
    --repo "$PROJECT_ROOT"
  if component_selected enterprise-ai-portal; then
    assert_npm_cache_context_unchanged
  fi
  assert_build_identity_unchanged "$BUILD_TOOLCHAIN" docker ||
    die 'Buildx identity drifted during Task4 image construction'
fi

prepare_compose
prepare_docker

while read -r image profile kind component expected_digest dockerfile context; do
  case "$kind:$component" in
    first-party:enterprise-ai-portal)
      legacy_path='task4/portal-image-receipt.json'
      legacy_sha="$(image_provenance_sha256 "$TASK4_RECEIPT_DIR/portal-image-receipt.json")"
      legacy_json="$(python3 - "$legacy_path" "$legacy_sha" \
        "$TASK4_RECEIPT_DIR/portal-image-receipt.json" <<'PY'
import json
import pathlib
import sys
path, digest, receipt_path = sys.argv[1:]
receipt = json.loads(pathlib.Path(receipt_path).read_text(encoding="utf-8"))
print(json.dumps({"legacy_receipt": {"path": path, "sha256": digest},
                  "build_engine": receipt.get("build_engine")},
                 sort_keys=True, separators=(",", ":")))
PY
      )"
      portal_build_args_json="$(jq -cn --arg billing "${BILLING_ENABLED:-false}" \
        '{NEXT_PUBLIC_BILLING_ENABLED:$billing}')"
      record_source_image "$image" "$profile" "$kind" "$component" "$dockerfile" "$context" \
        "$portal_build_args_json" "$legacy_json"
      ;;
    first-party:tier1-classifier)
      legacy_path='task4/tier1-image-receipt.json'
      legacy_sha="$(image_provenance_sha256 "$TASK4_RECEIPT_DIR/tier1-image-receipt.json")"
      legacy_json="$(python3 - "$legacy_path" "$legacy_sha" \
        "$TASK4_RECEIPT_DIR/tier1-image-receipt.json" <<'PY'
import json
import pathlib
import sys
path, digest, receipt_path = sys.argv[1:]
receipt = json.loads(pathlib.Path(receipt_path).read_text(encoding="utf-8"))
print(json.dumps({"legacy_receipt": {"path": path, "sha256": digest},
                  "build_engine": receipt.get("build_engine")},
                 sort_keys=True, separators=(",", ":")))
PY
      )"
      record_source_image "$image" "$profile" "$kind" "$component" "$dockerfile" "$context" \
        '{}' "$legacy_json"
      ;;
    first-party:*)
      build_first_party_image "$image" "$profile" "$component" "$dockerfile" "$context"
      ;;
    upstream-source:llm-judge)
      build_llm_judge "$image" "$profile" "$component" "$dockerfile" "$context"
      ;;
    home-runtime:portal-proxy)
      build_portal_proxy "$image" "$profile" "$component" "$dockerfile" "$context"
      ;;
    third-party:*)
      pull_third_party_image "$image" "$profile" "$component" "$expected_digest"
      ;;
    *) die "unsupported image catalog entry: kind=$kind component=$component" ;;
  esac
done <<<"$catalog_rows"

assert_build_identity_unchanged "$BUILD_TOOLCHAIN" docker ||
  die 'Buildx identity drifted after all image construction'
finalize_image_provenance \
  "$IMAGE_PROVENANCE_FILE" "$RECORD_DIR" "$SOURCE_ATTESTATION_FILE" \
  "$SOURCE_ARCHIVE_SHA256" "$PLATFORM" "$BUILD_TOOLCHAIN" "$BUNDLE_PROFILE" "$INCLUDE_CHAT"

verifier_args=(
  --catalog "$SOURCE_ROOT/deploy/docker-compose/images.lst" \
  --receipt "$IMAGE_PROVENANCE_FILE" \
  --source-receipt "$SOURCE_ATTESTATION_FILE" \
  --repository "$PROJECT_ROOT" \
  --profile "$BUNDLE_PROFILE" \
  --include-chat "$INCLUDE_CHAT"
)
if [[ "$BUNDLE_PROFILE" == full ]]; then
  verifier_args+=(--upstream-receipt "$LLAMA_UPSTREAM_RECEIPT")
fi
python3 "$SOURCE_ROOT/deploy/docker-compose/verify-image-provenance.py" "${verifier_args[@]}"

log "all $TARGET_ARCH images are ready with provenance: $IMAGE_PROVENANCE_FILE"
