#!/bin/sh
set -eu

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname "$0")" && pwd)"

fail() {
  echo "[error] release toolchain verification failed: $1" >&2
  exit 1
}

sha256_file() {
  sha256sum "$1" | awk '{print $1}'
}

verify_regular_file() {
  path="$1"
  [ -f "$path" ] && [ ! -L "$path" ] ||
    fail "required asset is missing, non-regular, or a symbolic link: $path"
}

verify_sha256() {
  path="$1"
  expected="$2"
  actual="$(sha256_file "$path")" || fail 'unable to hash a required asset'
  [ "$actual" = "$expected" ] || fail "required asset SHA-256 does not match the lock: $path"
}

[ "$#" -eq 1 ] || {
  if [ "$#" -ne 5 ] ||
    [ "${2:-}" != "--fixture-root" ] ||
    [ "${4:-}" != "--lock" ] ||
    [ "${JJDGUARD_RELEASE_TOOLCHAIN_TESTING:-0}" != "1" ]; then
    fail 'invalid verifier arguments'
  fi
}

target_arch="$1"
[ "$target_arch" = amd64 ] || [ "$target_arch" = arm64 ] || fail 'release toolchain only supports amd64 and arm64'

if [ "$#" -eq 1 ]; then
  LOCK_FILE="$SCRIPT_DIR/release-toolchain.lock"
  SYFT_BIN=/home/dev/tool-cache/syft-1.44.0/syft
  SYFT_ARCHIVE=/home/dev/tool-cache/syft-1.44.0/syft_1.44.0_linux_amd64.tar.gz
  TOOLCHAIN_ASSET_DIR="$("$SCRIPT_DIR/release-toolchain-cache-dir.sh" "$target_arch")" ||
    fail 'unable to resolve the locked Docker and Compose cache directory'
  OFFLINE_TARGET_ARCH="$target_arch" "$SCRIPT_DIR/prepare-release-toolchain.sh" verify ||
    fail 'locked Docker and Compose cache verification failed'
  DOCKER_STATIC_TGZ="$TOOLCHAIN_ASSET_DIR/docker-static.tgz"
  DOCKER_COMPOSE_BINARY="$TOOLCHAIN_ASSET_DIR/docker-compose"
  JUDGE_GGUF="${JUDGE_OWNED_MODEL_INPUT:-}"
  [ -n "$JUDGE_GGUF" ] || fail 'JUDGE_OWNED_MODEL_INPUT is required for a formal release'
else
  fixture_root="$3"
  LOCK_FILE="$5"
  [ -d "$fixture_root" ] && [ ! -L "$fixture_root" ] || fail 'fixture root is invalid'
  SYFT_BIN="$fixture_root/syft"
  SYFT_ARCHIVE="$fixture_root/syft-archive"
  DOCKER_STATIC_TGZ="$fixture_root/docker-static.tgz"
  DOCKER_COMPOSE_BINARY="$fixture_root/docker-compose"
  JUDGE_GGUF="$fixture_root/judge.gguf"
fi

verify_regular_file "$LOCK_FILE"
command -v sha256sum >/dev/null 2>&1 || fail 'sha256sum is unavailable'
command -v stat >/dev/null 2>&1 || fail 'stat is unavailable'

seen_syft_version=
seen_syft_binary_sha256=
seen_syft_archive_sha256=
seen_docker_static_amd64_sha256=
seen_docker_compose_amd64_sha256=
seen_docker_static_arm64_sha256=
seen_docker_compose_arm64_sha256=
seen_llama_cpp_revision=
seen_judge_gguf_sha256=
seen_judge_gguf_size=

while IFS= read -r line || [ -n "$line" ]; do
  case "$line" in
    *=*) ;;
    *) fail 'toolchain lock contains a malformed line' ;;
  esac
  key="${line%%=*}"
  value="${line#*=}"
  [ -n "$value" ] || fail 'toolchain lock contains an empty value'
  case "$key" in
    syft_version)
      [ -z "$seen_syft_version" ] || fail 'toolchain lock contains a duplicate key'
      seen_syft_version=1
      syft_version="$value"
      ;;
    syft_binary_sha256)
      [ -z "$seen_syft_binary_sha256" ] || fail 'toolchain lock contains a duplicate key'
      seen_syft_binary_sha256=1
      syft_binary_sha256="$value"
      ;;
    syft_archive_sha256)
      [ -z "$seen_syft_archive_sha256" ] || fail 'toolchain lock contains a duplicate key'
      seen_syft_archive_sha256=1
      syft_archive_sha256="$value"
      ;;
    docker_static_amd64_sha256)
      [ -z "$seen_docker_static_amd64_sha256" ] || fail 'toolchain lock contains a duplicate key'
      seen_docker_static_amd64_sha256=1
      docker_static_amd64_sha256="$value"
      ;;
    docker_compose_amd64_sha256)
      [ -z "$seen_docker_compose_amd64_sha256" ] || fail 'toolchain lock contains a duplicate key'
      seen_docker_compose_amd64_sha256=1
      docker_compose_amd64_sha256="$value"
      ;;
    docker_static_arm64_sha256)
      [ -z "$seen_docker_static_arm64_sha256" ] || fail 'toolchain lock contains a duplicate key'
      seen_docker_static_arm64_sha256=1
      docker_static_arm64_sha256="$value"
      ;;
    docker_compose_arm64_sha256)
      [ -z "$seen_docker_compose_arm64_sha256" ] || fail 'toolchain lock contains a duplicate key'
      seen_docker_compose_arm64_sha256=1
      docker_compose_arm64_sha256="$value"
      ;;
    llama_cpp_revision)
      [ -z "$seen_llama_cpp_revision" ] || fail 'toolchain lock contains a duplicate key'
      seen_llama_cpp_revision=1
      llama_cpp_revision="$value"
      ;;
    judge_gguf_sha256)
      [ -z "$seen_judge_gguf_sha256" ] || fail 'toolchain lock contains a duplicate key'
      seen_judge_gguf_sha256=1
      judge_gguf_sha256="$value"
      ;;
    judge_gguf_size)
      [ -z "$seen_judge_gguf_size" ] || fail 'toolchain lock contains a duplicate key'
      seen_judge_gguf_size=1
      judge_gguf_size="$value"
      ;;
    *) fail 'toolchain lock contains an unknown key' ;;
  esac
done <"$LOCK_FILE"

for required in \
  "$seen_syft_version" \
  "$seen_syft_binary_sha256" \
  "$seen_syft_archive_sha256" \
  "$seen_docker_static_amd64_sha256" \
  "$seen_docker_compose_amd64_sha256" \
  "$seen_docker_static_arm64_sha256" \
  "$seen_docker_compose_arm64_sha256" \
  "$seen_llama_cpp_revision" \
  "$seen_judge_gguf_sha256" \
  "$seen_judge_gguf_size"; do
  [ "$required" = 1 ] || fail 'toolchain lock is incomplete'
done

[ "$syft_version" = 1.44.0 ] || fail 'Syft lock version is not approved'
[ "$llama_cpp_revision" = 3653e6d6d547ec763317d9ecd0ace334a7e21359 ] ||
  fail 'llama.cpp revision is not approved'
for digest in \
  "$syft_binary_sha256" \
  "$syft_archive_sha256" \
  "$docker_static_amd64_sha256" \
  "$docker_compose_amd64_sha256" \
  "$docker_static_arm64_sha256" \
  "$docker_compose_arm64_sha256" \
  "$judge_gguf_sha256"; do
  printf '%s\n' "$digest" | grep -Eq '^[0-9a-f]{64}$' ||
    fail 'toolchain lock contains an invalid SHA-256'
done
printf '%s\n' "$judge_gguf_size" | grep -Eq '^[1-9][0-9]*$' ||
  fail 'toolchain lock contains an invalid GGUF size'

for asset in \
  "$SYFT_BIN" \
  "$SYFT_ARCHIVE" \
  "$DOCKER_STATIC_TGZ" \
  "$DOCKER_COMPOSE_BINARY" \
  "$JUDGE_GGUF"; do
  verify_regular_file "$asset"
done
[ -x "$SYFT_BIN" ] || fail 'fixed Syft binary is not executable'
[ -x "$DOCKER_COMPOSE_BINARY" ] || fail 'fixed Docker Compose binary is not executable'

verify_sha256 "$SYFT_BIN" "$syft_binary_sha256"
verify_sha256 "$SYFT_ARCHIVE" "$syft_archive_sha256"
if [ "$target_arch" = arm64 ]; then
  docker_static_sha256="$docker_static_arm64_sha256"
  docker_compose_sha256="$docker_compose_arm64_sha256"
else
  docker_static_sha256="$docker_static_amd64_sha256"
  docker_compose_sha256="$docker_compose_amd64_sha256"
fi
verify_sha256 "$DOCKER_STATIC_TGZ" "$docker_static_sha256"
verify_sha256 "$DOCKER_COMPOSE_BINARY" "$docker_compose_sha256"
verify_sha256 "$JUDGE_GGUF" "$judge_gguf_sha256"

actual_gguf_size="$(stat -c '%s' "$JUDGE_GGUF")" ||
  fail 'unable to read GGUF size'
[ "$actual_gguf_size" = "$judge_gguf_size" ] || fail 'GGUF size does not match the lock'

actual_syft_version="$("$SYFT_BIN" version 2>/dev/null |
  awk '$1 == "Version:" { print $2 }')"
[ "$actual_syft_version" = "$syft_version" ] || fail 'Syft runtime version does not match the lock'

echo '[ok] release toolchain matches the reviewed lock'
