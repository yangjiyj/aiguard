#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOCK_FILE="$SCRIPT_DIR/release-toolchain.lock"
TARGET_ARCH="${1:-}"

case "$TARGET_ARCH" in
  x86_64|amd64) TARGET_ARCH=amd64 ;;
  aarch64|arm64) TARGET_ARCH=arm64 ;;
  *)
    printf '[error] unsupported release toolchain architecture: %s\n' "$TARGET_ARCH" >&2
    exit 1
    ;;
esac

[[ -f "$LOCK_FILE" && ! -L "$LOCK_FILE" ]] || {
  printf '[error] release toolchain lock is unavailable: %s\n' "$LOCK_FILE" >&2
  exit 1
}

LOCK_SHA256="$(sha256sum "$LOCK_FILE" | awk '{print $1}')"
[[ "$LOCK_SHA256" =~ ^[0-9a-f]{64}$ ]] || {
  printf '[error] cannot hash release toolchain lock\n' >&2
  exit 1
}

printf '/home/dev/tool-cache/jjdguard-release-toolchain/%s/%s\n' \
  "$LOCK_SHA256" "$TARGET_ARCH"
