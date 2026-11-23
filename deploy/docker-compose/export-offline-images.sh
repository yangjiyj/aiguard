#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"
. "$SCRIPT_DIR/lib-arch.sh"

TARGET_ARCH="$(normalize_offline_arch "${OFFLINE_TARGET_ARCH:-$(uname -m)}")"
PLATFORM="linux/$TARGET_ARCH"
OUTPUT_DIR="${1:-$SCRIPT_DIR/offline-artifacts}"
STAMP="$(date +%Y%m%d-%H%M%S)"
IMAGE_ARCHIVE="$OUTPUT_DIR/jjdguard-offline-images-${STAMP}.tar.gz"
CHECKSUM_FILE="${IMAGE_ARCHIVE}.sha256"
ARCHIVE_TMP="${IMAGE_ARCHIVE}.tmp.$$"
CHECKSUM_TMP="${CHECKSUM_FILE}.tmp.$$"
IMAGE_STORE_LOCK_FILE="${JJDGUARD_IMAGE_STORE_LOCK_FILE:-/home/dev/.cache/jjdguard/release-image-store.lock}"
ARCHIVE_COMMITTED=0

mkdir -p "$OUTPUT_DIR"
[[ -d "$OUTPUT_DIR" && ! -L "$OUTPUT_DIR" ]] || {
  echo "[error] offline image output is not a real directory: $OUTPUT_DIR" >&2
  exit 1
}
[[ ! -e "$IMAGE_ARCHIVE" && ! -L "$IMAGE_ARCHIVE" &&
   ! -e "$CHECKSUM_FILE" && ! -L "$CHECKSUM_FILE" ]] || {
  echo '[error] refusing to overwrite an existing offline image archive' >&2
  exit 1
}

cleanup_failed_export() {
  local status=$?
  if [[ "$status" -ne 0 ]]; then
    rm -f -- "$ARCHIVE_TMP" "$CHECKSUM_TMP"
    if [[ "$ARCHIVE_COMMITTED" == 1 ]]; then
      rm -f -- "$IMAGE_ARCHIVE" "$CHECKSUM_FILE"
    fi
  fi
  exit "$status"
}
trap cleanup_failed_export EXIT
trap 'exit 1' HUP INT TERM

prepare_image_store_lock() {
  local parent
  [[ "$IMAGE_STORE_LOCK_FILE" == /* ]] || {
    echo '[error] JJDGUARD_IMAGE_STORE_LOCK_FILE must be absolute' >&2
    exit 1
  }
  parent="$(dirname "$IMAGE_STORE_LOCK_FILE")"
  mkdir -p "$parent"
  [[ -d "$parent" && ! -L "$parent" ]] || {
    echo '[error] image store lock parent is not a real directory' >&2
    exit 1
  }
  chmod 0700 "$parent"
  [[ ! -e "$IMAGE_STORE_LOCK_FILE" && ! -L "$IMAGE_STORE_LOCK_FILE" ]] || {
    [[ -f "$IMAGE_STORE_LOCK_FILE" && ! -L "$IMAGE_STORE_LOCK_FILE" ]] || {
      echo '[error] image store lock is not a regular file' >&2
      exit 1
    }
  }
  : >>"$IMAGE_STORE_LOCK_FILE"
  chmod 0600 "$IMAGE_STORE_LOCK_FILE"
  command -v flock >/dev/null 2>&1 || {
    echo '[error] flock is required for the controlled image-store lock' >&2
    exit 1
  }
}

verify_live_provenance() {
  local -a args
  : "${PROVENANCE_CATALOG:?PROVENANCE_CATALOG is required}"
  : "${IMAGE_PROVENANCE_FILE:?IMAGE_PROVENANCE_FILE is required}"
  : "${SOURCE_ATTESTATION_FILE:?SOURCE_ATTESTATION_FILE is required}"
  : "${PROVENANCE_REPOSITORY:?PROVENANCE_REPOSITORY is required}"
  args=(python3 "$SCRIPT_DIR/verify-image-provenance.py"
    --catalog "$PROVENANCE_CATALOG"
    --receipt "$IMAGE_PROVENANCE_FILE"
    --source-receipt "$SOURCE_ATTESTATION_FILE"
    --repository "$PROVENANCE_REPOSITORY"
    --profile "$BUNDLE_PROFILE"
    --include-chat "$INCLUDE_CHAT")
  if [[ "$BUNDLE_PROFILE" == full ]]; then
    : "${PROVENANCE_UPSTREAM_RECEIPT:?PROVENANCE_UPSTREAM_RECEIPT is required for full exports}"
    args+=(--upstream-receipt "$PROVENANCE_UPSTREAM_RECEIPT")
  fi
  "${args[@]}"
}

verify_saved_archive() {
  python3 "$SCRIPT_DIR/verify-offline-image-archive.py" \
    --archive "$ARCHIVE_TMP" \
    --catalog "$PROVENANCE_CATALOG" \
    --receipt "$IMAGE_PROVENANCE_FILE" \
    --profile "$BUNDLE_PROFILE" \
    --include-chat "$INCLUDE_CHAT" \
    --capture-config-digests
}

. "$SCRIPT_DIR/lib-images.sh"
BUNDLE_PROFILE="${BUNDLE_PROFILE:-lite}"
INCLUDE_CHAT="${INCLUDE_CHAT:-0}"
IMAGES_LST="${IMAGES_LST:-$SCRIPT_DIR/images.lst}"
export IMAGES_LST INCLUDE_CHAT
required_images="$(read_images_for_profile "$BUNDLE_PROFILE")"
[[ -n "$required_images" ]] || {
  echo '[error] selected image catalog is empty' >&2
  exit 1
}
echo "[info] BUNDLE_PROFILE=$BUNDLE_PROFILE images: $(echo "$required_images" | tr '\n' ' ')"

prepare_image_store_lock
exec {IMAGE_STORE_LOCK_FD}>"$IMAGE_STORE_LOCK_FILE"
flock -x "$IMAGE_STORE_LOCK_FD"

# The live receipt check, docker save, and byte-level archive check all share
# one lock. A concurrent image retag cannot cross this validation boundary.
verify_live_provenance
for image in $required_images; do
  docker image inspect "$image" >/dev/null 2>&1 || {
    echo "[error] image not found: $image" >&2
    exit 1
  }
done

echo "[step] exporting offline images -> $IMAGE_ARCHIVE"
mapfile -t image_args <<<"$required_images"
[[ "${#image_args[@]}" -gt 0 ]] || {
  echo '[error] selected image catalog is empty' >&2
  exit 1
}
docker save --platform "$PLATFORM" "${image_args[@]}" | gzip -1 >"$ARCHIVE_TMP"
verify_saved_archive
mv -f -- "$ARCHIVE_TMP" "$IMAGE_ARCHIVE"
ARCHIVE_COMMITTED=1

if command -v shasum >/dev/null 2>&1; then
  (cd "$OUTPUT_DIR" && shasum -a 256 "$(basename "$IMAGE_ARCHIVE")" >"$(basename "$CHECKSUM_TMP")")
else
  (cd "$OUTPUT_DIR" && sha256sum "$(basename "$IMAGE_ARCHIVE")" >"$(basename "$CHECKSUM_TMP")")
fi
mv -f -- "$CHECKSUM_TMP" "$CHECKSUM_FILE"

echo "[ok] image archive created"
echo "[info] archive:  $IMAGE_ARCHIVE"
echo "[info] checksum: $CHECKSUM_FILE"
