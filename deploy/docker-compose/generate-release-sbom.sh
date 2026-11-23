#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOCK_FILE="$SCRIPT_DIR/release-toolchain.lock"
VERIFIER="$SCRIPT_DIR/verify-sbom-index.py"
IMAGE_ARCHIVE_SELECTOR="$SCRIPT_DIR/select-offline-image-archive.py"
SYFT_BIN=/home/dev/tool-cache/syft-1.44.0/syft
BUNDLE_DIR=
PROVENANCE_FILE=
WORK_DIR=

fail() {
  printf '[error] release SBOM generation failed: %s\n' "$1" >&2
  exit 1
}

cleanup() {
  [[ -z "$WORK_DIR" ]] || rm -rf -- "$WORK_DIR"
}
trap cleanup EXIT HUP INT TERM

sha256_file() {
  sha256sum "$1" | awk '{print $1}'
}

while (($#)); do
  case "$1" in
    --bundle) BUNDLE_DIR=$2; shift 2 ;;
    --provenance) PROVENANCE_FILE=$2; shift 2 ;;
    *) fail "unknown argument: $1" ;;
  esac
done
[[ "$BUNDLE_DIR" == /* && -d "$BUNDLE_DIR" && ! -L "$BUNDLE_DIR" ]] ||
  fail '--bundle must be an absolute real directory'
[[ "$PROVENANCE_FILE" == /* && -f "$PROVENANCE_FILE" && ! -L "$PROVENANCE_FILE" ]] ||
  fail '--provenance must be an absolute regular file'
[[ ! -e "$BUNDLE_DIR/sbom" && ! -L "$BUNDLE_DIR/sbom" ]] ||
  fail 'bundle already contains an SBOM directory'
[[ -x "$VERIFIER" && ! -L "$VERIFIER" ]] || fail 'SBOM verifier is unavailable'
[[ -x "$IMAGE_ARCHIVE_SELECTOR" && ! -L "$IMAGE_ARCHIVE_SELECTOR" ]] ||
  fail 'offline image archive selector is unavailable'

if [[ "${JJD_RELEASE_TESTING:-0}" == 1 ]]; then
  test_syft_bin="${JJD_TEST_SYFT_BIN:?JJD_TEST_SYFT_BIN is required in test mode}"
  SYFT_BIN="$test_syft_bin"
  expected_syft_sha="${JJD_TEST_SYFT_SHA256:?JJD_TEST_SYFT_SHA256 is required in test mode}"
else
  [[ -f "$LOCK_FILE" && ! -L "$LOCK_FILE" ]] || fail 'release toolchain lock is unavailable'
  expected_syft_sha="$(sed -n 's/^syft_binary_sha256=//p' "$LOCK_FILE")"
  [[ "$SYFT_BIN" == /home/dev/tool-cache/syft-1.44.0/syft ]] || fail 'fixed Syft path drifted'
fi
[[ "$expected_syft_sha" =~ ^[0-9a-f]{64}$ ]] || fail 'fixed Syft hash is invalid'
[[ -x "$SYFT_BIN" && ! -L "$SYFT_BIN" ]] || fail "fixed Syft binary is unavailable: $SYFT_BIN"
actual_syft_sha="$(sha256_file "$SYFT_BIN")"
[[ "$actual_syft_sha" == "$expected_syft_sha" ]] || fail 'fixed Syft binary hash mismatched'

WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/jjdguard-sbom.XXXXXX")"
chmod 0700 "$WORK_DIR"
provenance_rows="$(python3 - "$PROVENANCE_FILE" <<'PY'
import json
import pathlib
import re
import sys

payload = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
images = payload.get("images") if isinstance(payload, dict) else None
platform = payload.get("platform") if isinstance(payload, dict) else None
if platform not in {"linux/amd64", "linux/arm64"}:
    raise SystemExit("provenance platform is invalid")
if not isinstance(images, list) or not images:
    raise SystemExit("provenance images are invalid")
seen = set()
print(platform)
for image in images:
    if not isinstance(image, dict):
        raise SystemExit("provenance image is invalid")
    component = image.get("component")
    image_id = image.get("image_id")
    runtime_tag = image.get("runtime_tag")
    config_digest = image.get("oci_config_digest")
    if (not isinstance(component, str)
            or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", component)
            or not isinstance(image_id, str)
            or not re.fullmatch(r"sha256:[0-9a-f]{64}", image_id)
            or not isinstance(runtime_tag, str) or not runtime_tag
            or any(ch.isspace() for ch in runtime_tag)
            or not isinstance(config_digest, str)
            or not re.fullmatch(r"sha256:[0-9a-f]{64}", config_digest)
            or image.get("platform") != platform
            or component in seen):
        raise SystemExit("provenance component or image identity is invalid")
    seen.add(component)
    print("\t".join((component, image_id, runtime_tag, config_digest)))
PY
)" || fail 'image provenance is invalid for SBOM generation'
mapfile -t provenance_lines <<<"$provenance_rows"
(( ${#provenance_lines[@]} > 1 )) || fail 'image provenance is empty for SBOM generation'
target_platform=${provenance_lines[0]}
image_rows=("${provenance_lines[@]:1}")

bundle_tmp="$WORK_DIR/bundle.spdx.json"
"$SYFT_BIN" scan "dir:$BUNDLE_DIR" -o "spdx-json=$bundle_tmp"
[[ -s "$bundle_tmp" && ! -L "$bundle_tmp" ]] || fail 'Syft did not produce the bundle SPDX document'

archive_dir="$BUNDLE_DIR/deploy/docker-compose/offline-artifacts"
[[ -d "$archive_dir" && ! -L "$archive_dir" ]] || fail 'offline image archive directory is missing'
mapfile -t image_archives < <(find "$archive_dir" -mindepth 1 -maxdepth 1 -type f \
  -name 'jjdguard-offline-images-*.tar.gz' -print | sort)
[[ "${#image_archives[@]}" == 1 && -f "${image_archives[0]}" && ! -L "${image_archives[0]}" ]] ||
  fail 'bundle must contain exactly one regular offline image archive'
source_image_tar="$WORK_DIR/offline-images.tar"
gzip -dc -- "${image_archives[0]}" >"$source_image_tar" || fail 'unable to decompress verified offline image archive'
[[ -s "$source_image_tar" && ! -L "$source_image_tar" ]] || fail 'decompressed offline image archive is invalid'
chmod 0400 "$source_image_tar"

mkdir -m 0700 "$WORK_DIR/images"
for row in "${image_rows[@]}"; do
  IFS=$'\t' read -r component image_id runtime_tag config_digest <<<"$row"
  image_tmp="$WORK_DIR/images/$component.spdx.json"
  selected_archive="$WORK_DIR/images/$component.docker.tar"
  python3 "$IMAGE_ARCHIVE_SELECTOR" \
    --archive "$source_image_tar" \
    --tag "$runtime_tag" \
    --config-digest "$config_digest" \
    --platform "$target_platform" \
    --output "$selected_archive"
  "$SYFT_BIN" scan "docker-archive:$selected_archive" -o "spdx-json=$image_tmp"
  [[ -s "$image_tmp" && ! -L "$image_tmp" ]] ||
    fail "Syft did not produce the image SPDX document: $component"
  rm -f -- "$selected_archive"
done

index_tmp="$WORK_DIR/index.json"
python3 - "$index_tmp" "$actual_syft_sha" "$bundle_tmp" "${image_rows[@]}" <<'PY'
import hashlib
import json
import pathlib
import sys

index_path = pathlib.Path(sys.argv[1])
syft_sha = sys.argv[2]
bundle_spdx = pathlib.Path(sys.argv[3])
rows = sys.argv[4:]

def sha256(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()

images = []
for row in rows:
    component, image_id, _, _ = row.split("\t", 3)
    path = bundle_spdx.parent / "images" / f"{component}.spdx.json"
    images.append({"component": component, "image_id": image_id,
                   "path": f"sbom/images/{component}.spdx.json", "sha256": sha256(path)})
payload = {
    "schema": "jjdguard-release-sbom-index/v1",
    "syft": {"version": "1.44.0", "binary_sha256": syft_sha},
    "bundle": {"path": "sbom/bundle.spdx.json", "sha256": sha256(bundle_spdx)},
    "images": images,
}
index_path.write_text(json.dumps(payload, sort_keys=True, indent=2) + "\n", encoding="utf-8")
PY

install -d -m 0755 "$BUNDLE_DIR/sbom/images"
install -m 0444 "$bundle_tmp" "$BUNDLE_DIR/sbom/bundle.spdx.json"
for row in "${image_rows[@]}"; do
  IFS=$'\t' read -r component _ _ _ <<<"$row"
  install -m 0444 "$WORK_DIR/images/$component.spdx.json" "$BUNDLE_DIR/sbom/images/$component.spdx.json"
done
install -m 0444 "$index_tmp" "$BUNDLE_DIR/sbom/index.json"
python3 "$VERIFIER" --bundle "$BUNDLE_DIR" --provenance "$PROVENANCE_FILE" \
  --index "$BUNDLE_DIR/sbom/index.json"
printf '[ok] release SBOM generated: images=%s syft=1.44.0\n' "${#image_rows[@]}"
