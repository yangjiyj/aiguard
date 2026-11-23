#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VERIFIER="$SCRIPT_DIR/verify-security-engine-python-deps.py"
REQUIREMENTS_LOCK="$SCRIPT_DIR/../../apps/security-engine/requirements.offline.lock"

source_image=
output=

die() {
  printf '[security-engine-python-deps][error] %s\n' "$*" >&2
  exit 1
}

while (($#)); do
  case "$1" in
    --source-image) source_image=$2; shift 2 ;;
    --output) output=$2; shift 2 ;;
    *) die "unknown argument: $1" ;;
  esac
done

[[ -n "$source_image" && "$output" == /* ]] ||
  die '--source-image and absolute --output are required'
[[ -x "$VERIFIER" && -f "$REQUIREMENTS_LOCK" ]] ||
  die 'security-engine dependency verifier or offline lock is unavailable'
[[ ! -e "$output" && ! -L "$output" ]] ||
  die "output already exists: $output"
command -v docker >/dev/null 2>&1 || die 'docker is required'
command -v jq >/dev/null 2>&1 || die 'jq is required'
command -v python3 >/dev/null 2>&1 || die 'python3 is required'

parent="$(dirname "$output")"
if [[ ! -e "$parent" ]]; then
  install -d -m 0700 "$parent"
fi
[[ -d "$parent" && ! -L "$parent" && "$(realpath -e "$parent")" == "$parent" ]] ||
  die "output parent must be a canonical real directory: $parent"

image_id="$(docker image inspect "$source_image" --format '{{.Id}}')" ||
  die "source image is unavailable locally: $source_image"
[[ "$image_id" =~ ^sha256:[0-9a-f]{64}$ ]] || die 'source image ID is invalid'

tmp="$(mktemp -d "$parent/.security-engine-python-deps.XXXXXX")"
cid=
cleanup() {
  if [[ -n "$cid" ]]; then
    docker rm "$cid" >/dev/null 2>&1 || true
  fi
  if [[ -n "$tmp" && -d "$tmp" ]]; then
    rm -rf -- "$tmp"
  fi
}
trap cleanup EXIT HUP INT TERM

cid="$(docker create --network none "$source_image")"
docker cp "$cid:/usr/local/lib/python3.11/site-packages" "$tmp/site-packages"
docker rm "$cid" >/dev/null
cid=
jq -cn \
  --arg schema jjdguard-security-engine-python-deps-source/v1 \
  --arg origin home-existing-security-engine-image \
  --arg image "$source_image" \
  --arg image_id "$image_id" \
  '{schema:$schema,origin:$origin,source_image:$image,source_image_id:$image_id}' \
  >"$tmp/source.json"

receipt="$(python3 "$VERIFIER" --requirements-lock "$REQUIREMENTS_LOCK" --input "$tmp")" ||
  die 'copied source image dependencies do not match requirements.offline.lock'
mv "$tmp" "$output"
tmp=
printf '%s\n' "$receipt"
