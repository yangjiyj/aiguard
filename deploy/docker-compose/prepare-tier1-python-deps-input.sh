#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VERIFIER="$SCRIPT_DIR/verify-tier1-python-deps.py"
REQUIREMENTS_LOCK="$SCRIPT_DIR/../../apps/tier1-classifier/requirements.lock"

source_image=
output=

die() {
  printf '[tier1-python-deps][error] %s\n' "$*" >&2
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
  die 'Tier1 dependency verifier or requirements lock is unavailable'
[[ ! -e "$output" && ! -L "$output" ]] ||
  die "output already exists: $output"
command -v docker >/dev/null 2>&1 || die 'docker is required'
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

tmp="$(mktemp -d "$parent/.tier1-python-deps.XXXXXX")"
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
  --arg schema jjdguard-tier1-python-deps-source/v1 \
  --arg origin home-existing-tier1-image \
  --arg image "$source_image" \
  --arg image_id "$image_id" \
  '{schema:$schema,origin:$origin,source_image:$image,source_image_id:$image_id}' \
  >"$tmp/source.json"

receipt="$(python3 "$VERIFIER" --requirements-lock "$REQUIREMENTS_LOCK" --input "$tmp")" ||
  die 'copied source image dependencies do not match requirements.lock'
mv "$tmp" "$output"
tmp=
printf '%s\n' "$receipt"
