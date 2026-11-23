#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

source_image=
output=

die() {
  printf '[alpine-runtime-input][error] %s\n' "$*" >&2
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
[[ ! -e "$output" && ! -L "$output" ]] || die "output already exists: $output"
command -v docker >/dev/null 2>&1 || die 'docker is required'
command -v jq >/dev/null 2>&1 || die 'jq is required'

parent="$(dirname "$output")"
if [[ ! -e "$parent" ]]; then
  install -d -m 0700 "$parent"
fi
[[ -d "$parent" && ! -L "$parent" && "$(realpath -e "$parent")" == "$parent" ]] ||
  die "output parent must be a canonical real directory: $parent"

image_id="$(docker image inspect "$source_image" --format '{{.Id}}')" ||
  die "source image is unavailable locally: $source_image"
[[ "$image_id" =~ ^sha256:[0-9a-f]{64}$ ]] || die 'source image ID is invalid'

tmp="$(mktemp -d "$parent/.alpine-runtime.XXXXXX")"
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

install -d -m 0700 "$tmp/etc" "$tmp/usr/share"
cid="$(docker create --network none "$source_image")"
docker cp "$cid:/etc/ssl" "$tmp/etc"
docker cp "$cid:/etc/ca-certificates.conf" "$tmp/etc/ca-certificates.conf"
docker cp "$cid:/usr/share/zoneinfo" "$tmp/usr/share"
docker rm "$cid" >/dev/null
cid=

jq -cn \
  --arg schema jjdguard-alpine-runtime-input/v1 \
  --arg origin home-existing-gateway-runtime \
  --arg image "$source_image" \
  --arg image_id "$image_id" \
  '{schema:$schema,origin:$origin,source_image:$image,source_image_id:$image_id}' \
  >"$tmp/source.json"

[[ -d "$tmp/etc/ssl/certs" && -f "$tmp/etc/ssl/cert.pem" &&
   -f "$tmp/etc/ca-certificates.conf" && -d "$tmp/usr/share/zoneinfo" ]] ||
  die 'source image does not provide the required CA and timezone runtime files'
mv "$tmp" "$output"
tmp=
printf '[ok] prepared local Alpine runtime input from %s\n' "$source_image"
