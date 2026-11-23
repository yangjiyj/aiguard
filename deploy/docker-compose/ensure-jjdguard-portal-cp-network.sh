#!/usr/bin/env bash
set -Eeuo pipefail

name="${JJD_PORTAL_CP_NETWORK:-jjdguard-portal-control-net}"
owner="jjdguard"
remove=0
usage() {
  echo "Usage: $0 [--name NETWORK] [--owner OWNER] [--remove-if-owner OWNER]" >&2
}
while (($#)); do
  case "$1" in
    --name) shift; name="${1:-}" ;;
    --owner) shift; owner="${1:-}" ;;
    --remove-if-owner) shift; owner="${1:-}"; remove=1 ;;
    -h|--help) usage; exit 0 ;;
    *) usage; exit 64 ;;
  esac
  shift
done
case "$name" in
  ''|*[!a-zA-Z0-9_.-]*) echo '[error] invalid network name' >&2; exit 64 ;;
esac
case "$owner" in
  ''|*[!a-zA-Z0-9_.-]*) echo '[error] invalid network owner' >&2; exit 64 ;;
esac

exists=0
if docker network inspect "$name" >/dev/null 2>&1; then exists=1; fi
if ((remove)); then
  ((exists)) || exit 0
  actual_owner="$(docker network inspect "$name" --format '{{index .Labels "com.jjdguard.owner"}}')"
  purpose="$(docker network inspect "$name" --format '{{index .Labels "com.jjdguard.purpose"}}')"
  if [[ "$actual_owner" != "$owner" || "$purpose" != "portal-control" ]]; then
    echo '[error] refusing to remove network with different owner or purpose' >&2
    exit 1
  fi
  members="$(docker network inspect "$name" --format '{{len .Containers}}')"
  if [[ "$members" != "0" ]]; then
    echo '[error] refusing to remove non-empty portal-control network' >&2
    exit 1
  fi
  docker network rm "$name" >/dev/null
  printf 'portal_control_network=removed name=%s owner=%s\n' "$name" "$owner"
  exit 0
fi

if ((exists)); then
  driver="$(docker network inspect "$name" --format '{{.Driver}}')"
  internal="$(docker network inspect "$name" --format '{{.Internal}}')"
  actual_owner="$(docker network inspect "$name" --format '{{index .Labels "com.jjdguard.owner"}}')"
  purpose="$(docker network inspect "$name" --format '{{index .Labels "com.jjdguard.purpose"}}')"
  if [[ "$driver" != "bridge" || "$internal" != "true" || "$actual_owner" != "$owner" || "$purpose" != "portal-control" ]]; then
    printf '[error] network attribute drift: name=%s\n' "$name" >&2
    exit 1
  fi
  printf 'portal_control_network=ready name=%s owner=%s created=0\n' "$name" "$owner"
  exit 0
fi

docker network create \
  --driver bridge \
  --internal \
  --label "com.jjdguard.owner=$owner" \
  --label com.jjdguard.purpose=portal-control \
  "$name" >/dev/null
driver="$(docker network inspect "$name" --format '{{.Driver}}')"
internal="$(docker network inspect "$name" --format '{{.Internal}}')"
actual_owner="$(docker network inspect "$name" --format '{{index .Labels "com.jjdguard.owner"}}')"
purpose="$(docker network inspect "$name" --format '{{index .Labels "com.jjdguard.purpose"}}')"
if [[ "$driver" != "bridge" || "$internal" != "true" || "$actual_owner" != "$owner" || "$purpose" != "portal-control" ]]; then
  echo '[error] created network failed verification' >&2
  exit 1
fi
printf 'portal_control_network=ready name=%s owner=%s created=1\n' "$name" "$owner"
