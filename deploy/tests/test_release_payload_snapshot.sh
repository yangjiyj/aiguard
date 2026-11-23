#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PACKAGER="$ROOT/deploy/docker-compose/package-offline-bundle.sh"
HELPER="$ROOT/deploy/docker-compose/lib-release-payload-snapshot.sh"

fail() {
  printf '[release-payload-snapshot-test] %s\n' "$*" >&2
  exit 1
}

[[ -f "$HELPER" ]] || fail 'release payload snapshot helper is missing'
grep -Fq '. "$SCRIPT_DIR/lib-release-payload-snapshot.sh"' "$PACKAGER" ||
  fail 'packager does not load the immutable payload snapshot helper'
grep -Fq 'create_release_payload_snapshot "$PROJECT_ROOT" "$SOURCE_REVISION" "$PAYLOAD_SOURCE_ROOT"' "$PACKAGER" ||
  fail 'packager does not snapshot the verified source revision'
grep -Fq 'cp -R "$PAYLOAD_SOURCE_ROOT/deploy/offline-installer"' "$PACKAGER" ||
  fail 'packager copies installer payload from the immutable source snapshot'
grep -Fq 'cd "$PAYLOAD_SOURCE_ROOT/apps/control-plane"' "$PACKAGER" ||
  fail 'packager generates the trial license from the immutable source snapshot'

scratch="$(mktemp -d "${TMPDIR:-/tmp}/jjdguard-payload-snapshot-test.XXXXXX")"
cleanup() {
  rm -rf "$scratch"
}
trap cleanup EXIT HUP INT TERM

repo="$scratch/source"
snapshot="$scratch/snapshot"
mkdir -p "$repo/deploy/offline-installer"
mkdir -p "$snapshot"
git -C "$repo" init -q
git -C "$repo" config user.name 'JJDGuard release test'
git -C "$repo" config user.email 'release-test@example.invalid'
printf 'original-version\n' >"$repo/VERSION"
printf 'original-installer\n' >"$repo/deploy/offline-installer/install.sh"
git -C "$repo" add VERSION deploy/offline-installer/install.sh
git -C "$repo" commit -qm 'test snapshot source'
revision="$(git -C "$repo" rev-parse HEAD)"

# shellcheck disable=SC1090
. "$HELPER"
caller_umask="$(umask)"
create_release_payload_snapshot "$repo" "$revision" "$snapshot"
[[ "$(umask)" == "$caller_umask" ]] ||
  fail 'snapshot helper changed the caller umask'

printf 'mutated-version\n' >"$repo/VERSION"
printf 'mutated-installer\n' >"$repo/deploy/offline-installer/install.sh"
[[ "$(cat "$snapshot/VERSION")" == 'original-version' ]] ||
  fail 'snapshot version changed after worktree mutation'
[[ "$(cat "$snapshot/deploy/offline-installer/install.sh")" == 'original-installer' ]] ||
  fail 'snapshot installer changed after worktree mutation'

printf '[ok] release payload copies are bound to the verified Git revision snapshot\n'
