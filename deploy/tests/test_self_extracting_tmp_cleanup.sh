#!/usr/bin/env bash
# Regression: a successful v2 .run installation must remove its temporary payload.
set -Eeuo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
HEADER="$ROOT/deploy/offline-installer/self-extracting-header.sh"
# shellcheck source=lib-self-extracting-v2-fixture.sh
. "$ROOT/deploy/tests/lib-self-extracting-v2-fixture.sh"

fail() { echo "[fail] $*" >&2; exit 1; }
assert_contains() { grep -Fq -- "$2" "$1" || fail "$1 missing: $2"; }

[[ -f "$HEADER" ]] || fail "missing header: $HEADER"
command -v docker >/dev/null 2>&1 || { echo '[skip] docker unavailable'; exit 0; }
docker info >/dev/null 2>&1 || { echo '[skip] docker daemon unavailable'; exit 0; }
stamp_image='python:3.12-slim'
docker image inspect "$stamp_image" >/dev/null 2>&1 || { echo "[skip] $stamp_image not available"; exit 0; }

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
fixture_root="$tmp/payload/jjdguard-fixture"
mkdir -p "$tmp/payload"
openssl genpkey -algorithm Ed25519 -out "$tmp/release.key" >/dev/null 2>&1
openssl pkey -in "$tmp/release.key" -pubout -out "$tmp/release.pub" >/dev/null 2>&1
jjd_v2_make_bundle "$fixture_root" "$tmp/release.key" amd64 "$ROOT/deploy/docker-compose/release-toolchain.lock"
printf '%s\n' '#!/usr/bin/env bash' 'set -Eeuo pipefail' "echo 'fixture install: ok'" >"$fixture_root/install.sh"
chmod 755 "$fixture_root/install.sh"
jjd_v2_write_inventory "$fixture_root"
jjd_v2_seal_run "$HEADER" "$tmp/release.key" "$tmp/release.pub" "$fixture_root" "$tmp/fixture.run" "$tmp/outer" amd64

verify_output="$(bash "$tmp/fixture.run" --verify-only)"
[[ -n "$verify_output" ]] || fail 'fixture verification produced no success output'

# This test is only about cleanup after an isolated candidate install. Formal
# promotion verification is covered by test_offline_promotion.sh through the
# independently pre-provisioned verifier.
f13_output="$(docker run --rm -v "$tmp:/fixture:ro" "$stamp_image" \
  bash -c 'bash /fixture/fixture.run >/tmp/run.log 2>&1; rc=$?; echo "EXIT=$rc"; if ls -d /tmp/jjdguard-installer.* >/dev/null 2>&1; then echo RESIDUE; else echo CLEANED; fi')"
assert_contains <(printf '%s' "$f13_output") 'EXIT=0'
assert_contains <(printf '%s' "$f13_output") 'CLEANED'
echo '[ok] self-extracting temporary payload is cleaned after successful v2 installation'
