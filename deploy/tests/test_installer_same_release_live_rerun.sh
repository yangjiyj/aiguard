#!/usr/bin/env bash
# Regression: re-running the same signed .run while its own release is live must
# take the same-release repair path, not the live upgrader (which self-copies tls/).
set -Eeuo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
INSTALLER="$ROOT/deploy/offline-installer/installer.sh"
PACKAGER="$ROOT/deploy/docker-compose/package-offline-bundle.sh"

fail() { echo "[fail] $*" >&2; exit 1; }

candidate_gate="$(sed -n '/^run_candidate_static_gates()/,/^}/p' "$PACKAGER")"
[[ "$candidate_gate" == *'test_installer_same_release_live_rerun.sh'* ]] || \
  fail 'candidate package gate must run the same-release live rerun regression'

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
mkdir -p "$tmp/releases/jjdguard-x/deploy/docker-compose" "$tmp/releases/jjdguard-old/deploy/docker-compose"

run_main() {
  local live_dir="$1"
  JJD_INSTALLER_LIB_ONLY=1 bash -s -- "$INSTALLER" "$tmp" "$live_dir" <<'BASH'
set -Eeuo pipefail
source "$1"
tmp="$2"; live_dir="$3"
preflight() { :; }
acquire_install_lock() { :; }
discover_running_compose() { [[ -z "$live_dir" ]] || printf 'proj|%s\n' "$live_dir"; }
discover_current() { :; }
stage_release() { printf '%s\n' "$tmp/releases/jjdguard-x"; }
live_upgrade_install() { echo "CALL live_upgrade_install $1 $2"; }
# upgrade_install derives old_dc from the caller-scoped $old while expanding its
# own locals, so main must set old to the same release before calling it.
upgrade_install() { echo "CALL upgrade_install $1 $2 old=${old:-}"; }
fresh_install() { echo "CALL fresh_install $1"; }
main
BASH
}

rel="$tmp/releases/jjdguard-x"

out="$(run_main "$rel/deploy/docker-compose")"
grep -Fxq "CALL upgrade_install $rel $rel old=$rel" <<<"$out" || fail "same release live rerun must use repair path: $out"
grep -Fq 'CALL live_upgrade_install' <<<"$out" && fail "same release must not use live upgrader: $out"

# Same directory reached through a different spelling must still match.
out="$(run_main "$rel/deploy/../deploy/docker-compose")"
grep -Fxq "CALL upgrade_install $rel $rel old=$rel" <<<"$out" || fail "equivalent path must match: $out"

old="$tmp/releases/jjdguard-old/deploy/docker-compose"
out="$(run_main "$old")"
grep -Fxq "CALL live_upgrade_install $rel proj|$old" <<<"$out" || fail "different live release must use live upgrader: $out"

out="$(run_main '')"
grep -Fxq "CALL fresh_install $rel" <<<"$out" || fail "no instance must fresh install: $out"

echo '[ok] same-release live rerun routes to repair path'
