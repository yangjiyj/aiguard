#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
INSTALLER="$ROOT/deploy/offline-installer/installer.sh"
UPGRADE_BUNDLE="$ROOT/deploy/docker-compose/upgrade-bundle.sh"
fail() { echo "[fail] $*" >&2; exit 1; }

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
opt_root="$tmp/opt/jjdguard"
development_root="$opt_root/development-releases"
dev_release="$development_root/dev-legacy-20260906"
new_release="$opt_root/releases/jjdguard-2.6.7-amd64"
mkdir -p "$dev_release" "$new_release/deploy/docker-compose/.upgrade"

printf '%s\n' '{"status":"deployed","release_id":"dev-legacy-20260906","revision":"0123456789abcdef0123456789abcdef01234567","version":"2.6.5","services":{"gateway-core":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},"backup":"/opt/jjdguard/development-releases/dev-legacy-20260906/state/database.dump"}' >"$dev_release/receipt.json"
chmod 0600 "$dev_release/receipt.json"
receipt_sha="$(sha256sum "$dev_release/receipt.json" | awk '{print $1}')"
printf '%s\n' "{\"release\":\"$dev_release\",\"receipt_sha256\":\"$receipt_sha\"}" >"$development_root/current.json"
chmod 0600 "$development_root/current.json"

JJD_INSTALLER_LIB_ONLY=1
source "$INSTALLER"
OPT_ROOT="$opt_root"
capture_development_receipt "$new_release"

copied="$new_release/deploy/docker-compose/.upgrade/development-receipt"
# 必须与 upgrade-bundle.sh 的 validate_digest_from_development_receipt 读取路径一致：
# 该函数用自己的 SCRIPT_DIR（<release>/deploy/docker-compose）拼 .upgrade/development-receipt。
grep -q 'receipt_dir="\$SCRIPT_DIR/.upgrade/development-receipt"' "$UPGRADE_BUNDLE" ||
  { echo "[fail] upgrade-bundle receipt path contract changed"; exit 1; }
[[ -f "$copied/current.json" && -f "$copied/receipt.json" && -f "$copied/receipt.sha256" ]] ||
  fail 'development receipt was not copied into the new release'
[[ "$(cat "$copied/receipt.sha256")" == "$receipt_sha" ]] ||
  fail 'copied development receipt digest changed'
[[ "$(stat -c '%a' "$copied/current.json")" == 600 ]] ||
  fail 'copied development receipt index mode is unsafe'
[[ "$(stat -c '%a' "$copied/receipt.json")" == 600 ]] ||
  fail 'copied development receipt mode is unsafe'
[[ "$DEVELOPMENT_RECEIPT_DIR" == "$copied" ]] ||
  fail 'installer did not retain the development receipt location'
grep -Fq 'validate_digest_from_development_receipt' "$UPGRADE_BUNDLE" ||
  fail 'bundle upgrade does not recognize development rollback receipts'
grep -Fq 'validate_digest_from_installed_release' "$UPGRADE_BUNDLE" ||
  fail 'bundle upgrade does not recognize a verified installed release as a legacy rollback source'
! grep -Eq 'verify-development-rollback[.]py|python3' "$UPGRADE_BUNDLE" ||
  fail 'customer bundle upgrade reintroduced a Python rollback verifier'

printf '%s\n' "{\"release\":\"$dev_release\",\"receipt_sha256\":\"$(printf bad | sha256sum | awk '{print $1}')\"}" >"$development_root/current.json"
chmod 0600 "$development_root/current.json"
set +e
(capture_development_receipt "$new_release") >/tmp/jjdguard-development-receipt-test.out 2>&1
bad_status=$?
set -e
[[ "$bad_status" -ne 0 ]] || fail 'tampered development receipt was accepted'

echo '[ok] development deployment receipt is validated, preserved, and fail-closed'
