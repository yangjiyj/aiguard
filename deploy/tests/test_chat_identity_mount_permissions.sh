#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
HELPER="$ROOT_DIR/deploy/docker-compose/lib-identity-mounts.sh"
DEPLOY_SCRIPT="$ROOT_DIR/deploy/docker-compose/deploy-offline.sh"
PACKAGE_SCRIPT="$ROOT_DIR/deploy/docker-compose/package-offline-bundle.sh"

fail() {
  echo "[fail] $*" >&2
  exit 1
}

file_mode() {
  if stat -c '%a' "$1" >/dev/null 2>&1; then
    stat -c '%a' "$1"
  else
    stat -f '%Lp' "$1"
  fi
}

make_payload() {
  local root="$1"
  (
    umask 077
    mkdir -p \
      "$root/chat/keycloak-realm/nested" \
      "$root/chat/keycloak-themes/jjdguard/login/resources" \
      "$root/directory-truststore/certs"
    printf '%s\n' '{"realm":"jjdguard"}' >"$root/chat/keycloak-realm/realm-jjdguard.json"
    printf '%s\n' 'theme' >"$root/chat/keycloak-themes/jjdguard/login/theme.properties"
    printf '%s\n' 'certificate' >"$root/directory-truststore/certs/customer.pem"
  )
}

assert_payload_modes() {
  local root="$1" path
  while IFS= read -r path; do
    [[ "$(file_mode "$path")" == 755 ]] ||
      fail "directory mode for $path is $(file_mode "$path"), want 755"
  done < <(find \
    "$root/chat/keycloak-realm" \
    "$root/chat/keycloak-themes/jjdguard" \
    "$root/directory-truststore" \
    -type d -print)

  while IFS= read -r path; do
    [[ "$(file_mode "$path")" == 644 ]] ||
      fail "file mode for $path is $(file_mode "$path"), want 644"
  done < <(find \
    "$root/chat/keycloak-realm" \
    "$root/chat/keycloak-themes/jjdguard" \
    "$root/directory-truststore" \
    -type f -print)
}

snapshot_modes() {
  local root="$1"
  find \
    "$root/chat/keycloak-realm" \
    "$root/chat/keycloak-themes/jjdguard" \
    "$root/directory-truststore" \
    -printf '%m %P\n' | LC_ALL=C sort
}

expect_failure() {
  local label="$1" root="$2" output
  if output="$(sh "$HELPER" "$root" 2>&1)"; then
    fail "$label was accepted"
  fi
  [[ "$output" == '[error] invalid built-in identity mount payload' ]] ||
    fail "$label returned unstable output: <$output>"
}

function_body() {
  local name="$1" file="$2"
  awk -v signature="${name}() {" '
    $0 == signature { found = 1 }
    found { print }
    found && /^}$/ { exit }
  ' "$file"
}

[[ -f "$HELPER" ]] || fail "identity mount helper is missing: $HELPER"
grep -Fqx 'prepare_chat_identity_mounts() {' "$DEPLOY_SCRIPT" ||
  fail 'deploy script does not define prepare_chat_identity_mounts'
grep -Fq 'cp "$PAYLOAD_SOURCE_ROOT/deploy/docker-compose"/lib-identity-mounts.sh "$BUNDLE_DIR/deploy/docker-compose/"' "$PACKAGE_SCRIPT" ||
  fail 'packager does not copy the identity mount helper into the bundle'
grep -Fq 'cp -R "$PAYLOAD_SOURCE_ROOT/deploy/docker-compose/directory-truststore" "$BUNDLE_DIR/deploy/docker-compose/"' "$PACKAGE_SCRIPT" ||
  fail 'chat bundle does not copy the built-in directory truststore payload'
grep -Fq 'sh "$BUNDLE_DIR/deploy/docker-compose/lib-identity-mounts.sh" "$BUNDLE_DIR/deploy/docker-compose"' "$PACKAGE_SCRIPT" ||
  fail 'chat bundle does not validate its copied identity mount payload'

fixture_root="$(mktemp -d)"
trap 'rm -rf "$fixture_root"' EXIT

internal="$fixture_root/internal"
make_payload "$internal"
sh "$HELPER" "$internal"
assert_payload_modes "$internal"
first_snapshot="$(snapshot_modes "$internal")"
sh "$HELPER" "$internal"
[[ "$(snapshot_modes "$internal")" == "$first_snapshot" ]] ||
  fail 'identity mount permission preparation is not idempotent'

spaced="$fixture_root/path with spaces"
make_payload "$spaced"
sh "$HELPER" "$spaced"
assert_payload_modes "$spaced"

missing_realm="$fixture_root/missing-realm"
make_payload "$missing_realm"
rm -rf "$missing_realm/chat/keycloak-realm"
expect_failure 'missing realm directory' "$missing_realm"
[[ "$(file_mode "$missing_realm/chat/keycloak-themes/jjdguard")" == 700 ]] ||
  fail 'preflight failure changed theme permissions'

missing_theme="$fixture_root/missing-theme"
make_payload "$missing_theme"
rm -rf "$missing_theme/chat/keycloak-themes/jjdguard"
expect_failure 'missing theme directory' "$missing_theme"
[[ "$(file_mode "$missing_theme/chat/keycloak-realm")" == 700 ]] ||
  fail 'preflight failure changed realm permissions'

symlink_case="$fixture_root/symlink"
make_payload "$symlink_case"
printf '%s\n' 'do-not-follow' >"$symlink_case/outside"
chmod 0600 "$symlink_case/outside"
ln -s "$symlink_case/outside" "$symlink_case/chat/keycloak-realm/linked"
expect_failure 'symbolic link member' "$symlink_case"
[[ "$(file_mode "$symlink_case/outside")" == 600 ]] ||
  fail 'symbolic link target permissions were changed'
[[ "$(file_mode "$symlink_case/chat/keycloak-realm")" == 700 ]] ||
  fail 'symlink preflight failure changed payload permissions'

fifo_case="$fixture_root/fifo"
make_payload "$fifo_case"
mkfifo "$fifo_case/chat/keycloak-themes/jjdguard/login/blocked.fifo"
expect_failure 'FIFO member' "$fifo_case"
[[ "$(file_mode "$fifo_case/chat/keycloak-realm")" == 700 ]] ||
  fail 'special-file preflight failure changed payload permissions'

byo="$fixture_root/byo"
mkdir -p "$byo"
harness="$fixture_root/run-byo.sh"
{
  printf '%s\n' '#!/bin/sh' 'set -eu'
  function_body prepare_chat_identity_mounts "$DEPLOY_SCRIPT"
  printf '%s\n' \
    "SCRIPT_DIR='$byo'" \
    'BUNDLE_CHAT=1' \
    'CHAT_BYO_IDP=true' \
    'prepare_chat_identity_mounts'
} >"$harness"
sh "$harness"
[[ -z "$(find "$byo" -mindepth 1 -print -quit)" ]] ||
  fail 'CHAT_BYO_IDP=true touched built-in identity payload paths'

echo '[ok] chat identity mount permissions are safe under umask 077'
