#!/usr/bin/env bash
set -Eeuo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
upgrade="$root/deploy/docker-compose/upgrade-bundle.sh"
tmp="$(mktemp -d)"
trap 'rm -rf -- "$tmp"' EXIT

extract() {
  local name="$1"
  awk -v name="$name" '$0 ~ "^" name "\\(\\) \\{" {inside=1} inside {print} inside && /^}/ {exit}' "$upgrade"
}
extract generated_image_pin_layer >"$tmp/functions.sh"
extract prepare_active_configuration >>"$tmp/functions.sh"
[[ "$(grep -Fc 'generated_image_pin_layer "$snapshot" && continue' "$upgrade")" -eq 2 ]] ||
  { echo 'both upgrade and legacy rollback anchor must filter generated image pins' >&2; exit 1; }

mkdir -p "$tmp/old/active-config/first" "$tmp/new" "$tmp/snapshots"
base="$tmp/old/docker-compose.offline.yml"
customer="$tmp/old/active-config/first/customer.yml"
pin="$tmp/old/backups/20260929T000000Z/rollback-compose.yml"
mkdir -p "${pin%/*}"
printf 'services:\n  redis:\n    image: valkey/valkey:8.1.10-alpine\n' >"$base"
printf 'services:\n  gateway-core:\n    environment:\n      CUSTOMER_SETTING: retained\n' >"$customer"
printf 'services:\n  redis:\n    image: sha256:%064d\n  postgres:\n    image: sha256:%064d\n' 0 0 >"$pin"
cp "$base" "$tmp/snapshots/base.yml"
cp "$customer" "$tmp/snapshots/customer.yml"
cp "$pin" "$tmp/snapshots/pin.yml"

source "$tmp/functions.sh"
fail() { echo "$*" >&2; exit 1; }
validate_config_snapshots() { :; }
sha256_file() { sha256sum "$1" | cut -d' ' -f1; }
SCRIPT_DIR="$tmp/new"
EXISTING_WORK_DIR="$tmp/old"
DEVELOPMENT_NORMALIZED_CONFIG=0
UPGRADE_RUN_TIMESTAMP=20260929T010000Z
EXISTING_CONFIG_FILES="$base,$customer,$pin"
OLD_CONFIG_SNAPSHOT_FILES="$tmp/snapshots/base.yml,$tmp/snapshots/customer.yml,$tmp/snapshots/pin.yml"
prepare_active_configuration
[[ "$(find "$ACTIVE_CONFIG_DIR" -type f | wc -l)" -eq 1 ]] || fail 'generated image pin was inherited'
grep -Fq CUSTOMER_SETTING "$ACTIVE_CONFIG_FILES" || fail 'customer override was lost'
! grep -Rq 'sha256:' "$ACTIVE_CONFIG_DIR" || fail 'old Redis image survived the retry'

# A second failed attempt must not grow an inherited digest-pin chain.
first="$ACTIVE_CONFIG_FILES"
UPGRADE_RUN_TIMESTAMP=20260929T020000Z
EXISTING_CONFIG_FILES="$base,$first,$pin"
OLD_CONFIG_SNAPSHOT_FILES="$tmp/snapshots/base.yml,$first,$tmp/snapshots/pin.yml"
prepare_active_configuration
[[ "$(find "$ACTIVE_CONFIG_DIR" -type f | wc -l)" -eq 1 ]] || fail 'retry accumulated image pins'
grep -Fq CUSTOMER_SETTING "$ACTIVE_CONFIG_FILES" || fail 'customer override was lost on retry'

printf 'services:\n  redis:\n    image: sha256:%064d\n    command: custom\n' 0 >"$tmp/not-pure.yml"
if generated_image_pin_layer "$tmp/not-pure.yml"; then
  fail 'a customer setting must keep its override layer'
fi
echo 'retry after failed upgrade: PASS'
