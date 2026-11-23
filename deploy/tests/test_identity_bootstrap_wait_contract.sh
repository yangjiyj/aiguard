#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(CDPATH= cd -- "$(dirname "$0")/../.." && pwd)"
IDENTITY="$ROOT_DIR/deploy/docker-compose/chat/bootstrap-identity-runtime.sh"
DIRECTORY="$ROOT_DIR/deploy/docker-compose/chat/bootstrap-directory-runtime.sh"

fail() {
  echo "[fail] $*" >&2
  exit 1
}

for script in "$IDENTITY" "$DIRECTORY"; do
  bash -n "$script"
  grep -q 'IDENTITY_BOOTSTRAP_MAX_ATTEMPTS:-180' "$script" ||
    fail "$script must retain the six-minute bounded default"
done

count="$(grep -c 'IDENTITY_BOOTSTRAP_MAX_ATTEMPTS:-180' "$IDENTITY")"
[ "$count" -eq 2 ] || fail "identity bootstrap must use the same bound for discovery and reconciliation"

grep -q 'IDENTITY_BOOTSTRAP_INTERVAL_SECONDS:-2' "$IDENTITY" ||
  fail "identity bootstrap interval contract is missing"
grep -q 'IDENTITY_BOOTSTRAP_INTERVAL_SECONDS:-2' "$DIRECTORY" ||
  fail "directory bootstrap interval contract is missing"

echo '[ok] identity bootstrap wait remains bounded and covers first-start augmentation'
