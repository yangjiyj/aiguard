#!/usr/bin/env bash
set -Eeuo pipefail
umask 077
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
UPGRADE="$ROOT/deploy/docker-compose/upgrade-bundle.sh"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
source "$UPGRADE"
validate_config_snapshots() { return 0; }

EXISTING_WORK_DIR="$tmp/old/deploy/docker-compose"
SCRIPT_DIR="$tmp/new/deploy/docker-compose"
mkdir -p "$EXISTING_WORK_DIR/active-config" "$SCRIPT_DIR"
release_id="dev-test-20260923T000000Z"
source_file="$EXISTING_WORK_DIR/active-config/$release_id.json"
snapshot="$tmp/config-000.yml"
printf '%s\n' '{"name":"jjdguard","services":{"gateway-core":{"image":"sha256:old","environment":{"GATEWAY_INPUT_SECURITY_REQUEST_TIMEOUT":"60"},"ports":["8080:8080"]}}}' >"$source_file"
cp "$source_file" "$snapshot"
EXISTING_CONFIG_FILES="$source_file"
OLD_CONFIG_SNAPSHOT_FILES="$snapshot"
hash="$(sha256sum "$snapshot" | cut -d' ' -f1)"
receipt="$tmp/receipt.json"
printf '{"compose_sha256":"%s"}\n' "$hash" >"$receipt"
development_normalized_config_matches_receipt "$receipt" "$release_id" ||
  { echo "valid normalized configuration rejected" >&2; exit 1; }

DEVELOPMENT_NORMALIZED_CONFIG=1
UPGRADE_RUN_TIMESTAMP=20260923T000000Z
prepare_active_configuration
# A normalized historical base is rollback evidence, not an override for the
# new base: copying it appends ports and keeps old release mount paths. The
# customer's .env and extra overrides are inherited by the upgrade contract.
[[ -z "$ACTIVE_CONFIG_FILES" ]] || { echo "historical canonical base layered over new release" >&2; exit 1; }

printf '%s\n' 'services: {}' >"$EXISTING_WORK_DIR/docker-compose.offline.yml"
COMPOSE_WRAPPER=/bin/true
EXISTING_PROJECT_NAME=jjdguard
OLD_ENV_SNAPSHOT_FILE="$tmp/old.env"
BACKUP_DIR="$tmp/backup"
mkdir -p "$BACKUP_DIR"
touch "$OLD_ENV_SNAPSHOT_FILE" "$BACKUP_DIR/rollback-compose.yml"
old_compose_args
printf '%s\n' "${OLD_COMPOSE_ARGS[@]}" | grep -Fxq "$snapshot" ||
  { echo "rollback omitted normalized snapshot" >&2; exit 1; }
if printf '%s\n' "${OLD_COMPOSE_ARGS[@]}" | grep -Fxq "$EXISTING_WORK_DIR/docker-compose.offline.yml"; then
  echo "rollback incorrectly used old formal base" >&2; exit 1
fi

printf '%s\n' '{"compose_sha256":"0000000000000000000000000000000000000000000000000000000000000000"}' >"$receipt"
if development_normalized_config_matches_receipt "$receipt" "$release_id"; then
  echo "wrong receipt hash accepted" >&2; exit 1
fi
printf '{"compose_sha256":"%s"}\n' "$hash" >"$receipt"
printf '\n' >>"$snapshot"
if development_normalized_config_matches_receipt "$receipt" "$release_id"; then
  echo "changed Compose snapshot accepted" >&2; exit 1
fi
cp "$source_file" "$snapshot"
EXISTING_CONFIG_FILES="$tmp/other.json"
if development_normalized_config_matches_receipt "$receipt" "$release_id"; then
  echo "unrelated Compose source accepted" >&2; exit 1
fi
EXISTING_CONFIG_FILES="$source_file"
DEVELOPMENT_NORMALIZED_CONFIG=0
if (prepare_active_configuration) >/dev/null 2>&1; then
  echo "unproved normalized configuration accepted" >&2; exit 1
fi
# A non-recreated postgres retains the old base label after a development
# release. The read-only version probe may inspect it within the same trusted
# project, while backup still requires the exact active chain after healing.
printf '%s\n' 'services: {}' >"$EXISTING_WORK_DIR/docker-compose.offline.yml"
touch "$EXISTING_WORK_DIR/.env"
chmod 600 "$EXISTING_WORK_DIR/.env"
EXISTING_CONFIG_OWNER_UID="$(id -u)"
EXISTING_CONFIG_OWNER_GID="$(id -g)"
EXISTING_CONFIG_ROOT="$EXISTING_WORK_DIR"
EXISTING_ENV_FILE="$EXISTING_WORK_DIR/.env"
EXISTING_ENV_FILE_RAW="$EXISTING_ENV_FILE"
EXISTING_CONFIG_FILES_RAW="$source_file"
read_container_metadata() {
  case "$1" in
    stale-postgres)
      printf 'jjdguard|%s|%s|%s|sha256:old\n' "$EXISTING_WORK_DIR" "$EXISTING_WORK_DIR/docker-compose.offline.yml" "$EXISTING_ENV_FILE" ;;
    wrong-project)
      printf 'other|%s|%s|%s|sha256:old\n' "$EXISTING_WORK_DIR" "$EXISTING_WORK_DIR/docker-compose.offline.yml" "$EXISTING_ENV_FILE" ;;
    wrong-path)
      printf 'jjdguard|%s|%s|%s|sha256:old\n' "$tmp" "$EXISTING_WORK_DIR/docker-compose.offline.yml" "$EXISTING_ENV_FILE" ;;
    *) return 1 ;;
  esac
}
assert_container_matches_readonly_scope stale-postgres ||
  { echo "stale postgres label rejected during read-only version probe" >&2; exit 1; }
if assert_container_matches_deployment stale-postgres; then
  echo "stale postgres bypassed the strict backup identity" >&2; exit 1
fi
if assert_container_matches_readonly_scope wrong-project ||
   assert_container_matches_readonly_scope wrong-path; then
  echo "unrelated postgres passed read-only scope check" >&2; exit 1
fi
echo "[ok] stale postgres is scoped for read-only probe and strict for backup"
echo "[ok] receipt-bound development Compose inheritance and rollback"
