#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CORE_SCRIPT="$ROOT_DIR/deploy/docker-compose/upgrade-bundle.sh"

fail() { echo "[fail] $*" >&2; exit 1; }
assert_contains() { grep -Fq -- "$2" "$1" || fail "expected $1 to contain: $2"; }
assert_not_contains() { ! grep -Fq -- "$2" "$1" || fail "expected $1 not to contain: $2"; }
assert_no_backup_artifacts() {
  local fixture="$1"
  if find "$fixture/new/backups" -type f \( -name '*.dump' -o -name '*.partial*' \) -print -quit 2>/dev/null | grep -q .; then
    fail "failed backup left a usable or partial dump"
  fi
}

make_fixture() {
  local fixture="$1"
  mkdir -p "$fixture/bin" "$fixture/new" "$fixture/old/tls" "$fixture/old/.upgrade"
  cp "$CORE_SCRIPT" "$fixture/new/upgrade-bundle.sh"
  cp "$ROOT_DIR/deploy/docker-compose/upgrade-min-data-version" "$fixture/new/upgrade-min-data-version"
  cp "$ROOT_DIR/deploy/docker-compose/upgrade-bridge-target-version" "$fixture/new/upgrade-bridge-target-version"
  # upgrade-bundle.sh sources the shared Tier-1 topology helper; a deploy
  # directory without it is an incomplete artifact and the script refuses to run.
  cp "$ROOT_DIR/deploy/docker-compose/tier1-topology.sh" "$fixture/new/tier1-topology.sh"
  printf 'services: {}\n' >"$fixture/old/docker-compose.yml"
  printf 'services: {}\n' >"$fixture/old/extra.yml"
  chmod 0644 "$fixture/old/docker-compose.yml" "$fixture/old/extra.yml"
  printf 'POSTGRES_PASSWORD%s\n' '=original-secret' >"$fixture/old/.env"
  printf 'certificate\n' >"$fixture/old/tls/server.crt"
  printf 'rollback-state\n' >"$fixture/old/.upgrade/state"
  chmod 0640 "$fixture/old/.env"
  chmod 0750 "$fixture/old/tls"
  chmod 0600 "$fixture/old/tls/server.crt"
  chmod 0700 "$fixture/old/.upgrade"
  chmod 0600 "$fixture/old/.upgrade/state"
  : >"$fixture/actions.log"

  cat >"$fixture/bin/docker" <<'BASH'
#!/usr/bin/env bash
set -Eeuo pipefail
log="${FAKE_LOG:?}"
printf 'docker' >>"$log"; printf ' %q' "$@" >>"$log"; printf '\n' >>"$log"
case "${1:-}" in
  ps)
    args="$*"
    if [[ "$args" == *'com.docker.compose.service=gateway-core'* ]]; then
      case "${FAKE_GATEWAY_COUNT:-1}" in 0) ;; 1) echo gateway-one ;; 2) printf 'gateway-one\ngateway-two\n' ;; esac
    elif [[ "$args" == *'com.docker.compose.service=chat-postgres'* ]]; then
      case "${FAKE_CHAT_COUNT:-1}" in 0) ;; 1) echo chat-postgres-one ;; 2) printf 'chat-postgres-one\nchat-postgres-two\n' ;; esac
    elif [[ "$args" == *'com.docker.compose.service=postgres'* ]]; then
      case "${FAKE_POSTGRES_COUNT:-1}" in 0) ;; 1) echo postgres-one ;; 2) printf 'postgres-one\npostgres-two\n' ;; esac
    fi
    ;;
  inspect)
    joined="$*"; container="${@: -1}"
    if [[ "$joined" == *'.Config.Env'* ]]; then
      if [[ "$container" == postgres-* ]]; then
        printf '%s\n' 'POSTGRES_USER=jjdguard' 'POSTGRES_DB=jjdguard' "POSTGRES_PASSWORD"'=main-password-must-not-log'
      else
        printf '%s\n' 'PGUSER=postgres' 'PGDATABASE=enterprise_ai_portal' "POSTGRES_PASSWORD"'=chat-password-must-not-log'
      fi
      exit 0
    fi
    project="${FAKE_GATEWAY_PROJECT-jjdguard}"
    work_dir="${FAKE_GATEWAY_WORK_DIR-${FAKE_OLD_DIR:?}}"
    config_files="${FAKE_GATEWAY_CONFIG_FILES-${FAKE_OLD_DIR:?}/docker-compose.yml}"
    env_file="${FAKE_GATEWAY_ENV_FILE-${FAKE_OLD_DIR:?}/.env}"
    image="${FAKE_GATEWAY_IMAGE-docker-compose-gateway-core:latest}"
    if [[ "$container" == postgres-* ]]; then
      project="${FAKE_POSTGRES_PROJECT-$project}"
      work_dir="${FAKE_POSTGRES_WORK_DIR-$work_dir}"
      config_files="${FAKE_POSTGRES_CONFIG_FILES-$config_files}"
      env_file="${FAKE_POSTGRES_ENV_FILE-$env_file}"
      image=postgres:16-alpine
    elif [[ "$container" == chat-postgres-* ]]; then
      project="${FAKE_CHAT_PROJECT-$project}"
      work_dir="${FAKE_CHAT_WORK_DIR-$work_dir}"
      config_files="${FAKE_CHAT_CONFIG_FILES-$config_files}"
      env_file="${FAKE_CHAT_ENV_FILE-$env_file}"
      image=postgres:16-alpine
    fi
    if [[ "$container" == gateway-* && "$joined" == *'.State.Running'* ]]; then
      running="${FAKE_GATEWAY_REVALIDATE_RUNNING-true}"
      case "${FAKE_GATEWAY_REVALIDATE_DRIFT-}" in
        project) project=drifted ;;
        workdir) work_dir="${FAKE_OLD_DIR:?}/drifted" ;;
        config) config_files="${FAKE_OLD_DIR:?}/extra.yml" ;;
        env) env_file="${FAKE_OLD_DIR:?}/drifted.env" ;;
        image) image=untrusted/gateway:drifted ;;
      esac
      printf '%s|%s|%s|%s|%s|%s\n' "$running" "$project" "$work_dir" "$config_files" "$env_file" "$image"
    else
      printf '%s|%s|%s|%s|%s\n' "$project" "$work_dir" "$config_files" "$env_file" "$image"
    fi
    ;;
  exec)
    shift
    [[ "${1:-}" == -i ]] && shift
    container="${1:-}"; shift || true
    if [[ "${1:-}" == psql ]]; then
      # 数据版本探测：默认返回满足下限的水位；置空可测拒绝路径。
      printf '%s\n' "${FAKE_DATA_VERSION-804_billing_customer_group_ratio.sql}"
      exit 0
    fi
    if [[ "${1:-}" == pg_dump ]]; then
      if [[ "$container" == postgres-one && "${FAKE_MAIN_DUMP_FAIL:-0}" == 1 ]] ||
         [[ "$container" == chat-postgres-one && "${FAKE_CHAT_DUMP_FAIL:-0}" == 1 ]]; then
        exit 31
      fi
      if [[ "$container" == postgres-one && "${FAKE_MAIN_DUMP_EMPTY:-0}" == 1 ]] ||
         [[ "$container" == chat-postgres-one && "${FAKE_CHAT_DUMP_EMPTY:-0}" == 1 ]]; then
        exit 0
      fi
      if [[ "$container" == postgres-one && "${FAKE_MAIN_DUMP_INVALID:-0}" == 1 ]] ||
         [[ "$container" == chat-postgres-one && "${FAKE_CHAT_DUMP_INVALID:-0}" == 1 ]]; then
        printf 'INVALID:%s\n' "$container"
      else
        printf 'VALIDDUMP:%s\n' "$container"
      fi
    elif [[ "${1:-}" == pg_restore && "${2:-}" == --list ]]; then
      payload="$(cat)"
      [[ "$payload" == VALIDDUMP:* ]] || exit 41
      printf 'fake archive listing\n'
    fi
    ;;
  load) exit 90 ;;
esac
BASH
  chmod +x "$fixture/bin/docker"

  for command in mkdir cp mv rm; do
    cat >"$fixture/bin/$command" <<BASH
#!/usr/bin/env bash
+printf '$command' >>"\${FAKE_LOG:?}"
+printf ' %q' "\$@" >>"\${FAKE_LOG:?}"
+printf '\\n' >>"\${FAKE_LOG:?}"
+exec /usr/bin/$command "\$@"
BASH
    sed -i 's/^+//' "$fixture/bin/$command"
    chmod +x "$fixture/bin/$command"
  done
}

run_sourced() {
  local fixture="$1" body="$2" timestamp="${3-20260714T120000Z}"
  (
    export PATH="$fixture/bin:$PATH"
    export FAKE_LOG="$fixture/actions.log"
    export FAKE_OLD_DIR="$fixture/old"
    export UPGRADE_TIMESTAMP="$timestamp"
    cd "$fixture/new"
    source ./upgrade-bundle.sh
    # 本文件仅验证任务 1/2 的发现、配置继承和数据库备份；后续升级阶段由独立测试覆盖。
    capture_rollback_images() { :; }
    create_legacy_release_anchor() { :; }
    load_offline_images() { :; }
    write_release_image_override() { :; }
    persist_active_compose_chain() { :; }
    preflight_old_services_in_new_compose() { :; }
    run_upgrade_preflight() { :; }
    run_database_migrations() { :; }
    run_in_place_upgrade() { :; }
    persist_bundle_upgrade_state() { :; }
    eval "$body"
  )
}

assert_fails_before_mutation() {
  local fixture="$1" timestamp="${2-20260714T120000Z}" status
  shift 2 || true
  set +e
  run_sourced "$fixture" main "$timestamp" >/dev/null 2>&1
  status=$?
  set -e
  (( status != 0 )) || fail "unsafe deployment identity must fail"
  assert_not_contains "$fixture/actions.log" 'mkdir '
  assert_not_contains "$fixture/actions.log" 'cp '
  assert_not_contains "$fixture/actions.log" 'pg_dump'
}

test_unique_instance_and_configuration() {
  local fixture output before_hashes after_hashes before_modes after_modes
  fixture="$(mktemp -d)"; trap 'rm -rf "$fixture"' RETURN; make_fixture "$fixture"
  before_hashes="$(sha256sum "$fixture/old/.env" "$fixture/old/tls/server.crt" "$fixture/old/.upgrade/state")"
  before_modes="$(stat -c '%n|%a' "$fixture/old/.env" "$fixture/old/tls" \
    "$fixture/old/tls/server.crt" "$fixture/old/.upgrade" "$fixture/old/.upgrade/state")"
  output="$(run_sourced "$fixture" 'discover_existing_deployment; printf "%s|%s|%s\n" "$EXISTING_PROJECT_NAME" "$EXISTING_WORK_DIR" "$EXISTING_CONFIG_FILES"')"
  [[ "$output" == "jjdguard|$fixture/old|$fixture/old/docker-compose.yml" ]] || fail "unexpected discovery: $output"
  run_sourced "$fixture" 'discover_existing_deployment; validate_upgrade_timestamp; revalidate_existing_deployment; inherit_configuration'
  run_sourced "$fixture" '[[ "$(umask)" == 0077 ]]' || fail "sourced script must enforce umask 077"
  after_hashes="$(sha256sum "$fixture/old/.env" "$fixture/old/tls/server.crt" "$fixture/old/.upgrade/state")"
  after_modes="$(stat -c '%n|%a' "$fixture/old/.env" "$fixture/old/tls" \
    "$fixture/old/tls/server.crt" "$fixture/old/.upgrade" "$fixture/old/.upgrade/state")"
  [[ "$before_hashes" == "$after_hashes" ]] || fail "original configuration content changed"
  [[ "$before_modes" == "$after_modes" ]] || fail "original configuration permissions changed"
  cmp "$fixture/old/.env" "$fixture/new/.env"
  cmp "$fixture/old/tls/server.crt" "$fixture/new/tls/server.crt"
  cmp "$fixture/old/.upgrade/state" "$fixture/new/.upgrade/state"
  [[ "$(stat -c %a "$fixture/new/.env")" == 600 ]] || fail ".env snapshot permissions changed"
  [[ "$(stat -c %a "$fixture/new/tls")" == 750 ]] || fail "tls directory permissions changed"
  [[ "$(stat -c %a "$fixture/new/tls/server.crt")" == 600 ]] || fail "tls file permissions changed"
  [[ "$(stat -c %a "$fixture/new/.upgrade")" == 700 ]] || fail ".upgrade directory permissions changed"
  [[ "$(stat -c %a "$fixture/new/.upgrade/state")" == 600 ]] || fail ".upgrade file permissions changed"
}

test_formal_upgrade_does_not_layer_complete_development_model() {
  local fixture output
  fixture="$(mktemp -d)"; trap 'rm -rf "$fixture"' RETURN; make_fixture "$fixture"
  output="$(run_sourced "$fixture" '
    discover_existing_deployment
    validate_upgrade_timestamp
    revalidate_existing_deployment
    DEVELOPMENT_NORMALIZED_CONFIG=1
    prepare_active_configuration
    printf "ACTIVE=%s\n" "$ACTIVE_CONFIG_FILES"
  ')"
  [[ "$output" == *'ACTIVE='* ]] || fail 'development model probe did not run'
  [[ "$output" != *'inherited-000.yml'* ]] ||
    fail 'formal upgrade layered the complete development Compose model over the official base'
}

test_inherit_configuration_preserves_current_development_receipt() {
  local fixture
  fixture="$(mktemp -d)"; trap 'rm -rf "$fixture"' RETURN; make_fixture "$fixture"
  mkdir -p "$fixture/new/.upgrade/development-receipt" "$fixture/old/.upgrade/development-receipt"
  printf 'current-receipt\n' >"$fixture/new/.upgrade/development-receipt/receipt.json"
  printf 'historical-receipt\n' >"$fixture/old/.upgrade/development-receipt/receipt.json"
  chmod 0600 "$fixture/new/.upgrade/development-receipt/receipt.json" \
    "$fixture/old/.upgrade/development-receipt/receipt.json"

  run_sourced "$fixture" 'discover_existing_deployment; validate_upgrade_timestamp; revalidate_existing_deployment; inherit_configuration'

  [[ "$(cat "$fixture/new/.upgrade/development-receipt/receipt.json")" == current-receipt ]] ||
    fail 'inherit_configuration replaced the installer-captured development receipt'
  [[ "$(cat "$fixture/new/.upgrade/state")" == rollback-state ]] ||
    fail 'inherit_configuration stopped inheriting historical upgrade state'
}

test_retry_after_rollback_accepts_ordered_absolute_configs() {
  local fixture rollback configs output
  fixture="$(mktemp -d)"; make_fixture "$fixture"
  rollback="$fixture/new/deploy/docker-compose/backups/20260714T110000Z/rollback-compose.yml"
  mkdir -p "$(dirname "$rollback")"; printf 'services: {}\n' >"$rollback"
  chmod 0700 "$(dirname "$rollback")"; chmod 0600 "$rollback"
  configs="$fixture/old/docker-compose.yml,$rollback"
  output="$(FAKE_GATEWAY_CONFIG_FILES="$configs" run_sourced "$fixture" '
    discover_existing_deployment
    BACKUP_DIR="$FAKE_OLD_DIR/backup"; mkdir -p "$BACKUP_DIR"
    old_compose_args
    printf "%s\n" "$EXISTING_CONFIG_FILES"
    printf "ARG=%s\n" "${OLD_COMPOSE_ARGS[@]}"')"
  [[ "$output" == *"$configs"* ]] || fail "multi-config discovery did not preserve order"
  [[ "$output" == *"ARG=--project-directory"*"$fixture/old"* ]] || fail "old project directory missing"
  [[ "$output" == *"ARG=-f"*"config-000.yml"*"ARG=-f"*"config-001.yml"* ]] || fail "snapshot compose args lost order"
  FAKE_GATEWAY_CONFIG_FILES="$configs" FAKE_POSTGRES_CONFIG_FILES="$configs" FAKE_CHAT_CONFIG_FILES="$configs" \
    run_sourced "$fixture" main
  rm -rf "$fixture"
}

test_config_file_entries_fail_closed_without_injection() {
  local fixture value marker_file evil bad_config
  fixture="$(mktemp -d)"; make_fixture "$fixture"
  bad_config="$(printf '/tmp/good.yml\\n/tmp/evil.yml')"
  for value in relative.yml /definitely/missing-compose.yml "$fixture/old" \
    "$fixture/old/docker-compose.yml,,/etc/hosts" "$bad_config"; do
    export FAKE_GATEWAY_CONFIG_FILES="$value"
    assert_fails_before_mutation "$fixture" 20260714T120000Z
  done
  unset FAKE_GATEWAY_CONFIG_FILES
  marker_file="$fixture/new/PWNED"
  evil="$fixture/old/\$(touch PWNED).yml"
  printf 'services: {}\n' >"$evil"
  chmod 0644 "$evil"
  FAKE_GATEWAY_CONFIG_FILES="$evil" run_sourced "$fixture" '
    discover_existing_deployment
    BACKUP_DIR="$FAKE_OLD_DIR/backup"; mkdir -p "$BACKUP_DIR"
    old_compose_args
    printf "%s\n" "${OLD_COMPOSE_ARGS[@]}" >/dev/null'
  [[ ! -e "$marker_file" ]] || fail 'config path executed as a command'
  rm -rf "$fixture"
}

test_source_change_uses_private_snapshot() {
  local fixture output
  fixture="$(mktemp -d)"; make_fixture "$fixture"
  output="$(run_sourced "$fixture" '
    discover_existing_deployment
    printf "services: {attacker: {}}\n" >"$FAKE_OLD_DIR/docker-compose.yml"
    BACKUP_DIR="$FAKE_OLD_DIR/backup"; mkdir -p "$BACKUP_DIR"
    old_compose_args
    printf "%s\n" "${OLD_COMPOSE_ARGS[@]}"')"
  [[ "$output" == *'config-000.yml'* && "$output" != *"$fixture/old/docker-compose.yml"* ]] || fail 'old compose did not stay on snapshot'
  rm -rf "$fixture"
}

test_snapshot_tampering_fails_before_old_compose() {
  local fixture mutation status
  for mutation in content symlink parent hardlink; do
    fixture="$(mktemp -d)"; make_fixture "$fixture"
    export SNAPSHOT_MUTATION="$mutation"
    set +e
    run_sourced "$fixture" '
      discover_existing_deployment
      snapshot="${OLD_CONFIG_SNAPSHOT_FILES%%,*}"
      case "$SNAPSHOT_MUTATION" in
        content) printf "services: {attacker: {}}\n" >"$snapshot" ;;
        symlink) rm -f "$snapshot"; ln -s "$FAKE_OLD_DIR/docker-compose.yml" "$snapshot" ;;
        parent) chmod 0777 "$OLD_CONFIG_SNAPSHOT_DIR" ;;
        hardlink) rm -f "$snapshot"; ln "$FAKE_OLD_DIR/docker-compose.yml" "$snapshot" ;;
      esac
      BACKUP_DIR="$FAKE_OLD_DIR/backup"; mkdir -p "$BACKUP_DIR"
      old_compose_args' >/dev/null 2>&1
    status=$?
    set -e
    (( status != 0 )) || fail "snapshot $mutation must fail before old compose"
    unset SNAPSHOT_MUTATION
    rm -rf "$fixture"
  done
}

test_source_race_after_policy_never_snapshots_replacement() {
  local fixture status
  fixture="$(mktemp -d)"; make_fixture "$fixture"
  set +e
  run_sourced "$fixture" '
    raced=0
    after_config_policy_hook() {
      if [[ "$raced" == 0 && "$1" == "$FAKE_OLD_DIR/docker-compose.yml" ]]; then
        raced=1
        mv "$1" "$1.trusted"
        printf "services: {attacker: {}}\n" >"$1"
        chmod 0644 "$1"
      fi
    }
    discover_existing_deployment' >/dev/null 2>&1
  status=$?
  set -e
  (( status != 0 )) || fail 'post-policy source replacement must fail'
  ! grep -Rqs 'attacker' "$fixture/new/backups" 2>/dev/null || fail 'malicious race content entered snapshot'
  rm -rf "$fixture"
}

test_trusted_sources_allow_normal_0775_workdir() {
  local fixture
  fixture="$(mktemp -d)"; make_fixture "$fixture"
  chmod 0775 "$fixture/old"
  run_sourced "$fixture" 'discover_existing_deployment; validate_config_snapshots'
  rm -rf "$fixture"
}

test_env_is_private_snapshot_and_original_changes_are_ignored() {
  local fixture output mutation
  for mutation in content symlink mode parent; do
    fixture="$(mktemp -d)"; make_fixture "$fixture"
    export ORIGINAL_ENV_MUTATION="$mutation"
    output="$(run_sourced "$fixture" '
      discover_existing_deployment
      case "$ORIGINAL_ENV_MUTATION" in
        content) printf "POSTGRES_PASSWORD=attacker\n" >"$FAKE_OLD_DIR/.env" ;;
        symlink) rm -f "$FAKE_OLD_DIR/.env"; ln -s /etc/hosts "$FAKE_OLD_DIR/.env" ;;
        mode) chmod 0666 "$FAKE_OLD_DIR/.env" ;;
        parent) chmod 0777 "$FAKE_OLD_DIR" ;;
      esac
      BACKUP_DIR="$FAKE_OLD_DIR/backup"; mkdir -p "$BACKUP_DIR"
      old_compose_args
      printf "ENV=%s\n" "$OLD_ENV_SNAPSHOT_FILE"
      printf "ARG=%s\n" "${OLD_COMPOSE_ARGS[@]}"
      grep -F "original-secret" "$OLD_ENV_SNAPSHOT_FILE"')"
    [[ "$output" == *'snapshot-env'* && "$output" != *"$fixture/old/.env"* ]] || fail "old compose did not isolate env after $mutation"
    [[ "$output" != *'attacker'* ]] || fail "mutated env entered compose snapshot after $mutation"
    unset ORIGINAL_ENV_MUTATION
    rm -rf "$fixture"
  done
}

test_env_snapshot_tampering_fails_before_old_compose() {
  local fixture mutation status
  for mutation in content symlink mode; do
    fixture="$(mktemp -d)"; make_fixture "$fixture"
    export ENV_SNAPSHOT_MUTATION="$mutation"
    set +e
    run_sourced "$fixture" '
      discover_existing_deployment
      case "$ENV_SNAPSHOT_MUTATION" in
        content) printf "POSTGRES_PASSWORD=attacker\n" >"$OLD_ENV_SNAPSHOT_FILE" ;;
        symlink) rm -f "$OLD_ENV_SNAPSHOT_FILE"; ln -s "$FAKE_OLD_DIR/.env" "$OLD_ENV_SNAPSHOT_FILE" ;;
        mode) chmod 0666 "$OLD_ENV_SNAPSHOT_FILE" ;;
      esac
      BACKUP_DIR="$FAKE_OLD_DIR/backup"; mkdir -p "$BACKUP_DIR"
      old_compose_args' >/dev/null 2>&1
    status=$?
    set -e
    (( status != 0 )) || fail "env snapshot $mutation must fail before old compose"
    unset ENV_SNAPSHOT_MUTATION
    rm -rf "$fixture"
  done
}

test_retry_uses_environment_file_label_snapshot_truth() {
  local fixture previous_dir previous_config previous_env rollback digest configs output
  fixture="$(mktemp -d)"; make_fixture "$fixture"
  previous_dir="$fixture/new/deploy/docker-compose/backups/.config-snapshot.Ab12Cd"
  previous_config="$previous_dir/config-000.yml"
  previous_env="$previous_dir/snapshot-env"
  mkdir -p "$previous_dir"; chmod 0700 "$previous_dir"
  printf 'services: {}\n' >"$previous_config"; chmod 0600 "$previous_config"
  printf 'CHAIN_SECRET=previous-secret\n' >"$previous_env"; chmod 0600 "$previous_env"
  digest="sha256:$(printf 'c%.0s' {1..64})"
  rollback="$fixture/new/deploy/docker-compose/backups/20260714T110000Z/rollback-compose.yml"
  mkdir -p "$(dirname "$rollback")"; chmod 0700 "$(dirname "$rollback")"
  printf 'services:\n  gateway-core:\n    image: %s\n' "$digest" >"$rollback"; chmod 0600 "$rollback"
  configs="$previous_config,$rollback"
  printf 'CHAIN_SECRET=malicious-old-env\n' >"$fixture/old/.env"; chmod 0600 "$fixture/old/.env"
  output="$(FAKE_GATEWAY_CONFIG_FILES="$configs" FAKE_GATEWAY_ENV_FILE="$previous_env" FAKE_GATEWAY_IMAGE="$digest" run_sourced "$fixture" '
    discover_existing_deployment
    validate_upgrade_timestamp
    revalidate_existing_deployment
    inherit_configuration
    BACKUP_DIR="$FAKE_OLD_DIR/backup"; mkdir -p "$BACKUP_DIR"
    old_compose_args
    grep -F previous-secret "$SCRIPT_DIR/.env"
    grep -F previous-secret "$OLD_ENV_SNAPSHOT_FILE"
    printf "SOURCE=%s\nSNAPSHOT=%s\nARG=%s\n" "$EXISTING_ENV_FILE" "$OLD_ENV_SNAPSHOT_FILE" "${OLD_COMPOSE_ARGS[@]}"')"
  [[ "$output" == *"SOURCE=$previous_env"* && "$output" == *'SNAPSHOT='*'.config-snapshot.'*'/snapshot-env'* ]] || fail 'retry did not continue environment label snapshot truth'
  [[ "$output" != *'malicious-old-env'* && "$output" == *'--env-file'* ]] || fail 'old workdir env leaked into retry'
  rm -rf "$fixture"
}

test_digest_image_requires_strict_trusted_rollback_override() {
  local fixture rollback configs digest other status variant backup work_dir active copied
  digest="sha256:$(printf 'a%.0s' {1..64})"
  other="sha256:$(printf 'b%.0s' {1..64})"

  fixture="$(mktemp -d)"; make_fixture "$fixture"
  rollback="$fixture/new/deploy/docker-compose/backups/20260714T110000Z/rollback-compose.yml"
  mkdir -p "$(dirname "$rollback")"; chmod 0700 "$(dirname "$rollback")"
  printf 'services:\n  gateway-core:\n    image: %s\n  control-plane:\n    image: %s\n' "$digest" "$other" >"$rollback"; chmod 0600 "$rollback"
  configs="$fixture/old/docker-compose.yml,$rollback"
  FAKE_GATEWAY_CONFIG_FILES="$configs" FAKE_GATEWAY_IMAGE="$digest" run_sourced "$fixture" \
    'discover_existing_deployment; validate_config_snapshots; cleanup_config_snapshot'
  rm -rf "$fixture"

  fixture="$(mktemp -d)"; make_fixture "$fixture"
  rollback="$fixture/new/deploy/docker-compose/backups/20260714T110000Z/rollback-compose.yml"
  mkdir -p "$(dirname "$rollback")"; chmod 0700 "$(dirname "$rollback")"
  printf 'services:\n  gateway-core: {image: %s}\n  control-plane: {image: %s}\n' "$digest" "$other" >"$rollback"
  chmod 0600 "$rollback"
  configs="$fixture/old/docker-compose.yml,$rollback"
  FAKE_GATEWAY_CONFIG_FILES="$configs" FAKE_GATEWAY_IMAGE="$digest" run_sourced "$fixture" \
    'discover_existing_deployment; validate_config_snapshots; cleanup_config_snapshot'
  rm -rf "$fixture"

  fixture="$(mktemp -d)"; make_fixture "$fixture"
  backup="$fixture/new/deploy/docker-compose/backups/20260714T110000Z"
  work_dir="$backup/legacy-release/deploy/docker-compose"
  active="$work_dir/active-config/20260714T110000Z"
  rollback="$backup/rollback-compose.yml"
  copied="$active/rollback-images.override.yml"
  mkdir -p "$active"; chmod 0700 "$backup" "$active"
  printf 'services: {}\n' >"$work_dir/docker-compose.offline.yml"
  printf 'CHAIN_SECRET=legacy\n' >"$work_dir/.env"
  printf 'services:\n  gateway-core:\n    image: %s\n' "$digest" >"$rollback"
  cp "$rollback" "$copied"
  chmod 0600 "$work_dir/docker-compose.offline.yml" "$work_dir/.env" "$rollback" "$copied"
  configs="$work_dir/docker-compose.offline.yml,$copied"
  FAKE_GATEWAY_WORK_DIR="$work_dir" FAKE_GATEWAY_CONFIG_FILES="$configs" \
    FAKE_GATEWAY_ENV_FILE="$work_dir/.env" FAKE_GATEWAY_IMAGE="$digest" \
    run_sourced "$fixture" 'discover_existing_deployment; validate_config_snapshots; cleanup_config_snapshot'
  rm -rf "$fixture"

  fixture="$(mktemp -d)"; make_fixture "$fixture"
  backup="$fixture/new/deploy/docker-compose/backups/20260714T110000Z"
  work_dir="$backup/legacy-release/deploy/docker-compose"
  active="$work_dir/active-config/20260714T110000Z"
  rollback="$backup/rollback-compose.yml"
  copied="$active/rollback-images.override.yml"
  mkdir -p "$active"; chmod 0700 "$backup" "$active"
  printf 'services: {}\n' >"$work_dir/docker-compose.offline.yml"
  printf 'CHAIN_SECRET=legacy\n' >"$work_dir/.env"
  printf 'services:\n  gateway-core:\n    image: %s\n' "$digest" >"$rollback"
  printf 'services:\n  gateway-core:\n    image: %s\n' "$other" >"$copied"
  chmod 0600 "$work_dir/docker-compose.offline.yml" "$work_dir/.env" "$rollback" "$copied"
  configs="$work_dir/docker-compose.offline.yml,$copied"
  set +e
  FAKE_GATEWAY_WORK_DIR="$work_dir" FAKE_GATEWAY_CONFIG_FILES="$configs" \
    FAKE_GATEWAY_ENV_FILE="$work_dir/.env" FAKE_GATEWAY_IMAGE="$digest" \
    run_sourced "$fixture" 'discover_existing_deployment' >/dev/null 2>&1
  status=$?
  set -e
  (( status != 0 )) || fail 'tampered legacy anchor rollback copy must fail digest trust'
  rm -rf "$fixture"

  for variant in no_override mismatch command volume ordinary; do
    fixture="$(mktemp -d)"; make_fixture "$fixture"
    rollback="$fixture/new/deploy/docker-compose/backups/20260714T110000Z/rollback-compose.yml"
    mkdir -p "$(dirname "$rollback")"; chmod 0700 "$(dirname "$rollback")"
    case "$variant" in
      no_override) configs="$fixture/old/docker-compose.yml" ;;
      mismatch) printf 'services:\n  gateway-core:\n    image: %s\n' "$other" >"$rollback"; chmod 0600 "$rollback"; configs="$fixture/old/docker-compose.yml,$rollback" ;;
      command) printf 'services:\n  gateway-core:\n    image: %s\n    command: evil\n' "$digest" >"$rollback"; chmod 0600 "$rollback"; configs="$fixture/old/docker-compose.yml,$rollback" ;;
      volume) printf 'services:\n  gateway-core:\n    image: %s\n    volumes: [/host:/host]\n' "$digest" >"$rollback"; chmod 0600 "$rollback"; configs="$fixture/old/docker-compose.yml,$rollback" ;;
      ordinary) rollback="$fixture/old/fake-rollback.yml"; printf 'services:\n  gateway-core:\n    image: %s\n' "$digest" >"$rollback"; chmod 0644 "$rollback"; configs="$fixture/old/docker-compose.yml,$rollback" ;;
    esac
    set +e
    FAKE_GATEWAY_CONFIG_FILES="$configs" FAKE_GATEWAY_IMAGE="$digest" run_sourced "$fixture" 'discover_existing_deployment' >/dev/null 2>&1
    status=$?
    set -e
    (( status != 0 )) || fail "digest rollback variant $variant must fail"
    assert_not_contains "$fixture/actions.log" 'pg_dump'
    ! find "$fixture/new/backups" -maxdepth 1 -type d -name '.config-snapshot.*' -print -quit 2>/dev/null | grep -q . || fail "digest failure $variant left snapshot"
    rm -rf "$fixture"
  done
}

test_private_group_writable_config_is_snapshotted() {
  local fixture
  fixture="$(mktemp -d)"; make_fixture "$fixture"
  chmod 0664 "$fixture/old/docker-compose.yml"
  run_sourced "$fixture" 'discover_existing_deployment; validate_config_snapshots; cleanup_config_snapshot'
  rm -rf "$fixture"

  fixture="$(mktemp -d)"; make_fixture "$fixture"
  chmod 0664 "$fixture/old/.env"
  assert_fails_before_mutation "$fixture" 20260714T120000Z
  rm -rf "$fixture"

  fixture="$(mktemp -d)"; make_fixture "$fixture"
  ln "$fixture/old/.env" "$fixture/old/.env.hardlink"
  assert_fails_before_mutation "$fixture" 20260714T120000Z
  rm -rf "$fixture"

  fixture="$(mktemp -d)"; make_fixture "$fixture"
  chmod 0666 "$fixture/old/docker-compose.yml"
  assert_fails_before_mutation "$fixture" 20260714T120000Z
  rm -rf "$fixture"
}

test_snapshot_cleanup_before_switch_and_after_success() {
  local fixture status
  fixture="$(mktemp -d)"; make_fixture "$fixture"
  run_sourced "$fixture" main
  ! find "$fixture/new/backups" -maxdepth 1 -type d -name '.config-snapshot.*' -print -quit 2>/dev/null | grep -q . || \
    fail 'successful upgrade left config snapshot'
  rm -rf "$fixture"

  fixture="$(mktemp -d)"; make_fixture "$fixture"
  set +e
  run_sourced "$fixture" 'backup_databases() { return 71; }; main' >/dev/null 2>&1
  status=$?
  set -e
  (( status != 0 )) || fail 'pre-switch failure injection must fail'
  ! find "$fixture/new/backups" -maxdepth 1 -type d -name '.config-snapshot.*' -print -quit 2>/dev/null | grep -q . || \
    fail 'pre-switch failure left config snapshot'
  rm -rf "$fixture"
}

test_gateway_count_and_identity_rejected_before_writes() {
  local fixture variable value
  for value in 0 2; do
    fixture="$(mktemp -d)"; make_fixture "$fixture"
    FAKE_GATEWAY_COUNT="$value" assert_fails_before_mutation "$fixture" 20260714T120000Z
    rm -rf "$fixture"
  done
  while IFS='|' read -r variable value; do
    fixture="$(mktemp -d)"; make_fixture "$fixture"
    export "$variable=$value"
    assert_fails_before_mutation "$fixture" 20260714T120000Z
    unset "$variable"
    rm -rf "$fixture"
  done <<EOF
FAKE_GATEWAY_PROJECT|<no value>
FAKE_GATEWAY_PROJECT|
FAKE_GATEWAY_PROJECT|Bad Project
FAKE_GATEWAY_WORK_DIR|<no value>
FAKE_GATEWAY_WORK_DIR|
FAKE_GATEWAY_WORK_DIR|relative/path
FAKE_GATEWAY_WORK_DIR|$ROOT_DIR/does-not-exist
FAKE_GATEWAY_CONFIG_FILES|<no value>
FAKE_GATEWAY_CONFIG_FILES|
FAKE_GATEWAY_CONFIG_FILES|$ROOT_DIR/does-not-exist.yml
FAKE_GATEWAY_IMAGE|untrusted/gateway:latest
FAKE_GATEWAY_IMAGE|<no value>
EOF

  for value in relative.env "$ROOT_DIR/missing.env" /etc/hosts '/tmp/a.env,/tmp/b.env' $'/tmp/good.env\n/tmp/evil.env'; do
    fixture="$(mktemp -d)"; make_fixture "$fixture"
    export FAKE_GATEWAY_ENV_FILE="$value"
    assert_fails_before_mutation "$fixture" 20260714T120000Z
    unset FAKE_GATEWAY_ENV_FILE
    rm -rf "$fixture"
  done

  fixture="$(mktemp -d)"; make_fixture "$fixture"
  printf 'EXTERNAL=forbidden\n' >"$fixture/external.env"; chmod 0600 "$fixture/external.env"
  FAKE_GATEWAY_ENV_FILE="$fixture/external.env" assert_fails_before_mutation "$fixture" 20260714T120000Z
  rm -rf "$fixture"

  fixture="$(mktemp -d)"; make_fixture "$fixture"
  FAKE_GATEWAY_ENV_FILE= run_sourced "$fixture" 'discover_existing_deployment; [[ "$EXISTING_ENV_FILE" == "$FAKE_OLD_DIR/.env" ]]' || \
    fail 'empty environment_file label must use legacy workdir fallback'
  rm -rf "$fixture"
}

test_configuration_symlink_escape_is_rejected_before_copy() {
  local fixture kind status external
  for kind in env tls upgrade; do
    fixture="$(mktemp -d)"; make_fixture "$fixture"
    external="$fixture/external"; mkdir -p "$external/tls" "$external/upgrade"
    printf 'outside-env\n' >"$external/env"
    printf 'outside-cert\n' >"$external/tls/server.crt"
    printf 'outside-state\n' >"$external/upgrade/state"
    case "$kind" in
      env) rm -f "$fixture/old/.env"; ln -s "$external/env" "$fixture/old/.env" ;;
      tls) rm -rf "$fixture/old/tls"; ln -s "$external/tls" "$fixture/old/tls" ;;
      upgrade) rm -rf "$fixture/old/.upgrade"; ln -s "$external/upgrade" "$fixture/old/.upgrade" ;;
    esac
    set +e
    run_sourced "$fixture" main >/dev/null 2>&1
    status=$?
    set -e
    (( status != 0 )) || fail "$kind configuration symlink escape must fail"
    assert_not_contains "$fixture/actions.log" 'pg_dump'
    rm -rf "$fixture"
  done
}

test_gateway_toctou_is_rejected_before_copy() {
  local fixture scenario status variable
  for scenario in project workdir config env image stopped; do
    fixture="$(mktemp -d)"; make_fixture "$fixture"
    if [[ "$scenario" == stopped ]]; then
      variable=FAKE_GATEWAY_REVALIDATE_RUNNING
      export "$variable=false"
    else
      variable=FAKE_GATEWAY_REVALIDATE_DRIFT
      export "$variable=$scenario"
    fi
    set +e
    run_sourced "$fixture" main >/dev/null 2>&1
    status=$?
    set -e
    (( status != 0 )) || fail "gateway revalidation drift $scenario must fail"
    assert_not_contains "$fixture/actions.log" 'pg_dump'
    unset "$variable"
    rm -rf "$fixture"
  done
}

test_timestamp_traversal_rejected_before_writes() {
  local fixture timestamp
  for timestamp in '../escaped' 20260714T120000 2026-07-14T120000Z ''; do
    fixture="$(mktemp -d)"; make_fixture "$fixture"
    assert_fails_before_mutation "$fixture" "$timestamp"
    [[ ! -e "$fixture/escaped" ]] || fail "timestamp escaped bundle directory"
    rm -rf "$fixture"
  done
}

test_database_identity_and_counts() {
  local fixture status variable
  for variable in 'FAKE_POSTGRES_COUNT=0' 'FAKE_POSTGRES_COUNT=2' 'FAKE_CHAT_COUNT=2' \
                  'FAKE_POSTGRES_PROJECT=other' 'FAKE_POSTGRES_WORK_DIR=/tmp' \
                  'FAKE_CHAT_CONFIG_FILES=/definitely/missing-compose.yml' \
                  'FAKE_POSTGRES_ENV_FILE=/tmp/mismatched-main.env' \
                  'FAKE_CHAT_ENV_FILE=/tmp/mismatched-chat.env'; do
    fixture="$(mktemp -d)"; make_fixture "$fixture"; export "$variable"
    set +e
    run_sourced "$fixture" 'capture_rollback_images() { echo phase:capture >>"$FAKE_LOG"; };
      load_offline_images() { echo phase:load >>"$FAKE_LOG"; };
      run_database_migrations() { echo phase:migrations >>"$FAKE_LOG"; }; main' >/dev/null 2>&1
    status=$?
    set -e
    (( status != 0 )) || fail "$variable must fail"
    assert_no_backup_artifacts "$fixture"
    assert_not_contains "$fixture/actions.log" 'phase:load'
    assert_not_contains "$fixture/actions.log" 'phase:capture'
    assert_not_contains "$fixture/actions.log" 'phase:migrations'
    unset "${variable%%=*}"; rm -rf "$fixture"
  done
}

test_chat_not_running_backs_up_only_main() {
  local fixture backup_dir
  fixture="$(mktemp -d)"; trap 'rm -rf "$fixture"' RETURN; make_fixture "$fixture"
  FAKE_CHAT_COUNT=0 run_sourced "$fixture" main
  backup_dir="$fixture/new/backups/20260714T120000Z"
  [[ -s "$backup_dir/postgres.dump" ]]
  [[ ! -e "$backup_dir/chat-postgres.dump" ]]
}

test_atomic_validated_private_backups() {
  local fixture backup_dir
  fixture="$(mktemp -d)"; trap 'rm -rf "$fixture"' RETURN; make_fixture "$fixture"
  run_sourced "$fixture" main
  backup_dir="$fixture/new/backups/20260714T120000Z"
  [[ "$(stat -c %a "$backup_dir")" == 700 ]] || fail "backup dir is not private"
  [[ "$(stat -c %a "$backup_dir/postgres.dump")" == 600 ]] || fail "main dump is not private"
  [[ "$(stat -c %a "$backup_dir/chat-postgres.dump")" == 600 ]] || fail "chat dump is not private"
  assert_contains "$backup_dir/postgres.dump" 'VALIDDUMP:postgres-one'
  assert_contains "$backup_dir/chat-postgres.dump" 'VALIDDUMP:chat-postgres-one'
  assert_contains "$fixture/actions.log" 'pg_restore --list'
  assert_contains "$fixture/actions.log" 'mv '
  assert_contains "$fixture/actions.log" "$backup_dir/.postgres.dump.partial."
  assert_contains "$fixture/actions.log" "$backup_dir/.chat-postgres.dump.partial."
  ! find "$backup_dir" -name '*.partial*' -print -quit | grep -q .
  assert_not_contains "$fixture/actions.log" 'main-password-must-not-log'
  assert_not_contains "$fixture/actions.log" 'chat-password-must-not-log'
}

test_failed_empty_or_invalid_backups_leave_no_artifacts() {
  local fixture variable status
  for variable in FAKE_MAIN_DUMP_FAIL FAKE_MAIN_DUMP_EMPTY FAKE_MAIN_DUMP_INVALID \
                  FAKE_CHAT_DUMP_FAIL FAKE_CHAT_DUMP_EMPTY FAKE_CHAT_DUMP_INVALID; do
    fixture="$(mktemp -d)"; make_fixture "$fixture"; export "$variable=1"
    set +e
    run_sourced "$fixture" 'capture_rollback_images() { echo phase:capture >>"$FAKE_LOG"; };
      load_offline_images() { echo phase:load >>"$FAKE_LOG"; };
      run_database_migrations() { echo phase:migrations >>"$FAKE_LOG"; }; main' >/dev/null 2>&1
    status=$?
    set -e
    (( status != 0 )) || fail "$variable must fail"
    assert_no_backup_artifacts "$fixture"
    assert_not_contains "$fixture/actions.log" 'docker load'
    assert_not_contains "$fixture/actions.log" 'phase:capture'
    assert_not_contains "$fixture/actions.log" 'phase:load'
    assert_not_contains "$fixture/actions.log" 'phase:migrations'
    unset "$variable"; rm -rf "$fixture"
  done
}

test_unique_instance_and_configuration
test_formal_upgrade_does_not_layer_complete_development_model
test_inherit_configuration_preserves_current_development_receipt
test_retry_after_rollback_accepts_ordered_absolute_configs
test_config_file_entries_fail_closed_without_injection
test_source_change_uses_private_snapshot
test_snapshot_tampering_fails_before_old_compose
test_source_race_after_policy_never_snapshots_replacement
test_trusted_sources_allow_normal_0775_workdir
test_env_is_private_snapshot_and_original_changes_are_ignored
test_env_snapshot_tampering_fails_before_old_compose
test_retry_uses_environment_file_label_snapshot_truth
test_digest_image_requires_strict_trusted_rollback_override
test_private_group_writable_config_is_snapshotted
test_snapshot_cleanup_before_switch_and_after_success
test_gateway_count_and_identity_rejected_before_writes
test_configuration_symlink_escape_is_rejected_before_copy
test_gateway_toctou_is_rejected_before_copy
test_timestamp_traversal_rejected_before_writes
test_database_identity_and_counts
test_chat_not_running_backs_up_only_main
test_atomic_validated_private_backups
test_failed_empty_or_invalid_backups_leave_no_artifacts


test_inherit_configuration_requires_revalidation() {
  local fixture status
  fixture="$(mktemp -d)"; trap 'rm -rf "$fixture"' RETURN; make_fixture "$fixture"
  set +e
  run_sourced "$fixture" 'discover_existing_deployment; validate_upgrade_timestamp; inherit_configuration' >/dev/null 2>&1
  status=$?
  set -e
  (( status != 0 )) || fail 'inherit_configuration must fail when revalidate_existing_deployment was skipped'
}
test_inherit_configuration_requires_revalidation

# jjdctl 启动读取 .upgrade/compose-files，升级却只按 gateway-core 容器标签发现配置链。
# 现场只给 control-plane 登记、也只重建了 control-plane 的覆盖层不在该标签里，
# 升级既不继承它，备份前的标签归一化还会把它摘掉；至少要点名告警，不能静默丢弃。
test_boot_chain_only_override_is_reported_not_silently_dropped() {
  local fixture site output
  fixture="$(mktemp -d)"; trap 'rm -rf "$fixture"' RETURN; make_fixture "$fixture"
  site="$fixture/old/active-config/site-20261018T013101Z/site.override.yml"
  mkdir -p "$(dirname "$site")"
  printf 'services:\n  control-plane:\n    environment:\n      - SITE_ONLY=1\n' >"$site"
  chmod 0600 "$site"
  printf '%s\n' "$site" >"$fixture/old/.upgrade/compose-files"
  chmod 0600 "$fixture/old/.upgrade/compose-files"
  output="$(run_sourced "$fixture" 'main; printf "ACTIVE=%s\n" "$ACTIVE_CONFIG_FILES"' 2>&1)" ||
    fail "warning-only boot-chain check must not block the upgrade: $output"
  [[ "$output" == *'[warn]'*'未进入升级继承范围'*"$site"* ]] ||
    fail "boot-chain-only override must be reported by path: $output"
  [[ "$(grep -cF -- "$site" <<<"$output")" -ge 2 ]] ||
    fail "upgrade summary must repeat the uninherited boot-chain override: $output"
  grep -qx 'ACTIVE=' <<<"$output" ||
    fail "the warning must not change the inherited configuration set: $output"
}

test_inherited_boot_chain_entries_and_image_pins_stay_silent() {
  local fixture pin configs output
  fixture="$(mktemp -d)"; trap 'rm -rf "$fixture"' RETURN; make_fixture "$fixture"
  pin="$fixture/old/active-config/20261017T232442Z/release-images.override.yml"
  mkdir -p "$(dirname "$pin")"
  printf 'services:\n  gateway-core:\n    image: sha256:%064d\n' 0 >"$pin"
  chmod 0600 "$pin"
  printf '%s\n' "$fixture/old/extra.yml" "$pin" >"$fixture/old/.upgrade/compose-files"
  chmod 0600 "$fixture/old/.upgrade/compose-files"
  configs="$fixture/old/docker-compose.yml,$fixture/old/extra.yml"
  output="$(FAKE_GATEWAY_CONFIG_FILES="$configs" FAKE_POSTGRES_CONFIG_FILES="$configs" FAKE_CHAT_CONFIG_FILES="$configs" \
    run_sourced "$fixture" main 2>&1)" || fail "upgrade with an inherited boot chain must succeed: $output"
  [[ "$output" != *'未进入升级继承范围'* ]] ||
    fail "inherited chain entries and generated image pins must not be reported: $output"
}
test_boot_chain_only_override_is_reported_not_silently_dropped
test_inherited_boot_chain_entries_and_image_pins_stay_silent
echo '[ok] upgrade discovery and atomic database backup hardening works'
