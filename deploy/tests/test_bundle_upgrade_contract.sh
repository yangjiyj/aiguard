#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PACKAGE_SCRIPT="$ROOT_DIR/deploy/docker-compose/package-offline-bundle.sh"
CORE_SCRIPT="$ROOT_DIR/deploy/docker-compose/upgrade-bundle.sh"

fail() {
  echo "[fail] $*" >&2
  exit 1
}

assert_file_contains() {
  local file="$1" needle="$2"
  grep -Fq -- "$needle" "$file" || fail "expected $file to contain: $needle"
}

assert_file_not_matches() {
  local file="$1" pattern="$2" description="$3"
  if grep -Eiq -- "$pattern" "$file"; then
    fail "$description is forbidden in $file"
  fi
}

assert_executable_source_not_matches() {
  local file="$1" pattern="$2" description="$3"
  if sed '/^[[:space:]]*#/d' "$file" | grep -Eiq -- "$pattern"; then
    fail "$description is forbidden in executable source of $file"
  fi
}

line_in_main() {
  local needle="$1"
  awk -v needle="$needle" '
    /^main\(\)[[:space:]]*\{/ { in_main = 1; next }
    in_main && /^[[:space:]]*}/ { exit }
    in_main {
      statement = $0
      sub(/^[[:space:]]*/, "", statement)
      sub(/[[:space:]]*$/, "", statement)
      if (statement == needle) {
        print NR
        exit
      }
    }
  ' "$CORE_SCRIPT"
}

assert_before() {
  local earlier="$1" later="$2"
  local earlier_line later_line
  earlier_line="$(line_in_main "$earlier")"
  later_line="$(line_in_main "$later")"
  [[ -n "$earlier_line" ]] || fail "main must call $earlier"
  [[ -n "$later_line" ]] || fail "main must call $later"
  (( earlier_line < later_line )) || fail "$earlier must run before $later"
}

generate_root_entry() {
  local fixture="$1" generator
  generator="$fixture/generator.sh"
  awk '
    /^write_upgrade_script\(\)[[:space:]]*\{/ { capture = 1 }
    /^write_status_script\(\)[[:space:]]*\{/ { capture = 0 }
    capture { print }
  ' "$PACKAGE_SCRIPT" >"$generator"
  assert_file_contains "$generator" 'write_upgrade_script()'
  BUNDLE_DIR="$fixture/bundle"
  mkdir -p "$BUNDLE_DIR"
  # shellcheck disable=SC1090
  source "$generator"
  write_upgrade_script
}

test_bundle_root_entry() {
  local fixture entry
  fixture="$(mktemp -d)"
  trap 'rm -rf "$fixture"' RETURN

  generate_root_entry "$fixture"
  entry="$fixture/bundle/upgrade.sh"
  [[ -x "$entry" ]] || fail "bundle root upgrade.sh must exist and be executable"
  # 根入口只验证 exec 路由；真实 core -> wrapper -> bundled binary 由 switch 测试覆盖。
  mkdir -p "$fixture/bundle/deploy/docker-compose"
  {
    echo '#!/usr/bin/env bash'
    echo 'echo "$*" >"${UPGRADE_ENTRY_LOG:?}"'
  } >"$fixture/bundle/deploy/docker-compose/upgrade-bundle.sh"
  chmod +x "$fixture/bundle/deploy/docker-compose/upgrade-bundle.sh"
  UPGRADE_ENTRY_LOG="$fixture/root-entry.log" sh "$entry" --probe-root-entry
  assert_file_contains "$fixture/root-entry.log" '--probe-root-entry'
  assert_file_contains "$entry" 'deploy/docker-compose/upgrade-bundle.sh'
  assert_file_contains "$PACKAGE_SCRIPT" 'cp "$PAYLOAD_SOURCE_ROOT/deploy/docker-compose"/upgrade-bundle.sh "$BUNDLE_DIR/deploy/docker-compose/"'
  awk '/^require_cmd docker$/ { in_main = 1 } in_main { print }' "$PACKAGE_SCRIPT" | \
    grep -Eq '^[[:space:]]*write_upgrade_script[[:space:]]*$' || \
    fail 'package-offline-bundle.sh top-level flow must invoke write_upgrade_script'
}

test_core_safety_contract() {
  [[ -f "$CORE_SCRIPT" ]] || fail "missing core upgrade script: $CORE_SCRIPT"
  [[ -x "$CORE_SCRIPT" ]] || fail "core upgrade script must be executable: $CORE_SCRIPT"
  assert_file_contains "$CORE_SCRIPT" 'compose-wrapper.sh'
  assert_file_contains "$CORE_SCRIPT" 'COMPOSE_WRAPPER="${COMPOSE_WRAPPER:-'
  assert_file_not_matches "$CORE_SCRIPT" '=[(]docker[[:space:]]+compose([[:space:]]|[)])' 'hard-coded system Compose command'

  assert_file_not_matches "$CORE_SCRIPT" '(^|[[:space:]])down[[:space:]]+([^#[:space:]]+[[:space:]]+)*-v([[:space:]]|$)' 'docker compose down -v'
  assert_file_not_matches "$CORE_SCRIPT" 'docker[[:space:]]+volume[[:space:]]+rm([[:space:]]|$)' 'docker volume rm'
  assert_file_not_matches "$CORE_SCRIPT" 'rm[[:space:]]+-rf([[:space:]]|$)' 'recursive directory deletion'
  assert_executable_source_not_matches "$CORE_SCRIPT" '(^|[;&|[:space:]])rm[[:space:]]+-[^[:space:]]*(rf|fr)[^[:space:]]*([[:space:]]|$)' 'recursive directory deletion with reordered flags'
  assert_executable_source_not_matches "$CORE_SCRIPT" "(^|[;&|[:space:]])rm([[:space:]]+-[^[:space:]]+)*[[:space:]]+['\"]?\\\$\\{?(old|original|existing)_(dir|install_dir)" 'deletion of the existing installation directory'
  assert_executable_source_not_matches "$CORE_SCRIPT" '(^|[;&|[:space:]])psql([^#]*[[:space:]])(-f|--file)(=|[[:space:]])' 'unvalidated psql file restore'
  assert_executable_source_not_matches "$CORE_SCRIPT" '(^|[;&|[:space:]])psql[^#]*(^|[[:space:]])[0-9]*<[[:space:]]*[^<]' 'unvalidated psql stdin restore'
  assert_before backup_databases capture_rollback_images
  assert_before backup_databases load_offline_images
  assert_before backup_databases run_in_place_upgrade
  assert_before capture_rollback_images load_offline_images
  assert_before capture_rollback_images run_in_place_upgrade
}

function_in_main() {
  local fn="$1"
  awk -v fn="$fn" '
    /^main\(\)[[:space:]]*\{/ { in_main = 1; next }
    in_main && /^[[:space:]]*}/ { exit }
    in_main {
      line = $0
      sub(/^[[:space:]]*/, "", line)
      if (line == fn) { print NR; exit }
    }
  ' "$CORE_SCRIPT"
}

function_body_contains() {
  local fn="$1" needle="$2"
  awk -v fn="$fn" -v needle="$needle" '
    $0 ~ "^" fn "\\(\\)" { capture = 1; next }
    capture && /^\}/ { capture = 0 }
    capture { if (index($0, needle) > 0) { found=1 } }
    END { exit found ? 0 : 1 }
  ' "$CORE_SCRIPT"
}

function_body_line() {
  local fn="$1" needle="$2"
  awk -v fn="$fn" -v needle="$needle" '
    $0 ~ "^" fn "\\(\\)" { capture = 1; next }
    capture && /^}/ { exit }
    capture && index($0, needle) > 0 { print NR; exit }
  ' "$CORE_SCRIPT"
}

test_application_rollback_preserves_database_contract() {
  local stop_line mutation_line migration_line
  assert_file_contains "$CORE_SCRIPT" 'pg_dump -U "$pguser" -d "$pgdatabase" -Fc'
  function_body_contains backup_one_database 'pg_restore --list' ||
    fail 'database backups must be validated as custom-format archives'
  if function_body_contains upgrade_failure 'restore_upgrade_databases'; then
    fail 'automatic rollback must not restore an online snapshot over new writes'
  fi
  function_body_contains upgrade_failure 'database preserved' ||
    fail 'failure diagnostics must state that data was preserved'
  function_body_contains upgrade_failure 'rollback_old_services' ||
    fail 'post-switch failure must restart the old image set'
  function_body_contains old_compose_args 'EXISTING_WORK_DIR/docker-compose.offline.yml' ||
    fail 'rollback compose must retain the original base Compose file for re-upgrade'
  if function_body_contains run_in_place_upgrade 'refresh_final_database_backups'; then
    fail 'full database backup must not be repeated during service interruption'
  fi
  stop_line="$(function_body_line run_in_place_upgrade quiesce_old_database_writers)"
  mutation_line="$(function_body_line run_in_place_upgrade 'DATABASE_MUTATION_STARTED=1')"
  migration_line="$(function_body_line run_in_place_upgrade run_database_migrations)"
  (( stop_line < mutation_line && mutation_line < migration_line )) ||
    fail 'writers must stop before schema mutation'
}

test_upgrade_verification_and_summary_contract() {
  local identity_line verify_line
  assert_file_contains "$ROOT_DIR/apps/security-engine/tests/test_detectors.py" '-----BEGIN RSA PRIVATE KEY-----'
  assert_file_contains "$ROOT_DIR/apps/security-engine/tests/test_detectors.py" 'f.category == "ssh_private_key"'
  assert_file_contains "$ROOT_DIR/apps/security-engine/app/detectors/engine.py" '"ssh_private_key": re.compile'
  function_body_contains run_in_place_upgrade 'verify_upgrade' || \
    fail "run_in_place_upgrade must call verify_upgrade inside the failure-trap zone"
  function_body_contains verify_security_events_persistence 'upgrade-verification-$random_hex' || \
    fail "upgrade verification content must be unique per run to avoid fingerprint-cache reuse"
  function_body_contains run_in_place_upgrade 'ensure_builtin_identity_runtime' || \
    fail "run_in_place_upgrade must restore built-in identity before acceptance"
  identity_line="$(function_body_line run_in_place_upgrade ensure_builtin_identity_runtime)"
  verify_line="$(function_body_line run_in_place_upgrade verify_upgrade)"
  [[ -n "$identity_line" && -n "$verify_line" && "$identity_line" -lt "$verify_line" ]] ||
    fail "built-in identity readiness must run before final upgrade verification"
  function_body_contains ensure_builtin_identity_runtime 'NEW_COMPOSE_ARGS[@]' || \
    fail "built-in identity recovery must reuse the trusted Compose chain"
  function_body_contains ensure_builtin_identity_runtime 'bootstrap-identity-runtime.sh' || \
    fail "built-in identity recovery must reconcile the runtime client"
  function_body_contains ensure_builtin_identity_runtime 'verify_control_plane_identity_runtime' || \
    fail "built-in identity recovery must verify control-plane injection"
  function_body_contains verify_control_plane_identity_runtime '.Config.Env' || \
    fail "identity readiness must inspect the running control-plane environment"
  assert_file_contains "$CORE_SCRIPT" 'CHAT_BYO_IDP:-false'
  assert_file_contains "$CORE_SCRIPT" '外部 IdP 模式：跳过 JJDGuard 内置本地身份运行态初始化'
  assert_file_not_matches "$CORE_SCRIPT" '--remove-orphans' 'identity upgrade orphan removal'
  function_in_main print_upgrade_summary >/dev/null || \
    fail "main must call print_upgrade_summary"
  function_body_contains print_upgrade_summary 'EXISTING_WORK_DIR' || \
    fail "summary must print the original installation directory"
  function_body_contains print_upgrade_summary 'EXISTING_PROJECT_NAME' || \
    fail "summary must print the Compose project name"
  function_body_contains print_upgrade_summary 'rollback-images.tsv' || \
    fail "summary must print the rollback manifest path"
  function_body_contains print_upgrade_summary 'postgres.dump' || \
    fail "summary must print the main database backup path"
  function_body_contains print_upgrade_summary '原安装目录暂时不要删除' || \
    fail "summary must warn to keep the original directory"

  assert_file_contains "$CORE_SCRIPT" 'INSERT INTO internal_keys'
  assert_file_contains "$CORE_SCRIPT" 'DELETE FROM internal_keys'
  assert_file_contains "$CORE_SCRIPT" 'expires_at'
  assert_file_not_matches "$CORE_SCRIPT" '跳过 security_events 落库验证' 'security_events skip warning'
  assert_file_not_matches "$CORE_SCRIPT" 'BOOTSTRAP_ADMIN_PASSWORD' 'bootstrap admin password dependency'
  assert_file_not_matches "$CORE_SCRIPT" '/admin/v1/login' 'administrator login dependency'
  assert_file_not_matches "$CORE_SCRIPT" 'Bearer[[:space:]]+\$\{raw_key\}' 'raw verification key in curl argv'

  assert_file_not_matches "$CORE_SCRIPT" '(^|[[:space:]])down[[:space:]]+([^#[:space:]]+[[:space:]]+)*-v([[:space:]]|$)' 'docker compose down -v'
}

test_stale_compose_label_healing_contract() {
  local heal_line assert_line
  # 历史发布留下的落后 Compose 标签必须在任何归属断言之前被归一化，
  # 否则 postgres / chat-postgres 的断言会把可升级的部署判成非法部署。
  function_body_contains backup_databases 'heal_project_container_labels' || \
    fail "backup_databases must heal stale Compose project labels first"
  heal_line="$(function_body_line backup_databases heal_project_container_labels)"
  assert_line="$(function_body_line backup_databases assert_container_matches_deployment)"
  [[ -n "$heal_line" && -n "$assert_line" && "$heal_line" -lt "$assert_line" ]] || \
    fail "label healing must run before container ownership assertions"
  function_body_contains heal_project_container_labels 'validate_config_snapshots' || \
    fail "label healing must revalidate the private config snapshots first"
  function_body_contains heal_project_container_labels 'assert_container_matches_deployment' || \
    fail "label healing must select containers by the ownership assertion"
  function_body_contains heal_project_container_labels 'EXISTING_COMPOSE_ARGS' || \
    fail "label healing must reuse the discovered trusted Compose chain"
  function_body_contains heal_project_container_labels 'force-recreate' || \
    fail "label healing must recreate the stale containers"
  function_body_contains existing_compose_args 'EXISTING_CONFIG_FILES_RAW' || \
    fail "the healing Compose chain must be the discovered raw config chain"
  function_body_contains existing_compose_args 'EXISTING_ENV_FILE_RAW' || \
    fail "the healing Compose chain must reuse the discovered environment file"
  # 切换与回滚都必须强制重建，否则无变更的有状态服务会继续留在旧链上，
  # 让下一次升级重新踩到同一个 fail-closed。
  function_body_contains run_in_place_upgrade 'up -d --force-recreate' || \
    fail "the image switch must force-recreate every old running service"
  function_body_contains rollback_old_services 'up -d --no-deps --force-recreate' || \
    fail "rollback must force-recreate every old running service"
  assert_file_not_matches "$CORE_SCRIPT" 'up -d --no-deps "\$\{OLD_RUNNING_SERVICES' 'rollback without force-recreate'
  # docker save/load 不保留构建期 image id，已安装 release 的信任链必须能靠
  # 镜像自身的来源标签闭合，否则「全新装完再升级」永远过不了摘要校验。
  function_body_contains validate_digest_from_installed_release 'org.opencontainers.image.revision' || \
    fail "installed-release trust must accept the load-stable source revision label"
  function_body_contains validate_digest_from_installed_release 'com.jjdguard.source.tree' || \
    fail "installed-release trust must bind the source tree label"
  function_body_contains validate_digest_from_installed_release 'git@github.com:yangjiyj/aiguard.git' || \
    fail "installed-release trust must require the approved Gitee source label"
  function_body_contains validate_digest_from_installed_release 'source_revision' || \
    fail "installed-release trust must compare labels against the release manifest identity"
}

test_bundle_root_entry
test_core_safety_contract
test_application_rollback_preserves_database_contract
test_upgrade_verification_and_summary_contract
test_stale_compose_label_healing_contract

echo '[ok] bundle one-command in-place upgrade contract is locked'
