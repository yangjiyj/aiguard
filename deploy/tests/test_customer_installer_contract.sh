#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
INSTALLER="$ROOT/deploy/offline-installer/installer.sh"
CTL="$ROOT/deploy/offline-installer/jjdctl"
SERVICE="$ROOT/deploy/offline-installer/jjdguard.service"
PACKAGER="$ROOT/deploy/docker-compose/package-offline-bundle.sh"
RUN_HEADER="$ROOT/deploy/offline-installer/self-extracting-header.sh"
TRUST_VERIFIER="$ROOT/deploy/offline-installer/verify-promoted-release.py"
RUNBOOK="$ROOT/docs/release-runbook.md"
COMPOSE_README="$ROOT/deploy/docker-compose/README.md"
DEPLOY_OFFLINE="$ROOT/deploy/docker-compose/deploy-offline.sh"
SMOKE_TEST="$ROOT/deploy/docker-compose/smoke-test.sh"

fail() { echo "[fail] $*" >&2; exit 1; }
assert_file() { [[ -f "$1" ]] || fail "missing file: $1"; }
assert_contains() { grep -Fq -- "$2" "$1" || fail "$1 missing: $2"; }

test_builtin_chat_issuer_is_always_normalized_to_public_url() {
  assert_contains "$DEPLOY_OFFLINE" '_chat_byo_idp='
  assert_contains "$DEPLOY_OFFLINE" 'if [ "$_chat_byo_idp" != "true" ]; then'
  assert_contains "$DEPLOY_OFFLINE" 'CHAT_OIDC_ISSUER=${_jjd_sso_public}/sso/realms/jjdguard'
}

test_rollback_tracks_all_first_party_runtime_images() {
  for name in LLM_JUDGE_IMAGE TIER1_CLASSIFIER_IMAGE CHAT_PORTAL_UI_IMAGE CHAT_PORTAL_PROXY_IMAGE; do
    assert_contains "$INSTALLER" "$name"
    assert_contains "$CTL" "$name"
  done
  assert_contains "$CTL" 'write_rollback_state'
  assert_contains "$CTL" 'current-digests.env'
  assert_contains "$CTL" 'MODE=rollback'
  assert_contains "$CTL" 'rollback_chain.rollback-'
}

test_rollback_does_not_implicitly_restore_database() {
  local body
  body="$(sed -n '/^rollback_cmd() {/,/^}/p' "$CTL")"
  [[ "$body" != *'restore_database '* ]] || fail 'normal rollback must preserve post-upgrade writes'
  assert_contains "$CTL" 'disaster_restore_cmd()'
  assert_contains "$CTL" '--confirm-data-loss'
}

test_jjdctl_status_returns_zero_without_deploy_result() {
  local fixture release dc output status
  fixture="$(mktemp -d)"
  trap 'rm -rf "$fixture"' RETURN
  release="$fixture/release"
  dc="$release/deploy/docker-compose"
  mkdir -p "$dc"
  printf 'POSTGRES_USER=jjdguard\nPOSTGRES_DB=jjdguard\n' >"$dc/.env"
  printf 'services: {}\n' >"$dc/docker-compose.offline.yml"
  cat >"$dc/compose-wrapper.sh" <<'EOF'
#!/usr/bin/env sh
if [ "${1:-}" = "-f" ]; then
  shift 2
fi
if [ "${1:-}" = "ps" ]; then
  echo "NAME STATUS"
  echo "jjdguard-postgres running"
  exit 0
fi
echo "unexpected compose args: $*" >&2
exit 91
EOF
  chmod +x "$dc/compose-wrapper.sh"
  cat >"$dc/smoke-test.sh" <<'EOF'
#!/usr/bin/env sh
echo "smoke ok"
EOF
  chmod +x "$dc/smoke-test.sh"

  sed '/^main "\$@"$/d' "$CTL" >"$release/jjdctl"
  mkdir -p "$release/deploy/lib"; cp "$ROOT/deploy/lib/jjd-env.sh" "$release/deploy/lib/"
  chmod +x "$release/jjdctl"

  set +e
  output="$(
    ROOT="$release" DC="$dc" ENV="$dc/.env" COMPOSE="$dc/docker-compose.offline.yml" \
      bash -c 'source "$1"; ROOT="$2"; DC="$3"; ENV="$4"; COMPOSE="$5"; status_cmd' \
        bash "$release/jjdctl" "$release" "$dc" "$dc/.env" "$dc/docker-compose.offline.yml" 2>&1
  )"
  status=$?
  set -e

  [[ "$status" -eq 0 ]] || fail "jjdctl status should return 0 without .deploy-result, got $status: $output"
  assert_contains <(printf '%s' "$output") 'NAME STATUS'
  assert_contains <(printf '%s' "$output") 'smoke ok'
}

test_smoke_accepts_rotated_bootstrap_password() {
  assert_contains "$SMOKE_TEST" "printf '%s\\n'"
  assert_contains "$SMOKE_TEST" '-v "smoke_username=$BOOTSTRAP_ADMIN_USERNAME"'
  assert_contains "$SMOKE_TEST" '-At'
  if grep -Fq -- '-Atqc' "$SMOKE_TEST"; then
    fail 'smoke test still relies on psql -c variable substitution for rotated-password detection'
  fi
}

test_jjdctl_uses_only_protected_active_compose_state() {
  local fixture release dc fake_bin log inherited images output status
  fixture="$(mktemp -d)"
  trap 'rm -rf "$fixture"' RETURN
  release="$fixture/release"
  dc="$release/deploy/docker-compose"
  fake_bin="$fixture/bin"
  log="$fixture/compose.args"
  inherited="$dc/active-config/test/inherited-001.yml"
  images="$dc/active-config/test/release-images.override.yml"
  mkdir -p "$dc/.upgrade" "$(dirname "$inherited")" "$fake_bin"
  printf 'POSTGRES_USER=jjdguard\nPOSTGRES_DB=jjdguard\n' >"$dc/.env"
  printf 'services: {}\n' >"$dc/docker-compose.offline.yml"
  cp "$dc/docker-compose.offline.yml" "$inherited"
  cp "$dc/docker-compose.offline.yml" "$images"
  printf '%s\n%s\n' "$inherited" "$images" >"$dc/.upgrade/compose-files"
  printf 'live-project\n' >"$dc/.upgrade/project-name"
  printf '%s\n' "$dc" >"$dc/.upgrade/project-directory"
  chmod 600 "$dc/.upgrade/compose-files" "$dc/.upgrade/project-name" \
    "$dc/.upgrade/project-directory" "$inherited" "$images"
  cat >"$dc/compose-wrapper.sh" <<'EOF'
#!/usr/bin/env sh
printf '%s\n' "$@" >"$JJD_TEST_COMPOSE_LOG"
EOF
  chmod +x "$dc/compose-wrapper.sh"
  cat >"$fake_bin/stat" <<'EOF'
#!/usr/bin/env sh
case "$*" in
  *'%u'*) printf '%s\n' "${JJD_TEST_STAT_UID:-0}" ;;
  *'%a'*) printf '600\n' ;;
  *) exec /usr/bin/stat "$@" ;;
esac
EOF
  chmod +x "$fake_bin/stat"
  sed '/^main "\$@"$/d' "$CTL" >"$release/jjdctl"
  mkdir -p "$release/deploy/lib"; cp "$ROOT/deploy/lib/jjd-env.sh" "$release/deploy/lib/"

  PATH="$fake_bin:$PATH" JJD_TEST_COMPOSE_LOG="$log" \
    bash -c 'source "$1"; ROOT="$2"; DC="$3"; ENV="$4"; COMPOSE="$5"; compose ps' \
      bash "$release/jjdctl" "$release" "$dc" "$dc/.env" "$dc/docker-compose.offline.yml"
  grep -Fxq -- '--project-name' "$log" || fail 'jjdctl omitted active Compose project name'
  grep -Fxq -- 'live-project' "$log" || fail 'jjdctl omitted active Compose project value'
  grep -Fxq -- '--project-directory' "$log" || fail 'jjdctl omitted active Compose project directory'
  grep -Fxq -- "$inherited" "$log" || fail 'jjdctl omitted inherited active Compose override'
  grep -Fxq -- "$images" "$log" || fail 'jjdctl omitted immutable image override'

  set +e
  output="$(
    PATH="$fake_bin:$PATH" JJD_TEST_STAT_UID=1000 JJD_TEST_COMPOSE_LOG="$log" \
      bash -c 'source "$1"; ROOT="$2"; DC="$3"; ENV="$4"; COMPOSE="$5"; compose ps' \
        bash "$release/jjdctl" "$release" "$dc" "$dc/.env" "$dc/docker-compose.offline.yml" 2>&1
  )"
  status=$?
  set -e
  [[ "$status" -ne 0 && "$output" == *'属主或权限不安全'* ]] || \
    fail 'jjdctl must reject an active Compose state file not owned by root'
}

test_rollback_start_converges_and_fails_closed() {
  local fixture release previous counter output status
  fixture="$(mktemp -d)"
  trap 'rm -rf "$fixture"' RETURN
  release="$fixture/release"
  previous="$fixture/previous"
  counter="$fixture/start-count"
  mkdir -p "$release" "$previous/deploy/docker-compose"
  : >"$previous/deploy/docker-compose/.env"
  : >"$previous/deploy/docker-compose/docker-compose.offline.yml"
  sed '/^main "\$@"$/d' "$CTL" >"$release/jjdctl"
  mkdir -p "$release/deploy/lib"; cp "$ROOT/deploy/lib/jjd-env.sh" "$release/deploy/lib/"
  cat >"$previous/deploy/docker-compose/compose-wrapper.sh" <<'EOF'
#!/bin/sh
set -eu
case " $* " in *' --force-recreate '*) ;; *) exit 91 ;; esac
count=0
[ ! -f "$JJD_TEST_START_COUNT" ] || read -r count <"$JJD_TEST_START_COUNT"
count=$((count + 1))
printf '%s\n' "$count" >"$JJD_TEST_START_COUNT"
[ "$count" -ge "$JJD_TEST_START_SUCCEED_AT" ]
EOF
  chmod 0755 "$release/jjdctl" "$previous/deploy/docker-compose/compose-wrapper.sh"

  JJD_TEST_START_COUNT="$counter" JJD_TEST_START_SUCCEED_AT=2 \
    bash -c 'source "$1"; ROLLBACK_START_TIMEOUT=2 ROLLBACK_START_INTERVAL=0.01 start_rollback_release "$2"' \
      bash "$release/jjdctl" "$previous"
  [[ "$(<"$counter")" == 2 ]] || fail 'rollback start did not converge after a transient dependency failure'

  rm -f "$counter"
  set +e
  output="$(
    JJD_TEST_START_COUNT="$counter" JJD_TEST_START_SUCCEED_AT=999999 \
      bash -c 'source "$1"; ROLLBACK_START_TIMEOUT=1 ROLLBACK_START_INTERVAL=0.05 start_rollback_release "$2"' \
        bash "$release/jjdctl" "$previous" 2>&1
  )"
  status=$?
  set -e
  [[ "$status" -ne 0 && "$output" == *'旧版本服务在回滚窗口内未恢复'* ]] ||
    fail 'rollback start must fail closed after its convergence deadline'
  [[ "$(<"$counter")" -gt 1 ]] || fail 'rollback start timeout did not retry the old release'
}

test_installer_persists_exact_package_metadata() {
  local fixture bundle env_file target output status copy_env_line persist_metadata_line upgrade_line
  fixture="$(mktemp -d)"
  trap 'rm -rf "$fixture"' RETURN
  copy_env_line="$(grep -n 'install -m 600 "$old_dc/.env" "$new_dc/.env"' "$INSTALLER" | cut -d: -f1)"
  persist_metadata_line="$(grep -n 'persist_package_metadata "$new_dc/.env"' "$INSTALLER" | cut -d: -f1)"
  upgrade_line="$(grep -n 'UPGRADE_OFFLINE_MODE=1' "$INSTALLER" | cut -d: -f1)"
  [[ -n "$copy_env_line" && -n "$persist_metadata_line" && -n "$upgrade_line" ]] ||
    fail 'customer upgrade metadata binding hooks are incomplete'
  [[ "$copy_env_line" -lt "$persist_metadata_line" && "$persist_metadata_line" -lt "$upgrade_line" ]] ||
    fail 'customer upgrade must bind metadata after inheritance and before switching services'
  bundle="$fixture/jjdguard-2.1-test"
  mkdir -p "$bundle/deploy/docker-compose"
  cat >"$bundle/manifest.json" <<'EOF'
{
  "version": "2.1",
  "source_revision": "0123456789abcdef0123456789abcdef01234567",
  "source_tree": "89abcdef0123456789abcdef0123456789abcdef",
  "built_at": "2026-08-14T10:00:00Z"
}
EOF
  env_file="$bundle/deploy/docker-compose/.env"
  printf '%s\n' \
    'POSTGRES_USER=jjdguard' \
    'JJD_VERSION=2.0' \
    'JJD_VERSION=stale-duplicate' \
    'JJD_COMMIT=' \
    'JJD_BUILT_AT=2026-08-12T00:08:37Z' >"$env_file"
  chmod 640 "$env_file"

  (
    export JJD_INSTALLER_LIB_ONLY=1 JJD_PAYLOAD_ROOT="$bundle"
    source "$INSTALLER"
    persist_package_metadata "$env_file"
  )

  [[ "$(grep -c '^JJD_VERSION=' "$env_file")" -eq 1 ]] || fail 'installer must emit one JJD_VERSION'
  [[ "$(grep -c '^JJD_COMMIT=' "$env_file")" -eq 1 ]] || fail 'installer must emit one JJD_COMMIT'
  [[ "$(grep -c '^JJD_BUILT_AT=' "$env_file")" -eq 1 ]] || fail 'installer must emit one JJD_BUILT_AT'
  assert_contains "$env_file" 'JJD_VERSION=2.1'
  assert_contains "$env_file" 'JJD_COMMIT=0123456789abcdef0123456789abcdef01234567'
  assert_contains "$env_file" 'JJD_BUILT_AT=2026-08-14T10:00:00Z'
  [[ "$(stat -c '%a' "$env_file")" == 600 ]] || fail 'installer must protect metadata env'

  target="$fixture/env.target"
  mv "$env_file" "$target"
  chmod 640 "$target"
  ln -s "$target" "$env_file"
  set +e
  output="$(
    export JJD_INSTALLER_LIB_ONLY=1 JJD_PAYLOAD_ROOT="$bundle"
    source "$INSTALLER"
    persist_package_metadata "$env_file" 2>&1
  )"
  status=$?
  set -e
  [[ "$status" -ne 0 ]] || fail 'installer must reject a symbolic-link env'
  [[ "$output" == *'inherited environment file is missing or unsafe'* ]] || fail 'symlink rejection is not explicit'
  [[ "$(stat -c '%a' "$target")" == 640 ]] || fail 'installer followed the env symlink'
}

test_deploy_failure_stops_current_compose_project() {
  local fixture cleanup wrapper status
  fixture="$(mktemp -d)"
  trap 'rm -rf "$fixture"' RETURN
  cleanup="$fixture/cleanup.sh"
  wrapper="$fixture/compose-wrapper.sh"
  awk '
    /^cleanup_failed_deploy\(\) \{/ { inside = 1 }
    inside { print }
    inside && /^}$/ { exit }
  ' "$DEPLOY_OFFLINE" >"$cleanup"
  [[ -s "$cleanup" ]] || fail 'unable to extract deployment failure cleanup'
  printf '%s\n' '#!/bin/sh' 'printf "%s\n" "$*" >> "$(dirname "$0")/compose.calls"' >"$wrapper"
  chmod +x "$wrapper"

  set +e
  (
    DEPLOY_STARTED=1
    DEPLOY_SUCCEEDED=0
    COMPOSE_WRAPPER="$wrapper"
    # shellcheck disable=SC1090
    . "$cleanup"
    false
    cleanup_failed_deploy
  ) >"$fixture/cleanup.out" 2>&1
  status=$?
  set -e
  [[ "$status" -ne 0 ]] || fail 'failed deployment cleanup must preserve the original failure status'
  assert_contains "$fixture/compose.calls" 'stop'
  assert_contains "$fixture/cleanup.out" '正在停止本次启动的服务'
}

test_installer_discovers_running_compose_from_labels() {
  local fixture workdir config env_file output
  fixture="$(mktemp -d)"
  trap 'rm -rf "$fixture"' RETURN
  workdir="$fixture/jjdguard/upgrade-runs/home/compose.before"
  config="$workdir/docker-compose.offline.yml"
  env_file="$workdir/.env"
  mkdir -p "$fixture/bin" "$workdir"
  printf 'services: {}\n' >"$config"
  printf 'COMPOSE_PROJECT_NAME=live-project\n' >"$env_file"
  cat >"$fixture/bin/docker" <<EOF
#!/usr/bin/env bash
set -Eeuo pipefail
if [[ "\${1:-}" == ps && "\$*" == *'com.docker.compose.service=gateway-core'* ]]; then echo gateway-one; exit 0; fi
if [[ "\${1:-}" == ps && "\$*" == *'com.docker.compose.project=live-project'* && "\$*" == *'com.docker.compose.service=postgres'* ]]; then echo postgres-one; exit 0; fi
if [[ "\${1:-}" == inspect ]]; then printf '%s|%s|%s|%s\n' live-project '$workdir' '$config' '$env_file'; exit 0; fi
exit 0
EOF
  chmod +x "$fixture/bin/docker"
  output="$(PATH="$fixture/bin:$PATH" JJD_INSTALLER_LIB_ONLY=1 bash -c 'source "$1"; discover_running_compose' bash "$INSTALLER")"
  [[ "$output" == "live-project|$workdir" ]] || fail "installer did not discover the live Compose deployment: $output"
}

assert_file "$INSTALLER"
assert_file "$CTL"
assert_file "$SERVICE"
assert_file "$RUN_HEADER"
assert_file "$TRUST_VERIFIER"
assert_file "$RUNBOOK"
assert_file "$COMPOSE_README"
assert_file "$DEPLOY_OFFLINE"

assert_contains "$INSTALLER" '安装和升级必须使用 root 或 sudo 权限'
assert_contains "$INSTALLER" '未检测到受支持的 init 系统'
assert_contains "$INSTALLER" 'rc-service jjdguard start'
assert_contains "$INSTALLER" 'service jjdguard start'
assert_contains "$INSTALLER" '/opt/jjdguard/releases'
assert_contains "$INSTALLER" '/opt/jjdguard/current'
assert_contains "$INSTALLER" '/opt/jjdguard/previous'
assert_contains "$INSTALLER" '/etc/jjdguard/install.env'
assert_contains "$INSTALLER" '/var/backups/jjdguard'
assert_contains "$INSTALLER" 'target_arch'
assert_contains "$INSTALLER" 'deploy-offline.sh'
assert_contains "$INSTALLER" 'upgrade.sh'
assert_contains "$INSTALLER" 'UPGRADE_OFFLINE_MODE=1'
assert_contains "$INSTALLER" "say '[修复] 当前版本已释放，复用现有 .env'"
if grep -Fq "log '当前版本已释放" "$INSTALLER"; then
  fail 'same-release repair must use an installer output function that exists'
fi
assert_contains "$INSTALLER" '"$old_dc/.env" -ef "$new_dc/.env"'
assert_contains "$INSTALLER" 'if [[ "$same_release" == 0 ]]'
assert_contains "$INSTALLER" '--worker'
assert_contains "$INSTALLER" '--min-data-version'
assert_contains "$PACKAGER" 'min_data_version'
assert_contains "$INSTALLER" 'systemctl enable --now jjdguard.service'
assert_contains "$INSTALLER" 'systemctl enable docker.service'
! grep -Fq 'systemctl enable --now docker.service' "$INSTALLER" ||
  fail "$INSTALLER must not enable and start an existing shared Docker service"
assert_contains "$INSTALLER" 'Docker 已安装但当前用户无 Engine 权限'
assert_contains "$INSTALLER" 'Docker CLI 已安装但 Engine 不可用'
assert_contains "$DEPLOY_OFFLINE" 'OFFLINE_PORT_SEARCH_LIMIT'
assert_contains "$DEPLOY_OFFLINE" 'port" -ge 65535'
assert_contains "$RUN_HEADER" 'required_kb=$((run_size / 1024 * 3 + 1048576))'
assert_contains "$INSTALLER" 'preflight_runtime_storage'
assert_contains "$INSTALLER" "docker info --format '{{.DockerRootDir}}'"
# 模型灌卷已抽到安装与升级共用的 deploy/lib/judge-model-load.sh。
JUDGE_MODEL_LIB="$ROOT/deploy/lib/judge-model-load.sh"
assert_contains "$DEPLOY_OFFLINE" 'lib/judge-model-load.sh'
assert_contains "$JUDGE_MODEL_LIB" '.$name.incoming'
assert_contains "$JUDGE_MODEL_LIB" 'status=progress'
assert_contains "$JUDGE_MODEL_LIB" '.$name.interrupted'
assert_contains "$DEPLOY_OFFLINE" 'recover_pending_install_ports'
assert_contains "$DEPLOY_OFFLINE" '.env.ports.XXXXXX'

pin_line="$(grep -n 'pin_old_release' "$INSTALLER" | tail -1 | cut -d: -f1)"
load_line="$(grep -n 'verify_and_load_images "$release"' "$INSTALLER" | tail -1 | cut -d: -f1)"
[[ -n "$pin_line" && -n "$load_line" && "$pin_line" -lt "$load_line" ]] ||
  fail 'old release must be pinned before loading replacement tags'

assert_contains "$CTL" 'JJDGuard 管理命令'
for command in status start stop restart backup rollback diagnose; do
  assert_contains "$CTL" "$command"
done
assert_contains "$CTL" 'cert import'
assert_contains "$CTL" 'openssl x509'
assert_contains "$CTL" 'openssl pkey'
assert_contains "$CTL" 'web-console.crt'
assert_contains "$CTL" 'last-upgrade.env'
assert_contains "$CTL" 'dropdb --if-exists --force'
assert_contains "$CTL" 'database restore completed'

assert_contains "$SERVICE" 'After=docker.service network-online.target'
assert_contains "$SERVICE" 'ExecStartPre=/opt/jjdguard/current/deploy/offline-installer/wait-docker.sh'
assert_contains "$SERVICE" 'ExecStart=/opt/jjdguard/current/jjdctl start'
assert_contains "$SERVICE" 'WantedBy=multi-user.target'

assert_contains "$DEPLOY_OFFLINE" "grep -q '^COMPOSE_PROFILES='"
assert_contains "$DEPLOY_OFFLINE" "printf 'COMPOSE_PROFILES=%s"
persist_line="$(grep -n "printf 'COMPOSE_PROFILES=%s" "$DEPLOY_OFFLINE" | head -n 1 | cut -d: -f1)"
start_line="$(grep -n 'starting offline services' "$DEPLOY_OFFLINE" | head -n 1 | cut -d: -f1)"
[[ -n "$persist_line" && -n "$start_line" && "$persist_line" -lt "$start_line" ]] ||
  fail 'bundle profiles must be persisted before services are started'

assert_contains "$DEPLOY_OFFLINE" 'cleanup_failed_deploy()'
assert_contains "$DEPLOY_OFFLINE" 'trap cleanup_failed_deploy EXIT HUP INT TERM'
assert_contains "$DEPLOY_OFFLINE" 'sh "$COMPOSE_WRAPPER" stop'
assert_contains "$DEPLOY_OFFLINE" 'DEPLOY_STARTED=1'
assert_contains "$DEPLOY_OFFLINE" 'FRESH_INSTALL=1'
assert_contains "$DEPLOY_OFFLINE" "! -path './deploy/docker-compose/.env'"
assert_contains "$DEPLOY_OFFLINE" "! -path './deploy/docker-compose/tls/web-console.key'"
assert_contains "$DEPLOY_OFFLINE" 'enabling bundled Chat / SSO portal for first installation'
assert_contains "$DEPLOY_OFFLINE" "UPDATE system_settings SET value='true'"
if grep -Eq '(^|[[:space:]])(docker[[:space:]]+compose|compose-wrapper\.sh)[^\n]*(down|volume[[:space:]]+rm)' "$DEPLOY_OFFLINE"; then
  fail 'first-install failure cleanup must not delete Compose resources or volumes'
fi

assert_contains "$PACKAGER" 'package-offline-bundle.sh'
assert_contains "$PACKAGER" 'deploy/offline-installer'
assert_contains "$PACKAGER" 'installer.sh'
assert_contains "$TRUST_VERIFIER" '--release-dir'
assert_contains "$TRUST_VERIFIER" 'release-public.pem'
for customer_doc in "$COMPOSE_README"; do
  assert_contains "$customer_doc" 'sudo ./JJDGuard-offline-'
  assert_contains "$customer_doc" '.run.sha256'
done
if grep -Fq -- '--verify-release' "$COMPOSE_README" "$RUNBOOK"; then
  fail 'customer-visible release instructions must not trust a verifier embedded in the delivered run'
fi
if ! grep -Eq 'sudo[[:space:]]+\./JJDGuard-offline-.*\.run' "$COMPOSE_README"; then
  fail 'customer-visible release instructions must use direct run execution'
fi
if grep -Fq -- '--accept-candidate' "$PACKAGER" "$RUNBOOK" "$COMPOSE_README"; then
  fail 'customer-visible release instructions must not expose candidate acceptance mode'
fi
if grep -Fq -- '执行：sh install.sh' "$PACKAGER"; then
  fail 'customer-visible package README must not direct users around the promotion sidecar'
fi
if grep -Fq -- 'customer flow: trusted verifier + external public key -> verified extraction -> sh install.sh' "$PACKAGER"; then
  fail 'package output must not describe a raw archive installation as the customer flow'
fi
if grep -Fq -- 'OFFLINE_SKIP_N1_GATE' "$PACKAGER"; then
  fail 'candidate N-1 gate must not have a production skip switch'
fi
if grep -Fq -- 'sh install.sh' "$COMPOSE_README"; then
  fail 'compose README must not teach an unsigned raw archive installation path'
fi

readme_customer_upgrade="$(sed -n '/^### Offline bundle in-place upgrade (customer one-command)$/,/^## Ports$/p' "$COMPOSE_README")"
[[ -n "$readme_customer_upgrade" ]] || fail 'compose README is missing the customer offline upgrade section'
if grep -Eq '(^|[[:space:]])tar([[:space:]]|$).*(-x|--extract)' <<<"$readme_customer_upgrade"; then
  fail 'compose README customer upgrade must not direct raw tar extraction'
fi
if grep -Eq '(^|[[:space:]])(sh|bash)[[:space:]]+upgrade\.sh([[:space:]]|$)' <<<"$readme_customer_upgrade"; then
  fail 'compose README customer upgrade must not direct internal upgrade.sh'
fi

runbook_customer_upgrade="$(sed -n '/^## 5\. /,/^## 6\. /p' "$RUNBOOK")"
[[ -n "$runbook_customer_upgrade" ]] || fail 'release runbook is missing the customer upgrade section'
if grep -Eq '(^|[[:space:]])tar([[:space:]]|$).*(-x|--extract)' <<<"$runbook_customer_upgrade"; then
  fail 'release runbook customer upgrade must not direct raw tar extraction'
fi
if grep -Eq '(^|[[:space:]])(sh|bash)[[:space:]]+upgrade\.sh([[:space:]]|$)' <<<"$runbook_customer_upgrade"; then
  fail 'release runbook customer upgrade must not direct internal upgrade.sh'
fi
if grep -Fq -- 'cp "$SCRIPT_DIR"/README.md' "$PACKAGER"; then
  fail 'customer bundle must not ship the internal compose README as a second installation guide'
fi

for file in "$INSTALLER" "$CTL"; do
  bash -n "$file"
done

(
  export JJD_INSTALLER_LIB_ONLY=1
  # shellcheck disable=SC1090
  source "$INSTALLER"
  [[ "$(normalize_arch x86_64)" == amd64 ]]
  [[ "$(normalize_arch aarch64)" == arm64 ]]
)

test_installer_persists_exact_package_metadata
test_builtin_chat_issuer_is_always_normalized_to_public_url
test_rollback_does_not_implicitly_restore_database
test_rollback_tracks_all_first_party_runtime_images
test_jjdctl_status_returns_zero_without_deploy_result
test_smoke_accepts_rotated_bootstrap_password
test_jjdctl_uses_only_protected_active_compose_state
test_rollback_start_converges_and_fails_closed
test_deploy_failure_stops_current_compose_project
test_installer_discovers_running_compose_from_labels

echo '[ok] customer installer contract passed'
