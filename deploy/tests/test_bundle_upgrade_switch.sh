#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CORE_SCRIPT="$ROOT_DIR/deploy/docker-compose/upgrade-bundle.sh"
fail() { echo "[fail] $*" >&2; exit 1; }
has() { grep -Fq -- "$2" "$1" || fail "expected $1 to contain: $2"; }
lacks() { ! grep -Fq -- "$2" "$1" || fail "expected $1 not to contain: $2"; }
line_of() { grep -Fn -- "$2" "$1" | head -1 | cut -d: -f1; }

make_fixture() {
  local f="$1" archive sum
  mkdir -p "$f/bin" "$f/lib" "$f/offline-installer" "$f/new/bin" "$f/new/offline-artifacts" "$f/new/backups/run" "$f/new/.upgrade" "$f/new/tls" "$f/new/chat" "$f/old/chat"
  # 夹具里伪造的脚本是 bash 写的，而升级器按 sh 调用它们；/bin/sh 是 dash 的构建机（Ubuntu）上会在 set -o pipefail 处失败。
  # 让夹具自带一个指向 bash 的 sh，测试结果不再取决于构建机的 /bin/sh。
  ln -s "$(command -v bash)" "$f/bin/sh"
  cp "$CORE_SCRIPT" "$f/new/upgrade-bundle.sh"
  # 与正式包一致：升级器引入与安装器共用的 judge 模型灌卷库。
  cp "$(dirname "$CORE_SCRIPT")/../lib/judge-model-load.sh" "$f/lib/judge-model-load.sh"
  # 回退 release 里的 jjdctl / smoke-test / backup-db / diagnose 都靠它安全读取 .env，升级器必须把它带进回退 release。
  cp "$ROOT_DIR/deploy/lib/jjd-env.sh" "$f/lib/jjd-env.sh"
  cp "$ROOT_DIR/deploy/docker-compose/compose-wrapper.sh" "$f/new/compose-wrapper.sh"
  # Match the shipped bundle: the upgrader must migrate Redis keys to Valkey after quiescing writers.
  cp "$ROOT_DIR/deploy/docker-compose/redis-valkey-migrate-lib.sh" "$f/new/redis-valkey-migrate-lib.sh"
  # The upgrader restores the scaled Tier-1 topology from the shared helper;
  # a bundle without it is incomplete and the upgrader refuses to run.
  cp "$ROOT_DIR/deploy/docker-compose/tier1-topology.sh" "$f/new/tier1-topology.sh"
  cp "$ROOT_DIR/deploy/offline-installer/jjdctl" "$f/offline-installer/jjdctl"
  cp "$ROOT_DIR/deploy/offline-installer/wait-docker.sh" "$f/offline-installer/wait-docker.sh"
  chmod 0755 "$f/offline-installer/jjdctl"
  printf 'services: {}\n' >"$f/new/docker-compose.offline.yml"
  printf '#!/usr/bin/env bash\nprintf "captcha fixture\\n"\n' >"$f/lib/captcha-login.sh"
  chmod 0755 "$f/lib/captcha-login.sh"
  printf 'fixture certificate\n' >"$f/new/tls/web-console.crt"
  printf 'services: {}\n' >"$f/old/base.yml"; printf 'services: {}\n' >"$f/old/extra.yml"
  printf 'fixture caddy config\n' >"$f/old/chat/Caddyfile"
  cat >"$f/new/chat/bootstrap-identity-runtime.sh" <<'BASH'
#!/usr/bin/env bash
set -Eeuo pipefail
printf 'identity-bootstrap project=%s files=%s separator=%s profiles=%s env=%s runtime=%s\n' \
  "${COMPOSE_PROJECT_NAME:-}" "${COMPOSE_FILE:-}" "${COMPOSE_PATH_SEPARATOR:-}" \
  "${COMPOSE_PROFILES:-}" "${JJD_ENV_FILE:-}" "${IDENTITY_RUNTIME_ENV_FILE:-}" >>"${FAKE_LOG:?}"
[[ "${FAKE_IDENTITY_BOOTSTRAP_FAIL:-0}" != 1 ]] || exit 73
cat >"${IDENTITY_RUNTIME_ENV_FILE:?}" <<'ENV'
JJD_SSO_PUBLIC_URL=https://sso.example.test
JJD_IDENTITY_RUNTIME_URL=http://chat-idp:8180/sso
JJD_IDENTITY_RUNTIME_CLIENT_ID=jjdguard-identity-orchestrator
JJD_IDENTITY_RUNTIME_CLIENT_SECRET=fixture-runtime-secret
JJD_SSO_ALLOW_INSECURE_PUBLIC_URL=false
ENV
chmod 0600 "$IDENTITY_RUNTIME_ENV_FILE"
BASH
  cat >"$f/new/chat/bootstrap-directory-runtime.sh" <<'BASH'
#!/usr/bin/env bash
set -Eeuo pipefail
printf 'directory-bootstrap project=%s files=%s separator=%s profiles=%s\n' \
  "${COMPOSE_PROJECT_NAME:-}" "${COMPOSE_FILE:-}" "${COMPOSE_PATH_SEPARATOR:-}" \
  "${COMPOSE_PROFILES:-}" >>"${FAKE_LOG:?}"
[[ -s "${IDENTITY_RUNTIME_ENV_FILE:?}" ]] || exit 74
BASH
  chmod 0755 "$f/new/chat/bootstrap-identity-runtime.sh" "$f/new/chat/bootstrap-directory-runtime.sh"
  chmod 0644 "$f/old/base.yml" "$f/old/extra.yml"
  printf 'POSTGRES_PASSWORD=trusted-old\n' >"$f/old/.env"; chmod 0640 "$f/old/.env"
  printf '%s\n' 'POSTGRES_PASSWORD=test' 'REDIS_PASSWORD=fixture-redis-password' 'JJD_VERSION=2.0' 'JJD_VERSION=stale-duplicate' \
    'JJD_COMMIT=old-revision' 'JJD_BUILT_AT=old-build-time' >"$f/new/.env"
  cat >"$f/new/manifest.json" <<'JSON'
{
  "version": "2.1",
  "source_revision": "0123456789abcdef0123456789abcdef01234567",
  "target_arch": "amd64",
  "built_at": "2026-08-14T00:00:00Z"
}
JSON
  archive="$f/new/offline-artifacts/jjdguard-offline-images-test.tar.gz"; printf 'fake image stream\n' | gzip >"$archive"
  sum="$(sha256sum "$archive" | awk '{print $1}')"; printf '%s  %s\n' "$sum" "$(basename "$archive")" >"$archive.sha256"
  : >"$f/actions.log"
  cat >"$f/bin/docker" <<'BASH'
#!/usr/bin/env bash
set -Eeuo pipefail
log="${FAKE_LOG:?}"; printf 'docker' >>"$log"; printf ' %q' "$@" >>"$log"; printf '\n' >>"$log"
if [[ "${1:-}" == load ]]; then cat >/dev/null; exit 0; fi
if [[ "${1:-}" == ps ]]; then
  printf '%s\n' 'gw|gateway-core' 'cp|control-plane' 'se|security-engine' 'pg|postgres'
  [[ "${FAKE_WITH_REDIS_CACHE:-0}" == 1 ]] && echo 'rc|redis-cache'
  [[ "${FAKE_WITH_FULL:-0}" == 1 ]] && echo 'judge|llm-judge'; [[ "${FAKE_WITH_CHAT:-0}" == 1 ]] && echo 'portal|chat-portal-ui'; [[ "${FAKE_WITH_IDP:-0}" == 1 ]] && echo 'idp|chat-idp'; exit 0
fi
if [[ "${1:-}" == inspect || ( "${1:-}" == image && "${2:-}" == inspect ) ]]; then
  joined="$*"; target="${@: -1}"
  if [[ "$joined" == *'.Config.Env'* && "$target" == *control-plane* ]]; then
    [[ -f "${FAKE_LOG}.identity-control-plane-recreated" ]] || exit 52
    printf '%s\n' \
      'JJD_SSO_PUBLIC_URL=https://sso.example.test' \
      'JJD_IDENTITY_RUNTIME_URL=http://chat-idp:8180/sso' \
      'JJD_IDENTITY_RUNTIME_CLIENT_ID=jjdguard-identity-orchestrator' \
      'JJD_IDENTITY_RUNTIME_CLIENT_SECRET=fixture-runtime-secret' \
      'JJD_SSO_ALLOW_INSECURE_PUBLIC_URL=false'
    exit 0
  fi
  if [[ "$joined" == *'.Config.Env'* ]]; then
    [[ "${FAKE_DATABASE_IDENTITY_FAIL:-0}" != 1 ]] || exit 51
    printf '%s\n' 'POSTGRES_USER=jjdguard' 'POSTGRES_DB=jjdguard'
    exit 0
  fi
  if [[ "$joined" == *'.Architecture'* ]]; then
    [[ "$target" == new/hidden-profile:1 && "${FAKE_HIDDEN_IMAGE_MISSING:-0}" == 1 ]] && exit 1
    [[ "$target" == new/hidden-profile:1 ]] && echo "${FAKE_HIDDEN_IMAGE_ARCH:-amd64}" || echo "${FAKE_IMAGE_ARCH:-amd64}"
    exit 0
  fi
  # verify_upgrade probes (Config.Image / State.Running / Health.Status) — must short-circuit
  # before the sha256-by-container-name branch used by capture_rollback_images ({{.Image}}).
  if [[ "$joined" == *'.Config.Image'* ]]; then
    case "$target" in *portal*|*chat-portal-ui*) echo "${FAKE_PORTAL_IMAGE:-enterprise-ai-portal:0.2.0-slim}";; *) echo 'new/image:1';; esac
    exit 0
  fi
  if [[ "$joined" == *'{{.Id}}'* && "${1:-}" == image && "${2:-}" == inspect ]]; then
    case "$target" in
      enterprise-ai-portal:0.2.0-slim) printf 'sha256:%064s\n' '' | tr ' ' f ;;
      *) echo healthy ;;
    esac
    exit 0
  fi
  if [[ "$joined" == *'{{.Image}}'* && "$target" == *portal* ]]; then
    if [[ -n "${FAKE_PORTAL_CONTAINER_IMAGE_ID:-}" ]]; then
      printf '%s\n' "$FAKE_PORTAL_CONTAINER_IMAGE_ID"
    else
      printf 'sha256:%064s\n' '' | tr ' ' f
    fi
    exit 0
  fi
  if [[ "$target" == health-container ]]; then
    count_file="${FAKE_LOG}.health-count"; count=0; [[ -f "$count_file" ]] && read -r count <"$count_file"; count=$((count + 1)); printf '%s\n' "$count" >"$count_file"
    case "${FAKE_HEALTH_MODE:-healthy}" in starting_then_healthy) (( count <= 3 )) && echo starting || echo healthy;; starting) echo starting;; *) echo healthy;; esac
    exit 0
  fi
  if [[ "$joined" == *'Health.Status'* || "$joined" == *'State.Health'* ]]; then echo healthy; exit 0; fi
  if [[ "$joined" == *'.State.Running'* ]]; then echo true; exit 0; fi
  case "$target" in gw) c=a;; cp) c=b;; se) c=c;; pg) c=d;; judge) c=e;; portal) c=f;; idp) c=1;; rc) c=2;; *) echo healthy; exit 0;; esac
  printf 'sha256:%064s\n' '' | tr ' ' "$c"; exit 0
fi
if [[ "${1:-}" == exec ]]; then
  if [[ "$*" == *'pg_dump'* ]]; then
    if [[ -f "${FAKE_LOG}.db-state" ]]; then cat "${FAKE_LOG}.db-state"; else echo 'fixture custom archive'; fi
    exit 0
  fi
  if [[ "$*" == *'pg_restore --list'* ]]; then cat >/dev/null; exit 0; fi
  if [[ "$*" == *'pg_restore --no-owner'* ]]; then
    printf 'restored ' >>"$log"; cat >>"$log"; printf '\n' >>"$log"; exit 0
  fi
  if [[ "$*" == *'openid-configuration'* && -n "${FAKE_OIDC_MODE:-}" ]]; then
    exit 71
  fi
  case "$*" in
    *"SELECT count(*) FROM security_events"*)
      [[ "${FAKE_POLL_FAIL:-0}" != 1 || ! -f "${FAKE_LOG}.temp-key-created" ]] || exit 58
      if [[ "$*" == *'JOIN request_logs'* && "$*" == *'rl.client_id='* ]]; then
        if [[ "$*" == *"rl.provider_id='prov_upgrade_"* && "$*" == *"rl.model_id='model_upgrade_"* && "$*" == *"se.event_type='security_check'"* && "$*" == *"matched_summary->>'category'='ssh_private_key'"* && "$*" == *"se.severity IN ('high','critical')"* ]]; then
          [[ -f "${FAKE_LOG}.event-count" && "${FAKE_ATTRIBUTED_EVENT:-1}" == 1 && "${FAKE_WRONG_PROVIDER:-0}" != 1 && "${FAKE_WRONG_MODEL:-0}" != 1 && "${FAKE_EVENT_KIND:-ssh_private_key}" == ssh_private_key ]] && echo 1 || echo 0
        else
          echo 0
        fi
      else
        [[ -f "${FAKE_LOG}.event-count" ]] && echo 1 || echo 0
      fi;;
    *"INSERT INTO providers"*)
      [[ "${FAKE_INSERT_FAIL:-0}" != 1 && "${FAKE_INSERT_COLLISION:-0}" != 1 ]] || exit 57
      [[ "$*" == *'INSERT INTO model_endpoint_capability_overrides'* &&
         "$*" == *"'chat','supported','upgrade verification','system'"* ]] || exit 65
      touch "${FAKE_LOG}.temp-provider-created" "${FAKE_LOG}.temp-credential-created" "${FAKE_LOG}.temp-model-created" "${FAKE_LOG}.temp-override-created" "${FAKE_LOG}.temp-key-created"
      if [[ "$*" == *"'tenant_default','project_default',NULL"* ]]; then
        touch "${FAKE_LOG}.probe-default-project"
      fi
      if [[ "$*" == *'INSERT INTO projects'* ]]; then
        [[ "$*" == *"'project_upgrade_verify_"* && "$*" == *"'production','active'"* ]] || exit 83
        touch "${FAKE_LOG}.temp-project-created"
        echo '1|1|1|1|1|1'
      else
        echo '1|1|1|1|1'
      fi;;
    *"UPDATE request_logs SET provider_id="*)
      [[ "$*" == *"provider_id=CASE WHEN provider_id='prov_upgrade_"* && "$*" == *"THEN NULL ELSE provider_id END,model_id=CASE WHEN model_id='model_upgrade_"* && "$*" == *"THEN NULL ELSE model_id END"* ]] || exit 58
      [[ "$*" == *"WHERE client_id='key_upgrade_verify_"* && "$*" == *"AND (provider_id='prov_upgrade_"* && "$*" == *"OR model_id='model_upgrade_"* ]] || exit 59
      [[ "$*" == *'DELETE FROM model_endpoint_capability_overrides'* && "$*" == *'DELETE FROM models'* && "$*" == *'DELETE FROM provider_credentials'* && "$*" == *'DELETE FROM providers'* && "$*" == *'DELETE FROM internal_keys'* ]] || exit 60
      [[ "$*" == *"id='meco_upgrade_"* && "$*" == *"endpoint_type='chat'"* && "$*" == *"state='supported'"* && "$*" == *"reason='upgrade verification'"* && "$*" == *"actor_user_id='system'"* ]] || exit 66
      [[ "$*" == *"models WHERE id='model_upgrade_"* && "$*" == *"AND provider_id='prov_upgrade_"* && "$*" == *"AND model_name='upgrade-verify-"* ]] || exit 61
      [[ "$*" == *"credential_name='verify-"* && "$*" == *"tenant_id='tenant_default'"* && "$*" == *"name='UpgradeVerify-"* && "$*" == *"base_url='http://127.0.0.1:9'"* ]] || exit 62
      [[ "$*" == *"key_hash='"* && "$*" == *"key_prefix='sk-upgra'"* ]] || exit 63
      if [[ "${FAKE_CATALOG_SYNC_ROW:-0}" == 1 ]]; then
        [[ "$*" == *'DELETE FROM model_catalog_entries'* && "$*" == *'DELETE FROM model_catalog_sync_state'* ]] || exit 86
      fi
      cleanup_sql="${*#*UPDATE request_logs}"; cleanup_sql="${cleanup_sql#*DELETE FROM model_endpoint_capability_overrides}"; cleanup_sql="${cleanup_sql#*DELETE FROM models}"; cleanup_sql="${cleanup_sql#*DELETE FROM provider_credentials}"; cleanup_sql="${cleanup_sql#*DELETE FROM providers}"
      [[ "$cleanup_sql" == *'DELETE FROM internal_keys'* ]] || exit 64
      touch "${FAKE_LOG}.request-logs-detached"
      if [[ "${FAKE_WRONG_PROVIDER:-0}" == 1 && "${FAKE_WRONG_MODEL:-0}" != 1 ]]; then touch "${FAKE_LOG}.temp-model-column-detached"; fi
      if [[ "${FAKE_WRONG_MODEL:-0}" == 1 && "${FAKE_WRONG_PROVIDER:-0}" != 1 ]]; then touch "${FAKE_LOG}.temp-provider-column-detached"; fi
      if [[ "${FAKE_WRONG_MODEL:-0}" == 1 && "${FAKE_WRONG_PROVIDER:-0}" == 1 ]]; then touch "${FAKE_LOG}.customer-route-preserved"; fi
      touch "${FAKE_LOG}.temp-override-deleted" "${FAKE_LOG}.temp-model-deleted" "${FAKE_LOG}.temp-credential-deleted" "${FAKE_LOG}.temp-provider-deleted" "${FAKE_LOG}.temp-key-deleted"
      if [[ -f "${FAKE_LOG}.temp-project-created" ]]; then
        [[ "$*" == *"UPDATE projects SET status='deleted'"* && "$*" == *"WHERE id='project_upgrade_verify_"* && "$*" == *"AND status='active'"* && "$*" == *"code='upv_"* ]] || exit 84
        [[ "$*" != *'DELETE FROM projects'* ]] || exit 85
        touch "${FAKE_LOG}.temp-project-retired"
        echo '1|1|1|1|1|1|1'
      else
        echo '1|1|1|1|1|1'
      fi;;
    *v1/models*) echo '{"data":[{"id":"bundled-judge"}]}' ;;
    *) ;;
  esac
  exit 0
fi
if [[ "${1:-}" == compose ]]; then
  exit 127
fi
BASH
  chmod +x "$f/bin/docker"
  cat >"$f/bin/openssl" <<'BASH'
#!/usr/bin/env bash
printf '%s\n' '0123456789abcdef0123456789abcdef0123456789abcdef'
BASH
  chmod +x "$f/bin/openssl"
cat >"$f/bin/curl" <<'BASH'
#!/usr/bin/env bash
printf 'curl' >>"${FAKE_LOG:?}"; printf ' %q' "$@" >>"$FAKE_LOG"; printf '\n' >>"$FAKE_LOG"
if [[ "$*" == *'/v1/chat/completions'* ]]; then
  [[ "$*" == *'upgrade-verification-0123456789abcdef0123456789abcdef0123456789abcdef'* ]] || exit 64
  if [[ "$*" == *'--config -'* ]]; then
    config="$(cat)"
    [[ "$config" == *'Authorization: Bearer sk-upgrade-'* ]] || exit 63
  fi
  # 客户默认应用只允许已登记模型，不能为了出包放开它；自检必须使用独立应用。
  if [[ "${FAKE_PROJECT_MODEL_DENY:-0}" == 1 && -f "${FAKE_LOG}.probe-default-project" ]]; then
    printf '403'
    exit 0
  fi
  [[ "${FAKE_ATTRIBUTED_EVENT:-1}" != 1 ]] || printf '1\n' >"${FAKE_LOG:?}.event-count"
  [[ "${FAKE_REQUEST_FAIL:-0}" != 1 ]] || exit 62
  printf '%s' "${FAKE_HTTP_STATUS:-200}"
  exit 0
fi
if [[ "$*" == *'/realms/'* && "$*" == *'/.well-known/openid-configuration'* ]]; then
  count_file="${FAKE_LOG:?}.oidc-count"; count=0
  [[ -f "$count_file" ]] && read -r count <"$count_file"
  count=$((count + 1)); printf '%s\n' "$count" >"$count_file"
  case "${FAKE_OIDC_MODE:-ready}" in
    starting_then_ready) (( count < 3 )) && printf '503' || printf '200' ;;
    unavailable) printf '503' ;;
    *) printf '200' ;;
  esac
  exit 0
fi
if [[ -n "${FAKE_GENERIC_HTTP_STATUS:-}" ]]; then
  printf '%s' "$FAKE_GENERIC_HTTP_STATUS"
  exit 0
fi
printf '200'
BASH
  chmod +x "$f/bin/curl"
  printf '#!/usr/bin/env bash\n[[ "${1:-}" == 1 ]] && exit 0\nexec /usr/bin/sleep "$@"\n' >"$f/bin/sleep"
  chmod +x "$f/bin/sleep"
  cat >"$f/new/bin/docker-compose" <<'BASH'
#!/usr/bin/env bash
set -Eeuo pipefail
printf 'bundled docker-compose' >>"${FAKE_LOG:?}"
printf ' %q' "$@" >>"$FAKE_LOG"
echo >>"$FAKE_LOG"
joined="$*"
if [[ "$joined" == *'config --services'* ]]; then
  for item in gateway-core control-plane security-engine postgres redis redis-cache; do echo "$item"; done
  [[ "$joined" == *'--profile full'* ]] && echo llm-judge
  if [[ "$joined" == *'--profile chat'* ]]; then echo chat-portal-ui; echo chat-idp; fi
elif [[ "$joined" == *'config --images'* ]]; then
  for item in new/gateway:1 new/control:1 new/security:1 postgres:16; do echo "$item"; done
  if [[ "$joined" == *'--profile *'* ]]; then echo new/judge:1; echo new/portal:1; echo new/hidden-profile:1; fi
elif [[ "$joined" == *' up -d'* ]]; then
  [[ "${FAKE_UP_FAIL:-0}" == 1 ]] && exit 42
  if [[ "$joined" == *control-plane* && -s identity-runtime.env && "${FAKE_IDENTITY_RECREATE_NO_LOAD:-0}" != 1 ]]; then
    touch "${FAKE_LOG}.identity-control-plane-recreated"
  fi
  case "${FAKE_MUTATE_SNAPSHOT_AFTER_UP:-}" in
    content) printf 'services: {attacker: {}}\n' >"${OLD_CONFIG_SNAPSHOT_FILES%%,*}" ;;
    parent) chmod 0777 "${OLD_CONFIG_SNAPSHOT_DIR:?}" ;;
    envcontent) printf 'POSTGRES_PASSWORD=attacker\n' >"${OLD_ENV_SNAPSHOT_FILE:?}" ;;
  esac
elif [[ "$joined" == *' stop --timeout 60'* ]]; then
  if [[ "${FAKE_SIMULATE_LATE_EVIDENCE:-0}" == 1 ]]; then
    echo 'post-backup-evidence' >"${FAKE_LOG}.db-state"
  fi
elif [[ "$joined" == *'ps --status running --services'* ]]; then
  for item in gateway-core control-plane security-engine; do echo "$item"; done
elif [[ "$joined" == *' exec -T redis redis-cli '* ]]; then
  echo "${FAKE_SHARED_STATE_PROBE_OUTPUT:-PONG}"
elif [[ "$joined" == *' ps -q '* ]]; then
  echo health-container
fi
exit 0
BASH
  chmod +x "$f/new/bin/docker-compose"

  cat >"$f/new/migrate-private.sh" <<'BASH'
#!/usr/bin/env bash
set -Eeuo pipefail
printf 'migration project=%s files=%s profiles=%s wrapper=%s\n' "${COMPOSE_PROJECT_NAME:-}" "${COMPOSE_FILE:-}" "${COMPOSE_PROFILES:-}" "${COMPOSE_WRAPPER:-}" >>"${FAKE_LOG:?}"
BASH
  chmod +x "$f/new/migrate-private.sh"
}

run_flow() {
  local f="$1"
  ( cd "$f/new"; PATH="$f/bin:$PATH" FAKE_LOG="$f/actions.log" EXISTING_PROJECT_NAME=customer EXISTING_WORK_DIR="$f/old" \
    EXISTING_CONFIG_FILES="${EXISTING_CONFIG_FILES_OVERRIDE:-$f/old/base.yml,$f/old/extra.yml}" EXISTING_ENV_FILE="$f/old/.env" BACKUP_DIR="$f/new/backups/run" \
    UPGRADE_RUN_TIMESTAMP=20260714T120000Z UPGRADE_BASE_HOST=127.0.0.127 VERIFY_HEALTH_TIMEOUT=5 SMOKE_SKIP_LOGIN=true \
    bash -c 'source ./upgrade-bundle.sh; EXISTING_CONFIG_FILES="$(normalize_config_files "$EXISTING_WORK_DIR" "$EXISTING_CONFIG_FILES")"; create_config_snapshots; capture_rollback_images; create_legacy_release_anchor; load_offline_images; ACTIVE_CONFIG_DIR="$SCRIPT_DIR"; ACTIVE_CONFIG_FILES="$OLD_CONFIG_SNAPSHOT_FILES"; RELEASE_IMAGE_OVERRIDE="$SCRIPT_DIR/release-images.override.yml"; printf "services: {}\n" >"$RELEASE_IMAGE_OVERRIDE"; chmod 0600 "$RELEASE_IMAGE_OVERRIDE"; export ACTIVE_CONFIG_DIR ACTIVE_CONFIG_FILES RELEASE_IMAGE_OVERRIDE; run_in_place_upgrade' )
}

run_rollback() {
  local f="$1"
  ( cd "$f/new"; PATH="$f/bin:$PATH" FAKE_LOG="$f/actions.log" EXISTING_PROJECT_NAME=customer EXISTING_WORK_DIR="$f/old" \
    EXISTING_CONFIG_FILES="$f/old/base.yml,$f/old/extra.yml" EXISTING_ENV_FILE="$f/old/.env" BACKUP_DIR="$f/new/backups/run" ROLLBACK_HEALTH_TIMEOUT="${ROLLBACK_HEALTH_TIMEOUT:-2}" ROLLBACK_HEALTH_INTERVAL="${ROLLBACK_HEALTH_INTERVAL:-0.05}" \
    bash -c 'source ./upgrade-bundle.sh; EXISTING_CONFIG_FILES="$(normalize_config_files "$EXISTING_WORK_DIR" "$EXISTING_CONFIG_FILES")"; create_config_snapshots; capture_rollback_images; rollback_old_services' )
}

test_success_and_profile_preservation() {
  local f manifest override service capture_line load_line stop_line dump_line migrate_line switch_line helper
  f="$(mktemp -d)"; trap 'rm -rf "$f"' RETURN; make_fixture "$f"; FAKE_WITH_FULL=1 FAKE_WITH_CHAT=1 FAKE_WITH_IDP=1 run_flow "$f"
  manifest="$f/new/backups/run/rollback-images.tsv"; override="$f/new/backups/run/rollback-compose.yml"
  [[ "$(stat -c %a "$manifest")" == 600 && "$(stat -c %a "$override")" == 600 ]] || fail 'rollback files must be 0600'
  for service in gateway-core control-plane security-engine postgres llm-judge chat-portal-ui chat-idp; do has "$manifest" "$service"; has "$override" "  $service:"; done
  has "$f/actions.log" '--project-name customer'; has "$f/actions.log" '--profile full'; has "$f/actions.log" '--profile chat'; lacks "$f/actions.log" '--profile chat-idp'
  has "$f/actions.log" '--profile \*'
  lacks "$f/actions.log" "$f/old/base.yml"; lacks "$f/actions.log" "$f/old/extra.yml"
  has "$f/actions.log" 'migration project=customer'; has "$f/actions.log" 'docker-compose.offline.yml'; has "$f/actions.log" 'profiles=full,chat'; has "$f/actions.log" 'docker load'; [[ "$(grep -c ' up -d' "$f/actions.log")" -eq 2 ]] || fail 'built-in identity upgrade must switch once and recreate control-plane once'
  has "$f/actions.log" 'up -d --force-recreate'
  capture_line="$(line_of "$f/actions.log" 'docker ps')"; load_line="$(line_of "$f/actions.log" 'docker load')"
  stop_line="$(line_of "$f/actions.log" ' stop --timeout 60')"; lacks "$f/actions.log" 'pg_dump'
  migrate_line="$(line_of "$f/actions.log" 'migration project=customer')"; switch_line="$(line_of "$f/actions.log" ' up -d')"
  (( capture_line < load_line && load_line < stop_line && stop_line < migrate_line && migrate_line < switch_line )) || fail 'cutover must quiesce writers before migration without repeating the online backup'
  [[ -f "$f/actions.log.temp-key-created" && -f "$f/actions.log.temp-key-deleted" ]] || fail 'temporary verification key must be created and deleted'
  for kind in provider credential model override key; do [[ -f "$f/actions.log.temp-$kind-created" && -f "$f/actions.log.temp-$kind-deleted" ]] || fail "temporary $kind must be created and deleted"; done
  helper="$f/new/backups/run/legacy-release/deploy/lib/captcha-login.sh"
  [[ -f "$helper" && ! -L "$helper" && "$(stat -c %a "$helper")" == 755 ]] || fail 'legacy release captcha helper is incomplete or unsafe'
  cmp -s "$f/lib/captcha-login.sh" "$helper" || fail 'legacy release captcha helper differs from the signed release helper'
  helper="$f/new/backups/run/legacy-release/deploy/lib/jjd-env.sh"
  [[ -f "$helper" && ! -L "$helper" && "$(stat -c %a "$helper")" == 755 ]] || fail 'legacy release must carry the safe .env loader'
  cmp -s "$f/lib/jjd-env.sh" "$helper" || fail 'legacy release .env loader differs from the release loader'
  cmp -s "$f/old/chat/Caddyfile" "$f/new/backups/run/legacy-release/deploy/docker-compose/chat/Caddyfile" ||
    fail 'legacy release relative bind asset was not preserved'
  [[ "$(<"$f/new/backups/run/legacy-release/deploy/docker-compose/.upgrade/project-directory")" == \
     "$f/new/backups/run/legacy-release/deploy/docker-compose" ]] ||
    fail 'legacy release project directory must be self-contained for re-upgrade discovery'
  has "$f/actions.log" 'INSERT\ INTO\ internal_keys'
  has "$f/actions.log" 'DELETE\ FROM\ internal_keys'
  lacks "$f/actions.log" 'sk-upgrade-0123456789abcdef0123456789abcdef0123456789abcdef'
  has "$f/new/.env" 'POSTGRES_PASSWORD=test'
  [[ "$(grep -c '^JJD_VERSION=' "$f/new/.env")" -eq 1 ]] || fail 'target env must contain exactly one JJD_VERSION'
  [[ "$(grep -c '^JJD_COMMIT=' "$f/new/.env")" -eq 1 ]] || fail 'target env must contain exactly one JJD_COMMIT'
  [[ "$(grep -c '^JJD_BUILT_AT=' "$f/new/.env")" -eq 1 ]] || fail 'target env must contain exactly one JJD_BUILT_AT'
  has "$f/new/.env" 'JJD_VERSION=2.1'
  has "$f/new/.env" 'JJD_COMMIT=0123456789abcdef0123456789abcdef01234567'
  has "$f/new/.env" 'JJD_BUILT_AT=2026-08-14T00:00:00Z'
}

test_builtin_identity_runtime_is_repaired_and_injected() {
  local f
  f="$(mktemp -d)"; make_fixture "$f"
  FAKE_WITH_CHAT=1 FAKE_WITH_IDP=1 run_flow "$f" >/dev/null
  has "$f/actions.log" 'identity-bootstrap project=customer'
  has "$f/actions.log" "files=$f/new/docker-compose.offline.yml|"
  has "$f/actions.log" "$f/new/release-images.override.yml"
  has "$f/actions.log" 'separator=| profiles=chat'
  has "$f/actions.log" "env=$f/new/.env runtime=$f/new/identity-runtime.env"
  has "$f/actions.log" 'directory-bootstrap project=customer'
  [[ -s "$f/new/identity-runtime.env" && "$(stat -c %a "$f/new/identity-runtime.env")" == 600 ]] ||
    fail 'identity runtime env was not securely generated'
  [[ -f "$f/actions.log.identity-control-plane-recreated" ]] ||
    fail 'control-plane was not recreated after identity bootstrap'
  rm -rf "$f"
}

test_builtin_identity_runtime_failure_rolls_back() {
  local f status
  f="$(mktemp -d)"; make_fixture "$f"
  set +e
  FAKE_WITH_CHAT=1 FAKE_WITH_IDP=1 FAKE_IDENTITY_BOOTSTRAP_FAIL=1 run_flow "$f" >/dev/null 2>&1
  status=$?
  set -e
  (( status != 0 )) || fail 'built-in identity bootstrap failure must fail the upgrade'
  [[ "$(grep -c ' up -d' "$f/actions.log")" -eq 2 ]] ||
    fail 'identity bootstrap failure must switch once and roll back once'
  rm -rf "$f"
}

test_builtin_identity_runtime_injection_failure_rolls_back() {
  local f status
  f="$(mktemp -d)"; make_fixture "$f"
  set +e
  FAKE_WITH_CHAT=1 FAKE_WITH_IDP=1 FAKE_IDENTITY_RECREATE_NO_LOAD=1 run_flow "$f" >/dev/null 2>&1
  status=$?
  set -e
  (( status != 0 )) || fail 'missing control-plane identity injection must fail the upgrade'
  [[ "$(grep -c ' up -d' "$f/actions.log")" -eq 3 ]] ||
    fail 'identity injection failure must include recreate and rollback'
  rm -rf "$f"
}

test_external_idp_and_no_chat_skip_local_identity_bootstrap() {
  local f
  f="$(mktemp -d)"; make_fixture "$f"
  printf '%s\n' 'CHAT_BYO_IDP=true' 'CHAT_OIDC_ISSUER=https://login.example.test/tenant' >>"$f/new/.env"
  FAKE_WITH_CHAT=1 run_flow "$f" >/dev/null
  lacks "$f/actions.log" 'identity-bootstrap'
  rm -rf "$f"

  f="$(mktemp -d)"; make_fixture "$f"
  run_flow "$f" >/dev/null
  lacks "$f/actions.log" 'identity-bootstrap'
  rm -rf "$f"
}

assert_all_verification_artifacts_deleted() {
  local log="$1" kind
  for kind in provider credential model override key; do [[ -f "$log.temp-$kind-deleted" ]] || fail "temporary $kind was not cleaned"; done
  if [[ -f "$log.temp-project-created" ]]; then
    [[ -f "$log.temp-project-retired" ]] || fail 'temporary verification project must be retired without deleting evidence references'
  fi
}

test_verification_resource_failures_clean_everything() {
  local f status mode
  for mode in insert request poll; do
    f="$(mktemp -d)"; make_fixture "$f"
    set +e
    case "$mode" in
      insert) FAKE_INSERT_FAIL=1 run_flow "$f" >/dev/null 2>&1 ;;
      request) FAKE_REQUEST_FAIL=1 run_flow "$f" >/dev/null 2>&1 ;;
      poll) FAKE_POLL_FAIL=1 run_flow "$f" >/dev/null 2>&1 ;;
    esac
    status=$?
    set -e
    (( status != 0 )) || fail "$mode verification failure must fail"
    if [[ "$mode" == insert ]]; then
      [[ ! -f "$f/actions.log.temp-key-deleted" ]] || fail 'failed atomic insert must not arm cleanup'
    else
      assert_all_verification_artifacts_deleted "$f/actions.log"
      [[ -f "$f/actions.log.request-logs-detached" ]] || fail 'request logs must detach before FK cleanup'
    fi
    rm -rf "$f"
  done
}

test_http_404_without_event_fails_and_reports_status() {
  local f status output
  f="$(mktemp -d)"; make_fixture "$f"
  set +e; output="$(FAKE_HTTP_STATUS=404 FAKE_ATTRIBUTED_EVENT=0 run_flow "$f" 2>&1)"; status=$?; set -e
  (( status != 0 )) || fail 'HTTP 404 without event must fail'
  [[ "$output" == *'HTTP 404'* ]] || fail 'final verification failure must report HTTP status'
  assert_all_verification_artifacts_deleted "$f/actions.log"
  rm -rf "$f"
}

test_http_error_events_require_exact_route_attribution() {
  local f status code mismatch
  for code in 403 404 500; do
    f="$(mktemp -d)"; make_fixture "$f"; FAKE_HTTP_STATUS="$code" run_flow "$f" >/dev/null
    assert_all_verification_artifacts_deleted "$f/actions.log"; rm -rf "$f"
  done
  f="$(mktemp -d)"; make_fixture "$f"
  set +e; FAKE_HTTP_STATUS=403 FAKE_ATTRIBUTED_EVENT=0 run_flow "$f" >/dev/null 2>&1; status=$?; set -e
  (( status != 0 )) || fail 'HTTP 403 without event must fail'
  assert_all_verification_artifacts_deleted "$f/actions.log"; rm -rf "$f"
  for mismatch in FAKE_WRONG_PROVIDER FAKE_WRONG_MODEL; do
    f="$(mktemp -d)"; make_fixture "$f"; export "$mismatch=1"
    set +e; FAKE_HTTP_STATUS=403 run_flow "$f" >/dev/null 2>&1; status=$?; set -e
    (( status != 0 )) || fail "$mismatch event must not pass attribution"
    assert_all_verification_artifacts_deleted "$f/actions.log"
    if [[ "$mismatch" == FAKE_WRONG_PROVIDER ]]; then
      [[ -f "$f/actions.log.temp-model-column-detached" && ! -f "$f/actions.log.temp-provider-column-detached" ]] || fail 'wrong provider must detach only temporary model column'
    else
      [[ -f "$f/actions.log.temp-provider-column-detached" && ! -f "$f/actions.log.temp-model-column-detached" ]] || fail 'wrong model must detach only temporary provider column'
    fi
    unset "$mismatch"; rm -rf "$f"
  done
  f="$(mktemp -d)"; make_fixture "$f"
  set +e; FAKE_HTTP_STATUS=403 FAKE_WRONG_PROVIDER=1 FAKE_WRONG_MODEL=1 run_flow "$f" >/dev/null 2>&1; status=$?; set -e
  (( status != 0 )) || fail 'fully customer-routed same-key event must not pass attribution'
  assert_all_verification_artifacts_deleted "$f/actions.log"
  [[ -f "$f/actions.log.customer-route-preserved" ]] || fail 'fully customer route must not be modified'
  rm -rf "$f"
}

test_insert_collision_never_deletes_customer_records() {
  local f status
  f="$(mktemp -d)"; make_fixture "$f"
  set +e; FAKE_INSERT_COLLISION=1 run_flow "$f" >/dev/null 2>&1; status=$?; set -e
  (( status != 0 )) || fail 'verification id collision must fail'
  [[ ! -f "$f/actions.log.temp-key-deleted" ]] || fail 'collision must not delete pre-existing records'
  rm -rf "$f"
}

test_database_identity_failure_blocks_upgrade() {
  local f status
  f="$(mktemp -d)"; make_fixture "$f"
  set +e; FAKE_DATABASE_IDENTITY_FAIL=1 run_flow "$f" >/dev/null 2>&1; status=$?; set -e
  (( status != 0 )) || fail 'database identity failure must fail the upgrade'
  rm -rf "$f"
}

test_unattributed_event_does_not_pass_and_cleans_key() {
  local f status
  f="$(mktemp -d)"; make_fixture "$f"
  set +e; FAKE_ATTRIBUTED_EVENT=0 run_flow "$f" >/dev/null 2>&1; status=$?; set -e
  (( status != 0 )) || fail 'unrelated global security event must not pass verification'
  [[ -f "$f/actions.log.temp-key-deleted" ]] || fail 'stalled attributed verification must delete temporary key'
  [[ "$(grep -c ' up -d' "$f/actions.log")" -eq 2 ]] || fail 'verification failure must switch back to old images once'
  [[ -f "$f/actions.log.health-count" ]] || fail 'verification rollback must wait for core health'
  rm -rf "$f"
}

test_request_failure_cleans_key() {
  local f status
  f="$(mktemp -d)"; make_fixture "$f"
  set +e; FAKE_REQUEST_FAIL=1 run_flow "$f" >/dev/null 2>&1; status=$?; set -e
  (( status != 0 )) || fail 'gateway verification request failure must fail upgrade'
  [[ -f "$f/actions.log.temp-key-deleted" ]] || fail 'failed request must delete temporary key'
  [[ "$(grep -c ' up -d' "$f/actions.log")" -eq 2 ]] || fail 'request failure must roll back old images'
  rm -rf "$f"
}

test_http_401_fails_even_with_attributed_event() {
  local f status
  f="$(mktemp -d)"; make_fixture "$f"
  set +e; FAKE_HTTP_STATUS=401 run_flow "$f" >/dev/null 2>&1; status=$?; set -e
  (( status != 0 )) || fail 'HTTP 401 must fail even when an attributed event exists'
  [[ -f "$f/actions.log.temp-key-deleted" ]] || fail 'HTTP 401 must delete temporary key'
  [[ "$(grep -c ' up -d' "$f/actions.log")" -eq 2 ]] || fail 'HTTP 401 must roll back old images'
  rm -rf "$f"
}

test_unrelated_same_key_event_does_not_pass_upstream_failure() {
  local f status http_status
  for http_status in 429 500; do
    f="$(mktemp -d)"; make_fixture "$f"
    set +e; FAKE_HTTP_STATUS="$http_status" FAKE_EVENT_KIND=governor run_flow "$f" >/dev/null 2>&1; status=$?; set -e
    (( status != 0 )) || fail "HTTP $http_status unrelated same-key event must not pass private-key verification"
    [[ -f "$f/actions.log.temp-key-deleted" ]] || fail "HTTP $http_status unrelated event must delete temporary key"
    [[ "$(grep -c ' up -d' "$f/actions.log")" -eq 2 ]] || fail "HTTP $http_status unrelated event must roll back old images"
    rm -rf "$f"
  done
}

test_private_key_event_can_pass_upstream_failure() {
  local f
  f="$(mktemp -d)"; make_fixture "$f"
  FAKE_HTTP_STATUS=500 FAKE_EVENT_KIND=ssh_private_key run_flow "$f" >/dev/null
  [[ -f "$f/actions.log.temp-key-deleted" ]] || fail 'private-key event must clean temporary key'
  [[ "$(grep -c ' up -d' "$f/actions.log")" -eq 1 ]] || fail 'attributed private-key event should pass despite upstream 500'
  rm -rf "$f"
}

test_oidc_discovery_retries_until_ready() {
  local f count
  f="$(mktemp -d)"; make_fixture "$f"
  FAKE_WITH_CHAT=1 FAKE_OIDC_MODE=starting_then_ready \
    OIDC_VERIFY_MAX_ATTEMPTS=3 OIDC_VERIFY_INTERVAL=0 run_flow "$f" >/dev/null
  read -r count <"$f/actions.log.oidc-count"
  [[ "$count" -eq 3 ]] || fail "OIDC discovery should become ready on attempt 3, got $count"
  lacks "$f/actions.log" 'docker exec customer-chat-edge-1'
  [[ "$(grep -c ' up -d' "$f/actions.log")" -eq 2 ]] || fail 'eventual OIDC readiness must recreate control-plane without rollback'
  rm -rf "$f"
}

test_oidc_discovery_timeout_rolls_back_once() {
  local f status count
  f="$(mktemp -d)"; make_fixture "$f"
  set +e
  FAKE_WITH_CHAT=1 FAKE_OIDC_MODE=unavailable \
    OIDC_VERIFY_MAX_ATTEMPTS=3 OIDC_VERIFY_INTERVAL=0 run_flow "$f" >/dev/null 2>&1
  status=$?
  set -e
  (( status != 0 )) || fail 'permanently unavailable OIDC discovery must fail upgrade'
  read -r count <"$f/actions.log.oidc-count"
  [[ "$count" -eq 3 ]] || fail "OIDC discovery must stop after 3 attempts, got $count"
  [[ "$(grep -c ' up -d' "$f/actions.log")" -eq 3 ]] || fail 'OIDC timeout must recreate control-plane and switch back to old images once'
  rm -rf "$f"
}

test_http_ok_accepts_all_2xx_only() {
  local f status
  f="$(mktemp -d)"; make_fixture "$f"
  for status in 200 201 204 299; do
    ( cd "$f/new"; PATH="$f/bin:$PATH" FAKE_LOG="$f/actions.log" FAKE_GENERIC_HTTP_STATUS="$status" \
      bash -c 'source ./upgrade-bundle.sh; http_ok http://status.test' ) || fail "HTTP $status should pass"
  done
  for status in 199 300 401 500; do
    set +e
    ( cd "$f/new"; PATH="$f/bin:$PATH" FAKE_LOG="$f/actions.log" FAKE_GENERIC_HTTP_STATUS="$status" \
      bash -c 'source ./upgrade-bundle.sh; http_ok http://status.test' )
    result=$?
    set -e
    (( result != 0 )) || fail "HTTP $status should fail"
  done
  rm -rf "$f"
}

test_oidc_discovery_url_selection() {
  local f output status
  f="$(mktemp -d)"; make_fixture "$f"
  output="$(cd "$f/new"; CHAT_BYO_IDP=false CHAT_OIDC_HOST=idp.internal \
    WEB_HTTPS_PORT=9443 TLS_ENABLED=true bash -c 'source ./upgrade-bundle.sh; oidc_discovery_url')"
  [[ "$output" == 'https://idp.internal:9443/sso/realms/jjdguard/.well-known/openid-configuration' ]] || \
    fail "unexpected built-in discovery URL: $output"

  output="$(cd "$f/new"; CHAT_BYO_IDP=false \
    JJD_SSO_PUBLIC_URL=https://sso.example.test/ \
    bash -c 'source ./upgrade-bundle.sh; oidc_discovery_url')"
  [[ "$output" == 'https://sso.example.test/sso/realms/jjdguard/.well-known/openid-configuration' ]] || \
    fail "unexpected public JJDGuard discovery URL: $output"

  for public_url in ftp://sso.example.test 'https://sso.example.test/base' \
    'https://sso.example.test?bad=1' 'https://user@sso.example.test'; do
    set +e
    ( cd "$f/new"; CHAT_BYO_IDP=false JJD_SSO_PUBLIC_URL="$public_url" \
      bash -c 'source ./upgrade-bundle.sh; oidc_discovery_url' ) >/dev/null 2>&1
    status=$?
    set -e
    (( status != 0 )) || fail "invalid JJD_SSO_PUBLIC_URL should fail: $public_url"
  done

  output="$(cd "$f/new"; CHAT_BYO_IDP=true \
    CHAT_OIDC_ISSUER=https://login.example.test/custom/tenant/// \
    bash -c 'source ./upgrade-bundle.sh; oidc_discovery_url')"
  [[ "$output" == 'https://login.example.test/custom/tenant/.well-known/openid-configuration' ]] || \
    fail "unexpected external discovery URL: $output"

  for issuer in '' ftp://login.example.test/tenant 'https:///' 'https://:443/tenant' \
    'https://login.example.test:70000/tenant' 'https://login.example.test/tenant?bad=1'; do
    set +e
    ( cd "$f/new"; CHAT_BYO_IDP=true CHAT_OIDC_ISSUER="$issuer" \
      bash -c 'source ./upgrade-bundle.sh; oidc_discovery_url' ) >/dev/null 2>&1
    status=$?
    set -e
    (( status != 0 )) || fail "invalid external issuer should fail: $issuer"
  done
  rm -rf "$f"
}

test_builtin_oidc_host_authority_validation() {
  local f host output status
  f="$(mktemp -d)"; make_fixture "$f"
  output="$(cd "$f/new"; CHAT_BYO_IDP=false CHAT_OIDC_HOST='[2001:db8::1]' \
    WEB_HTTPS_PORT=9443 TLS_ENABLED=true bash -c 'source ./upgrade-bundle.sh; oidc_discovery_url')"
  [[ "$output" == 'https://[2001:db8::1]:9443/sso/realms/jjdguard/.well-known/openid-configuration' ]] || \
    fail "unexpected IPv6 discovery URL: $output"
  for host in '' 'user@idp.test' 'idp.test:8180' '2001:db8::1' 'idp.test/path' \
    'idp.test?query' 'idp.test#fragment' 'idp test'; do
    set +e
    ( cd "$f/new"; CHAT_BYO_IDP=false CHAT_OIDC_HOST="$host" WEB_HTTPS_PORT=443 \
      bash -c 'source ./upgrade-bundle.sh; oidc_discovery_url' ) >/dev/null 2>&1
    status=$?
    set -e
    (( status != 0 )) || fail "invalid built-in OIDC host should fail: $host"
  done
  rm -rf "$f"
}

test_oversized_oidc_numbers_fail_before_curl() {
  local f assignment status
  f="$(mktemp -d)"; make_fixture "$f"
  for assignment in \
    OIDC_VERIFY_TIMEOUT=18446744073709551616 \
    OIDC_VERIFY_INTERVAL=18446744073709551616 \
    OIDC_VERIFY_REQUEST_TIMEOUT=18446744073709551616 \
    OIDC_VERIFY_CONNECT_TIMEOUT=18446744073709551616 \
    OIDC_VERIFY_MAX_ATTEMPTS=18446744073709551616; do
    : >"$f/actions.log"
    set +e
    ( cd "$f/new"; PATH="$f/bin:$PATH" FAKE_LOG="$f/actions.log" env "$assignment" \
      bash -c 'source ./upgrade-bundle.sh; wait_oidc_discovery http://idp.test/discovery' ) >/dev/null 2>&1
    status=$?
    set -e
    (( status != 0 )) || fail "oversized OIDC number should fail: $assignment"
    lacks "$f/actions.log" 'curl '
  done
  for port in 18446744073709551616 999999999999999999999999; do
    set +e
    ( cd "$f/new"; CHAT_BYO_IDP=false CHAT_OIDC_HOST=idp.test WEB_HTTPS_PORT="$port" \
      bash -c 'source ./upgrade-bundle.sh; oidc_discovery_url' ) >/dev/null 2>&1
    status=$?
    set -e
    (( status != 0 )) || fail "oversized built-in port should fail: $port"
    set +e
    ( cd "$f/new"; CHAT_BYO_IDP=true CHAT_OIDC_ISSUER="https://idp.test:$port/tenant" \
      bash -c 'source ./upgrade-bundle.sh; oidc_discovery_url' ) >/dev/null 2>&1
    status=$?
    set -e
    (( status != 0 )) || fail "oversized issuer port should fail: $port"
  done
  rm -rf "$f"
}

test_oidc_curl_timeout_is_bounded_by_deadline() {
  local f
  f="$(mktemp -d)"; make_fixture "$f"
  ( cd "$f/new"; PATH="$f/bin:$PATH" FAKE_LOG="$f/actions.log" FAKE_OIDC_MODE=unavailable \
    OIDC_VERIFY_TIMEOUT=1 OIDC_VERIFY_REQUEST_TIMEOUT=9 OIDC_VERIFY_CONNECT_TIMEOUT=7 \
    OIDC_VERIFY_MAX_ATTEMPTS=1 OIDC_VERIFY_INTERVAL=0 \
    bash -c 'source ./upgrade-bundle.sh; ! wait_oidc_discovery http://idp.test/realms/r/.well-known/openid-configuration' )
  has "$f/actions.log" '--connect-timeout 1'
  has "$f/actions.log" '--max-time 1'
  rm -rf "$f"
}

test_slow_oidc_timeout_budget_is_accepted() {
  local f count
  f="$(mktemp -d)"; make_fixture "$f"
  ( cd "$f/new"; PATH="$f/bin:$PATH" FAKE_LOG="$f/actions.log" FAKE_OIDC_MODE=unavailable \
    OIDC_VERIFY_TIMEOUT=1200 OIDC_VERIFY_MAX_ATTEMPTS=1 OIDC_VERIFY_INTERVAL=0 \
    bash -c 'source ./upgrade-bundle.sh; ! wait_oidc_discovery http://idp.test/realms/r/.well-known/openid-configuration' )
  read -r count <"$f/actions.log.oidc-count"
  [[ "$count" -eq 1 ]] || fail 'slow-disk OIDC timeout budget must reach the bounded discovery probe'
  rm -rf "$f"
}

test_builtin_oidc_uses_inherited_certificate() {
  local f
  f="$(mktemp -d)"; make_fixture "$f"
  mkdir -p "$f/new/tls"
  printf 'fixture certificate\n' >"$f/new/tls/web-console.crt"
  ( cd "$f/new"; PATH="$f/bin:$PATH" FAKE_LOG="$f/actions.log" CHAT_BYO_IDP=false \
    OIDC_VERIFY_MAX_ATTEMPTS=1 OIDC_VERIFY_INTERVAL=0 \
    bash -c 'source ./upgrade-bundle.sh; wait_oidc_discovery https://idp.test/realms/r/.well-known/openid-configuration' )
  has "$f/actions.log" "--cacert $f/new/tls/web-console.crt"
  lacks "$f/actions.log" '--insecure'
  rm -rf "$f"
}

test_external_oidc_keeps_system_ca_verification() {
  local f
  f="$(mktemp -d)"; make_fixture "$f"
  ( cd "$f/new"; PATH="$f/bin:$PATH" FAKE_LOG="$f/actions.log" CHAT_BYO_IDP=true \
    OIDC_VERIFY_MAX_ATTEMPTS=1 OIDC_VERIFY_INTERVAL=0 \
    bash -c 'source ./upgrade-bundle.sh; wait_oidc_discovery https://idp.test/realms/r/.well-known/openid-configuration' )
  lacks "$f/actions.log" '--cacert'
  lacks "$f/actions.log" '--insecure'
  rm -rf "$f"
}

test_builtin_oidc_missing_certificate_fails_closed() {
  local f status
  f="$(mktemp -d)"; make_fixture "$f"
  rm -f "$f/new/tls/web-console.crt"
  set +e
  ( cd "$f/new"; PATH="$f/bin:$PATH" FAKE_LOG="$f/actions.log" CHAT_BYO_IDP=false \
    OIDC_VERIFY_MAX_ATTEMPTS=1 OIDC_VERIFY_INTERVAL=0 \
    bash -c 'source ./upgrade-bundle.sh; wait_oidc_discovery https://idp.test/realms/r/.well-known/openid-configuration' )
  status=$?
  set -e
  (( status != 0 )) || fail 'built-in HTTPS OIDC must fail without the inherited deployment certificate'
  lacks "$f/actions.log" 'curl '
  rm -rf "$f"
}

test_oidc_wait_settings_are_validated() {
  local f assignment status
  f="$(mktemp -d)"; make_fixture "$f"
  for assignment in \
    OIDC_VERIFY_TIMEOUT=0 OIDC_VERIFY_TIMEOUT=1801 \
    OIDC_VERIFY_INTERVAL=-1 OIDC_VERIFY_INTERVAL=11 \
    OIDC_VERIFY_REQUEST_TIMEOUT=0 OIDC_VERIFY_REQUEST_TIMEOUT=16 \
    OIDC_VERIFY_CONNECT_TIMEOUT=0 OIDC_VERIFY_CONNECT_TIMEOUT=11 \
    OIDC_VERIFY_MAX_ATTEMPTS=1001; do
    set +e
    ( cd "$f/new"; PATH="$f/bin:$PATH" FAKE_LOG="$f/actions.log" env "$assignment" \
      bash -c 'source ./upgrade-bundle.sh; wait_oidc_discovery http://idp.test/discovery' ) >/dev/null 2>&1
    status=$?
    set -e
    (( status != 0 )) || fail "invalid OIDC wait setting should fail: $assignment"
  done
  rm -rf "$f"
}

test_enabled_service_verification_fails_closed() {
  local f status portal_id
  f="$(mktemp -d)"; make_fixture "$f"
  set +e
  ( cd "$f/new"; PATH="$f/bin:$PATH" FAKE_LOG="$f/actions.log" EXISTING_PROJECT_NAME=customer bash -c '
      source ./upgrade-bundle.sh; OLD_RUNNING_SERVICES=(gateway-core web-console)
      http_ok() { return 1; }; project_container() { [[ "$1" != web-console ]] && printf present; }
      verify_web_console' ) >/dev/null 2>&1
  status=$?; set -e; (( status != 0 )) || fail 'previously running web-console must be required'; rm -rf "$f"

  for missing in chat-portal-ui chat-portal-proxy; do
    f="$(mktemp -d)"; make_fixture "$f"
    set +e
    ( cd "$f/new"; PATH="$f/bin:$PATH" FAKE_LOG="$f/actions.log" EXISTING_PROJECT_NAME=customer MISSING="$missing" bash -c '
        source ./upgrade-bundle.sh; http_ok() { return 0; }
        project_container() { [[ "$1" != "$MISSING" ]] && { [[ "$1" == chat-portal-ui ]] && printf portal || printf proxy; }; }
        verify_chat_profile' ) >/dev/null 2>&1
    status=$?; set -e; (( status != 0 )) || fail "chat profile must require $missing"; rm -rf "$f"
  done

  f="$(mktemp -d)"; make_fixture "$f"
  set +e
  ( cd "$f/new"; PATH="$f/bin:$PATH" FAKE_LOG="$f/actions.log" FAKE_PORTAL_IMAGE=registry.invalid/enterprise-ai-portal:0.2.0-slim EXISTING_PROJECT_NAME=customer bash -c '
      source ./upgrade-bundle.sh; http_ok() { return 0; }
      project_container() { [[ "$1" == chat-portal-ui ]] && printf wrong-portal || printf proxy; }
      verify_chat_profile' ) >/dev/null 2>&1
  status=$?; set -e; (( status != 0 )) || fail 'portal image must match exact repository and tag'; rm -rf "$f"

  portal_id="sha256:$(printf '%064s' '' | tr ' ' f)"
  f="$(mktemp -d)"; make_fixture "$f"
  set +e
  ( cd "$f/new"; PATH="$f/bin:$PATH" FAKE_LOG="$f/actions.log" FAKE_PORTAL_CONTAINER_IMAGE_ID="sha256:$(printf '%064s' '' | tr ' ' e)" EXISTING_PROJECT_NAME=customer bash -c '
      source ./upgrade-bundle.sh; http_ok() { return 0; }
      project_container() { [[ "$1" == chat-portal-ui ]] && printf portal || printf proxy; }
      verify_chat_profile' ) >/dev/null 2>&1
  status=$?; set -e; (( status != 0 )) || fail 'portal container image ID must match the trusted release image ID'; rm -rf "$f"

  f="$(mktemp -d)"; make_fixture "$f"
  ( cd "$f/new"; PATH="$f/bin:$PATH" FAKE_LOG="$f/actions.log" FAKE_PORTAL_IMAGE="$portal_id" EXISTING_PROJECT_NAME=customer bash -c '
      source ./upgrade-bundle.sh; http_ok() { return 0; }
      project_container() { [[ "$1" == chat-portal-ui ]] && printf portal || printf proxy; }
      verify_chat_profile' ) >/dev/null 2>&1 ||
    fail 'portal image pinned by the trusted image ID must pass verification'
  rm -rf "$f"
}

test_pre_switch_failures() {
  local f status
  f="$(mktemp -d)"; make_fixture "$f"; printf '%064d  bad\n' 0 >"$f/new/offline-artifacts/jjdguard-offline-images-test.tar.gz.sha256"
  set +e; run_flow "$f" >/dev/null 2>&1; status=$?; set -e; (( status != 0 )) || fail 'checksum mismatch must fail'; lacks "$f/actions.log" ' up -d'; rm -rf "$f"
  f="$(mktemp -d)"; make_fixture "$f"; set +e; FAKE_IMAGE_ARCH=arm64 run_flow "$f" >/dev/null 2>&1; status=$?; set -e; (( status != 0 )) || fail 'architecture mismatch must fail'; lacks "$f/actions.log" ' up -d'; rm -rf "$f"
  f="$(mktemp -d)"; make_fixture "$f"; printf '{"target_arch":"arm64"}\n' >"$f/new/manifest.json"; set +e; run_flow "$f" >/dev/null 2>&1; status=$?; set -e; (( status != 0 )) || fail 'manifest architecture mismatch must fail'; lacks "$f/actions.log" ' up -d'; rm -rf "$f"
  f="$(mktemp -d)"; make_fixture "$f"; set +e; FAKE_HIDDEN_IMAGE_ARCH=arm64 run_flow "$f" >/dev/null 2>&1; status=$?; set -e; (( status != 0 )) || fail 'disabled-profile image architecture mismatch must fail'; lacks "$f/actions.log" ' up -d'; rm -rf "$f"
  f="$(mktemp -d)"; make_fixture "$f"; set +e; FAKE_HIDDEN_IMAGE_MISSING=1 run_flow "$f" >/dev/null 2>&1; status=$?; set -e; (( status != 0 )) || fail 'disabled-profile missing image must fail'; lacks "$f/actions.log" ' up -d'; rm -rf "$f"
}

test_failure_rolls_back_and_keeps_backup() {
  local f status stop_line main_restore_line chat_restore_line rollback_line
  f="$(mktemp -d)"; trap 'rm -rf "$f"' RETURN; make_fixture "$f"
  printf 'fixture main custom archive\n' >"$f/new/backups/run/postgres.dump"
  printf 'fixture chat custom archive\n' >"$f/new/backups/run/chat-postgres.dump"
  set +e; UPGRADE_TEST_FAIL_AFTER_SWITCH=1 run_flow "$f" >/dev/null 2>&1; status=$?; set -e
  (( status != 0 )) || fail 'fault injection must fail'; [[ -d "$f/new/backups/run" ]] || fail 'backup must be retained'; [[ "$(grep -c ' up -d' "$f/actions.log")" -eq 2 ]] || fail 'must switch then rollback once'
  find "$f/new/backups" -maxdepth 1 -type d -name '.config-snapshot.*' -print -quit | grep -q . || fail 'rollback must retain config snapshot'
  has "$f/actions.log" '--project-directory'; has "$f/actions.log" 'config-000.yml'; has "$f/actions.log" 'config-001.yml'; has "$f/actions.log" 'rollback-compose.yml'; has "$f/actions.log" 'ps -q gateway-core'
  lacks "$f/actions.log" 'pg_restore --no-owner --no-privileges'
  lacks "$f/actions.log" 'dropdb'
  lacks "$f/actions.log" 'createdb'
  # 旧部署没有 redis-cache：回滚后必须按服务名用新链移除它，且不删卷、不清理其他孤儿。
  has "$f/actions.log" 'docker-compose.offline.yml'
  grep -E "^bundled docker-compose .* rm -s -f redis-cache$" "$f/actions.log" | grep -Fq -- "--project-directory $f/new" ||
    fail 'rollback must remove the redis-cache added by the new release'
  lacks "$f/actions.log" 'rm -s -f -v'
  lacks "$f/actions.log" 'remove-orphans'

}

test_rollback_keeps_redis_cache_that_old_release_already_ran() {
  local f status
  f="$(mktemp -d)"; trap 'rm -rf "$f"' RETURN; make_fixture "$f"
  set +e; FAKE_WITH_REDIS_CACHE=1 UPGRADE_TEST_FAIL_AFTER_SWITCH=1 run_flow "$f" >/dev/null 2>&1; status=$?; set -e
  (( status != 0 )) || fail 'fault injection must fail'
  lacks "$f/actions.log" 'rm -s -f redis-cache'
  # 旧版已有的 redis-cache 是基础服务：写入方停机时不能被停掉。
  ! grep -E ' stop --timeout 60 .*redis-cache' "$f/actions.log" >/dev/null ||
    fail 'writer quiesce must keep redis-cache running'
}

test_rollback_preserves_late_evidence_without_database_restore() {
  local f status
  f="$(mktemp -d)"; trap 'rm -rf "$f"' RETURN; make_fixture "$f"
  printf 'fixture main custom archive\\n' >"$f/new/backups/run/postgres.dump"
  set +e
  FAKE_SIMULATE_LATE_EVIDENCE=1 UPGRADE_TEST_FAIL_AFTER_SWITCH=1 run_flow "$f" >/dev/null 2>&1
  status=$?
  set -e
  (( status != 0 )) || fail 'fault injection must fail'
  has "$f/actions.log.db-state" 'post-backup-evidence'
  lacks "$f/actions.log" 'dropdb'
  lacks "$f/actions.log" 'pg_restore --no-owner --no-privileges'
  lacks "$f/actions.log" 'pg_dump'
}

test_retry_failure_appends_current_override_and_rolls_back_once() {
  local f previous configs status
  f="$(mktemp -d)"; make_fixture "$f"
  previous="$f/new/deploy/docker-compose/backups/.config-snapshot.Ab12Cd/config-001.yml"
  mkdir -p "$(dirname "$previous")"; chmod 0700 "$(dirname "$previous")"
  printf 'services: {}\n' >"$previous"; chmod 0600 "$previous"
  configs="$f/old/base.yml,$previous"
  set +e
  EXISTING_CONFIG_FILES_OVERRIDE="$configs" UPGRADE_TEST_FAIL_AFTER_SWITCH=1 run_flow "$f" >/dev/null 2>&1
  status=$?
  set -e
  (( status != 0 )) || fail 'retry fault injection must fail'
  [[ "$(grep -c ' up -d' "$f/actions.log")" -eq 2 ]] || fail 'retry must switch once and roll back once'
  has "$f/actions.log" 'config-001.yml'; has "$f/actions.log" "$f/new/backups/run/rollback-compose.yml"
  has "$f/actions.log" 'snapshot-env'; lacks "$f/actions.log" "$f/old/.env"
  rm -rf "$f"
}

test_snapshot_is_revalidated_before_each_old_compose_command() {
  local f mutation status
  for mutation in content parent envcontent; do
    f="$(mktemp -d)"; make_fixture "$f"
    set +e
    FAKE_MUTATE_SNAPSHOT_AFTER_UP="$mutation" run_rollback "$f" >/dev/null 2>&1
    status=$?
    set -e
    (( status != 0 )) || fail "snapshot $mutation after up must fail"
    [[ "$(grep -c ' up -d' "$f/actions.log")" -eq 1 ]] || fail 'old compose up must run exactly once'
    lacks "$f/actions.log" ' ps -q '
    find "$f/new/backups" -maxdepth 1 -type d -name '.config-snapshot.*' -print -quit | grep -q . || fail 'failed rollback must retain snapshot'
    rm -rf "$f"
  done
}

test_rollback_health_waits_until_healthy_and_times_out() {
  local f status count
  f="$(mktemp -d)"; make_fixture "$f"; FAKE_HEALTH_MODE=starting_then_healthy run_rollback "$f"
  read -r count <"$f/actions.log.health-count"; (( count >= 6 )) || fail 'rollback did not retry starting containers'; rm -rf "$f"
  f="$(mktemp -d)"; make_fixture "$f"; set +e; FAKE_HEALTH_MODE=starting ROLLBACK_HEALTH_TIMEOUT=2 run_rollback "$f" >/dev/null 2>&1; status=$?; set -e
  (( status != 0 )) || fail 'permanent starting state must time out'; read -r count <"$f/actions.log.health-count"; (( count > 3 )) || fail 'rollback timeout did not poll'; rm -rf "$f"
}

test_upgrade_health_waits_for_running_full_profile_services() {
  local f status count
  f="$(mktemp -d)"; make_fixture "$f"
  ( cd "$f/new"; PATH="$f/bin:$PATH" FAKE_LOG="$f/actions.log" FAKE_HEALTH_MODE=starting_then_healthy \
      VERIFY_HEALTH_TIMEOUT=5 VERIFY_HEALTH_INTERVAL=0.05 bash -c '
        source ./upgrade-bundle.sh
        OLD_RUNNING_SERVICES=(gateway-core control-plane security-engine llm-judge tier1-classifier)
        project_container() { printf health-container; }
        wait_core_services_healthy' )
  read -r count <"$f/actions.log.health-count"
  (( count >= 8 )) || fail 'upgrade readiness did not wait for running full-profile services'
  rm -rf "$f"

  f="$(mktemp -d)"; make_fixture "$f"
  set +e
  ( cd "$f/new"; PATH="$f/bin:$PATH" FAKE_LOG="$f/actions.log" FAKE_HEALTH_MODE=starting \
      VERIFY_HEALTH_TIMEOUT=1 VERIFY_HEALTH_INTERVAL=0.05 bash -c '
        source ./upgrade-bundle.sh
        OLD_RUNNING_SERVICES=(gateway-core control-plane security-engine llm-judge tier1-classifier)
        project_container() { printf health-container; }
        wait_core_services_healthy' ) >/dev/null 2>&1
  status=$?
  set -e
  (( status != 0 )) || fail 'permanently starting full-profile service must fail upgrade readiness'
  rm -rf "$f"
}

test_invalid_service_name_rejected() {
  local f status manifest override
  f="$(mktemp -d)"; trap 'rm -rf "$f"' RETURN; make_fixture "$f"
  # overwrite the fake docker so ps emits a malicious service label
  cat >"$f/bin/docker" <<'DOCKER'
#!/usr/bin/env bash
set -Eeuo pipefail
log="${FAKE_LOG:?}"; printf 'docker' >>"$log"; printf ' %q' "$@" >>"$log"; printf '\n' >>"$log"
if [[ "${1:-}" == ps ]]; then
  printf '%s\n' 'gw|gateway-core' 'evil|evil;rm -rf SENTINEL'
  exit 0
fi
if [[ "${1:-}" == inspect ]]; then
  target="${@: -1}"
  case "$target" in gw) printf 'sha256:%064s\n' '' | tr ' ' a;; *) printf 'sha256:%064s\n' '' | tr ' ' b;; esac
  exit 0
fi
exit 0
DOCKER
  chmod +x "$f/bin/docker"
  set +e; ( cd "$f/new"; PATH="$f/bin:$PATH" FAKE_LOG="$f/actions.log" EXISTING_PROJECT_NAME=customer EXISTING_WORK_DIR="$f/old" \
    EXISTING_CONFIG_FILES="$f/old/base.yml,$f/old/extra.yml" BACKUP_DIR="$f/new/backups/run" \
    bash -c 'source ./upgrade-bundle.sh; capture_rollback_images' ) >/dev/null 2>&1; status=$?; set -e
  (( status != 0 )) || fail 'malicious service name must be rejected before writing rollback manifest'
  manifest="$f/new/backups/run/rollback-images.tsv"; override="$f/new/backups/run/rollback-compose.yml"
  if [[ -f "$manifest" ]] && grep -Fq 'rm -rf' "$manifest"; then fail 'malicious service name leaked into rollback manifest'; fi
  if [[ -f "$override" ]] && grep -Fq 'rm -rf' "$override"; then fail 'malicious service name leaked into rollback override'; fi
}
test_migration_receives_compose_wrapper_override() {
  local f custom_wrapper
  f="$(mktemp -d)"; trap 'rm -rf "$f"' RETURN; make_fixture "$f"
  custom_wrapper="$f/custom-compose"
  (
    cd "$f/new"
    export PATH="$f/bin:$PATH" FAKE_LOG="$f/actions.log" EXISTING_PROJECT_NAME=customer
    bash -c 'source ./upgrade-bundle.sh; OLD_PROFILES=(); COMPOSE_WRAPPER="$1"; run_database_migrations' _ "$custom_wrapper"
  )
  has "$f/actions.log" "wrapper=$custom_wrapper"
}

test_bundled_compose_fallback() {
  local f
  f="$(mktemp -d)"; trap 'rm -rf "$f"' RETURN; make_fixture "$f"
  FAKE_SYSTEM_COMPOSE_UNAVAILABLE=1 run_flow "$f"
  has "$f/actions.log" 'bundled docker-compose'
  has "$f/actions.log" ' up -d'
}

test_project_model_policy_does_not_block_probe() {
  local f
  f="$(mktemp -d)"; make_fixture "$f"
  if ! FAKE_PROJECT_MODEL_DENY=1 run_flow "$f" >"$f/output.log" 2>&1; then
    fail '客户应用模型白名单不应阻断独立升级自检'
  fi
  [[ -f "$f/actions.log.temp-project-created" && -f "$f/actions.log.temp-project-retired" ]] || fail 'probe project must be created and retired'
  [[ ! -f "$f/actions.log.probe-default-project" ]] || fail 'probe key must not belong to the customer default project'
  has "$f/actions.log" 'INSERT\ INTO\ projects'
  lacks "$f/actions.log" 'DELETE\ FROM\ projects'
  lacks "$f/actions.log" 'UPDATE\ model_policies'
  lacks "$f/actions.log" 'DELETE\ FROM\ model_policies'
  lacks "$f/actions.log" 'INSERT\ INTO\ model_policies'
  assert_all_verification_artifacts_deleted "$f/actions.log"
  rm -rf "$f"
}

test_failed_upgrade_preserves_boot_image_pins() {
  local f status before chain entry count=0
  f="$(mktemp -d)"; make_fixture "$f"
  cp "$f/old/base.yml" "$f/old/docker-compose.offline.yml"
  before="$(sha256sum "$f/old/.env" | awk '{print $1}')"
  set +e; FAKE_REQUEST_FAIL=1 run_flow "$f" >"$f/output.log" 2>&1; status=$?; set -e
  (( status != 0 )) || fail 'injected gateway failure must reject the upgrade'
  chain="$f/old/.upgrade/compose-files"
  [[ -s "$chain" && ! -L "$chain" && "$(stat -c %a "$chain")" == 600 ]] || fail 'automatic recovery must persist its immutable image chain for old jjdctl startup'
  while IFS= read -r entry; do
    [[ "$entry" == "$f/old/active-config/"* && -f "$entry" && ! -L "$entry" && "$(stat -c %a "$entry")" == 600 ]] || fail 'recovery startup entry must satisfy the jjdctl path and permission contract'
    count=$((count+1))
  done <"$chain"
  (( count >= 2 )) || fail 'recovery startup must retain inherited override and old image pins'
  entry="$(tail -1 "$chain")"
  cmp -s "$entry" "$f/new/backups/run/rollback-compose.yml" || fail 'startup must pin the captured old image identities after tags were replaced'
  has "$entry" 'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
  [[ "$(cat "$f/old/.upgrade/project-name")" == customer ]] || fail 'recovery startup project must stay unchanged'
  [[ "$(cat "$f/old/.upgrade/project-directory")" == "$f/old" ]] || fail 'recovery startup project directory must stay unchanged'
  [[ "$(sha256sum "$f/old/.env" | awk '{print $1}')" == "$before" ]] || fail 'recovery must preserve the original customer environment bytes'
  rm -rf "$f"
}

# 升级前共享状态（valkey）探测：离线包升级器必须像 upgrade.sh 一样，在重建应用容器之前确认
# valkey DB 3 可用；不可用则中止并回退，不能把检测链带停之后才发现。
test_shared_state_probe_runs_between_migrations_and_cutover() {
  local f migrate_line probe_line switch_line
  f="$(mktemp -d)"; trap 'rm -rf "$f"' RETURN; make_fixture "$f"
  run_flow "$f" >"$f/output.log" 2>&1 || fail 'healthy valkey must let the upgrade finish'
  has "$f/actions.log" 'exec -T redis redis-cli --no-auth-warning -a fixture-redis-password -n 3 ping'
  has "$f/output.log" 'valkey DB 3 应答 PONG'
  migrate_line="$(line_of "$f/actions.log" 'migration project=customer')"
  probe_line="$(line_of "$f/actions.log" 'redis-cli')"
  switch_line="$(line_of "$f/actions.log" 'up -d --force-recreate')"
  (( migrate_line < probe_line && probe_line < switch_line )) ||
    fail 'the shared-state probe must run after the migrations and before the application containers are recreated'
}

test_shared_state_probe_failure_blocks_cutover_and_rolls_back() {
  local f status
  f="$(mktemp -d)"; trap 'rm -rf "$f"' RETURN; make_fixture "$f"
  set +e
  FAKE_SHARED_STATE_PROBE_OUTPUT='Could not connect to Redis at redis:6379: Connection refused' SHARED_STATE_PROBE_TIMEOUT=0 \
    run_flow "$f" >"$f/output.log" 2>&1
  status=$?
  set -e
  (( status != 0 )) || fail 'an unusable valkey DB must abort the upgrade'
  has "$f/output.log" '共享状态探测'
  has "$f/output.log" 'Connection refused'
  has "$f/output.log" 'REDIS_PASSWORD'
  has "$f/output.log" '重新执行升级'
  lacks "$f/output.log" 'fixture-redis-password'
  # 新栈一次都没有被重建；只剩回滚旧版本那一次 up。
  lacks "$f/actions.log" 'up -d --force-recreate'
  has "$f/actions.log" 'up -d --no-deps --force-recreate'
  [[ "$(grep -c ' up -d' "$f/actions.log")" -eq 1 ]] || fail 'only the rollback of the old services may run up -d'
  [[ -d "$f/new/backups/run" ]] || fail 'backup must be retained'
}

test_probe_catalog_sync_foreign_keys_are_cleaned() {
  local f
  f="$(mktemp -d)"; make_fixture "$f"
  if ! FAKE_CATALOG_SYNC_ROW=1 run_flow "$f" >"$f/output.log" 2>&1; then
    fail 'temporary provider catalog bookkeeping must not prevent probe cleanup'
  fi
  assert_all_verification_artifacts_deleted "$f/actions.log"
  has "$f/actions.log" 'DELETE\ FROM\ model_catalog_entries'
  has "$f/actions.log" 'DELETE\ FROM\ model_catalog_sync_state'
  rm -rf "$f"
}

test_probe_catalog_sync_foreign_keys_are_cleaned
test_shared_state_probe_runs_between_migrations_and_cutover
test_shared_state_probe_failure_blocks_cutover_and_rolls_back
test_failed_upgrade_preserves_boot_image_pins
test_project_model_policy_does_not_block_probe
test_migration_receives_compose_wrapper_override; test_bundled_compose_fallback; test_success_and_profile_preservation; test_builtin_identity_runtime_is_repaired_and_injected; test_builtin_identity_runtime_failure_rolls_back; test_builtin_identity_runtime_injection_failure_rolls_back; test_external_idp_and_no_chat_skip_local_identity_bootstrap; test_database_identity_failure_blocks_upgrade; test_unattributed_event_does_not_pass_and_cleans_key; test_request_failure_cleans_key; test_verification_resource_failures_clean_everything; test_http_404_without_event_fails_and_reports_status; test_http_error_events_require_exact_route_attribution; test_insert_collision_never_deletes_customer_records; test_http_401_fails_even_with_attributed_event; test_unrelated_same_key_event_does_not_pass_upstream_failure; test_private_key_event_can_pass_upstream_failure; test_enabled_service_verification_fails_closed; test_pre_switch_failures; test_failure_rolls_back_and_keeps_backup; test_rollback_preserves_late_evidence_without_database_restore; test_rollback_health_waits_until_healthy_and_times_out; test_upgrade_health_waits_for_running_full_profile_services; test_invalid_service_name_rejected
test_oidc_discovery_retries_until_ready; test_oidc_discovery_timeout_rolls_back_once
test_http_ok_accepts_all_2xx_only; test_oidc_discovery_url_selection; test_oidc_curl_timeout_is_bounded_by_deadline
test_slow_oidc_timeout_budget_is_accepted
test_builtin_oidc_uses_inherited_certificate; test_external_oidc_keeps_system_ca_verification
test_builtin_oidc_missing_certificate_fails_closed
test_oidc_wait_settings_are_validated
test_builtin_oidc_host_authority_validation; test_oversized_oidc_numbers_fail_before_curl
test_retry_failure_appends_current_override_and_rolls_back_once
test_rollback_keeps_redis_cache_that_old_release_already_ran
test_snapshot_is_revalidated_before_each_old_compose_command
echo '[ok] offline bundle switches the original project and rolls back safely'
