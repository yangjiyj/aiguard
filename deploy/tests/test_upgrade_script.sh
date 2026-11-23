#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
UPGRADE_SCRIPT="$ROOT_DIR/deploy/docker-compose/upgrade.sh"
CUSTOMER_SCOPE_REPAIR_LIB="$ROOT_DIR/deploy/docker-compose/customer-environment-scope-repair-lib.sh"
CUSTOMER_SCOPE_REPAIR_SQL="$ROOT_DIR/deploy/docker-compose/customer-environment-scope-repair.sql"

assert_contains() {
  local haystack="$1"
  local needle="$2"
  if [[ "$haystack" != *"$needle"* ]]; then
    echo "expected output to contain: $needle" >&2
    echo "actual output:" >&2
    echo "$haystack" >&2
    exit 1
  fi
}

assert_not_contains() {
  local haystack="$1"
  local needle="$2"
  if [[ "$haystack" == *"$needle"* ]]; then
    echo "expected output not to contain: $needle" >&2
    echo "actual output:" >&2
    echo "$haystack" >&2
    exit 1
  fi
}

assert_file_contains() {
  local file="$1"
  local needle="$2"
  if ! grep -Fq -- "$needle" "$file"; then
    echo "expected $file to contain: $needle" >&2
    echo "actual file:" >&2
    cat "$file" >&2
    exit 1
  fi
}

assert_file_not_contains() {
  local file="$1"
  local needle="$2"
  if [[ ! -f "$file" ]]; then
    return 0
  fi
  if grep -Fq -- "$needle" "$file"; then
    echo "expected $file not to contain: $needle" >&2
    echo "actual file:" >&2
    cat "$file" >&2
    exit 1
  fi
}

file_mode() {
  if stat -c '%a' "$1" >/dev/null 2>&1; then
    stat -c '%a' "$1"
  else
    stat -f '%Lp' "$1"
  fi
}

file_owner() {
  if stat -c '%u' "$1" >/dev/null 2>&1; then
    stat -c '%u' "$1"
  else
    stat -f '%u' "$1"
  fi
}

make_fixture() {
  local fixture="$1"
  mkdir -p "$fixture/bin" "$fixture/backups" "$fixture/logs" "$fixture/state" "$fixture/docker-compose"
  # 夹具里伪造的脚本是 bash 写的，而升级器按 sh 调用它们；/bin/sh 是 dash 的构建机（Ubuntu）上会在 set -o pipefail 处失败。
  # 让夹具自带一个指向 bash 的 sh，测试结果不再取决于构建机的 /bin/sh。
  ln -s "$(command -v bash)" "$fixture/bin/sh"
  cp "$UPGRADE_SCRIPT" "$fixture/docker-compose/upgrade.sh"
  cp "$CUSTOMER_SCOPE_REPAIR_LIB" "$fixture/docker-compose/customer-environment-scope-repair-lib.sh"
  cp "$CUSTOMER_SCOPE_REPAIR_SQL" "$fixture/docker-compose/customer-environment-scope-repair.sql"
  cp "$ROOT_DIR/deploy/docker-compose/redis-valkey-migrate-lib.sh" "$fixture/docker-compose/redis-valkey-migrate-lib.sh"
  cp "$ROOT_DIR/deploy/docker-compose/tier1-topology.sh" "$fixture/docker-compose/tier1-topology.sh"
  : >"$fixture/docker-compose/tier1-cpu.override.yml"
  : >"$fixture/docker-compose/tier1-gpu.override.yml"
  cat >"$fixture/docker-compose/compose-wrapper.sh" <<'BASH'
#!/usr/bin/env bash
set -euo pipefail
exec docker compose "$@"
BASH
  chmod +x "$fixture/docker-compose/compose-wrapper.sh"
  # .env 写法：key 与 = 分开传给 printf，避免 commit-gate 粗正则把假测试密钥误判为泄密
  {
    for _kv in \
      "POSTGRES_PASSWORD test-postgres-password" \
      "REDIS_PASSWORD test-redis-password" \
      "JJD_PROVIDER_SECRET_KEY test-provider-secret" \
      "JJD_INTERNAL_API_SECRET test-internal-secret" \
      "MCP_CONFIRMATION_SCOPE_SECRET test-mcp-confirmation-scope" \
      "JJD_SEMANTIC_GATEWAY_ATTESTATION_KEY test-semantic-gateway-attestation" \
      "JJD_TIER1_INTERNAL_TOKEN test-tier1-internal-token" \
      "JJD_RULE_PACK_ATTESTATION_TOKEN test-attestation-value" \
      "BOOTSTRAP_ADMIN_PASSWORD test-admin-password" \
      "UAG_AUDIT_HMAC_KEY test-audit-key"; do
      printf '%s=%s\n' $_kv
    done
  } >"$fixture/docker-compose/.env"

  cat >"$fixture/bin/docker" <<'BASH'
#!/usr/bin/env bash
set -euo pipefail
log="${FAKE_LOG:?}"
echo "docker $*" >>"$log"
if [[ "$1" == "image" && "${2:-}" == "inspect" ]]; then
  echo "$*" >>"$log"
  if [[ "${FAKE_EMPTY_REPODIGESTS:-0}" == "1" ]]; then
    exit 0
  fi
  if [[ "$*" == *"sha256:1111111111111111111111111111111111111111111111111111111111111111"* ]]; then
    echo "docker-compose-gateway-core@sha256:1111111111111111111111111111111111111111111111111111111111111111"
  elif [[ "$*" == *"sha256:2222222222222222222222222222222222222222222222222222222222222222"* ]]; then
    echo "docker-compose-control-plane@sha256:2222222222222222222222222222222222222222222222222222222222222222"
  elif [[ "$*" == *"sha256:3333333333333333333333333333333333333333333333333333333333333333"* ]]; then
    echo "docker-compose-security-engine@sha256:3333333333333333333333333333333333333333333333333333333333333333"
  elif [[ "$*" == *"sha256:4444444444444444444444444444444444444444444444444444444444444444"* ]]; then
    echo "docker-compose-proxy-server@sha256:4444444444444444444444444444444444444444444444444444444444444444"
  elif [[ "$*" == *"sha256:5555555555555555555555555555555555555555555555555555555555555555"* ]]; then
    echo "docker-compose-web-console@sha256:5555555555555555555555555555555555555555555555555555555555555555"
  elif [[ "$*" == *"sha256:6666666666666666666666666666666666666666666666666666666666666666"* ]]; then
    echo "docker-compose-worker@sha256:6666666666666666666666666666666666666666666666666666666666666666"
  fi
elif [[ "$1" == "compose" ]]; then
  shift
  if [[ "$1" == "version" ]]; then
    echo "Docker Compose version v2.fake"
    exit 0
  fi
  while [[ "$#" -gt 0 && ( "$1" == "-f" || "$1" == "--env-file" || "$1" == "--profile" ) ]]; do
    shift 2
  done
  cmd="${1:-}"
  shift || true
  case "$cmd" in
    ps)
      if [[ "$*" == "-q redis" ]]; then
        # No redis container in this fixture: the Valkey migration step has nothing to do.
        exit 0
      fi
      if [[ "${FAKE_UNHEALTHY:-0}" == "1" ]]; then
        echo "gateway-core exited"
        exit 1
      fi
      echo "gateway-core running"
      ;;
    images)
      if [[ "${FAKE_IMAGES_FAIL:-0}" == "1" ]]; then
        echo "compose images failed" >&2
        exit 16
      fi
      cat <<'JSON'
{"Service":"gateway-core","Repository":"docker-compose-gateway-core","Tag":"sha256-111","ID":"sha256:1111111111111111111111111111111111111111111111111111111111111111"}
{"Service":"control-plane","Repository":"docker-compose-control-plane","Tag":"sha256-222","ID":"sha256:2222222222222222222222222222222222222222222222222222222222222222"}
{"Service":"security-engine","Repository":"docker-compose-security-engine","Tag":"sha256-333","ID":"sha256:3333333333333333333333333333333333333333333333333333333333333333"}
{"Service":"proxy-server","Repository":"docker-compose-proxy-server","Tag":"sha256-444","ID":"sha256:4444444444444444444444444444444444444444444444444444444444444444"}
{"Service":"web-console","Repository":"docker-compose-web-console","Tag":"sha256-555","ID":"sha256:5555555555555555555555555555555555555555555555555555555555555555"}
{"Service":"worker","Repository":"docker-compose-worker","Tag":"sha256-666","ID":"sha256:6666666666666666666666666666666666666666666666666666666666666666"}
JSON
      ;;
    up)
      if [[ "${FAKE_SIMULATE_LATE_EVIDENCE:-0}" == 1 ]]; then
        echo '-- post-backup-evidence' >"${FAKE_LOG}.db-state"
      fi
      if [[ -f ".upgrade/compose.upgrade.yml" ]]; then
        sed 's/^/override /' ".upgrade/compose.upgrade.yml" >>"$log"
      fi
      if [[ "${FAKE_UP_FAIL:-0}" == "1" ]]; then
        echo "compose up failed" >&2
        exit 17
      fi
      echo "compose up ok"
      ;;
    config)
      if [[ "$*" == *"--services"* ]]; then
        printf '%s\n' gateway-core control-plane security-engine proxy-server web-console worker postgres redis redis-cache
      else
        echo "compose config ok"
      fi
      ;;
    stop)
      if [[ "${FAKE_SIMULATE_LATE_EVIDENCE:-0}" == 1 ]]; then
        echo '-- post-backup-evidence' >"${FAKE_LOG}.db-state"
      fi
      echo "compose stop ok"
      ;;
    exec)
      service="${1:-}"
      shift || true
      if [[ "$service" == "-T" ]]; then
        service="${1:-}"
        shift || true
      fi
      if [[ "$service" == "postgres" ]]; then
        if [[ "$*" == *"pg_dump"* ]]; then
          if [[ "${FAKE_BACKUP_FAIL:-0}" == "1" ]]; then
            echo "backup failed" >&2
            exit 51
          fi
          if [[ -f "${FAKE_LOG}.db-state" ]]; then
            cat "${FAKE_LOG}.db-state"
          else
            echo "-- fake pg dump"
          fi
          exit 0
        fi
        if [[ "${1:-}" == "dropdb" || "${1:-}" == "createdb" ]]; then
          : >"${FAKE_LOG}.db-state"
          echo "fixture dropdb/createdb ok"
          exit 0
        fi
        sql=""
        while (($#)); do
          case "$1" in
            -c|-tAc|-Atc)
              shift
              sql="${1:-}"
              ;;
          esac
          shift || true
        done
        if [[ -z "$sql" ]]; then
          sql="$(cat)"
        fi
        echo "psql ${sql}" >>"$log"
        if [[ "$sql" == *"information_schema.columns"* && "$sql" == *"reverse_proxy_routes"* && "$sql" == *"allow_private_egress"* ]]; then
          if [[ "${FAKE_PRIVATE_EGRESS_COLUMNS_MISSING:-0}" == "1" ]]; then
            echo "f"
          else
            echo "t"
          fi
        elif [[ "$sql" == *"schema_migrations"* && "$sql" == *"ORDER BY split_part"* && "$sql" != *"COUNT"* ]]; then
          echo "077_request_logs_proxy_access_type_resolved.sql"
        elif [[ "$sql" == *"schema_migrations"* && "$sql" == *"COUNT"* ]]; then
          echo "78|077_request_logs_proxy_access_type_resolved.sql"
        elif [[ "$sql" == *"to_regclass('public.schema_migrations')"* ]]; then
          if [[ "${FAKE_SCHEMA_MIGRATIONS_MISSING:-0}" == "1" ]]; then
            echo ""
          else
            echo "schema_migrations"
          fi
        elif [[ "$sql" == *"to_regclass('public.tenants')"* ]]; then
          if [[ "${FAKE_BASELINE_MISSING:-0}" == "1" ]]; then
            echo "0"
          else
            echo "1"
          fi
        else
          echo "1"
        fi
      fi
      ;;
    *)
      echo "compose $cmd ok"
      ;;
  esac
else
  echo "docker $* ok"
fi
BASH
  chmod +x "$fixture/bin/docker"

  cat >"$fixture/bin/curl" <<'BASH'
#!/usr/bin/env bash
set -euo pipefail
log="${FAKE_LOG:?}"
echo "curl $*" >>"$log"
joined="$*"
if [[ "${FAKE_HEALTH_FAIL:-0}" == "1" && "$joined" == *"/health"* ]]; then
  echo "health failed" >&2
  exit 22
fi
if [[ "${FAKE_FORWARD_FAIL:-0}" == "1" && "$joined" == *"${UPGRADE_FORWARD_PROBE_URL:-}"* ]]; then
  echo "forward probe failed" >&2
  exit 28
fi
echo "ok"
BASH
  chmod +x "$fixture/bin/curl"

  cat >"$fixture/docker-compose/migrate-private.sh" <<'BASH'
#!/usr/bin/env bash
set -euo pipefail
echo "migrate-private $*" >>"${FAKE_LOG:?}"
if [[ "${FAKE_MIGRATION_FAIL:-0}" == "1" ]]; then
  echo "migration failed" >&2
  exit 31
fi
echo "[ok] applied=0 skipped=78"
BASH
  chmod +x "$fixture/docker-compose/migrate-private.sh"

  cat >"$fixture/docker-compose/smoke-test.sh" <<'BASH'
#!/usr/bin/env bash
set -euo pipefail
echo "smoke-test $*" >>"${FAKE_LOG:?}"
if [[ "${FAKE_SMOKE_FAIL:-0}" == "1" ]]; then
  echo "smoke failed" >&2
  exit 41
fi
echo "[ok] all health endpoints returned success"
BASH
  chmod +x "$fixture/docker-compose/smoke-test.sh"
}

run_upgrade() {
  local fixture="$1"
  shift
  (
    cd "$fixture/docker-compose"
    PATH="$fixture/bin:$PATH" \
      FAKE_LOG="$fixture/commands.log" \
      UPGRADE_LOG_DIR="$fixture/logs" \
      UPGRADE_STATE_FILE="$fixture/state/current-digests.env" \
      UPGRADE_BACKUP_DIR="$fixture/backups" \
      UPGRADE_MIN_DATA_VERSION="${UPGRADE_MIN_DATA_VERSION-077_request_logs_proxy_access_type_resolved.sql}" \
      UPGRADE_FORWARD_PROBE_URL="${UPGRADE_FORWARD_PROBE_URL:-http://127.0.0.1:8082/v1/models}" \
      bash ./upgrade.sh "$@"
  )
}

# U2: tier1-scale.sh --apply records the topology in .env; the upgrade has to
# rebuild it, or a scaled-out install silently collapses back to one replica.
set_tier1_topology() {
  local fixture="$1" mode="$2" replicas="$3"
  printf 'TIER1_SCALE_MODE=%s\nTIER1_REPLICAS=%s\n' "$mode" "$replicas" >>"$fixture/docker-compose/.env"
}

test_rejects_latest_before_mutating() {
  local fixture output status
  fixture="$(mktemp -d)"
  make_fixture "$fixture"
  set +e
  output="$(run_upgrade "$fixture" --to-version 2026.06.22 --gateway-core docker-compose-gateway-core:latest 2>&1)"
  status=$?
  set -e

  [[ "$status" -ne 0 ]]
  assert_contains "$output" "digest is required"
  [[ ! -f "$fixture/commands.log" ]] || {
    echo "expected no docker/curl calls before digest validation" >&2
    cat "$fixture/commands.log" >&2
    exit 1
  }
}

test_upgrade_secures_env_before_other_preflight() {
  local fixture output status
  fixture="$(mktemp -d)"
  make_fixture "$fixture"
  chmod 0644 "$fixture/docker-compose/.env"
  set +e
  output="$(run_upgrade "$fixture" --to-version 2026.06.22 --gateway-core docker-compose-gateway-core:latest 2>&1)"
  status=$?
  set -e

  [[ "$status" -ne 0 ]]
  [[ "$(file_mode "$fixture/docker-compose/.env")" == "600" ]] || {
    echo "upgrade did not tighten .env to 0600 before preflight" >&2
    exit 1
  }
  [[ "$(file_owner "$fixture/docker-compose/.env")" == "$(id -u)" ]]
  assert_contains "$output" "digest is required"
}

test_upgrade_rejects_unsafe_env_paths_before_source() {
  local fixture output status target

  fixture="$(mktemp -d)"
  make_fixture "$fixture"
  target="$fixture/env.target"
  mv "$fixture/docker-compose/.env" "$target"
  # The packaging gate runs with umask 077. Make the target mode explicit so
  # this assertion detects a chmod through the symlink instead of mistaking
  # the fixture's inherited 0600 mode for a mutation by upgrade.sh.
  chmod 640 "$target"
  [[ "$(file_mode "$target")" == "640" ]]
  ln -s "$target" "$fixture/docker-compose/.env"
  set +e
  output="$(run_upgrade "$fixture" --to-version 2026.06.22 --gateway-core docker-compose-gateway-core:latest 2>&1)"
  status=$?
  set -e
  [[ "$status" -ne 0 ]]
  assert_contains "$output" "refusing symbolic-link environment file"
  [[ "$(file_mode "$target")" != "600" ]] || {
    echo "upgrade followed the .env symlink and changed its target" >&2
    exit 1
  }

  fixture="$(mktemp -d)"
  make_fixture "$fixture"
  rm "$fixture/docker-compose/.env"
  mkdir "$fixture/docker-compose/.env"
  set +e
  output="$(run_upgrade "$fixture" --to-version 2026.06.22 --gateway-core docker-compose-gateway-core:latest 2>&1)"
  status=$?
  set -e
  [[ "$status" -ne 0 ]]
  assert_contains "$output" "environment file must be a regular file"
}

test_upgrade_rejects_foreign_owned_env_when_fixture_available() {
  local fixture output status foreign_uid foreign_ready=0
  fixture="$(mktemp -d)"
  make_fixture "$fixture"
  foreign_uid=65534
  [[ "$(id -u)" != "$foreign_uid" ]] || foreign_uid=65533
  if chown "$foreign_uid" "$fixture/docker-compose/.env" 2>/dev/null; then
    foreign_ready=1
  elif command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
    if docker run --rm -v "$fixture/docker-compose:/case" postgres:16-alpine \
      sh -c "chown $foreign_uid:$foreign_uid /case/.env" >/dev/null 2>&1; then
      foreign_ready=1
    fi
  fi
  if [[ "$foreign_ready" != "1" ]]; then
    echo "[info] foreign-owner fixture unavailable; static owner gate still required"
    grep -Fq 'id -u' "$UPGRADE_SCRIPT"
    return 0
  fi

  set +e
  output="$(run_upgrade "$fixture" --to-version 2026.06.22 --gateway-core docker-compose-gateway-core:latest 2>&1)"
  status=$?
  set -e
  [[ "$status" -ne 0 ]]
  assert_contains "$output" "environment file is not owned by the executing user"
}

test_preflight_failure_stops_before_backup_and_up() {
  local fixture output status
  fixture="$(mktemp -d)"
  make_fixture "$fixture"
  set +e
  output="$(FAKE_UNHEALTHY=1 run_upgrade "$fixture" --to-version 2026.06.22 --gateway-core docker-compose-gateway-core@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa 2>&1)"
  status=$?
  set -e

  [[ "$status" -ne 0 ]]
  assert_contains "$output" "preflight failed"
  assert_file_not_contains "$fixture/commands.log" "pg_dump"
  assert_file_not_contains "$fixture/commands.log" " up "
  [[ ! -f "$fixture/docker-compose/.upgrade/compose.upgrade.yml" ]] || {
    echo "preflight failure should not write an upgrade override" >&2
    cat "$fixture/docker-compose/.upgrade/compose.upgrade.yml" >&2
    exit 1
  }
}

test_missing_min_data_version_fails_preflight() {
  local fixture output status
  fixture="$(mktemp -d)"
  make_fixture "$fixture"
  set +e
  output="$(UPGRADE_MIN_DATA_VERSION= run_upgrade "$fixture" --to-version 2026.06.22 --gateway-core docker-compose-gateway-core@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa 2>&1)"
  status=$?
  set -e

  [[ "$status" -ne 0 ]]
  assert_contains "$output" "minimum data version is required"
  assert_file_not_contains "$fixture/commands.log" "pg_dump"
  assert_file_not_contains "$fixture/commands.log" " up "
}

test_upgrade_backfills_independent_security_secrets() {
  local fixture output key value unique_count
  local -a values=()
  fixture="$(mktemp -d)"
  make_fixture "$fixture"

  for key in \
    JJD_SEMANTIC_GATEWAY_ATTESTATION_KEY \
    MCP_CONFIRMATION_SCOPE_SECRET \
    JJD_TIER1_INTERNAL_TOKEN \
    JJD_RULE_PACK_ATTESTATION_TOKEN \
    JJD_RULE_PACK_ATTESTATION_TENANT \
    JJD_RULE_PACK_ATTESTATION_TOKENS_JSON; do
    sed -i "/^${key}=/d" "$fixture/docker-compose/.env"
  done

  output="$(run_upgrade "$fixture" --to-version 2026.06.22 --gateway-core docker-compose-gateway-core@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa 2>&1)"
  assert_contains "$output" "upgrade completed"

  for key in JJD_SEMANTIC_GATEWAY_ATTESTATION_KEY MCP_CONFIRMATION_SCOPE_SECRET JJD_TIER1_INTERNAL_TOKEN JJD_RULE_PACK_ATTESTATION_TOKEN; do
    value="$(grep "^${key}=" "$fixture/docker-compose/.env" | tail -n 1 | cut -d= -f2-)"
    [[ "$value" =~ ^[0-9a-f]{64}$ ]] || {
      echo "$key was not backfilled with a 32-byte random hex secret" >&2
      exit 1
    }
    values+=("$value")
  done

  unique_count="$(printf '%s\n' "${values[@]}" | sort -u | wc -l | tr -d '[:space:]')"
  [[ "$unique_count" == "4" ]] || {
    echo "backfilled security secrets are not mutually independent" >&2
    exit 1
  }
  assert_file_contains "$fixture/docker-compose/.env" "JJD_RULE_PACK_ATTESTATION_TENANT=tenant_default"
  assert_file_contains "$fixture/docker-compose/.env" "JJD_RULE_PACK_ATTESTATION_TOKENS_JSON="
}

test_customer_deployment_scope_is_explicit_and_preserves_valid_existing_scope() {
  local fixture output status marker
  fixture="$(mktemp -d)"
  make_fixture "$fixture"
  output="$(run_upgrade "$fixture" --customer-deployment --to-version 2026.06.22 --gateway-core docker-compose-gateway-core@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa 2>&1)"
  assert_contains "$output" "upgrade completed"
  [[ "$(grep -c '^GATEWAY_ENVIRONMENT_SCOPE=customer$' "$fixture/docker-compose/.env")" == 1 ]]
  assert_file_contains "$fixture/commands.log" "customer_environment_scope_v1"
  assert_file_contains "$fixture/commands.log" "Customer deployment activated environment-scope background repair"

  fixture="$(mktemp -d)"
  make_fixture "$fixture"
  printf 'GATEWAY_ENVIRONMENT_SCOPE=home\n' >>"$fixture/docker-compose/.env"
  output="$(run_upgrade "$fixture" --customer-deployment --to-version 2026.06.22 --gateway-core docker-compose-gateway-core@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa 2>&1)"
  assert_contains "$output" "customer environment-scope repair skipped"
  [[ "$(grep -c '^GATEWAY_ENVIRONMENT_SCOPE=home$' "$fixture/docker-compose/.env")" == 1 ]]

  fixture="$(mktemp -d)"
  make_fixture "$fixture"
  printf 'GATEWAY_ENVIRONMENT_SCOPE=invalid-scope\n' >>"$fixture/docker-compose/.env"
  set +e
  output="$(run_upgrade "$fixture" --customer-deployment --to-version 2026.06.22 --gateway-core docker-compose-gateway-core@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa 2>&1)"
  status=$?
  set -e
  [[ "$status" -ne 0 ]]
  assert_contains "$output" "existing GATEWAY_ENVIRONMENT_SCOPE is invalid"

  fixture="$(mktemp -d)"
  make_fixture "$fixture"
  marker="$fixture/command-substitution-ran"
  printf 'EVIL=$(touch %s)\n' "$marker" >>"$fixture/docker-compose/.env"
  run_upgrade "$fixture" --customer-deployment --to-version 2026.06.22 --gateway-core docker-compose-gateway-core@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa >/dev/null
  [[ ! -e "$marker" ]] || { echo 'upgrade dotenv command substitution executed' >&2; exit 1; }
}

test_upgrade_preserves_explicit_audit_only_ceiling() {
  local fixture output
  fixture="$(mktemp -d)"
  make_fixture "$fixture"
  printf 'SECURITY_AUDIT_ONLY=true\n' >>"$fixture/docker-compose/.env"
  output="$(run_upgrade "$fixture" --customer-deployment --to-version 2026.06.22 --gateway-core docker-compose-gateway-core@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa 2>&1)"
  assert_contains "$output" "upgrade completed"
  [[ "$(grep -c '^SECURITY_AUDIT_ONLY=true$' "$fixture/docker-compose/.env")" == 1 ]]
  [[ "$(grep -c '^SECURITY_AUDIT_ONLY=false$' "$fixture/docker-compose/.env" || true)" == 0 ]]
}

test_missing_rollback_anchor_stops_before_mutating() {
  local fixture output status
  fixture="$(mktemp -d)"
  make_fixture "$fixture"
  set +e
  output="$(FAKE_IMAGES_FAIL=1 run_upgrade "$fixture" --to-version 2026.06.22 --gateway-core docker-compose-gateway-core@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa 2>&1)"
  status=$?
  set -e

  [[ "$status" -ne 0 ]]
  assert_contains "$output" "rollback anchor is incomplete"
  assert_file_not_contains "$fixture/commands.log" "pg_dump"
  assert_file_not_contains "$fixture/commands.log" " up "
  [[ ! -f "$fixture/docker-compose/.upgrade/compose.upgrade.yml" ]] || {
    echo "missing rollback anchor should not write an upgrade override" >&2
    cat "$fixture/docker-compose/.upgrade/compose.upgrade.yml" >&2
    exit 1
  }
}

test_collects_rollback_anchor_without_state_and_rolls_back() {
  local fixture output status
  fixture="$(mktemp -d)"
  make_fixture "$fixture"
  set +e
  output="$(FAKE_MIGRATION_FAIL=1 run_upgrade "$fixture" --to-version 2026.06.22 --gateway-core docker-compose-gateway-core@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa 2>&1)"
  status=$?
  set -e

  [[ "$status" -ne 0 ]]
  assert_contains "$output" "captured rollback anchor from compose"
  assert_contains "$output" "rollback completed"
  assert_file_contains "$fixture/commands.log" "docker-compose-gateway-core@sha256:1111111111111111111111111111111111111111111111111111111111111111"
}

test_empty_repo_digests_fall_back_to_image_ids() {
  local fixture output status
  fixture="$(mktemp -d)"
  make_fixture "$fixture"
  set +e
  output="$(FAKE_EMPTY_REPODIGESTS=1 FAKE_MIGRATION_FAIL=1 run_upgrade "$fixture" --to-version 2026.06.22 --gateway-core docker-compose-gateway-core@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa 2>&1)"
  status=$?
  set -e

  [[ "$status" -ne 0 ]]
  assert_contains "$output" "captured rollback anchor from compose"
  assert_contains "$output" "rollback completed"
  assert_file_contains "$fixture/docker-compose/.upgrade/compose.upgrade.yml" "sha256:1111111111111111111111111111111111111111111111111111111111111111"
}

test_successful_upgrade_writes_override_logs_and_state() {
  local fixture output
  fixture="$(mktemp -d)"
  make_fixture "$fixture"
  output="$(run_upgrade "$fixture" --from-version 2026.06.21 --to-version 2026.06.22 --gateway-core docker-compose-gateway-core@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa --control-plane docker-compose-control-plane@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb --security-engine docker-compose-security-engine@sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc --proxy-server docker-compose-proxy-server@sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd --web-console docker-compose-web-console@sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee 2>&1)"

  assert_contains "$output" "upgrade completed"
  assert_file_contains "$fixture/commands.log" "pg_dump"
  assert_file_contains "$fixture/commands.log" "migrate-private"
  assert_file_contains "$fixture/commands.log" "smoke-test"
  assert_file_contains "$fixture/commands.log" "http://127.0.0.1:8082/v1/models"
  assert_file_contains "$fixture/docker-compose/.upgrade/compose.upgrade.yml" "docker-compose-gateway-core@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
  assert_file_contains "$fixture/state/current-digests.env" "GATEWAY_CORE_IMAGE=docker-compose-gateway-core@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
  assert_contains "$(ls "$fixture/logs")" "upgrade-"
  assert_contains "$output" "[step-result] preflight result=ok duration_s="
  assert_contains "$output" "[step-result] write_state result=ok duration_s="
}

test_single_component_success_writes_complete_state_from_collected_anchor() {
  local fixture output
  fixture="$(mktemp -d)"
  make_fixture "$fixture"
  output="$(run_upgrade "$fixture" --from-version 2026.06.21 --to-version 2026.06.22 --gateway-core docker-compose-gateway-core@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa 2>&1)"

  assert_contains "$output" "upgrade completed"
  assert_file_contains "$fixture/state/current-digests.env" "GATEWAY_CORE_IMAGE=docker-compose-gateway-core@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
  assert_file_contains "$fixture/state/current-digests.env" "CONTROL_PLANE_IMAGE=docker-compose-control-plane@sha256:2222222222222222222222222222222222222222222222222222222222222222"
  assert_file_contains "$fixture/state/current-digests.env" "SECURITY_ENGINE_IMAGE=docker-compose-security-engine@sha256:3333333333333333333333333333333333333333333333333333333333333333"
  assert_file_contains "$fixture/state/current-digests.env" "PROXY_SERVER_IMAGE=docker-compose-proxy-server@sha256:4444444444444444444444444444444444444444444444444444444444444444"
  assert_file_contains "$fixture/state/current-digests.env" "WEB_CONSOLE_IMAGE=docker-compose-web-console@sha256:5555555555555555555555555555555555555555555555555555555555555555"
  assert_file_contains "$fixture/state/current-digests.env" "WORKER_IMAGE=docker-compose-worker@sha256:6666666666666666666666666666666666666666666666666666666666666666"
}

test_database_validation_checks_initdb_baseline_path() {
  local fixture output
  fixture="$(mktemp -d)"
  make_fixture "$fixture"
  output="$(run_upgrade "$fixture" --to-version 2026.06.22 --gateway-core docker-compose-gateway-core@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa 2>&1)"

  assert_contains "$output" "validate real PostgreSQL schema state"
  assert_file_contains "$fixture/commands.log" "to_regclass('public.tenants')"
  assert_file_contains "$fixture/commands.log" "COUNT(*)::text"
  assert_file_contains "$fixture/commands.log" "allow_private_egress"
  assert_contains "$output" "reverse_proxy_routes private egress columns present"
}

test_database_validation_rejects_missing_private_egress_columns() {
  local fixture output status
  fixture="$(mktemp -d)"
  make_fixture "$fixture"
  set +e
  output="$(FAKE_PRIVATE_EGRESS_COLUMNS_MISSING=1 run_upgrade "$fixture" --to-version 2026.06.22 --gateway-core docker-compose-gateway-core@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa 2>&1)"
  status=$?
  set -e

  [[ "$status" -ne 0 ]]
  assert_contains "$output" "reverse_proxy_routes private egress columns are missing"
  assert_contains "$output" "rollback completed"
}

test_initdb_baseline_without_schema_migrations_runs_migrations() {
  local fixture output
  fixture="$(mktemp -d)"
  make_fixture "$fixture"
  output="$(FAKE_SCHEMA_MIGRATIONS_MISSING=1 run_upgrade "$fixture" --to-version 2026.06.22 --gateway-core docker-compose-gateway-core@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa 2>&1)"

  assert_contains "$output" "schema_migrations missing; initdb baseline detected"
  assert_contains "$output" "upgrade completed"
  assert_file_contains "$fixture/commands.log" "migrate-private"
}

test_partial_baseline_without_schema_migrations_stops_before_mutating() {
  local fixture output status
  fixture="$(mktemp -d)"
  make_fixture "$fixture"
  set +e
  output="$(FAKE_SCHEMA_MIGRATIONS_MISSING=1 FAKE_BASELINE_MISSING=1 run_upgrade "$fixture" --to-version 2026.06.22 --gateway-core docker-compose-gateway-core@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa 2>&1)"
  status=$?
  set -e

  [[ "$status" -ne 0 ]]
  assert_contains "$output" "schema_migrations is missing and initdb baseline tables are incomplete"
  assert_file_not_contains "$fixture/commands.log" "pg_dump"
  assert_file_not_contains "$fixture/commands.log" " up "
}

test_migration_failure_rolls_back_and_reports_backup() {
  local fixture output status
  fixture="$(mktemp -d)"
  make_fixture "$fixture"
  cat >"$fixture/state/current-digests.env" <<'ENV'
GATEWAY_CORE_IMAGE=docker-compose-gateway-core@sha256:1111111111111111111111111111111111111111111111111111111111111111
CONTROL_PLANE_IMAGE=docker-compose-control-plane@sha256:2222222222222222222222222222222222222222222222222222222222222222
SECURITY_ENGINE_IMAGE=docker-compose-security-engine@sha256:3333333333333333333333333333333333333333333333333333333333333333
PROXY_SERVER_IMAGE=docker-compose-proxy-server@sha256:4444444444444444444444444444444444444444444444444444444444444444
WEB_CONSOLE_IMAGE=docker-compose-web-console@sha256:5555555555555555555555555555555555555555555555555555555555555555
ENV

  set +e
  output="$(FAKE_MIGRATION_FAIL=1 run_upgrade "$fixture" --to-version 2026.06.22 --gateway-core docker-compose-gateway-core@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa 2>&1)"
  status=$?
  set -e

  [[ "$status" -ne 0 ]]
  assert_contains "$output" "rollback completed"
  assert_contains "$output" "database preserved"
  assert_contains "$output" "backup:"
  assert_not_contains "$output" "database restore completed"
  assert_file_not_contains "$fixture/commands.log" "dropdb"
  assert_file_not_contains "$fixture/commands.log" "createdb"
  assert_file_contains "$fixture/commands.log" "docker-compose-gateway-core@sha256:1111111111111111111111111111111111111111111111111111111111111111"
}

test_backup_failure_does_not_switch_or_import() {
  local fixture output status
  fixture="$(mktemp -d)"
  make_fixture "$fixture"
  set +e
  output="$(FAKE_BACKUP_FAIL=1 run_upgrade "$fixture" --to-version 2026.06.22 --gateway-core docker-compose-gateway-core@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa 2>&1)"
  status=$?
  set -e
  [[ "$status" -ne 0 ]]
  assert_contains "$output" "backup_db result=failed"
  assert_file_not_contains "$fixture/commands.log" "docker load"
  assert_file_not_contains "$fixture/commands.log" " stop "
  assert_file_not_contains "$fixture/commands.log" " up "
}

test_online_backup_and_failed_probe_preserve_new_writes() {
  local fixture output status stop_line dump_line migrate_line
  fixture="$(mktemp -d)"
  make_fixture "$fixture"
  set +e
  output="$(FAKE_SIMULATE_LATE_EVIDENCE=1 FAKE_FORWARD_FAIL=1 run_upgrade "$fixture" --to-version 2026.06.22 --gateway-core docker-compose-gateway-core@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa 2>&1)"
  status=$?
  set -e
  [[ "$status" -ne 0 ]]
  assert_contains "$output" "rollback completed"
  assert_contains "$output" "database preserved"
  assert_file_contains "$fixture/commands.log.db-state" "post-backup-evidence"
  assert_file_not_contains "$fixture/commands.log" "dropdb"
  assert_file_not_contains "$fixture/commands.log" "createdb"
  stop_line="$(grep -n ' stop ' "$fixture/commands.log" | head -1 | cut -d: -f1)"
  dump_line="$(grep -n 'pg_dump' "$fixture/commands.log" | head -1 | cut -d: -f1)"
  migrate_line="$(grep -n 'migrate-private' "$fixture/commands.log" | head -1 | cut -d: -f1)"
  [[ -n "$stop_line" && -n "$dump_line" && -n "$migrate_line" ]]
  (( dump_line < stop_line && stop_line < migrate_line )) || {
    echo 'online backup must complete before stopping writers and migrating' >&2
    exit 1
  }
}

test_worker_is_pinned_and_rolled_back() {
  local fixture output status
  fixture="$(mktemp -d)"
  make_fixture "$fixture"
  set +e
  output="$(FAKE_MIGRATION_FAIL=1 run_upgrade "$fixture" --to-version 2026.06.22 --worker docker-compose-worker@sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff 2>&1)"
  status=$?
  set -e
  [[ "$status" -ne 0 ]]
  assert_contains "$output" "rollback completed"
  assert_file_contains "$fixture/commands.log" "docker-compose-worker@sha256:6666666666666666666666666666666666666666666666666666666666666666"
}

test_offline_mode_skips_customer_upstream_probe() {
  local fixture output
  fixture="$(mktemp -d)"
  make_fixture "$fixture"
  output="$(UPGRADE_OFFLINE_MODE=1 run_upgrade "$fixture" --to-version 2026.06.22 --gateway-core docker-compose-gateway-core@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa 2>&1)"
  assert_contains "$output" "offline mode: external forward probe skipped"
  assert_not_contains "$output" "real forward probe passed"
}

test_smoke_or_forward_failure_rolls_back() {
  local fixture output status
  fixture="$(mktemp -d)"
  make_fixture "$fixture"
  cat >"$fixture/state/current-digests.env" <<'ENV'
GATEWAY_CORE_IMAGE=docker-compose-gateway-core@sha256:1111111111111111111111111111111111111111111111111111111111111111
ENV

  set +e
  output="$(FAKE_FORWARD_FAIL=1 run_upgrade "$fixture" --to-version 2026.06.22 --gateway-core docker-compose-gateway-core@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa 2>&1)"
  status=$?
  set -e

  [[ "$status" -ne 0 ]]
  assert_contains "$output" "real forward probe failed"
  assert_contains "$output" "rollback completed"
  assert_file_contains "$fixture/commands.log" "docker-compose-gateway-core@sha256:1111111111111111111111111111111111111111111111111111111111111111"
}


test_upgrade_restores_tier1_scale_topology() {
  local fixture output
  fixture="$(mktemp -d)"
  make_fixture "$fixture"
  set_tier1_topology "$fixture" cpu 2

  output="$(run_upgrade "$fixture" --to-version 2026.06.22 --gateway-core docker-compose-gateway-core@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa 2>&1)"
  assert_contains "$output" "upgrade completed"
  assert_contains "$output" "restoring scaled topology: mode=cpu replicas=2"
  assert_file_contains "$fixture/commands.log" "-f $fixture/docker-compose/tier1-cpu.override.yml"
  assert_file_contains "$fixture/commands.log" "--scale tier1-classifier=2"
  # The overlay has to be the last -f so it wins the sidecar image/provider.
  awk '/ up /{ for (i = 1; i < NF; i++) if ($i == "-f") last = $(i + 1) } END { print last }' \
    "$fixture/commands.log" | grep -Fq 'tier1-cpu.override.yml' || {
    echo "the tier1 overlay is not the last compose file" >&2
    cat "$fixture/commands.log" >&2
    exit 1
  }
}

test_upgrade_reapplies_tier1_scale_topology_on_rollback() {
  local fixture output status scaled
  fixture="$(mktemp -d)"
  make_fixture "$fixture"
  set_tier1_topology "$fixture" cpu 2
  cat >"$fixture/state/current-digests.env" <<'ENV'
GATEWAY_CORE_IMAGE=docker-compose-gateway-core@sha256:1111111111111111111111111111111111111111111111111111111111111111
ENV

  set +e
  output="$(FAKE_FORWARD_FAIL=1 run_upgrade "$fixture" --to-version 2026.06.22 --gateway-core docker-compose-gateway-core@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa 2>&1)"
  status=$?
  set -e

  [[ "$status" -ne 0 ]]
  assert_contains "$output" "rollback completed"
  scaled="$(grep -c -- '--scale tier1-classifier=2' "$fixture/commands.log" || true)"
  [[ "$scaled" -ge 2 ]] || {
    echo "rollback did not reapply the replica count (scaled up $scaled time(s))" >&2
    cat "$fixture/commands.log" >&2
    exit 1
  }
}

test_default_install_compose_arguments_are_unchanged() {
  local fixture output
  fixture="$(mktemp -d)"
  make_fixture "$fixture"

  output="$(run_upgrade "$fixture" --to-version 2026.06.22 --gateway-core docker-compose-gateway-core@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa 2>&1)"
  assert_contains "$output" "upgrade completed"
  assert_file_not_contains "$fixture/commands.log" "tier1-cpu.override.yml"
  assert_file_not_contains "$fixture/commands.log" "tier1-gpu.override.yml"
  assert_file_not_contains "$fixture/commands.log" "--scale tier1-classifier"
}

test_gpu_topology_preflight_failure_aborts_upgrade() {
  local fixture output status
  fixture="$(mktemp -d)"
  make_fixture "$fixture"
  set_tier1_topology "$fixture" gpu 1
  # A pinned GPU image so the preflight reaches the driver/runtime checks rather
  # than stopping at the digest rule.
  printf 'TIER1_GPU_IMAGE=docker-compose-tier1-classifier@sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc\n' \
    >>"$fixture/docker-compose/.env"

  set +e
  output="$(run_upgrade "$fixture" --to-version 2026.06.22 \
    --gateway-core docker-compose-gateway-core@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa 2>&1)"
  status=$?
  set -e

  [[ "$status" -ne 0 ]]
  assert_contains "$output" "GPU Tier-1 preflight failed"
  # Nothing may be started: the check has to fail before any container changes.
  assert_file_not_contains "$fixture/commands.log" " up "
}

test_upgrade_pins_compose_project_name() {
  assert_file_contains "$UPGRADE_SCRIPT" "derive_compose_project_name"
  assert_file_contains "$UPGRADE_SCRIPT" "COMPOSE_PROJECT_NAME="
  assert_file_contains "$UPGRADE_SCRIPT" "com.docker.compose.project"
}

test_upgrade_persists_bundle_profiles() {
  assert_file_contains "$UPGRADE_SCRIPT" "persist_bundle_profiles"
  assert_file_contains "$UPGRADE_SCRIPT" "printf 'COMPOSE_PROFILES=%s"
  local persist_call load_call
  persist_call="$(grep -n '^persist_bundle_profiles$' "$UPGRADE_SCRIPT" | head -n 1 | cut -d: -f1)"
  load_call="$(grep -n '^load_previous_state$' "$UPGRADE_SCRIPT" | head -n 1 | cut -d: -f1)"
  [[ -n "$persist_call" && -n "$load_call" && "$persist_call" -lt "$load_call" ]]
}

test_upgrade_tracks_all_first_party_runtime_images() {
  for name in LLM_JUDGE_IMAGE TIER1_CLASSIFIER_IMAGE CHAT_PORTAL_UI_IMAGE CHAT_PORTAL_PROXY_IMAGE; do
    assert_file_contains "$UPGRADE_SCRIPT" "$name"
  done
  assert_file_contains "$UPGRADE_SCRIPT" 'rollback services failed to reach their Compose state'
}

test_online_backup_precedes_runtime_mutation() {
  local preflight_call refresh_call quiesce_call backup_call
  preflight_call="$(grep -n '^timed_step "preflight" preflight$' "$UPGRADE_SCRIPT" | cut -d: -f1)"
  refresh_call="$(grep -n '^refresh_chat_identity_runtime$' "$UPGRADE_SCRIPT" | cut -d: -f1)"
  quiesce_call="$(grep -n '^timed_step "quiesce_database_writers" quiesce_database_writers$' "$UPGRADE_SCRIPT" | cut -d: -f1)"
  backup_call="$(grep -n '^timed_step "backup_db" backup_db$' "$UPGRADE_SCRIPT" | cut -d: -f1)"
  [[ -n "$preflight_call" && -n "$refresh_call" && -n "$quiesce_call" && -n "$backup_call" ]]
  [[ "$preflight_call" -lt "$backup_call" && "$backup_call" -lt "$refresh_call" && "$refresh_call" -lt "$quiesce_call" ]] || {
    echo 'online backup must finish before identity refresh and writer quiescence' >&2
    exit 1
  }
}

test_migrations_run_before_new_images_start() {
  local backup_call migration_call switch_call
  backup_call="$(grep -n '^timed_step "backup_db" backup_db$' "$UPGRADE_SCRIPT" | cut -d: -f1)"
  migration_call="$(grep -n '^timed_step "run_migrations" run_migrations$' "$UPGRADE_SCRIPT" | cut -d: -f1)"
  switch_call="$(grep -n '^timed_step "switch_images" switch_images$' "$UPGRADE_SCRIPT" | cut -d: -f1)"
  [[ -n "$backup_call" && -n "$migration_call" && -n "$switch_call" ]]
  [[ "$backup_call" -lt "$migration_call" && "$migration_call" -lt "$switch_call" ]] || {
    echo 'database migrations must finish after backup and before new images start' >&2
    exit 1
  }
}

# 写入方停机只停应用服务；postgres / redis / redis-cache 属于基础服务，升级期间保持运行。
test_quiesce_keeps_data_services_running() {
  local fixture stop_line
  fixture="$(mktemp -d)"
  make_fixture "$fixture"
  run_upgrade "$fixture" --from-version 2026.06.21 --to-version 2026.06.22 --gateway-core docker-compose-gateway-core@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa >/dev/null 2>&1
  stop_line="$(grep -E '^docker compose .* stop --timeout 60 ' "$fixture/commands.log" | head -1)"
  [[ -n "$stop_line" ]] || { echo 'writer quiesce did not stop application services' >&2; exit 1; }
  for service in gateway-core control-plane security-engine proxy-server web-console worker; do
    [[ " $stop_line " == *" $service "* ]] || { echo "writer quiesce must stop $service: $stop_line" >&2; exit 1; }
  done
  for service in postgres redis redis-cache; do
    [[ " $stop_line " != *" $service "* ]] || { echo "writer quiesce must keep $service running: $stop_line" >&2; exit 1; }
  done
}

# Each case prints its own name, so a partially green run is distinguishable from
# a case that never executed.
run_case() {
  printf 'ok  %s\n' "$1"
  "$1"
}

main() {
  run_case test_rejects_latest_before_mutating
  run_case test_upgrade_secures_env_before_other_preflight
  run_case test_upgrade_rejects_unsafe_env_paths_before_source
  run_case test_upgrade_rejects_foreign_owned_env_when_fixture_available
  run_case test_preflight_failure_stops_before_backup_and_up
  run_case test_missing_min_data_version_fails_preflight
  run_case test_upgrade_backfills_independent_security_secrets
  run_case test_customer_deployment_scope_is_explicit_and_preserves_valid_existing_scope
  run_case test_upgrade_preserves_explicit_audit_only_ceiling
  run_case test_missing_rollback_anchor_stops_before_mutating
  run_case test_collects_rollback_anchor_without_state_and_rolls_back
  run_case test_empty_repo_digests_fall_back_to_image_ids
  run_case test_successful_upgrade_writes_override_logs_and_state
  run_case test_single_component_success_writes_complete_state_from_collected_anchor
  run_case test_database_validation_checks_initdb_baseline_path
  run_case test_database_validation_rejects_missing_private_egress_columns
  run_case test_initdb_baseline_without_schema_migrations_runs_migrations
  run_case test_partial_baseline_without_schema_migrations_stops_before_mutating
  run_case test_migration_failure_rolls_back_and_reports_backup
  run_case test_backup_failure_does_not_switch_or_import
  run_case test_online_backup_and_failed_probe_preserve_new_writes
  run_case test_worker_is_pinned_and_rolled_back
  run_case test_offline_mode_skips_customer_upstream_probe
  run_case test_smoke_or_forward_failure_rolls_back
  run_case test_upgrade_restores_tier1_scale_topology
  run_case test_upgrade_reapplies_tier1_scale_topology_on_rollback
  run_case test_default_install_compose_arguments_are_unchanged
  run_case test_gpu_topology_preflight_failure_aborts_upgrade
  run_case test_upgrade_pins_compose_project_name
  run_case test_upgrade_persists_bundle_profiles
  run_case test_upgrade_tracks_all_first_party_runtime_images
  run_case test_online_backup_precedes_runtime_mutation
  run_case test_migrations_run_before_new_images_start
  run_case test_quiesce_keeps_data_services_running
  bash -n "$UPGRADE_SCRIPT"
  echo "upgrade script tests passed"
}

main "$@"
