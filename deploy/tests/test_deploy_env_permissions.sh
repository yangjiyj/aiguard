#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
DEPLOY_SCRIPT="$ROOT_DIR/deploy/docker-compose/deploy-offline.sh"

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

file_owner() {
  if stat -c '%u' "$1" >/dev/null 2>&1; then
    stat -c '%u' "$1"
  else
    stat -f '%u' "$1"
  fi
}

make_harness() {
  local case_dir="$1"
  local harness="$case_dir/deploy/docker-compose/deploy-offline.sh"
  mkdir -p "$(dirname "$harness")"
  awk '/^require_cmd docker$/ { exit } { print }' "$DEPLOY_SCRIPT" >"$harness"
  # 安装器开头 source 共享灌卷库；夹具按正式包的相对位置放一份。
  mkdir -p "$case_dir/deploy/lib"
  cp "$ROOT_DIR/deploy/lib/judge-model-load.sh" "$case_dir/deploy/lib/"
  cp "$ROOT_DIR/deploy/lib/jjd-env.sh" "$case_dir/deploy/lib/"
  cat >>"$harness" <<'EOF'
secure_env_file
ensure_env
secure_env_file
EOF
  chmod 700 "$harness"
}

run_harness() {
  local case_dir="$1" path_prefix="${2:-}"
  (
    umask 0002
    [[ -z "$path_prefix" ]] || export PATH="$path_prefix:$PATH"
    cd "$case_dir/deploy/docker-compose"
    sh ./deploy-offline.sh
  )
}

grep -Eq '^umask[[:space:]]+077$' "$DEPLOY_SCRIPT" || fail "deploy entrypoint must set umask 077"
grep -Fq '[ -L "$ENV_FILE" ]' "$DEPLOY_SCRIPT" || fail "deploy must reject an env symlink before reading it"
grep -Fq 'id -u' "$DEPLOY_SCRIPT" || fail "deploy must compare env owner to the executing uid"
grep -Fq 'chmod 600 "$ENV_FILE"' "$DEPLOY_SCRIPT" || fail "deploy must tighten env permissions"
grep -Fqx 'secure_env_file' "$DEPLOY_SCRIPT" || fail "deploy main path must validate .env before use"
grep -Fq 'set -C' "$DEPLOY_SCRIPT" || fail "new .env creation must refuse an existing path"

tmp_root="$(mktemp -d)"
trap 'rm -rf "$tmp_root"' EXIT

new_case="$tmp_root/new"
make_harness "$new_case"
run_harness "$new_case" >/dev/null
new_env="$new_case/deploy/docker-compose/.env"
[[ -f "$new_env" && ! -L "$new_env" ]] || fail "new .env is not a regular non-symlink file"
[[ "$(file_mode "$new_env")" == "600" ]] || fail "new .env mode=$(file_mode "$new_env") want=600"
[[ "$(file_owner "$new_env")" == "$(id -u)" ]] || fail "new .env is not owned by the executing user"
grep -Fqx 'SECURITY_AUDIT_ONLY=false' "$new_env" || fail "fresh offline .env must leave the deployment audit-only ceiling unlocked"

# Fresh installs must advance past occupied defaults and reserve every chosen
# port so services whose ranges overlap cannot collide with each other.
occupied_case="$tmp_root/occupied"
make_harness "$occupied_case"
mkdir -p "$occupied_case/bin"
cat >"$occupied_case/bin/ss" <<'EOF'
#!/bin/sh
case "$*" in
  *:3000*|*:443*|*:8080*|*:8082*|*:8000*|*:3128*|*:5432*|*:6379*)
    port="${*##*:}"
    printf 'LISTEN 0 128 0.0.0.0:%s 0.0.0.0:*\n' "$port"
    ;;
esac
EOF
chmod 0755 "$occupied_case/bin/ss"
run_harness "$occupied_case" "$occupied_case/bin" >/dev/null
occupied_env="$occupied_case/deploy/docker-compose/.env"
expected_ports=(
  WEB_PORT=3001
  WEB_HTTPS_PORT=444
  GATEWAY_PORT=8081
  PROXY_PORT=8083
  CONTROL_PORT=8084
  SECURITY_PORT=8001
  FORWARD_PROXY_PORT=3129
  POSTGRES_PORT=5433
  REDIS_PORT=6380
)
for expected in "${expected_ports[@]}"; do
  grep -Fqx "$expected" "$occupied_env" || fail "occupied-port allocation missing $expected"
done
echo '[ok] fresh offline .env advances occupied and overlapping ports'

existing_case="$tmp_root/existing"
make_harness "$existing_case"
printf 'PRESERVE_ME=yes\nSECURITY_AUDIT_ONLY=true\n' >"$existing_case/deploy/docker-compose/.env"
chmod 0644 "$existing_case/deploy/docker-compose/.env"
run_harness "$existing_case" >/dev/null
[[ "$(file_mode "$existing_case/deploy/docker-compose/.env")" == "600" ]] || fail "existing .env was not tightened to 0600"
grep -Fqx 'PRESERVE_ME=yes' "$existing_case/deploy/docker-compose/.env" || fail "existing .env content was replaced"
grep -Fqx 'SECURITY_AUDIT_ONLY=true' "$existing_case/deploy/docker-compose/.env" || fail "existing explicit deployment audit-only ceiling was replaced"
if grep -Fqx 'SECURITY_AUDIT_ONLY=false' "$existing_case/deploy/docker-compose/.env"; then
  fail "existing explicit audit-only ceiling was overridden by the fresh-install default"
fi

symlink_case="$tmp_root/symlink"
make_harness "$symlink_case"
printf 'DO_NOT_FOLLOW=yes\n' >"$symlink_case/target.env"
chmod 0644 "$symlink_case/target.env"
ln -s "$symlink_case/target.env" "$symlink_case/deploy/docker-compose/.env"
if run_harness "$symlink_case" >"$symlink_case/stdout" 2>"$symlink_case/stderr"; then
  fail "symlink .env was accepted"
fi
[[ "$(file_mode "$symlink_case/target.env")" == "644" ]] || fail "symlink target permissions were changed"
grep -Fqx 'DO_NOT_FOLLOW=yes' "$symlink_case/target.env" || fail "symlink target content was changed"

nonregular_case="$tmp_root/nonregular"
make_harness "$nonregular_case"
mkdir "$nonregular_case/deploy/docker-compose/.env"
if run_harness "$nonregular_case" >"$nonregular_case/stdout" 2>"$nonregular_case/stderr"; then
  fail "non-regular .env was accepted"
fi

# Dynamic non-owner coverage is used when the runner can create a foreign-owned
# file. The static owner comparison above remains mandatory on restricted hosts.
nonowner_case="$tmp_root/nonowner"
make_harness "$nonowner_case"
printf 'FOREIGN_OWNER=yes\n' >"$nonowner_case/deploy/docker-compose/.env"
foreign_uid=65534
if [[ "$(id -u)" == "$foreign_uid" ]]; then
  foreign_uid=65533
fi
foreign_owner_ready=0
if chown "$foreign_uid" "$nonowner_case/deploy/docker-compose/.env" 2>/dev/null; then
  foreign_owner_ready=1
elif command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
  if docker run --rm \
    -v "$nonowner_case/deploy/docker-compose:/case" \
    postgres:16-alpine \
    sh -c "chown $foreign_uid:$foreign_uid /case/.env" >/dev/null 2>&1; then
    foreign_owner_ready=1
  fi
fi
if [[ "$foreign_owner_ready" == "1" ]]; then
  [[ "$(file_owner "$nonowner_case/deploy/docker-compose/.env")" != "$(id -u)" ]] || fail "foreign-owner fixture was not created"
  if run_harness "$nonowner_case" >"$nonowner_case/stdout" 2>"$nonowner_case/stderr"; then
    fail "foreign-owned .env was accepted"
  fi
  echo '[ok] dynamic foreign-owner rejection exercised'
else
  echo '[info] dynamic foreign-owner setup unavailable; static owner gate verified'
fi

echo '[ok] offline .env ownership, type, and mode safeguards passed'
