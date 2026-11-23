#!/usr/bin/env bash
# 审计签名密钥 UAG_AUDIT_HMAC_KEY：离线安装首次生成随机值；已有 .env 不覆盖、不补写（升级不变更）。
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
DEPLOY_SCRIPT="$ROOT_DIR/deploy/docker-compose/deploy-offline.sh"
ONECLICK_SCRIPT="$ROOT_DIR/deploy/docker-compose/deploy-oneclick.sh"
UPGRADE_SCRIPT="$ROOT_DIR/deploy/docker-compose/upgrade.sh"

fail() {
  echo "[fail] $*" >&2
  exit 1
}

make_harness() {
  local case_dir="$1"
  local harness="$case_dir/deploy/docker-compose/deploy-offline.sh"
  mkdir -p "$(dirname "$harness")" "$case_dir/deploy/lib"
  awk '/^require_cmd docker$/ { exit } { print }' "$DEPLOY_SCRIPT" >"$harness"
  cp "$ROOT_DIR/deploy/lib/judge-model-load.sh" "$case_dir/deploy/lib/"
  cp "$ROOT_DIR/deploy/lib/jjd-env.sh" "$case_dir/deploy/lib/"
  printf 'secure_env_file\nensure_env\nsecure_env_file\n' >>"$harness"
  chmod 700 "$harness"
}

run_harness() {
  (cd "$1/deploy/docker-compose" && sh ./deploy-offline.sh) >/dev/null
}

env_key() {
  sed -n 's/^UAG_AUDIT_HMAC_KEY=//p' "$1"
}

tmp_root="$(mktemp -d)"
trap 'rm -rf "$tmp_root"' EXIT

# 1. 全新安装：生成 64 位十六进制随机密钥，两次安装互不相同，且不是示例/开发默认值。
make_harness "$tmp_root/a"
make_harness "$tmp_root/b"
run_harness "$tmp_root/a"
run_harness "$tmp_root/b"
key_a="$(env_key "$tmp_root/a/deploy/docker-compose/.env")"
key_b="$(env_key "$tmp_root/b/deploy/docker-compose/.env")"
[[ "$key_a" =~ ^[0-9a-f]{64}$ ]] || fail "fresh install must generate a 64-hex audit key, got '$key_a'"
[[ "$key_a" != "$key_b" ]] || fail "two fresh installs produced the same audit key"
case "$key_a" in dev-insecure-key|change-me*) fail "fresh install used a placeholder audit key" ;; esac

# 2. 再次执行安装：已生成的密钥不覆盖。
run_harness "$tmp_root/a"
[[ "$(env_key "$tmp_root/a/deploy/docker-compose/.env")" == "$key_a" ]] || fail "re-running install changed the audit key"

# 3. 已有 .env 且已配置密钥：保持原值。
make_harness "$tmp_root/c"
printf 'UAG_AUDIT_HMAC_KEY=customer-existing-key\n' >"$tmp_root/c/deploy/docker-compose/.env"
chmod 600 "$tmp_root/c/deploy/docker-compose/.env"
run_harness "$tmp_root/c"
[[ "$(env_key "$tmp_root/c/deploy/docker-compose/.env")" == "customer-existing-key" ]] || fail "existing audit key was replaced"

# 4. 已有 .env 但没有密钥（历史上用开发默认密钥签过审计链）：安装器不补写，避免旧记录全部验签失败。
make_harness "$tmp_root/d"
printf 'PRESERVE_ME=yes\n' >"$tmp_root/d/deploy/docker-compose/.env"
chmod 600 "$tmp_root/d/deploy/docker-compose/.env"
run_harness "$tmp_root/d"
if grep -q '^UAG_AUDIT_HMAC_KEY=' "$tmp_root/d/deploy/docker-compose/.env"; then
  fail "installer must not inject a new audit key into an existing .env"
fi

# 5. 一键安装同样只在新建 .env 时生成；升级脚本只读校验、不生成。
grep -Fq 'AUDIT_HMAC_KEY="$(random_hex 32)"' "$ONECLICK_SCRIPT" || fail "oneclick installer must generate a random audit key"
awk '/^ensure_env\(\)/,/^}/' "$ONECLICK_SCRIPT" | grep -Fq 'if [ -f "$ENV_FILE" ]; then' || fail "oneclick installer must skip an existing .env"
if grep -Eq 'UAG_AUDIT_HMAC_KEY=.*random_hex|random_hex[^\n]*UAG_AUDIT_HMAC_KEY' "$UPGRADE_SCRIPT"; then
  fail "upgrade must never regenerate the audit key"
fi
grep -Fq 'UAG_AUDIT_HMAC_KEY' "$UPGRADE_SCRIPT" || fail "upgrade must require the audit key"

echo '[ok] audit HMAC key is generated on fresh install and never rotated by install/upgrade'
