#!/usr/bin/env bash
# 历史 checksum 白名单合约测试。
#
# 覆盖两个方向：
#   1. 命中白名单 → 保留历史记账并跳过执行（存量客户升级得以放行）
#   2. 未命中白名单 → 仍然硬阻断退出 2（防篡改能力不得被削弱）
#
# 用一次性 postgres 容器，不依赖任何既有部署。
set -Eeuo pipefail
# 临时容器：打测试标签、先回收被杀掉的测试进程留下的孤儿容器，清理用 docker rm -f -v（见该库说明）。
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib/test-containers.sh"
jjd_test_reap_orphan_containers
jjd_test_container_labels legacy-checksum-whitelist

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
RUNNER="$ROOT_DIR/deploy/lib/migration-runner.sh"
WHITELIST="$ROOT_DIR/deploy/lib/legacy-migration-checksums.tsv"
PROBE_MIGRATION="108_access_content_conversation_index.sql"

[[ -r "$RUNNER" ]] || { echo "缺少 migration-runner.sh" >&2; exit 1; }
[[ -r "$WHITELIST" ]] || { echo "缺少 legacy-migration-checksums.tsv" >&2; exit 1; }

if ! command -v docker >/dev/null 2>&1 \
  || ! docker info >/dev/null 2>&1 \
  || ! docker image inspect postgres:16-alpine >/dev/null 2>&1; then
  echo "SKIP: legacy checksum whitelist PostgreSQL test"
  exit 0
fi

# 从白名单里取该迁移的一条历史 checksum 作为「旧记账」输入。
legacy_checksum="$(awk -F'\t' -v v="$PROBE_MIGRATION" \
  '$1 == v { print $2; exit }' "$WHITELIST")"
[[ -n "$legacy_checksum" ]] || {
  echo "白名单里没有 $PROBE_MIGRATION 的条目" >&2
  exit 1
}
current_checksum="$(sha256sum "$ROOT_DIR/deploy/migrations/$PROBE_MIGRATION" | cut -d' ' -f1)"
[[ "$legacy_checksum" != "$current_checksum" ]] || {
  echo "白名单条目与当前文件 checksum 相同，测试前提不成立" >&2
  exit 1
}

container="jjdguard-legacy-checksum-$$-$RANDOM"
workdir="$(mktemp -d)"
bridge="$workdir/psql-bridge"
cleanup() {
  docker rm -f -v "$container" >/dev/null 2>&1 || true
  rm -rf "$workdir"
}
trap cleanup EXIT INT TERM

docker run "${JJD_TEST_CONTAINER_LABELS[@]}" --rm -d --name "$container" \
  -e POSTGRES_PASSWORD=test \
  -e POSTGRES_DB=test \
  postgres:16-alpine >/dev/null

ready=0
for _ in {1..90}; do
  if [[ "$(docker exec "$container" psql -U postgres -d test -tAc 'SELECT 1' 2>/dev/null)" == 1 ]]; then
    ready=1
    break
  fi
  sleep 1
done
[[ "$ready" == 1 ]] || { echo "PostgreSQL readiness timeout" >&2; exit 1; }

cat >"$bridge" <<BEOF
#!/usr/bin/env bash
set -euo pipefail
exec docker exec -i $container psql -U postgres -d test "\$@"
BEOF
chmod +x "$bridge"

mkdir -p "$workdir/migrations"
cp "$ROOT_DIR/deploy/migrations/$PROBE_MIGRATION" "$workdir/migrations/"

seed_recorded_checksum() {
  docker exec "$container" psql -v ON_ERROR_STOP=1 -U postgres -d test -c "
    DROP TABLE IF EXISTS schema_migrations;
    CREATE TABLE schema_migrations (
      version text PRIMARY KEY,
      checksum text,
      applied_at timestamptz DEFAULT now()
    );
    INSERT INTO schema_migrations (version, checksum)
      VALUES ('$PROBE_MIGRATION', '$1');" >/dev/null
}

recorded_checksum() {
  docker exec "$container" psql -U postgres -d test -tAc \
    "SELECT checksum FROM schema_migrations WHERE version = '$PROBE_MIGRATION'" | tr -d '[:space:]'
}

failures=0

# --- 用例 1：命中白名单 → 原样保留并跳过 ---
seed_recorded_checksum "$legacy_checksum"
if MIGRATION_PSQL="$bridge" bash "$RUNNER" --migrations-dir "$workdir/migrations" >"$workdir/out1" 2>&1; then
  if grep -q 'accepted immutable legacy checksum' "$workdir/out1" \
    && [[ "$(recorded_checksum)" == "$legacy_checksum" ]]; then
    echo "ok   命中白名单 → 保留历史记账并跳过执行"
  else
    echo "BAD  命中白名单但历史记账被改写"; sed 's/^/     /' "$workdir/out1"; failures=1
  fi
else
  echo "BAD  命中白名单却失败退出"; sed 's/^/     /' "$workdir/out1"; failures=1
fi

# --- 用例 2：未命中白名单 → 仍须硬阻断 ---
seed_recorded_checksum "deadbeef00000000000000000000000000000000000000000000000000000000"
if MIGRATION_PSQL="$bridge" bash "$RUNNER" --migrations-dir "$workdir/migrations" >"$workdir/out2" 2>&1; then
  echo "BAD  伪造 checksum 未被阻断（防篡改能力被削弱）"; sed 's/^/     /' "$workdir/out2"; failures=1
else
  if grep -q 'checksum mismatch' "$workdir/out2"; then
    echo "ok   未命中白名单 → 仍然硬阻断"
  else
    echo "BAD  阻断原因不是 checksum mismatch"; sed 's/^/     /' "$workdir/out2"; failures=1
  fi
fi

exit "$failures"
