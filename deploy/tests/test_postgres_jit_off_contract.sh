#!/usr/bin/env bash
set -Eeuo pipefail

# PostgreSQL JIT 关闭合约（2.9.22 批次 7）。
#
# 告警、留存这类报表查询的 JSON 展开会让 JIT 先花数秒编译几百个函数，客户现场留存页
# 关 JIT 前后差一个数量级（现场已于 11-17 在数据库层面关闭）。部署的 postgres 必须带
# -c jit=off 启动，不能靠现场手工改库；控制面的报表读查询另有 SET LOCAL jit = off 兜底。

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
COMPOSE_FILES=(
  "$ROOT_DIR/deploy/docker-compose/docker-compose.yml"
  "$ROOT_DIR/deploy/docker-compose/docker-compose.offline.yml"
)

fail() {
  echo "[fail] $*" >&2
  exit 1
}

for file in "${COMPOSE_FILES[@]}"; do
  [ -f "$file" ] || fail "缺少文件：$file"
  # 只看 postgres 服务块：从 "  postgres:" 到下一个两格缩进的服务名。
  block="$(awk "/^  postgres:/{on=1; print; next} on && /^  [A-Za-z0-9_-]+:/{on=0} on" "$file")"
  [ -n "$block" ] || fail "$(basename "$file") 没有 postgres 服务"
  printf "%s\n" "$block" | grep -Eq "^    command:.*\"-c\", *\"jit=off\"" \
    || fail "$(basename "$file") 的 postgres 没有以 -c jit=off 启动"
done

echo "[ok] postgres jit=off contract"
