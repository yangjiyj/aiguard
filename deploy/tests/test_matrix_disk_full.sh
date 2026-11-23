#!/usr/bin/env bash
# #6 磁盘不足测试：preflight_resources 在磁盘不足时必须安装前 die，
# 而不是装到一半磁盘满才失败。纯逻辑，用 df stub 注入。
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
INSTALLER="$ROOT/deploy/offline-installer/installer.sh"

fail() { echo "[fail] $*" >&2; exit 1; }
[[ -f "$INSTALLER" ]] || fail "missing installer"
bash -n "$INSTALLER" || fail "语法错误"

JJD_INSTALLER_LIB_ONLY=1 source "$INSTALLER"
WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT

# df 输出：可用空间只有 500MB（阈值默认 10240MB）
printf 'Filesystem      1K-blocks   Used  Avail Use%% Mounted on\n/dev/x 10000000 9500000 500000 95%% /\n' >"$WORK/df-small"

# 磁盘不足应 die（在子 shell 里跑，捕获 exit）
if ( JJD_PREFLIGHT_MIN_DISK_MB=10240 JJD_DF_STUB="$WORK/df-small" \
     JJD_NPROC_STUB=8 JJD_MEMINFO_STUB=/proc/meminfo preflight_resources ) >/tmp/disk.log 2>&1; then
  fail "磁盘不足应 die"
fi
grep -qiE "磁盘空间不足|disk" /tmp/disk.log || fail "未报磁盘不足: $(cat /tmp/disk.log)"
# 阈值边界：可用 500000KB≈488MB，设阈值 488MB 应通过（>=）
if ! ( JJD_PREFLIGHT_MIN_DISK_MB=488 JJD_DF_STUB="$WORK/df-small" \
       JJD_NPROC_STUB=8 JJD_MEMINFO_STUB=/proc/meminfo preflight_resources ) >/dev/null 2>&1; then
  fail "磁盘可用量 >= 阈值应通过"
fi
echo '[ok] #6: 磁盘不足安装前 die，够阈值通过'
echo '[ok] #6 磁盘不足测试通过'
