#!/usr/bin/env bash
# shellcheck disable=SC1090,SC1091
# #14 并发锁测试：installer.sh 必须用 flock 防止并发安装/升级。
# 验证：锁被占时，第二个 acquire_install_lock 必须立即失败（非零退出 + 明确报错）；
#       锁空闲时 acquire 成功。锁在进程退出后自动释放（可重入）。
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
INSTALLER="$ROOT/deploy/offline-installer/installer.sh"

fail() { echo "[fail] $*" >&2; exit 1; }
[[ -f "$INSTALLER" ]] || fail "missing installer: $INSTALLER"
bash -n "$INSTALLER" || fail "installer.sh 语法错误"
command -v flock >/dev/null 2>&1 || { echo "[skip] 无 flock；跳过并发锁测试"; exit 0; }

# 确认 installer.sh 引入了锁机制
grep -q 'acquire_install_lock' "$INSTALLER" || fail "installer.sh 未引入 acquire_install_lock"
grep -q 'flock' "$INSTALLER" || fail "installer.sh 未使用 flock"

LOCK_TEST_DIR="$(mktemp -d)"; trap 'rm -rf "$LOCK_TEST_DIR"' EXIT
# 必须在 source installer.sh 之前 export，因为 LOCK_FILE 在 source 时一次性求值
export JJD_INSTALL_LOCK_FILE="$LOCK_TEST_DIR/test-install.lock"

JJD_INSTALLER_LIB_ONLY=1 source "$INSTALLER"

# 1) 锁空闲：acquire 成功（在子 shell 持有 fd，退出即释放）
( acquire_install_lock && echo " acquired-ok" ) || fail "锁空闲时 acquire 应成功"
echo '[ok] 锁空闲时 acquire 成功'

# 2) 锁被占：后台进程持有锁，第二个 acquire 必须失败
# 用 flock 占住锁文件 5 秒
( exec 9>"$JJD_INSTALL_LOCK_FILE"; flock -x 9; sleep 5 ) &
HOLDER_PID=$!
# 等后台拿到锁
for _ in 1 2 3 4 5 6 7 8 9 10; do
  if [[ -e "$JJD_INSTALL_LOCK_FILE" ]]; then sleep 0.3; break; fi
  sleep 0.2
done
sleep 0.5  # 确保后台已 flock 成功

# 此时再 acquire 应立即失败（flock -n 非阻塞）
if ( acquire_install_lock ) >/tmp/lock2.out 2>&1; then
  kill "$HOLDER_PID" 2>/dev/null || true
  fail "锁被占时第二个 acquire 应失败"
fi
grep -qiE "另一个|正在运行|锁|lock|concurrent|busy" /tmp/lock2.out || fail "锁冲突未给出明确报错: $(cat /tmp/lock2.out)"
echo '[ok] 锁被占时第二个 acquire 立即失败并报错'
kill "$HOLDER_PID" 2>/dev/null || true
wait "$HOLDER_PID" 2>/dev/null || true

# 3) 锁释放后可再次 acquire（fd 关闭自动释放）
sleep 1  # 确保后台进程退出、锁释放
( acquire_install_lock && echo " reacquired-ok" ) || fail "锁释放后应可再次 acquire"
echo '[ok] 锁释放后可再次 acquire'

echo '[ok] 并发锁(#14)测试通过'
