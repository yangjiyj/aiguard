#!/usr/bin/env bash
# shellcheck disable=SC1090,SC1091
# preflight 增强测试：发行版识别 + 资源阈值 + 端口占用，安装前明确报错。
# 用 JJD_INSTALLER_LIB_ONLY=1 source installer.sh 加载函数，用环境变量注入 fake 环境。
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
INSTALLER="$ROOT/deploy/offline-installer/installer.sh"

fail() { echo "[fail] $*" >&2; exit 1; }
[[ -f "$INSTALLER" ]] || fail "missing installer: $INSTALLER"
bash -n "$INSTALLER" || fail "installer.sh 语法错误"

# 加载 installer.sh 的函数（不跑 main）
JJD_INSTALLER_LIB_ONLY=1 source "$INSTALLER"

# ---- fake manifest（manifest_value 需要）----
TMPF="$(mktemp -d)"; trap 'rm -rf "$TMPF"' EXIT
MANIFEST="$TMPF/manifest.json"
printf '{"product":"jjdguard-enterprise","version":"1.6.0","target_arch":"amd64","min_data_version":"001.sql"}' >"$MANIFEST"
CURRENT="$TMPF/opt/current"
RELEASES="$TMPF/opt/releases"
LEGACY_ROOT="$TMPF/legacy"
mkdir -p "$RELEASES"

capture() { ( "$@" ) >/tmp/pf.out 2>&1; local rc=$?; cat /tmp/pf.out; return $rc; }

# ===== 1) detect_distro：识别 debian/rhel/suse 族，不识别不致命 =====
# fake os-release（printf 的 \n 是真实换行）
printf 'NAME="Ubuntu"\nID=ubuntu\nID_LIKE=debian\n' >"$TMPF/os-release-ubuntu"
family="$(JJD_OS_RELEASE_FILE="$TMPF/os-release-ubuntu" detect_distro 2>/dev/null || true)"
[[ "$family" == debian ]] || fail "Ubuntu 应识别为 debian 族，实际: $family"

# Rocky (ID=rocky, ID_LIKE=rhel)
printf 'NAME="Rocky Linux"\nID=rocky\nID_LIKE=rhel\n' >"$TMPF/os-release-rocky"
family="$(JJD_OS_RELEASE_FILE="$TMPF/os-release-rocky" detect_distro 2>/dev/null || true)"
[[ "$family" == rhel ]] || fail "Rocky 应识别为 rhel 族，实际: $family"

# 未知发行版（ID_LIKE 空）应回退到 other 不退出
printf 'NAME="WeirdOS"\nID=weirdos\n' >"$TMPF/os-release-weird"
family="$(JJD_OS_RELEASE_FILE="$TMPF/os-release-weird" detect_distro 2>/dev/null || true)"
[[ "$family" == other ]] || fail "未知发行版应回退 other，实际: $family"
echo '[ok] detect_distro: ubuntu->debian / rocky->rhel / unknown->other'

# ===== 2) preflight_resources：资源不足安装前 die =====
# CPU 不足（设阈值 8，实际 stub 1 核）
if JJD_PREFLIGHT_MIN_CPU=8 JJD_NPROC_STUB=1 capture preflight_resources >/dev/null; then
  fail "CPU 不足应 die"
else
  echo '[ok] preflight_resources: CPU 不足正确报错'
fi
# 内存不足（设阈值 64GB，实际 stub 1GB-KB）
if JJD_PREFLIGHT_MIN_MEM_MB=65536 JJD_MEMINFO_STUB="$TMPF/mem-small" capture preflight_resources >/dev/null; then
  fail "内存不足应 die"
else
  echo '[ok] preflight_resources: 内存不足正确报错'
fi
printf 'MemTotal:       900000 kB\n' >"$TMPF/mem-small"
if JJD_PREFLIGHT_MIN_MEM_MB=65536 JJD_MEMINFO_STUB="$TMPF/mem-small" capture preflight_resources >/dev/null; then
  fail "内存不足应 die（meminfo 路径）"
else
  echo '[ok] preflight_resources: 内存不足正确报错（meminfo）'
fi
# 资源充足应通过（全部用 stub，避免依赖宿主真实 /opt/jjdguard 是否存在）
printf 'MemTotal:      8388608 kB\n' >"$TMPF/mem-ok"
printf 'Filesystem      1K-blocks   Used  Avail Use%% Mounted on\n/dev/x 50000000 10000000 38000000 21%% /\n' >"$TMPF/df-ok"
JJD_PREFLIGHT_MIN_CPU=2 JJD_NPROC_STUB=4 \
JJD_PREFLIGHT_MIN_MEM_MB=2048 JJD_MEMINFO_STUB="$TMPF/mem-ok" \
JJD_PREFLIGHT_MIN_DISK_MB=1024 JJD_DF_STUB="$TMPF/df-ok" \
  preflight_resources >/dev/null || fail "资源充足应通过"
echo '[ok] preflight_resources: 充足时通过'

# 资源充足-真实df：OPT_ROOT 指向不存在的目录（首次安装场景），不设 JJD_DF_STUB，
# 必须向上 fallback 到存在的祖先目录，取真实可用空间，不误报 0MB。
# 回归保护：曾因 df /opt/jjdguard（不存在）失败误报"磁盘空间不足"阻断首次安装。
if ! ( JJD_PREFLIGHT_MIN_CPU=2 JJD_NPROC_STUB=4 \
       JJD_PREFLIGHT_MIN_MEM_MB=2048 JJD_MEMINFO_STUB="$TMPF/mem-ok" \
       JJD_PREFLIGHT_MIN_DISK_MB=1024 OPT_ROOT="$TMPF/nonexistent/sub/dir" \
       preflight_resources ) >/dev/null 2>&1; then
  fail "OPT_ROOT 不存在时应 fallback 到祖先目录并取真实空间，不应误报磁盘不足"
fi
echo '[ok] preflight_resources: OPT_ROOT 不存在时 fallback 到祖先目录（首次安装场景）'

# ===== 3) preflight_ports：端口被占时提示，交给内层部署自动顺延 =====
# stub ss：报告 8080 被占（preflight_ports 用 BINDIR/ss 探测）
mkdir -p "$TMPF/ss-busy"
printf '#!/usr/bin/env bash\necho "LISTEN 0 0 *:8080 *:* users:((other,1234,5))"\nexit 0\n' >"$TMPF/ss-busy/ss"; chmod 755 "$TMPF/ss-busy/ss"
busy_output="$(JJD_PORT_CHECK_BINDIR="$TMPF/ss-busy" capture preflight_ports)" ||
  fail "端口被占不应阻断首次安装"
grep -Fq '首次部署将自动顺延到可用端口' <<<"$busy_output" ||
  fail "端口被占时未提示自动顺延"
echo '[ok] preflight_ports: 端口被占时提示并继续'
# stub ss：无端口被占
mkdir -p "$TMPF/ss-empty"
printf '#!/usr/bin/env bash\nexit 0\n' >"$TMPF/ss-empty/ss"; chmod 755 "$TMPF/ss-empty/ss"
JJD_PORT_CHECK_BINDIR="$TMPF/ss-empty" preflight_ports >/dev/null || fail "端口全空闲应通过"
echo '[ok] preflight_ports: 端口空闲时通过'

# ===== 4) preflight 主函数仍拒绝非 root / 非 systemd（回归保护）=====
# 这里不实际跑 preflight 主函数（会真实检测本机），只确认子函数已接进去
grep -q 'preflight_resources' "$INSTALLER" || fail "preflight 未接 preflight_resources"
grep -q 'preflight_ports' "$INSTALLER" || fail "preflight 未接 preflight_ports"
grep -q 'detect_distro' "$INSTALLER" || fail "preflight 未接 detect_distro"
echo '[ok] preflight 主函数已接入三个子检查'

# ==== preflight_ports 升级跳过：CURRENT 有值时跳过端口检查 ====
upgrade_release="$RELEASES/1.5.0-amd64"
mkdir -p "$upgrade_release/deploy/docker-compose"
printf 'COMPOSE_PROJECT_NAME=1-5-0-amd64\n' >"$upgrade_release/deploy/docker-compose/.env"
ln -s "$upgrade_release" "$CURRENT"
if JJD_PORT_CHECK_BINDIR="$TMPF/ss-busy" capture preflight_ports >/dev/null; then
  echo '[ok] preflight_ports: CURRENT 有值时跳过（升级场景）'
else
  fail "升级场景 CURRENT 有值时应跳过端口检查，不应 die"
fi

echo '[ok] preflight 增强测试全部通过'
