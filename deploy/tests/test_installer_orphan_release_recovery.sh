#!/usr/bin/env bash
# Regression: a healthy, uniquely identifiable release left before CURRENT was
# committed must be recovered as the upgrade source instead of being reported
# as a generic host-port conflict.
set -Eeuo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
INSTALLER="$ROOT/deploy/offline-installer/installer.sh"

fail() { echo "[fail] $*" >&2; exit 1; }

JJD_INSTALLER_LIB_ONLY=1 source "$INSTALLER"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

CURRENT="$tmp/opt/current"
RELEASES="$tmp/opt/releases"
LEGACY_ROOT="$tmp/legacy"
mkdir -p "$RELEASES" "$tmp/bin"

make_release() {
  local name="$1" project="$2" release
  release="$RELEASES/$name"
  mkdir -p "$release/deploy/docker-compose"
  printf '{"version":"1.7.1","target_arch":"amd64"}\n' >"$release/manifest.json"
  printf 'JJD_VERSION=1.7.1\nCOMPOSE_PROJECT_NAME=%s\n' "$project" >"$release/deploy/docker-compose/.env"
  printf 'services: {}\n' >"$release/deploy/docker-compose/docker-compose.offline.yml"
  chmod 600 "$release/deploy/docker-compose/.env"
}

make_release '1.7.1-amd64' '1-7-1-amd64'

cat >"$tmp/bin/docker" <<'SH'
#!/usr/bin/env bash
if [[ "$*" == 'ps -aq --filter label=com.docker.compose.project=1-7-1-amd64' ]]; then
  printf 'container-id\n'
fi
SH
chmod 755 "$tmp/bin/docker"

recovered="$(PATH="$tmp/bin:$PATH" discover_current)"
[[ "$recovered" == "$RELEASES/1.7.1-amd64" ]] ||
  fail "唯一且有匹配容器的旧 release 应恢复为升级来源，实际：$recovered"
echo '[ok] 唯一且有匹配 Compose 容器的旧 release 可恢复'

mkdir -p "$tmp/no-container-bin"
printf '#!/usr/bin/env bash\nexit 0\n' >"$tmp/no-container-bin/docker"
chmod 755 "$tmp/no-container-bin/docker"
recovered="$(PATH="$tmp/no-container-bin:$PATH" discover_current)" ||
  fail '没有匹配容器的暂存 release 应正常表示为无当前版本'
[[ -z "$recovered" ]] || fail "没有匹配容器的暂存 release 不得被认作当前版本：$recovered"
echo '[ok] 没有匹配容器时拒绝恢复'

make_release '1.7.1-amd64-second' '1-7-1-amd64-second'
cat >"$tmp/bin/docker" <<'SH'
#!/usr/bin/env bash
case "$*" in
  *1-7-1-amd64-second*) printf 'container-id-2\n' ;;
  *1-7-1-amd64*) printf 'container-id-1\n' ;;
esac
SH
chmod 755 "$tmp/bin/docker"
if recovered="$(PATH="$tmp/bin:$PATH" discover_current)" && [[ -n "$recovered" ]]; then
  fail "多个可恢复 release 必须拒绝，实际：$recovered"
fi
echo '[ok] 多个可恢复 release 时拒绝猜测'

echo '[ok] orphan release recovery regression passed'
