#!/usr/bin/env bash
set -Eeuo pipefail

# 打包与升级契约：jjdctl sso 依赖的 chat/set-public-sso-url.sh 必须
#   1) 随 -chat 离线包产出（执行打包器里真实的 chat 拷贝代码，而不是复制一份命令）；
#   2) 进入 offline-inventory.tsv（执行打包器里真实的清单生成代码），否则客户机验签会判“文件集不一致”；
#   3) 经 installer 的 stage 流程（cp -a 载荷 + 安装 jjdctl 到包根）后，按 jjdctl 的查找路径
#      <包根>/deploy/docker-compose/chat/set-public-sso-url.sh 能被找到并执行，经 /usr/local/bin 式软链调用同样成立；
#   4) 升级时 jjdctl 和脚本来自同一个新 release 目录，路径关系不变。

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PACKAGER="$ROOT_DIR/deploy/docker-compose/package-offline-bundle.sh"
RUNNER="$ROOT_DIR/deploy/docker-compose/package-offline-run.sh"
INSTALLER="$ROOT_DIR/deploy/offline-installer/installer.sh"
JJDCTL="$ROOT_DIR/deploy/offline-installer/jjdctl"
fail() { echo "[sso-packaging-contract] $*" >&2; exit 1; }

grep -Fq 'package-offline-bundle.sh' "$RUNNER" || fail "package-offline-run.sh 必须经 package-offline-bundle.sh 出包"
grep -Fq 'cp -R "$PAYLOAD_SOURCE_ROOT/deploy/docker-compose/chat" "$BUNDLE_DIR/deploy/docker-compose/chat"' "$PACKAGER" ||
  fail "打包器必须整目录拷贝 chat/（脚本不能靠逐文件白名单）"
if grep -En 'rm -f .*set-public-sso-url' "$PACKAGER" >/dev/null; then fail "打包器不得剔除 set-public-sso-url.sh"; fi
grep -Fq 'install -m 755 "$staged/deploy/offline-installer/jjdctl" "$staged/jjdctl"' "$INSTALLER" || fail "installer 必须把 jjdctl 安装到包根"
grep -Fq 'ln -sf "$CURRENT/jjdctl" /usr/local/bin/jjdctl' "$INSTALLER" || fail "installer 必须把 /usr/local/bin/jjdctl 指向当前 release 的 jjdctl"
grep -Fq 'DC="$ROOT/deploy/docker-compose"' "$JJDCTL" || fail "jjdctl 必须以包根推导 compose 目录"
grep -Fq '"$DC/chat/set-public-sso-url.sh"' "$JJDCTL" || fail "jjdctl 必须按 \$DC/chat/ 查找脚本"

tmp="$(mktemp -d "${TMPDIR:-/tmp}/sso-packaging.XXXXXX")"
trap 'rm -rf "$tmp"' EXIT

# 1) 执行打包器真实的 chat 载荷代码块
block="$(awk '/^  if \[ "\$INCLUDE_CHAT" = "1" \]; then$/ {on=1} on {print} on && /^  fi$/ {exit}' "$PACKAGER")"
[ -n "$block" ] || fail "找不到打包器的 chat 载荷代码块"
BUNDLE_DIR="$tmp/bundle"; PAYLOAD_SOURCE_ROOT="$ROOT_DIR"; INCLUDE_CHAT=1
mkdir -p "$BUNDLE_DIR/deploy/docker-compose" "$BUNDLE_DIR/deploy/offline-installer"
cp -R "$ROOT_DIR/deploy/docker-compose/directory-truststore" "$BUNDLE_DIR/deploy/docker-compose/"
cp "$ROOT_DIR/deploy/docker-compose/lib-identity-mounts.sh" "$BUNDLE_DIR/deploy/docker-compose/"
cp "$JJDCTL" "$BUNDLE_DIR/deploy/offline-installer/jjdctl"
(eval "$block") >/dev/null
[ -f "$BUNDLE_DIR/deploy/docker-compose/chat/set-public-sso-url.sh" ] || fail "-chat 离线包缺少 chat/set-public-sso-url.sh"
[ -x "$BUNDLE_DIR/deploy/docker-compose/chat/set-public-sso-url.sh" ] || fail "包内 set-public-sso-url.sh 丢失可执行位"
cmp -s "$ROOT_DIR/deploy/docker-compose/chat/set-public-sso-url.sh" "$BUNDLE_DIR/deploy/docker-compose/chat/set-public-sso-url.sh" || fail "包内脚本与源码不一致"
echo "[ok] 打包器 chat 载荷代码块产出 set-public-sso-url.sh"

# 2) 执行打包器真实的清单生成代码
inv_py="$tmp/inventory.py"
awk '/^write_offline_inventory\(\) \{/ {f=1} f && /^python3 - "\$BUNDLE_DIR" <<.PY.$/ {on=1; next} on && /^PY$/ {exit} on {print}' "$PACKAGER" >"$inv_py"
if [ ! -s "$inv_py" ]; then
  awk '/^write_offline_inventory\(\) \{/ {f=1} f && /python3 - "\$BUNDLE_DIR" <<.PY.$/ {on=1; next} on && /^PY$/ {exit} on {print}' "$PACKAGER" >"$inv_py"
fi
[ -s "$inv_py" ] || fail "无法从打包器提取清单生成代码"
python3 -I "$inv_py" "$BUNDLE_DIR" >/dev/null
python3 -I - "$BUNDLE_DIR" <<'PY' || fail "offline-inventory.tsv 未登记 chat/set-public-sso-url.sh 或哈希不符"
import base64, hashlib, pathlib, sys
root = pathlib.Path(sys.argv[1])
want = "deploy/docker-compose/chat/set-public-sso-url.sh"
for line in (root / "offline-inventory.tsv").read_text().splitlines():
    parts = line.split("\t")
    if parts[0] != "file":
        continue
    rel = base64.urlsafe_b64decode(parts[1] + "=" * (-len(parts[1]) % 4)).decode()
    if rel == want:
        assert parts[3] == hashlib.sha256((root / rel).read_bytes()).hexdigest()
        sys.exit(0)
sys.exit(1)
PY
echo "[ok] offline-inventory.tsv 登记该脚本（哈希一致）"

# 3) installer stage：cp -a 载荷 + install jjdctl 到包根；经软链调用
staged="$tmp/opt/releases/test-release"
mkdir -p "$staged"
cp -a "$BUNDLE_DIR/." "$staged/"
# 正式包的基础载荷（copy_payload）带 deploy/lib/jjd-env.sh，jjdctl 经它安全读取 .env；本测试只执行了 chat 载荷拷贝，补上这一份。
mkdir -p "$staged/deploy/lib"
cp "$ROOT_DIR/deploy/lib/jjd-env.sh" "$staged/deploy/lib/"
install -m 755 "$staged/deploy/offline-installer/jjdctl" "$staged/jjdctl"
mkdir -p "$tmp/opt" "$tmp/bin"
ln -s "$staged" "$tmp/opt/current"
ln -s "$tmp/opt/current/jjdctl" "$tmp/bin/jjdctl"
dc="$staged/deploy/docker-compose"
: >"$dc/docker-compose.offline.yml"
printf 'JJD_SSO_PUBLIC_URL=https://192.168.20.246\n' >"$dc/.env"
if command -v fakeroot >/dev/null 2>&1; then
  out="$(fakeroot -- "$tmp/bin/jjdctl" sso help 2>&1)" || fail "经软链调用 jjdctl sso help 失败: $out"
  echo "$out" | grep -q 'set-public-url' || fail "jjdctl sso help 未输出脚本用法"
  echo "$out" | grep -q 'rollback' || fail "jjdctl sso help 未包含 rollback"
  out="$(fakeroot -- "$tmp/bin/jjdctl" sso rollback 2>&1 || true)"
  echo "$out" | grep -q '用法' || fail "rollback 缺参数应给出用法"
  rm -rf "$dc/chat"
  out="$(fakeroot -- "$tmp/bin/jjdctl" sso help 2>&1 || true)"
  echo "$out" | grep -q '不含 chat/SSO 载荷' || fail "非 chat 包应给出清楚提示"
  echo "[ok] 经 /usr/local/bin 式软链调用 jjdctl sso 能找到脚本；非 chat 包提示清楚"
else
  echo "[skip] 无 fakeroot，跳过 jjdctl 软链调用验证"
fi
echo "[ok] sso set-public-url 打包与升级路径契约通过"
