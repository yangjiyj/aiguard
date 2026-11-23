#!/bin/sh
# install-response-cache.sh 契约测试：在临时目录里模拟一个已安装部署（offline 基础 + 开机链），
# 在断网的一次性容器里以 root 运行，用宿主的 compose 插件只做渲染（不启动任何容器），
# 验证 redis-cache 服务与网关缓存地址、幂等、调整内存上限、卸载与各类拒绝。
set -eu

IMAGE="${RESPONSE_CACHE_TEST_IMAGE:-python:3.12-alpine}"
if [ "${RESPONSE_CACHE_TEST_INNER:-}" != 1 ]; then
  ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)"
  command -v docker >/dev/null 2>&1 || { echo "SKIP test_response_cache_install: 无 docker"; exit 0; }
  docker image inspect "$IMAGE" >/dev/null 2>&1 || { echo "SKIP test_response_cache_install: 缺少镜像 $IMAGE"; exit 0; }
  PLUGIN=""
  for c in /usr/libexec/docker/cli-plugins/docker-compose /usr/local/lib/docker/cli-plugins/docker-compose "$HOME/.docker/cli-plugins/docker-compose"; do
    [ -x "$c" ] && { PLUGIN="$c"; break; }
  done
  [ -n "$PLUGIN" ] || { echo "SKIP test_response_cache_install: 无 compose 二进制"; exit 0; }
  exec docker run --rm --network none -e RESPONSE_CACHE_TEST_INNER=1 -v "$ROOT:/repo:ro" \
    -v "$PLUGIN:/usr/local/bin/docker-compose:ro" "$IMAGE" sh /repo/deploy/tests/test_response_cache_install.sh
fi

SCRIPT=/repo/deploy/response-cache/install-response-cache.sh
COMPOSE_BIN=/usr/local/bin/docker-compose
[ "$(id -u)" = 0 ] || { echo "FAIL: 容器内应为 root" >&2; exit 1; }
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
fail() { echo "FAIL: $*" >&2; exit 1; }
pass() { echo "PASS: $*"; }

make_deploy() {  # $1=目录 $2=基础 compose 是否已带 redis-cache(1/0)
  d="$1"
  mkdir -p "$d/.upgrade" "$d/active-config/20261024" "$d/bin"
  printf 'REDIS_PASSWORD=contract-pass\nPOSTGRES_PASSWORD=x\n' >"$d/.env"; chmod 600 "$d/.env"
  {
    printf 'services:\n'
    printf '  gateway-core:\n    image: busybox:latest\n    environment:\n      - REDIS_URL=redis://:${REDIS_PASSWORD}@redis:6379/0\n    networks: [jjdguard-net]\n'
    [ "$2" = 1 ] && printf '  redis-cache:\n    image: valkey/valkey:8.1.10-alpine\n    networks: [jjdguard-net]\n'
    printf '  redis:\n    image: valkey/valkey:8.1.10-alpine\n    networks: [jjdguard-net]\n'
    printf 'networks:\n  jjdguard-net: {}\n'
  } >"$d/docker-compose.offline.yml"
  printf 'services:\n  gateway-core:\n    image: busybox:1.36\n' >"$d/active-config/20261024/release-images.override.yml"
  chmod 600 "$d/active-config/20261024/release-images.override.yml"
  printf '%s\n' "$d/active-config/20261024/release-images.override.yml" >"$d/.upgrade/compose-files"
  printf 'jjdcontract\n' >"$d/.upgrade/project-name"
  chmod 600 "$d/.upgrade/compose-files" "$d/.upgrade/project-name"
  ln -s "$COMPOSE_BIN" "$d/bin/docker-compose"
}

render() {  # $1=目录：按开机链渲染成 JSON
  d="$1"; set -- -f "$d/docker-compose.offline.yml"
  while IFS= read -r entry; do [ -n "$entry" ] && set -- "$@" -f "$entry"; done <"$d/.upgrade/compose-files"
  (cd "$d" && "$COMPOSE_BIN" --project-name jjdcontract --project-directory "$d" --env-file "$d/.env" "$@" config --format json)
}

D="$WORK/rel1/dc"
make_deploy "$D" 0
sh "$SCRIPT" --deploy-dir "$D" --maxmemory 128mb >/dev/null
OV="$D/active-config/response-cache.override.yml"
[ -f "$OV" ] || fail "没有生成 override"
[ "$(stat -c '%a %u' "$OV")" = "600 0" ] || fail "override 必须是 root 0600"
[ "$(stat -c '%a %u' "$D/.upgrade/compose-files")" = "600 0" ] || fail "compose-files 权限被改动"
[ "$(tail -n 1 "$D/.upgrade/compose-files")" = "$OV" ] || fail "override 没有追加到开机链末尾"
render "$D" >"$WORK/model.json"
python3 - "$WORK/model.json" <<'PY'
import json, sys
m = json.load(open(sys.argv[1]))
rc = m["services"].get("redis-cache") or sys.exit("FAIL: 渲染结果没有 redis-cache")
cmd = " ".join(rc["command"])
for want in ("--save ''", "--appendonly no", "--maxmemory-policy allkeys-lru", "--requirepass"):
    assert want in cmd, "FAIL: redis-cache command 缺少 " + want
assert rc["environment"]["RESPONSE_CACHE_MAXMEMORY"] == "128mb", rc["environment"]
assert rc["environment"]["REDIS_PASSWORD"] == "contract-pass"
assert not rc.get("ports") and not rc.get("volumes"), "FAIL: 缓存实例不能发布端口或挂卷"
assert rc["image"] == "valkey/valkey:8.1.10-alpine"
assert "jjdguard-net" in rc["networks"]
gw = m["services"]["gateway-core"]["environment"]
assert gw["RESPONSE_CACHE_REDIS_URL"] == "redis://:contract-pass@redis-cache:6379/0", gw
assert gw["REDIS_URL"] == "redis://:contract-pass@redis:6379/0", "FAIL: 主 Redis 地址被改动"
assert m["services"]["gateway-core"]["image"] == "busybox:1.36", "FAIL: 开机链里已有的覆盖被打乱"
print("PASS: 渲染出 redis-cache（不持久化、128mb、LRU、无端口无卷）与网关缓存地址，原有配置不变")
PY

before="$(sha256sum "$OV" "$D/.upgrade/compose-files")"
sh "$SCRIPT" --deploy-dir "$D" --maxmemory 128mb >/dev/null
[ "$before" = "$(sha256sum "$OV" "$D/.upgrade/compose-files")" ] || fail "重复执行改变了文件"
[ "$(grep -Fxc "$OV" "$D/.upgrade/compose-files")" = 1 ] || fail "开机链里出现重复条目"
pass "重复执行幂等"

sh "$SCRIPT" --deploy-dir "$D" --maxmemory 512mb >/dev/null
grep -q 'RESPONSE_CACHE_MAXMEMORY=512mb' "$OV" || fail "改内存上限没有生效"
[ "$(grep -Fxc "$OV" "$D/.upgrade/compose-files")" = 1 ] || fail "改内存上限后开机链条目重复"
pass "可调整内存上限"

if sh "$SCRIPT" --deploy-dir "$D" --maxmemory '1gb;rm' >/dev/null 2>&1; then fail "非法内存值应被拒绝"; fi
pass "拒绝非法内存值"

sh "$SCRIPT" --uninstall --deploy-dir "$D" >/dev/null
[ ! -e "$OV" ] || fail "卸载后 override 仍在"
if grep -Fq "response-cache.override.yml" "$D/.upgrade/compose-files"; then fail "卸载后开机链仍有条目"; fi
[ "$(stat -c '%a %u' "$D/.upgrade/compose-files")" = "600 0" ] || fail "卸载改坏了 compose-files 权限"
render "$D" >"$WORK/model2.json"
python3 - "$WORK/model2.json" <<'PY'
import json, sys
m = json.load(open(sys.argv[1]))
assert "redis-cache" not in m["services"], "FAIL: 卸载后仍有 redis-cache"
assert "RESPONSE_CACHE_REDIS_URL" not in (m["services"]["gateway-core"].get("environment") or {}), "FAIL: 卸载后网关仍有缓存地址"
PY
pass "卸载后开机链恢复原状"

printf '# someone else\nservices: {}\n' >"$OV"; chmod 600 "$OV"
if sh "$SCRIPT" --uninstall --deploy-dir "$D" >/dev/null 2>&1; then fail "不是本脚本生成的 override 不应被删除"; fi
[ -e "$OV" ] || fail "外来文件被误删"
rm -f "$OV"
pass "不删除非本脚本生成的同名文件"

D2="$WORK/rel2/dc"
make_deploy "$D2" 1
sh "$SCRIPT" --deploy-dir "$D2" >/dev/null
[ ! -e "$D2/active-config/response-cache.override.yml" ] || fail "基础已带 redis-cache 时不应生成 override"
pass "新离线包（基础已带 redis-cache）不重复接入"

D3="$WORK/rel3/dc"
make_deploy "$D3" 0
sed -i '/^REDIS_PASSWORD=/d' "$D3/.env"
if sh "$SCRIPT" --deploy-dir "$D3" >/dev/null 2>&1; then fail "缺少 REDIS_PASSWORD 时应拒绝"; fi
[ ! -e "$D3/active-config/response-cache.override.yml" ] || fail "拒绝时不应留下 override"
pass "缺少 REDIS_PASSWORD 时拒绝且不留痕"
echo "test_response_cache_install: ok"
