#!/usr/bin/env bash
# 自建策略删除：隔离临时栈上的真实引擎 / 真实浏览器端到端。
#
# 起一套独立的 compose 项目（唯一项目名、回环端口、临时密钥），用本工作树构建的 control-plane /
# gateway-core / web-console 和挂载的 security-engine 代码，跑：
#   1) test_policy_delete_api.py   建 keyword+block 策略 → 真实拦截 → 删除 → 引擎规则包更新后同样请求放行，
#                                  告警/拦截记录仍显示策略名、同名重建、内置 409、旧接口、豁免、只读角色……
#   2) browser/delete-policy.mjs   （E2E_BROWSER=1）真实 Chrome 里点：详情抽屉 / 行内删除、计数同步、服务端报错、
#                                  各入口、内置与只读角色看不到删除
#   3) browser/residual-data-flows.mjs  （E2E_BROWSER=1）带残留数据的用户/应用/密钥/部门删除、禁用、编辑、跳转
# 结束后 down -v 清理；E2E_KEEP=1 保留。不碰任何长期运行的服务，不发布、不打包。
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WT="$(cd "$HERE/../../.." && pwd)"
export PATH="/usr/local/go/bin:$PATH"

export E2E_PROJECT="${E2E_PROJECT:-jjdguard-poldel-$(date +%m%d%H%M%S)}"
PORT_BASE="${E2E_PORT_BASE:-28400}"
export E2E_CP_PORT="${E2E_CP_PORT:-$((PORT_BASE + 1))}"
export E2E_GW_PORT="${E2E_GW_PORT:-$((PORT_BASE + 2))}"
export E2E_WEB_PORT="${E2E_WEB_PORT:-$((PORT_BASE + 3))}"
OWN_WORK=0
if [ -n "${E2E_WORK:-}" ]; then WORK="$E2E_WORK"; mkdir -p "$WORK"; else WORK="$(mktemp -d /tmp/policy-delete-e2e.XXXXXX)"; OWN_WORK=1; fi
export E2E_ENV_FILE="$WORK/stack.env"

die() { echo "[policy-delete-e2e] $*" >&2; exit 2; }
for tool in docker go python3 openssl; do command -v "$tool" >/dev/null || die "缺少 $tool"; done
for port in "$E2E_CP_PORT" "$E2E_GW_PORT" "$E2E_WEB_PORT"; do
  if ss -ltn 2>/dev/null | awk '{print $4}' | grep -q ":${port}\$"; then die "端口 $port 已被占用（用 E2E_PORT_BASE 换一段）"; fi
done

ENGINE_IMAGE="${E2E_ENGINE_IMAGE:-$(docker images --format '{{.Repository}}:{{.Tag}}' | grep -m1 '^jjdguard-dev/security-engine:' || true)}"
[ -n "$ENGINE_IMAGE" ] || ENGINE_IMAGE="$(docker images --format '{{.Repository}}:{{.Tag}}' | grep -m1 '^docker-compose-security-engine:' || true)"
[ -n "$ENGINE_IMAGE" ] || die "找不到带 Python 依赖的 security-engine 镜像，请用 E2E_ENGINE_IMAGE 指定（本工作树的 apps/security-engine/app 会被挂进去）"
export E2E_ENGINE_IMAGE="$ENGINE_IMAGE"

compose() { docker compose -p "$E2E_PROJECT" --env-file "$E2E_ENV_FILE" -f "$WORK/compose.yml" "$@"; }
cleanup() {
  if [ "${E2E_KEEP:-0}" = 1 ]; then
    echo "[policy-delete-e2e] 保留项目 $E2E_PROJECT（工作目录 $WORK）；清理：docker compose -p $E2E_PROJECT -f $WORK/compose.yml down -v"
  else
    compose down -v --remove-orphans >/dev/null 2>&1 || true
    if [ "$OWN_WORK" = 1 ]; then rm -rf -- "$WORK" 2>/dev/null || true; fi
  fi
}
mkdir -p "$WORK/bin"
trap cleanup EXIT

echo "== 构建（本工作树）"
(cd "$WT/apps/control-plane" && GOWORK=off GOFLAGS=-buildvcs=false CGO_ENABLED=0 go build -o "$WORK/bin/control-plane" ./cmd/server)
(cd "$WT/apps/gateway-core" && GOWORK=off GOFLAGS=-buildvcs=false CGO_ENABLED=0 go build -o "$WORK/bin/gateway-core" ./cmd/server)
if [ "${E2E_SKIP_WEB_BUILD:-0}" != 1 ]; then
  [ -d "$WT/apps/web-console/node_modules" ] || die "apps/web-console 没有 node_modules（先 npm ci，或软链一份）"
  (cd "$WT/apps/web-console" && npm run build >/dev/null)
fi
[ -f "$WT/apps/web-console/dist/index.html" ] || die "web-console 没有构建产物"

echo "== 生成临时密钥与 compose 文件（项目 $E2E_PROJECT，端口 $E2E_CP_PORT/$E2E_GW_PORT/$E2E_WEB_PORT）"
hex() { openssl rand -hex "$1"; }
cat > "$E2E_ENV_FILE" <<ENV
POSTGRES_PASSWORD=$(hex 24)
REDIS_PASSWORD=$(hex 24)
UAG_AUDIT_HMAC_KEY=$(hex 32)
JJD_PROVIDER_SECRET_KEY=$(hex 32)
JJD_INTERNAL_API_SECRET=$(hex 24)
JJD_SEMANTIC_GATEWAY_ATTESTATION_KEY=$(hex 24)
JJD_RULE_PACK_ATTESTATION_TOKEN=$(hex 24)
BOOTSTRAP_ADMIN_PASSWORD=Delbtn#E2e-20261109
WT=$WT
E2E_CP_PORT=$E2E_CP_PORT
E2E_GW_PORT=$E2E_GW_PORT
E2E_WEB_PORT=$E2E_WEB_PORT
E2E_ENGINE_IMAGE=$E2E_ENGINE_IMAGE
ENV
chmod 600 "$E2E_ENV_FILE"
cp "$HERE/compose.yml" "$HERE/mock_upstream.py" "$WORK/"

wait_healthy() { # service seconds
  local cid st i
  for i in $(seq 1 "$2"); do
    cid="$(compose ps -q "$1" 2>/dev/null || true)"
    st="$([ -n "$cid" ] && docker inspect -f '{{.State.Health.Status}}' "$cid" 2>/dev/null || true)"
    [ "$st" = healthy ] && return 0
    sleep 2
  done
  compose logs --tail 30 "$1" >&2 || true
  die "$1 没有变健康"
}

echo "== 数据库与全量迁移"
compose up -d postgres redis upstream >/dev/null
wait_healthy postgres 120
docker exec -e PGHOST=127.0.0.1 -e PGUSER=jjdguard -e "PGPASSWORD=$(grep '^POSTGRES_PASSWORD=' "$E2E_ENV_FILE" | cut -d= -f2-)" \
  -e PGDATABASE=jjdguard -e MIGRATION_PSQL=/usr/bin/psql "$E2E_PROJECT-postgres-1" \
  /bin/bash /mlib/migration-runner.sh --migrations-dir /migrations >"$WORK/migrate.log" 2>&1 || { tail -20 "$WORK/migrate.log" >&2; die "迁移失败"; }

echo "== 起 control-plane / security-engine / gateway-core / web-console"
compose up -d >/dev/null
wait_healthy control-plane 90
wait_healthy security-engine 90
wait_healthy gateway-core 90

cd "$HERE"
echo "== 造账号、供应商、模型、密钥"
python3 -I setup_accounts.py

echo "== 后端端到端（真实网关 + 真实引擎）"
python3 -I test_policy_delete_api.py

if [ "${E2E_BROWSER:-0}" = 1 ]; then
  echo "== 真实浏览器端到端"
  cd "$HERE/browser"
  [ -d node_modules/playwright-core ] || npm install --no-audit --no-fund >/dev/null
  E2E_ADMIN_PASSWORD="$(grep '^ADMIN_PASSWORD=' "$E2E_ENV_FILE" | cut -d= -f2-)" node delete-policy.mjs
  echo "== 控制台残留数据流程（用户/应用/密钥/部门的删除、禁用、编辑、跳转）"
  E2E_ADMIN_PASSWORD="$(grep '^ADMIN_PASSWORD=' "$E2E_ENV_FILE" | cut -d= -f2-)" node residual-data-flows.mjs
else
  echo "（跳过浏览器步骤：E2E_BROWSER=1 并提供 Chrome（E2E_CHROME）即可；也可以把 $E2E_WEB_PORT 端口转发到别的机器上跑 browser/delete-policy.mjs，见 README）"
fi
echo "[policy-delete-e2e] 全部通过"
