#!/usr/bin/env bash
set -Eeuo pipefail

# 双层代理（客户 PC -> 本正向代理 -> 客户出网代理 -> 互联网）的静态合约。
#
# 这个功能的危险之处不在于它会不会工作，而在于它「悄悄不工作」的两种方式：
#   1. 为了让内网的出网代理拨得通，把 SSRF 防线普遍放开——正向代理是攻击面
#      最大的组件，客户任意一台 PC 都能借它拨内网任意地址；
#   2. 上层代理不可用时静默退回直连——客户以为流量经他的出网代理，实际直连
#      出网，属于合规事故。
# 所以这两条必须常驻，不能被后续重构摘掉。

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
GUARD="$ROOT_DIR/apps/proxy-server/internal/handler/egress_guard.go"
UPSTREAM="$ROOT_DIR/apps/proxy-server/internal/handler/upstream_proxy.go"
PROXY="$ROOT_DIR/apps/proxy-server/internal/handler/proxy.go"
MAIN="$ROOT_DIR/apps/proxy-server/cmd/server/main.go"
ENV_EXAMPLE="$ROOT_DIR/deploy/docker-compose/.env.example"
COMPOSE_FILES=(
  "$ROOT_DIR/deploy/docker-compose/docker-compose.yml"
  "$ROOT_DIR/deploy/docker-compose/docker-compose.offline.yml"
)

fail() {
  echo "[fail] $*" >&2
  exit 1
}

has() {
  local file="$1" pattern="$2" why="$3"
  grep -Eq -- "$pattern" "$file" || fail "$(basename "$file") 缺少合约（$why）：$pattern"
}

for required in "$GUARD" "$UPSTREAM" "$PROXY" "$MAIN" "$ENV_EXAMPLE"; do
  [ -f "$required" ] || fail "缺少文件：$required"
done

# --- 合约 1：默认关闭，SSRF 防线不因这个功能松动 ---
has "$UPSTREAM" 'func ParseUpstreamProxy' '配置解析入口'
# 空值必须表示「不启用」而不是报错，否则默认部署起不来
grep -q 'return nil, nil' "$UPSTREAM" ||
  fail 'upstream_proxy.go 必须把空配置视为不启用（return nil, nil）'
# 豁免必须精确到 host:port，不能按网段放开
has "$UPSTREAM" 'func \(g \*EgressGuard\) upstreamProxyExemptAddress' '精确豁免判定'
has "$UPSTREAM" 'proxyPort != port' '豁免必须比对端口'
# 云元数据地址永不豁免
has "$UPSTREAM" 'isMetadataServiceIP' '云元数据地址永不豁免'
grep -q 'isBlockedMetadataHostname' "$UPSTREAM" ||
  fail 'upstream_proxy.go 必须拒绝把云元数据主机名当上层代理'
# 阻断判定仍在，只是多了一个精确豁免条件。2.9.22 起内网、回环、元数据是否放行读控制台出站设置
# （checkEgressIP，默认仍拒绝），上层代理的精确豁免照旧只多一个条件。
has "$GUARD" 'checkEgressIP\(settings, ip\)' '内网阻断按出站设置判定（默认拒绝）'
has "$GUARD" '!allowed && !exempt' '内网阻断保留，仅精确豁免例外'

# --- 合约 2：不静默退回直连 ---
has "$UPSTREAM" 'func \(g \*EgressGuard\) DialTunnelContext' 'CONNECT 隧道入口'
has "$UPSTREAM" 'CONNECT ' '必须真的发 CONNECT'
grep -q '上层出网代理拒绝建立隧道' "$UPSTREAM" ||
  fail 'DialTunnelContext 必须在代理拒绝时报错，不能静默直连'
# CONNECT 请求行由地址拼出，控制字符必须先挡（请求走私）
has "$UPSTREAM" 'ContainsAny\(address' 'CONNECT 目标需拒控制字符'
# 启动期配置非法必须 fail-closed
has "$MAIN" 'log\.Fatalf\("UPSTREAM_EGRESS_PROXY' '配置非法必须启动失败'

# --- 合约 3：两条裸 TCP 路径都得走隧道 ---
# tunnelDirect 与 MITM 手拨 TLS 兜底都不经 http.Transport，
# 只拨 TCP 不发 CONNECT 会让客户端 ClientHello 灌给代理、连上即挂死。
has "$PROXY" 'DialTunnelContext\(r\.Context\(\)' 'CONNECT 直通路径走隧道'
has "$PROXY" 'DialTLSThroughTunnel' 'MITM 手拨 TLS 兜底走隧道'
# keep-alive transport 是懒初始化的，Proxy 必须请求时现查而非初始化时快照
grep -q 'tr.Proxy = func(req \*http.Request)' "$PROXY" ||
  fail 'keep-alive transport 的 Proxy 必须每次请求现查，否则后设置的上层代理永不生效'

# --- 合约 4：只挂在正向代理服务上，并且有文档 ---
for compose in "${COMPOSE_FILES[@]}"; do
  grep -qF 'UPSTREAM_EGRESS_PROXY=${UPSTREAM_EGRESS_PROXY:-}' "$compose" ||
    fail "$(basename "$compose") 未透传 UPSTREAM_EGRESS_PROXY"
  # 不能挂到不读它的服务上：那会让运维以为配了就生效
  python3 - "$compose" <<'PY' || exit 1
import re
import sys

path = sys.argv[1]
service = None
wrong = []
for line in open(path, encoding="utf-8"):
    match = re.match(r"^  ([a-z0-9-]+):\s*$", line)
    if match:
        service = match.group(1)
    if "UPSTREAM_EGRESS_PROXY=" in line and service not in ("proxy-server", "proxy-server-vm"):
        wrong.append(service)
if wrong:
    print(f"[fail] {path}: UPSTREAM_EGRESS_PROXY 挂在不读它的服务上：{wrong}", file=sys.stderr)
    raise SystemExit(1)
PY
done
has "$ENV_EXAMPLE" 'UPSTREAM_EGRESS_PROXY=' '配置样例需文档化'
grep -q '云元数据地址' "$ENV_EXAMPLE" ||
  fail '.env.example 必须写明云元数据地址永不豁免的边界'

echo '[ok] 双层代理（上层出网代理）合约通过'
