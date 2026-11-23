#!/bin/bash
# D7：用真实 nginx 容器验证 nginx.conf 的旧书签重定向行为（需要 docker；与 server.js 的 legacyMcpConsoleRedirect 对照）。
# 用法：bash apps/web-console/nginx-legacy-redirect.e2e.sh    任一项 FAIL 则退出码非 0。
# 用真实 nginx 验证旧书签规则：把 nginx.conf 里的 upstream 主机名指向一个返回 "gateway" 的小后端。
set -u
# 临时容器：打测试标签、先回收被杀掉的测试进程留下的孤儿容器，清理用 docker rm -f -v（见该库说明）。
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/../../deploy/tests/lib/test-containers.sh"
jjd_test_reap_orphan_containers
jjd_test_container_labels nginx-legacy-redirect-e2e
W=$(cd "$(dirname "$0")" && pwd)
T=$(mktemp -d); trap 'docker rm -f -v ngx-d7 ngx-d7-up >/dev/null 2>&1; docker network rm ngx-d7-net >/dev/null 2>&1; rm -rf $T' EXIT
docker network create ngx-d7-net >/dev/null 2>&1
mkdir -p $T/html; echo "console shell" > $T/html/index.html
cat > $T/up.conf <<'CONF'
events {}
http { server { listen 8080; location / { default_type text/plain; return 200 "gateway"; } } }
CONF
docker run "${JJD_TEST_CONTAINER_LABELS[@]}" -d --name ngx-d7-up --network ngx-d7-net --network-alias gateway-core --network-alias control-plane -v $T/up.conf:/etc/nginx/nginx.conf:ro nginx:alpine >/dev/null 2>&1
docker run "${JJD_TEST_CONTAINER_LABELS[@]}" -d --name ngx-d7 --network ngx-d7-net -p 127.0.0.1:0:80 -v $W/nginx.conf:/etc/nginx/nginx.conf:ro -v $T/html:/usr/share/nginx/html:ro nginx:alpine >/dev/null 2>&1
sleep 2
command -v docker >/dev/null || { echo "SKIP: 需要 docker"; exit 0; }
docker exec ngx-d7 nginx -t 2>&1 | tail -1
P=$(docker port ngx-d7 80/tcp | head -1 | sed 's/.*://')
req() { curl -s -o /dev/null -w "%{http_code} %{redirect_url}" "$@"; }
H='Accept: text/html,application/xhtml+xml'
FAILED=0
check() { local name=$1 want=$2; shift 2; local got; got=$(req "$@" | sed -E "s#http://127.0.0.1(:[0-9]+)?##"); if [ "$got" == "$want" ]; then echo "OK   $name => $got"; else echo "FAIL $name => got [$got] want [$want]"; FAILED=1; fi; }
check "servers+html"        "302 /mcp-gateway/servers"                         -H "$H" http://127.0.0.1:$P/mcp/servers
check "audit+query+html"    "302 /mcp-gateway/audit?request_id=r1"             -H "$H" "http://127.0.0.1:$P/mcp/audit?request_id=r1"
check "overview+html"       "302 /mcp-gateway/audit"                           -H "$H" http://127.0.0.1:$P/mcp/overview
check "overview+query+html" "302 /mcp-gateway/audit"                           -H "$H" "http://127.0.0.1:$P/mcp/overview?x=1"
check "HEAD+html"           "302 /mcp-gateway/policies"                        -I -H "$H" http://127.0.0.1:$P/mcp/policies
check "POST不重定向"         "200 "                                              -X POST -H "$H" http://127.0.0.1:$P/mcp/servers
check "PUT不重定向"          "200 "                                              -X PUT -H "$H" http://127.0.0.1:$P/mcp/approvals
check "DELETE不重定向"       "200 "                                              -X DELETE -H "$H" http://127.0.0.1:$P/mcp/audit
check "sse不重定向"          "200 "                                              -H "Accept: text/event-stream" http://127.0.0.1:$P/mcp/servers
check "数据面serverID转发"   "200 "                                              -H "$H" http://127.0.0.1:$P/mcp/mcp_srv1
check "新页面回落SPA"        "200 "                                              -H "$H" http://127.0.0.1:$P/mcp-gateway/servers

if [ "${FAILED:-0}" != "0" ]; then exit 1; fi
