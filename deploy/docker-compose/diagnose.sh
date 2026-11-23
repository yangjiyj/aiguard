#!/bin/sh
# diagnose.sh — 智能体安全网关 离线部署现场排障采集脚本
#
# 适用场景：离线包已部署到客户内网机器，但"端口能 telnet 通、浏览器却打不开控制台"。
#   telnet 通只代表 TCP 端口在监听，网页打不开多半发生在更上层（TLS 握手 / HTTP 跳转 /
#   监听地址只在本机 / 容器不健康），本脚本一键采集这些层面的证据并打包回传。
#
# 设计要点：
#   - 纯离线、只读：不联网、不修改部署、不重启任何服务。
#   - 不依赖宿主机额外工具：宿主机若无 curl/openssl，自动改用随包镜像内的
#     openssl/wget 探测（docker run --network host 容器回退）。
#   - 脱敏：输出中的口令/密钥/Token/证书私钥一律打码；绝不采集 TLS 私钥(.key)。
#
# 用法：
#   sh diagnose.sh                 # 在离线包根目录直接运行（推荐）
#   sh deploy/docker-compose/diagnose.sh
#
set -u

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname "$0")" && pwd)"
DC_DIR="$SCRIPT_DIR"
cd "$DC_DIR"

COMPOSE_WRAPPER="$DC_DIR/compose-wrapper.sh"
COMPOSE_FILE="docker-compose.offline.yml"

RUN_ID="$(date +%Y%m%d-%H%M%S 2>/dev/null || echo run)"
OUT_DIR="$DC_DIR/diagnostics/$RUN_ID"
SUMMARY="$OUT_DIR/summary.txt"
ARCHIVE="$DC_DIR/jjdguard-diagnostics-${RUN_ID}.tar.gz"
mkdir -p "$OUT_DIR"

# 可用的 timeout 命令（避免在死端口上卡死），没有就空着
TIMEOUT=""
if command -v timeout >/dev/null 2>&1; then TIMEOUT="timeout"; fi

# 读取部署配置里的端口（缺省回退到默认值）
# 读 .env 不能用 source：未加引号且含空格的值（如 REDIS_EXTRA_ARGS=--a yes）会被当成命令执行，
# 值里的 $(...) / 反引号 / 分号也会被执行。统一经共享库按字面解析，见 deploy/lib/jjd-env.sh。
# diagnose.sh 是最后的排障手段：共享库缺失时降级为按默认端口探测，而不是退出，更不回退到 source。
JJD_ENV_LIB="$DC_DIR/../lib/jjd-env.sh"
if [ -f "$DC_DIR/.env" ]; then
  if [ -f "$JJD_ENV_LIB" ]; then
    # shellcheck source=../lib/jjd-env.sh
    . "$JJD_ENV_LIB"
    jjd_load_env_file "$DC_DIR/.env" || true
  else
    echo "[warn] 缺少安全读取 .env 的库 $JJD_ENV_LIB，已跳过 .env，端口按默认值探测" >&2
  fi
fi
WEB_PORT="${WEB_PORT:-3000}"
WEB_HTTPS_PORT="${WEB_HTTPS_PORT:-443}"
GATEWAY_PORT="${GATEWAY_PORT:-8080}"
CONTROL_PORT="${CONTROL_PORT:-8081}"
SECURITY_PORT="${SECURITY_PORT:-8000}"
PROXY_PORT="${PROXY_PORT:-8082}"
FORWARD_PROXY_PORT="${FORWARD_PROXY_PORT:-3128}"

# ---------------------------------------------------------------------------
# 脱敏：用 awk（busybox/gawk/mawk 通用），避免依赖 sed -E 的可移植性问题。
#   - scheme://user:pass@host  →  scheme://<redacted>@host
#   - Authorization/Cookie/Set-Cookie 等敏感请求头的值打码
#   - Bearer/Basic <token> 打码
#   - KEY=VALUE 形式中 key 含 PASSWORD/SECRET/TOKEN/KEY/HMAC 等的值打码
#   - PEM 私钥块整段丢弃（仅作兜底，正常不会出现）
# ---------------------------------------------------------------------------
sanitize_sensitive() {
  awk '
    BEGIN {
      private_key_phrase="PRIVATE" " KEY"
      begin_marker="-----BEGIN " private_key_phrase "-----"
      end_marker="-----END " private_key_phrase "-----"
    }
    $0 ~ ("-----BEGIN [A-Z ]*" private_key_phrase "-----") { print begin_marker" <redacted>"; inkey=1; next }
    inkey && $0 ~ ("-----END [A-Z ]*" private_key_phrase "-----") { print end_marker; inkey=0; next }
    inkey { next }
    {
      line=$0
      gsub(/\/\/[^/@ \t]+:[^@ \t]*@/, "//<redacted>@", line)
      low=tolower(line)
      if (low ~ /^[ \t]*(authorization|proxy-authorization|cookie|set-cookie|x-api-key|x-auth-token|x-csrf-token)[ \t]*:/) {
        sub(/:.*/, ": <redacted>", line)
      }
      gsub(/[Bb][Ee][Aa][Rr][Ee][Rr][ \t]+[A-Za-z0-9._~+\/=-]+/, "Bearer <redacted>", line)
      gsub(/[Bb][Aa][Ss][Ii][Cc][ \t]+[A-Za-z0-9._~+\/=-]+/, "Basic <redacted>", line)
      if (line ~ /^[ \t]*[A-Za-z_][A-Za-z0-9_]*[ \t]*=/) {
        eq=index(line,"=")
        key=substr(line,1,eq-1)
        ukey=toupper(key)
        if (ukey ~ /(PASSWORD|PASSWD|SECRET|TOKEN|APIKEY|API_KEY|AUTHKEY|_KEY|KEY$|PRIVATE|CREDENTIAL|LICENSE|HMAC|SALT|PASS)/) {
          line=key"=<redacted>"
        }
      }
      print line
    }
  '
}

# .env / .deploy-result 这类 KEY=VALUE 文件：保留非敏感键（端口、URL 等可见），
# 仅对敏感键打码并标注长度，便于核对"是否生成了"。
mask_env() {
  awk -F= '
    /^[ \t]*#/ { print; next }
    /^[ \t]*$/ { print; next }
    NF<2 { print; next }
    {
      key=$1
      val=substr($0, index($0,"=")+1)
      ukey=toupper(key)
      if (ukey ~ /(PASSWORD|PASSWD|SECRET|TOKEN|APIKEY|API_KEY|AUTHKEY|_KEY|KEY$|PRIVATE|CREDENTIAL|LICENSE|HMAC|SALT|PASS)/)
        printf "%s=<redacted len=%d>\n", key, length(val)
      else
        print
    }
  ' "$1" 2>/dev/null
}

# ---------------------------------------------------------------------------
# 输出助手：section 打标题（终端 + summary），capture 收集一段内容到独立文件，
# 并把前若干行汇总进 summary.txt。
# ---------------------------------------------------------------------------
section() {
  printf '\n===== %s =====\n' "$1"
  printf '\n===== %s =====\n' "$1" >>"$SUMMARY"
}

capture() {
  name="$1"
  f="$OUT_DIR/$name.txt"
  sanitize_sensitive >"$f"
  head -n 200 "$f" >>"$SUMMARY" 2>/dev/null
  lines="$(wc -l <"$f" 2>/dev/null || echo 0)"
  if [ "${lines:-0}" -gt 200 ]; then
    printf '... （完整内容见 %s.txt，共 %s 行）\n' "$name" "$lines" >>"$SUMMARY"
  fi
}

compose() {
  if [ -x "$COMPOSE_WRAPPER" ] || [ -f "$COMPOSE_WRAPPER" ]; then
    sh "$COMPOSE_WRAPPER" -f "$COMPOSE_FILE" "$@" 2>&1
  else
    echo "[skip] 未找到 compose-wrapper.sh"
  fi
}

# 探测随包镜像里哪个带 openssl（与 ensure-web-tls.sh 同源），结果缓存。
_OPENSSL_IMAGE_CACHE=""
detect_openssl_image() {
  if [ -n "$_OPENSSL_IMAGE_CACHE" ]; then printf '%s' "$_OPENSSL_IMAGE_CACHE"; return 0; fi
  imgs="docker-compose-security-engine:latest docker-compose-control-plane:latest docker-compose-gateway-core:latest docker-compose-proxy-server:latest docker-compose-web-console:latest postgres:16-alpine valkey/valkey:8.1.10-alpine"
  for img in $imgs; do
    if docker image inspect "$img" >/dev/null 2>&1 \
       && docker run --rm --entrypoint sh "$img" -c 'command -v openssl >/dev/null 2>&1' >/dev/null 2>&1; then
      _OPENSSL_IMAGE_CACHE="$img"; printf '%s' "$img"; return 0
    fi
  done
  return 1
}

# 运行一段使用 openssl 的 sh 命令：优先宿主机 openssl，缺失则进随包镜像
# （--network host 让容器内 127.0.0.1 = 宿主机回环，从而能连到对外发布的端口）。
openssl_sh() {
  cmd="$1"
  if command -v openssl >/dev/null 2>&1; then
    if [ -n "$TIMEOUT" ]; then $TIMEOUT 12 sh -c "$cmd"; else sh -c "$cmd"; fi
  else
    img="$(detect_openssl_image)" || true
    if [ -n "${img:-}" ]; then
      echo "[info] 宿主机无 openssl，改用随包镜像 $img 探测"
      if [ -n "$TIMEOUT" ]; then
        $TIMEOUT 35 docker run --rm --network host --entrypoint sh "$img" -c "$cmd"
      else
        docker run --rm --network host --entrypoint sh "$img" -c "$cmd"
      fi
    else
      echo "[skip] 宿主机与随包镜像均无 openssl，跳过该 TLS 探测"
      return 1
    fi
  fi
}

# 明文 HTTP 探测（尽力而为）：宿主机 curl → 宿主机 wget → 随包镜像 wget。
http_get_plain() {
  url="$1"
  if command -v curl >/dev/null 2>&1; then
    echo "[via] host curl"
    if [ -n "$TIMEOUT" ]; then $TIMEOUT 12 curl -k -sS -i --max-time 10 "$url" 2>&1; else curl -k -sS -i --max-time 10 "$url" 2>&1; fi
  elif command -v wget >/dev/null 2>&1; then
    echo "[via] host wget"
    if [ -n "$TIMEOUT" ]; then $TIMEOUT 12 wget -S -T 10 -qO- "$url" 2>&1; else wget -S -T 10 -qO- "$url" 2>&1; fi
  else
    img="docker-compose-web-console:latest"
    if docker image inspect "$img" >/dev/null 2>&1; then
      echo "[via] container wget ($img, --network host)"
      if [ -n "$TIMEOUT" ]; then
        $TIMEOUT 35 docker run --rm --network host --entrypoint sh "$img" -c "wget --no-check-certificate -S -T 10 -qO- '$url' 2>&1" 2>&1
      else
        docker run --rm --network host --entrypoint sh "$img" -c "wget --no-check-certificate -S -T 10 -qO- '$url' 2>&1" 2>&1
      fi
    else
      echo "[skip] 宿主机无 curl/wget 且无可用镜像，跳过 HTTP 探测：$url"
    fi
  fi
}

echo "================================================================"
echo " 智能体安全网关 · 现场排障采集"
echo " 采集目录：$OUT_DIR"
echo "================================================================"
{
  echo "智能体安全网关现场排障报告"
  echo "采集时间(RUN_ID)：$RUN_ID"
  echo "部署目录：$DC_DIR"
} >>"$SUMMARY"

# 1) 基本环境
section "1. 主机与环境"
{
  echo "# uname -a"; uname -a 2>&1
  echo; echo "# 当前用户 / id"; id 2>&1
  echo; echo "# 磁盘"; df -h 2>&1
  echo; echo "# 内存"; free -h 2>&1 || cat /proc/meminfo 2>&1 | head -n 5
} | capture host-env

# 2) 本机网络地址（提醒客户用对的 IP 访问）
section "2. 本机网络地址（浏览器应使用其中可达的 IP）"
{
  echo "# ip -br addr / ifconfig"; (ip -br addr 2>/dev/null || ifconfig 2>/dev/null || echo "无 ip/ifconfig")
  echo; echo "# hostname"; hostname 2>&1; hostname -I 2>/dev/null || true
} | capture host-ip

# 3) 部署结果（真实访问地址与端口 —— 排障第一现场）
section "3. 部署结果 .deploy-result（真实访问地址，已脱敏）"
if [ -f "$DC_DIR/.deploy-result" ]; then
  mask_env "$DC_DIR/.deploy-result" | capture deploy-result
else
  echo "[warn] 未找到 .deploy-result —— 可能尚未成功安装，或 .env 被删。" | capture deploy-result
fi

section "4. 关键端口（来自 .env，已据此进行探测）"
{
  echo "WEB_HTTPS_PORT (控制台 HTTPS) = $WEB_HTTPS_PORT"
  echo "WEB_PORT       (控制台 HTTP)  = $WEB_PORT"
  echo "GATEWAY_PORT   (网关)         = $GATEWAY_PORT"
  echo "CONTROL_PORT   (控制面/本机)  = $CONTROL_PORT"
  echo "SECURITY_PORT  (检测引擎/本机)= $SECURITY_PORT"
  echo "PROXY_PORT     (反向代理)     = $PROXY_PORT"
  echo "FORWARD_PROXY_PORT (正向代理) = $FORWARD_PROXY_PORT"
} | capture ports-config

# 5) .env 脱敏（确认密钥/证书是否生成）
section "5. .env（已脱敏，敏感值仅显示长度）"
if [ -f "$DC_DIR/.env" ]; then
  mask_env "$DC_DIR/.env" | capture env-masked
else
  echo "[warn] 未找到 .env" | capture env-masked
fi

# 6) Docker 与镜像
section "6. Docker 引擎与镜像"
{
  echo "# docker version"; docker version 2>&1
  echo; echo "# docker info (节选)"; docker info 2>&1 | sed -n '1,40p'
  echo; echo "# docker images（本产品相关）"; docker images 2>&1 | grep -E "REPOSITORY|docker-compose-|postgres|redis|valkey" || docker images 2>&1
} | capture docker-env

# 7) 容器状态（web-console 必须 Up 且 healthy）
section "7. 容器状态 compose ps"
compose ps -a | capture compose-ps
{
  echo "# docker ps -a（全量，含健康状态）"
  docker ps -a 2>&1
} | capture docker-ps

# 8) 监听端口（重点看绑定地址 0.0.0.0 vs 127.0.0.1）
section "8. 监听端口（关注是否 0.0.0.0/* 对外监听）"
{
  if command -v ss >/dev/null 2>&1; then
    echo "# ss -ltnp"; ss -ltnp 2>&1
  elif command -v netstat >/dev/null 2>&1; then
    echo "# netstat -ltnp"; netstat -ltnp 2>&1
  else
    echo "[skip] 无 ss/netstat；改看 docker 端口映射："
    docker ps --format '{{.Names}}  {{.Ports}}' 2>&1
  fi
} | capture listen-ports

# 9) 防火墙
section "9. 防火墙状态（远程访问被挡的常见原因）"
{
  echo "# ufw"; (ufw status verbose 2>&1 || echo "无 ufw / 需要权限")
  echo; echo "# firewalld"; (firewall-cmd --list-all 2>&1 || echo "无 firewalld / 需要权限")
  echo; echo "# iptables -S（需要 root，可能为空）"; (iptables -S 2>&1 || echo "无权限/无 iptables")
} | capture firewall

# 10) 控制台 HTTPS —— TLS 握手与对外提供的证书
section "10. 控制台 HTTPS:$WEB_HTTPS_PORT —— TLS 握手与证书"
{
  echo "# 握手摘要（CONNECTED / 协议 / Verify / 证书主题）"
  openssl_sh "echo Q | openssl s_client -connect 127.0.0.1:$WEB_HTTPS_PORT 2>&1 | grep -E 'CONNECTED|Protocol|Cipher|Verify return code|subject=|issuer=|no peer certificate|errno|refused|handshake'"
  echo
  echo "# 对外提供的证书内容（subject/issuer/有效期/SAN）"
  openssl_sh "echo Q | openssl s_client -connect 127.0.0.1:$WEB_HTTPS_PORT 2>/dev/null | openssl x509 -noout -subject -issuer -dates -ext subjectAltName 2>/dev/null"
} | capture tls-handshake

# 11) 控制台 HTTPS —— HTTP 层应答（用 openssl 直接发 GET，无需 curl）
section "11. 控制台 HTTPS:$WEB_HTTPS_PORT —— HTTP 应答（应为 200/302）"
{
  echo "# GET /"
  openssl_sh "printf 'GET / HTTP/1.0\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n' | openssl s_client -connect 127.0.0.1:$WEB_HTTPS_PORT -quiet 2>/dev/null | sed -n '1,40p'"
  echo
  echo "# GET /health"
  openssl_sh "printf 'GET /health HTTP/1.0\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n' | openssl s_client -connect 127.0.0.1:$WEB_HTTPS_PORT -quiet 2>/dev/null | sed -n '1,20p'"
} | capture https-http-layer

# 12) 控制台 HTTP（明文端口的跳转行为）
section "12. 控制台 HTTP:$WEB_PORT —— 跳转/应答"
http_get_plain "http://127.0.0.1:$WEB_PORT/" | capture http-redirect

# 13) 证书文件检查（只读 .crt；绝不读取 .key）
section "13. 证书文件 tls/web-console.crt（不采集私钥）"
{
  if [ -d "$DC_DIR/tls" ]; then
    echo "# tls 目录（仅元数据；不读取 .key 内容）"
    ls -l "$DC_DIR/tls" 2>&1
    echo
    crt="$DC_DIR/tls/web-console.crt"
    if [ -f "$crt" ]; then
      echo "# web-console.crt 大小：$(wc -c <"$crt" 2>/dev/null) 字节"
      if command -v openssl >/dev/null 2>&1; then
        openssl x509 -in "$crt" -noout -subject -issuer -dates -ext subjectAltName 2>&1
      else
        img="$(detect_openssl_image)" || true
        if [ -n "${img:-}" ]; then
          docker run --rm -v "$DC_DIR/tls:/tls:ro" --entrypoint sh "$img" -c 'openssl x509 -in /tls/web-console.crt -noout -subject -issuer -dates -ext subjectAltName 2>&1'
        else
          echo "[skip] 无 openssl，跳过证书文件解析（文件存在即说明已生成）"
        fi
      fi
    else
      echo "[warn] 未找到 tls/web-console.crt —— 证书可能未生成，web-console 将无法提供 HTTPS。"
    fi
  else
    echo "[warn] 未找到 tls 目录 —— 证书可能从未生成。"
  fi
} | capture tls-cert-file

# 14) 后端服务健康（次要，尽力而为）
section "14. 后端服务健康探测"
{
  echo "# 网关 gateway-core :$GATEWAY_PORT/health"
  http_get_plain "http://127.0.0.1:$GATEWAY_PORT/health"
  echo; echo "# 控制面 control-plane :$CONTROL_PORT/health（通常只监听 127.0.0.1）"
  http_get_plain "http://127.0.0.1:$CONTROL_PORT/health"
  echo; echo "# 检测引擎 security-engine :$SECURITY_PORT/health（通常只监听 127.0.0.1）"
  http_get_plain "http://127.0.0.1:$SECURITY_PORT/health"
} | capture backend-health

# 15) 各服务日志（web-console 最关键：找 cert/tls/port/bind 报错）
section "15. 容器日志（已脱敏，各取尾部）"
for svc in web-console gateway-core control-plane security-engine proxy-server postgres redis redis-cache; do
  echo "---- logs: $svc ----"
  compose logs --no-color --tail 200 "$svc" 2>&1 | sanitize_sensitive >"$OUT_DIR/logs-$svc.txt"
  tail -n 60 "$OUT_DIR/logs-$svc.txt" >>"$SUMMARY" 2>/dev/null
  echo "（$svc 日志完整见 logs-$svc.txt）" >>"$SUMMARY"
done
echo "已采集各服务日志到 logs-<服务>.txt"

# 16) Upgrade and backfill state. Queries expose metadata only, never customer
# request or response bodies.
section "16. 升级、迁移锁与后台回填状态（只读）"
{
  echo "# active migration PostgreSQL sessions"
  compose exec -T postgres psql -X -U "${POSTGRES_USER:-jjdguard}" -d "${POSTGRES_DB:-jjdguard}" -P pager=off -c "
SELECT a.pid,a.application_name,a.state,a.wait_event_type,a.wait_event,
       age(clock_timestamp(),a.xact_start) AS transaction_age,
       pg_blocking_pids(a.pid) AS blocking_pids
FROM pg_stat_activity a
WHERE a.datname=current_database()
  AND (a.application_name LIKE 'jjdguard-migration:%' OR cardinality(pg_blocking_pids(a.pid))>0)
ORDER BY a.query_start;"
  echo
  echo "# durable migration execution state"
  compose exec -T postgres psql -X -U "${POSTGRES_USER:-jjdguard}" -d "${POSTGRES_DB:-jjdguard}" -P pager=off -c "
SELECT version,status,backend_pid,wait_event_type,wait_event,started_at,
       heartbeat_at,finished_at,elapsed_seconds,error_summary
FROM migration_execution_status ORDER BY updated_at DESC LIMIT 50;"
  echo
  echo "# resumable background backfills"
  compose exec -T postgres psql -X -U "${POSTGRES_USER:-jjdguard}" -d "${POSTGRES_DB:-jjdguard}" -P pager=off -c "
SELECT task_name,task_version,state,validation_status,scanned,updated,skipped,failed,
       round(current_rate::numeric,1) AS rows_per_second,eta_seconds,
       heartbeat_at,lease_owner,lease_expires_at,error_summary
FROM migration_backfill_tasks ORDER BY priority,task_name,task_version;"
  echo
  echo "# estimated large tables (no COUNT(*))"
  compose exec -T postgres psql -X -U "${POSTGRES_USER:-jjdguard}" -d "${POSTGRES_DB:-jjdguard}" -P pager=off -c "
SELECT c.relname,COALESCE(c.reltuples,0)::bigint AS estimated_rows,
       pg_size_pretty(pg_total_relation_size(c.oid)) AS total_size
FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
WHERE n.nspname='public' AND c.relkind IN ('r','m')
ORDER BY pg_total_relation_size(c.oid) DESC LIMIT 20;"
} | capture upgrade-state

section "17. 存储位置、inode 与 WAL 风险"
{
  echo "# filesystem bytes and inodes"; df -h 2>&1; df -ih 2>&1
  echo; echo "# Docker data root"; docker info --format '{{.DockerRootDir}}' 2>&1
  echo; echo "# PostgreSQL database and WAL location sizes"
  compose exec -T postgres psql -X -U "${POSTGRES_USER:-jjdguard}" -d "${POSTGRES_DB:-jjdguard}" -P pager=off -c "
SELECT pg_size_pretty(pg_database_size(current_database())) AS database_size,
       pg_size_pretty(COALESCE((SELECT sum(size) FROM pg_ls_waldir()),0)) AS wal_directory_size;"
} | capture upgrade-storage

# 18) 阅读指引（telnet 通但网页打不开，按此顺序判读）
GUIDE="$OUT_DIR/00-怎么读这份报告.txt"
{
  echo "================================================================"
  echo " 怎么读这份报告：telnet 能通、但网页打不开，按顺序排查"
  echo "================================================================"
  echo
  echo "telnet 通 = TCP 端口在监听而已；网页打不开通常发生在更上层，按下列顺序看："
  echo
  echo "① 访问地址对不对（看第 3 段 .deploy-result）"
  echo "   浏览器必须用 WEB_URLS 里的 HTTPS 地址 https://<IP>:$WEB_HTTPS_PORT 。"
  echo "   端口可能因避让不是默认 443/3000；用错端口或用 HTTP 地址都打不开。"
  echo
  echo "② 监听地址（看第 8 段）"
  echo "   控制台端口应是 0.0.0.0:$WEB_HTTPS_PORT 或 *:$WEB_HTTPS_PORT（对所有网卡开放）。"
  echo "   若显示 127.0.0.1:$WEB_HTTPS_PORT，则只在本机监听 —— 本机 telnet 能通，"
  echo "   但其它机器的浏览器一定打不开。需检查端口映射/绑定地址(WEB_HTTPS_BIND)。"
  echo
  echo "③ 容器是否健康（看第 7 段 compose ps）"
  echo "   web-console 必须 Up 且 healthy。若 Restarting/Exited，去看第 15 段"
  echo "   web-console 日志里的报错（常见为证书/端口/绑定问题）。"
  echo
  echo "④ 证书 / TLS（看第 10、13 段）"
  echo "   - 自签证书 → 浏览器首次访问必然弹「不安全/证书风险」告警，这是正常的，"
  echo "     点「继续前往」即可；或把 tls/web-console.crt 导入受信任根。"
  echo "     很多「打不开」其实是卡在这个告警没点继续。"
  echo "   - 若第 10 段握手失败/无证书、或第 13 段证书文件缺失 → web-console 没能"
  echo "     加载证书，去第 15 段 web-console 日志找 cert/tls 报错。"
  echo
  echo "⑤ HTTP 跳转（看第 11、12 段）"
  echo "   HTTPS 正常应返回 200/302；若明文 HTTP 端口 301/302 跳到一个浏览器"
  echo "   到不了的地址，也会表现为「打不开」。"
  echo
  echo "⑥ 防火墙（看第 9 段）"
  echo "   若①~⑤都正常但远程仍打不开，检查 ufw/firewalld 是否放行 $WEB_HTTPS_PORT。"
  echo
  echo "把整个 $(basename "$ARCHIVE") 回传给实施/研发即可。"
} >"$GUIDE"
cat "$GUIDE"
{
  echo
  cat "$GUIDE"
} >>"$SUMMARY"

# 19) 打包
( cd "$DC_DIR/diagnostics" && tar -czf "$ARCHIVE" "$RUN_ID" ) 2>/dev/null
echo
echo "================================================================"
if [ -f "$ARCHIVE" ]; then
  echo "[ok] 采集完成，请把下面这个文件回传给实施/研发："
  echo "     $ARCHIVE"
else
  echo "[ok] 采集完成，结果目录（打包失败，可手动打包该目录）："
  echo "     $OUT_DIR"
fi
echo "     汇总速览：$SUMMARY"
echo "================================================================"
