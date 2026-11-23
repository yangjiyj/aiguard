#!/bin/sh
# 为「网关 API 的 HTTPS 前置 (gateway-tls)」生成自签证书（幂等：已存在则跳过）。
# 与 ensure-web-tls.sh 同一套路子：证书默认落脚本同级 ./tls（随仓库，已被 .gitignore 忽略）。
set -eu

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"
# 读 .env 不能用 source：未加引号且含空格的值（如 REDIS_EXTRA_ARGS=--a yes）会被当成命令执行，
# 值里的 $(...) / 反引号 / 分号也会被执行。统一经共享库按字面解析，见 deploy/lib/jjd-env.sh。
JJD_ENV_LIB="$SCRIPT_DIR/../lib/jjd-env.sh"
if [ ! -f "$JJD_ENV_LIB" ]; then
  echo "[error] 缺少安全读取 .env 的库: $JJD_ENV_LIB" >&2
  exit 1
fi
# shellcheck source=../lib/jjd-env.sh
. "$JJD_ENV_LIB"
if [ -f ./.env ]; then
  jjd_load_env_file ./.env
fi

TLS_DIR="${GATEWAY_TLS_DIR:-$SCRIPT_DIR/tls}"
CERT="$TLS_DIR/gateway.crt"
KEY="$TLS_DIR/gateway.key"
# 证书 SAN。默认只含通用主机名；本机/对外的具体 IP、域名请用 GATEWAY_TLS_HOSTS 注入
# （例如在 .env 写 GATEWAY_TLS_HOSTS=localhost,gateway-core,127.0.0.1,<你的IP或域名>）。
HOSTS="${GATEWAY_TLS_HOSTS:-localhost,gateway-core,gateway-tls,127.0.0.1}"
DAYS="${GATEWAY_TLS_DAYS:-825}"

if [ -f "$CERT" ] && [ -f "$KEY" ]; then
  echo "[ok] gateway-tls 证书已存在：$CERT"
  exit 0
fi

mkdir -p "$TLS_DIR"
CONF="$TLS_DIR/gateway-openssl.cnf"
cat >"$CONF" <<EOF
[req]
default_bits = 3072
prompt = no
distinguished_name = dn
x509_extensions = v3_req
[dn]
CN = AI Compute Security Gateway
[v3_req]
basicConstraints = critical,CA:false
keyUsage = critical,digitalSignature,keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names
[alt_names]
EOF
d=1; i=1
for h in $(printf '%s' "$HOSTS" | tr ',' ' '); do
  [ -n "$h" ] || continue
  case "$h" in
    *[!0-9.]*) printf 'DNS.%s = %s\n' "$d" "$h" >>"$CONF"; d=$((d+1));;
    *)         printf 'IP.%s = %s\n'  "$i" "$h" >>"$CONF"; i=$((i+1));;
  esac
done

IMG="${TLS_OPENSSL_IMAGE:-docker-compose-security-engine:latest}"
echo "[step] 生成自签证书 -> $CERT (SAN: $HOSTS)"
docker run --rm --user 0:0 --entrypoint sh -e DAYS="$DAYS" -v "$TLS_DIR:/certs" "$IMG" -eu -c \
  'openssl req -x509 -newkey rsa:3072 -sha256 -days "$DAYS" -nodes -keyout /certs/gateway.key -out /certs/gateway.crt -config /certs/gateway-openssl.cnf -extensions v3_req && chmod 644 /certs/gateway.crt && chmod 600 /certs/gateway.key'
echo "[ok] 已生成 $CERT"
