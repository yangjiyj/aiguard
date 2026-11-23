#!/bin/sh
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

TLS_DIR="${TLS_DIR:-$SCRIPT_DIR/tls}"
TLS_CERT_FILE="${TLS_CERT_FILE:-$TLS_DIR/web-console.crt}"
TLS_KEY_FILE="${TLS_KEY_FILE:-$TLS_DIR/web-console.key}"
TLS_CERT_HOSTS="${TLS_CERT_HOSTS:-localhost,127.0.0.1}"
TLS_CERT_DAYS="${TLS_CERT_DAYS:-825}"

if [ -f "$TLS_CERT_FILE" ] && [ -f "$TLS_KEY_FILE" ]; then
  # web-console 容器以非 root(node) 只读挂载本目录；root 装机 umask 可能让目录变 700 导致容器 EACCES。
  chmod 755 "$TLS_DIR" 2>/dev/null || true
  echo "[ok] web console TLS certificate already exists"
  exit 0
fi

mkdir -p "$TLS_DIR"
chmod 755 "$TLS_DIR"
CONFIG_FILE="$TLS_DIR/openssl.cnf"

cat >"$CONFIG_FILE" <<EOF
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

dns_idx=1
ip_idx=1
for host in $(printf '%s' "$TLS_CERT_HOSTS" | tr ',' ' '); do
  [ -n "$host" ] || continue
  case "$host" in
    *:*)
      printf 'IP.%s = %s\n' "$ip_idx" "$host" >>"$CONFIG_FILE"
      ip_idx=$((ip_idx + 1))
      ;;
    *[!0-9.]*)
      printf 'DNS.%s = %s\n' "$dns_idx" "$host" >>"$CONFIG_FILE"
      dns_idx=$((dns_idx + 1))
      ;;
    *)
      printf 'IP.%s = %s\n' "$ip_idx" "$host" >>"$CONFIG_FILE"
      ip_idx=$((ip_idx + 1))
      ;;
  esac
done

if [ "$dns_idx" -eq 1 ]; then
  echo 'DNS.1 = localhost' >>"$CONFIG_FILE"
fi
if [ "$ip_idx" -eq 1 ]; then
  echo 'IP.1 = 127.0.0.1' >>"$CONFIG_FILE"
fi

echo "[step] generating self-signed TLS certificate for web console"

# 在带 openssl 的随包镜像里生成自签证书（宿主机可能没有 openssl CLI）。
# 运行时探测镜像，避免硬编码“某镜像一定带 openssl”的假设：
# 优先 security-engine（已知带 openssl），探测失败再回退其它随包镜像。
# 用 --entrypoint sh 强制直接进 shell，规避镜像自带 ENTRYPOINT（如 web-console 的 docker-entrypoint.sh）。
TLS_OPENSSL_IMAGES="${TLS_OPENSSL_IMAGES:-docker-compose-security-engine:latest docker-compose-control-plane:latest docker-compose-gateway-core:latest docker-compose-proxy-server:latest docker-compose-web-console:latest postgres:16-alpine valkey/valkey:8.1.10-alpine}"

tls_image=""
for img in $TLS_OPENSSL_IMAGES; do
  if docker image inspect "$img" >/dev/null 2>&1 \
     && docker run --rm --entrypoint sh "$img" -c 'command -v openssl >/dev/null 2>&1'; then
    tls_image="$img"
    break
  fi
done

if [ -z "$tls_image" ]; then
  echo "[error] 随包镜像中未找到带 openssl 的镜像，无法生成 TLS 证书" >&2
  echo "[hint] 可通过环境变量 TLS_OPENSSL_IMAGES 指定一个含 openssl CLI 的镜像" >&2
  exit 1
fi

echo "[info] using image for openssl: $tls_image"
docker run --rm --user 0:0 --entrypoint sh \
  -e TLS_CERT_DAYS="$TLS_CERT_DAYS" \
  -v "$TLS_DIR:/certs" \
  "$tls_image" \
  -eu -c 'openssl req -x509 -newkey rsa:3072 -sha256 -days "$TLS_CERT_DAYS" -nodes -keyout /certs/web-console.key -out /certs/web-console.crt -config /certs/openssl.cnf -extensions v3_req && chown 1000:1000 /certs/web-console.key /certs/web-console.crt && chmod 600 /certs/web-console.key && chmod 644 /certs/web-console.crt'

echo "[ok] generated web console TLS certificate: $TLS_CERT_FILE"
