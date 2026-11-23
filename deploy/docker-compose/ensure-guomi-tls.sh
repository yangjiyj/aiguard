#!/bin/sh
# W10: generate a self-signed SM2 dual-certificate set (sign + enc) for the
# optional guomi-tls TLCP entry. Idempotent: existing files are kept.
#
# For production, replace tls/guomi/* with certificates issued by a GM CA;
# this script is only for evaluation and first boot.
#
# The certificates are produced by the Tongsuo binary shipped inside the
# guomi-tls image (the host does not need Tongsuo), with --network=none.
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
OUT="$TLS_DIR/guomi"
IMAGE="${GUOMI_TLS_IMAGE:-jjdguard/guomi-tls:local}"
CN="${GUOMI_TLS_CN:-AI Compute Security Gateway}"
DAYS="${GUOMI_TLS_DAYS:-825}"
HOSTS="${GUOMI_TLS_HOSTS:-${GATEWAY_TLS_HOSTS:-localhost,gateway-core,guomi-tls,127.0.0.1}}"

files="sm2_ca.crt sm2_sign.crt sm2_sign.key sm2_enc.crt sm2_enc.key"
all_present=1
for f in $files; do [ -s "$OUT/$f" ] || all_present=0; done
if [ "$all_present" = 1 ]; then
  echo "[ok] guomi-tls SM2 certificates already exist: $OUT"
  exit 0
fi

case "$HOSTS$CN" in
  *[\'\"\$\`\\]*) echo "[fail] GUOMI_TLS_HOSTS/GUOMI_TLS_CN contain unsupported characters" >&2; exit 64 ;;
esac

san=""
for host in $(printf '%s' "$HOSTS" | tr ',' ' '); do
  [ -n "$host" ] || continue
  case "$host" in
    *[!0-9.]*) case "$host" in *:*) san="$san,IP:$host" ;; *) san="$san,DNS:$host" ;; esac ;;
    *) san="$san,IP:$host" ;;
  esac
done
san="${san#,}"

mkdir -p "$OUT"
chmod 755 "$TLS_DIR" 2>/dev/null || true
chmod 755 "$OUT"

# Keys are written as the guomi-tls runtime user (uid inside the image) so the
# non-root nginx can read them with mode 0600 and nobody else can.
docker run --rm --network=none --user 0 \
  -e CN="$CN" -e DAYS="$DAYS" -e SAN="$san" \
  -v "$OUT:/out" --entrypoint /bin/sh "$IMAGE" -eu -c '
    T=/opt/guomi-tls/sbin/tongsuo
    cd /out
    umask 077
    $T ecparam -genkey -name SM2 -out sm2_ca.key
    $T req -new -x509 -sm3 -key sm2_ca.key -out sm2_ca.crt -days "$DAYS" \
      -subj "/CN=$CN SM2 Root" \
      -addext "basicConstraints=critical,CA:true" -addext "keyUsage=critical,keyCertSign,cRLSign"
    for role in sign enc; do
      if [ "$role" = sign ]; then ku="critical,digitalSignature"; else ku="critical,keyEncipherment,dataEncipherment,keyAgreement"; fi
      $T ecparam -genkey -name SM2 -out sm2_$role.key
      $T req -new -sm3 -key sm2_$role.key -out sm2_$role.csr -subj "/CN=$CN ($role)"
      printf "basicConstraints=critical,CA:false\nkeyUsage=%s\nextendedKeyUsage=serverAuth\nsubjectAltName=%s\n" "$ku" "$SAN" > $role.ext
      $T x509 -req -sm3 -in sm2_$role.csr -CA sm2_ca.crt -CAkey sm2_ca.key -CAcreateserial \
        -days "$DAYS" -extfile $role.ext -out sm2_$role.crt
      rm -f sm2_$role.csr $role.ext
    done
    rm -f sm2_ca.srl sm2_ca.key
    chown guomi:guomi sm2_sign.key sm2_enc.key
    chmod 0600 sm2_sign.key sm2_enc.key
    chmod 0644 sm2_ca.crt sm2_sign.crt sm2_enc.crt
  '
echo "[ok] generated SM2 sign/enc certificates in $OUT (CA key discarded)"
