#!/bin/sh
# Container entrypoint: render nginx.conf from the template (only
# ${GATEWAY_CORE_UPSTREAM} is substituted, nginx's own $vars are untouched),
# validate it, then exec nginx in the foreground.
set -eu
: "${GATEWAY_CORE_UPSTREAM:=gateway-core:8080}"
case "$GATEWAY_CORE_UPSTREAM" in
  *[!A-Za-z0-9.:_-]*|'') echo "[guomi-tls] invalid GATEWAY_CORE_UPSTREAM" >&2; exit 64 ;;
esac
for f in /certs/guomi/sm2_sign.crt /certs/guomi/sm2_sign.key /certs/guomi/sm2_enc.crt /certs/guomi/sm2_enc.key /certs/gateway.crt /certs/gateway.key; do
  [ -r "$f" ] || { echo "[guomi-tls] missing certificate file: $f (run ensure-guomi-tls.sh)" >&2; exit 66; }
done
mkdir -p /var/cache/guomi-tls/body /var/cache/guomi-tls/proxy /var/cache/guomi-tls/fastcgi \
  /var/cache/guomi-tls/uwsgi /var/cache/guomi-tls/scgi /tmp/guomi-tls
sed "s|\${GATEWAY_CORE_UPSTREAM}|$GATEWAY_CORE_UPSTREAM|g" /etc/guomi-tls/nginx.conf.template >/tmp/guomi-tls/nginx.conf
/opt/guomi-tls/sbin/nginx -e stderr -t -q -c /tmp/guomi-tls/nginx.conf
exec /opt/guomi-tls/sbin/nginx -e stderr -c /tmp/guomi-tls/nginx.conf -g 'daemon off;'
