#!/usr/bin/env bash
# W10: end-to-end handshake test for the optional guomi-tls entry.
#   - generates SM2 dual certificates with ensure-guomi-tls.sh
#   - starts the guomi-tls image in front of a stub upstream
#   - TLCP (NTLSv1.1, ECC-SM2-SM4-GCM-SM3 and ECDHE-SM2-SM4-CBC-SM3) must
#     complete and reach the upstream
#   - ordinary TLS 1.3 with the RSA certificate must still work
#   - negative: TLCP must fail if the enc certificate is removed
# Requires docker and GUOMI_TLS_IMAGE (default jjdguard/guomi-tls:local).
# Skips (exit 0 with SKIP) when the image is not present locally.
set -Eeuo pipefail
# 临时容器：打测试标签、先回收被杀掉的测试进程留下的孤儿容器，清理用 docker rm -f -v（见该库说明）。
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib/test-containers.sh"
jjd_test_reap_orphan_containers
jjd_test_container_labels guomi-tls-handshake
umask 077

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
DC="$ROOT/deploy/docker-compose"
IMAGE="${GUOMI_TLS_IMAGE:-jjdguard/guomi-tls:local}"
fail() { printf '[guomi-tls-handshake] FAIL %s\n' "$*" >&2; exit 1; }

if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
  printf '[guomi-tls-handshake] SKIP image %s not built\n' "$IMAGE"
  exit 0
fi

tmp="$(mktemp -d)"; chmod 0755 "$tmp"
tag="ws10-$$-$RANDOM"
net="guomi-tls-test-$tag"
cleanup() {
  docker rm -f -v "guomi-up-$tag" "guomi-tls-$tag" >/dev/null 2>&1 || true
  docker network rm "$net" >/dev/null 2>&1 || true
  docker run --rm --user 0 -v "$tmp:/w" --entrypoint /bin/rm "$IMAGE" -rf /w/tls >/dev/null 2>&1 || true
  rm -rf "$tmp"
}
trap cleanup EXIT

# 1) certificates (dual SM2) + an RSA certificate for the TLS fallback
mkdir -p "$tmp/tls"; chmod 0755 "$tmp/tls"
GATEWAY_TLS_DIR="$tmp/tls" GUOMI_TLS_IMAGE="$IMAGE" GUOMI_TLS_HOSTS="localhost,guomi-tls-$tag" \
  sh "$DC/ensure-guomi-tls.sh" >/dev/null
for f in sm2_ca.crt sm2_sign.crt sm2_sign.key sm2_enc.crt sm2_enc.key; do
  [[ -s "$tmp/tls/guomi/$f" ]] || fail "missing $f"
done
[[ ! -e "$tmp/tls/guomi/sm2_ca.key" ]] || fail 'CA private key must not be kept'
# idempotent second run
GATEWAY_TLS_DIR="$tmp/tls" GUOMI_TLS_IMAGE="$IMAGE" sh "$DC/ensure-guomi-tls.sh" | grep -q 'already exist' ||
  fail 'second run is not idempotent'
docker run --rm --network=none --user 0 -v "$tmp/tls:/certs" --entrypoint /bin/sh "$IMAGE" -ec '
  T=/opt/guomi-tls/sbin/tongsuo
  $T req -x509 -newkey rsa:2048 -sha256 -days 2 -nodes -subj /CN=localhost \
    -keyout /certs/gateway.key -out /certs/gateway.crt 2>/dev/null
  chown guomi:guomi /certs/gateway.key; chmod 600 /certs/gateway.key; chmod 644 /certs/gateway.crt
  $T x509 -in /certs/guomi/sm2_sign.crt -noout -text | grep -q "SM2"
  $T verify -CAfile /certs/guomi/sm2_ca.crt /certs/guomi/sm2_sign.crt /certs/guomi/sm2_enc.crt >/dev/null'

# 2) stub upstream + guomi-tls
docker network create --internal "$net" >/dev/null
docker run "${JJD_TEST_CONTAINER_LABELS[@]}" -d --name "guomi-up-$tag" --network "$net" --network-alias gateway-core \
  --entrypoint /bin/sh "$IMAGE" -c 'mkdir -p /tmp/w && cd /tmp/w && while true; do printf "HTTP/1.1 200 OK\r\nContent-Length: 11\r\nConnection: close\r\n\r\nupstream-ok" | nc -l -p 8080 >/dev/null 2>&1; done' >/dev/null
docker run "${JJD_TEST_CONTAINER_LABELS[@]}" -d --name "guomi-tls-$tag" --network "$net" --read-only \
  --tmpfs /tmp:rw,size=16m --tmpfs /var/cache/guomi-tls:rw,size=16m,uid=100,gid=101 --tmpfs /var/run/guomi-tls:rw,size=1m,uid=100,gid=101 \
  --cap-drop ALL --security-opt no-new-privileges:true \
  -e GATEWAY_CORE_UPSTREAM=gateway-core:8080 -v "$tmp/tls:/certs:ro" "$IMAGE" >/dev/null
for _ in $(seq 1 30); do
  docker exec "guomi-tls-$tag" sh -c 'nc -z 127.0.0.1 8443' 2>/dev/null && break
  sleep 1
done
docker exec "guomi-tls-$tag" sh -c 'nc -z 127.0.0.1 8443' || { docker logs "guomi-tls-$tag" >&2; fail 'guomi-tls did not listen'; }

client() {
  docker run --rm --network "$net" -v "$tmp/tls:/certs:ro" --entrypoint /bin/sh "$IMAGE" -c "$1"
}
S="/opt/guomi-tls/sbin/tongsuo s_client -connect guomi-tls-$tag:8443 -enable_ntls -ntls"
tlcp_req='printf "GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"'
# One-way TLCP (server authenticated with the SM2 dual certificate).
for suite in ECC-SM2-SM4-GCM-SM3 ECC-SM2-SM4-CBC-SM3; do
  out="$(client "$tlcp_req | $S -cipher $suite -CAfile /certs/guomi/sm2_ca.crt -verify_return_error -quiet 2>&1")" ||
    { printf '%s\n' "$out" >&2; fail "TLCP $suite handshake failed"; }
  grep -q 'upstream-ok' <<<"$out" || { printf '%s\n' "$out" >&2; fail "TLCP $suite did not reach upstream"; }
  info="$(client "echo | $S -cipher $suite -CAfile /certs/guomi/sm2_ca.crt 2>&1")"
  grep -Eq "New, NTLSv1.1, Cipher is $suite" <<<"$info" || { printf '%s\n' "$info" | tail -30 >&2; fail "$suite did not negotiate NTLSv1.1"; }
  printf '[guomi-tls-handshake] ok TLCP %s\n' "$suite"
done

# ECDHE-SM2 needs client SM2 dual certificates (GB/T 38636); without them it must fail.
docker run --rm --network=none --user 0 -v "$tmp/tls:/certs" --entrypoint /bin/sh "$IMAGE" -ec '
  T=/opt/guomi-tls/sbin/tongsuo; mkdir -p /certs/client; cd /certs/client
  for r in sign enc; do
    $T ecparam -genkey -name SM2 -out c_$r.key
    $T req -new -x509 -sm3 -key c_$r.key -out c_$r.crt -days 2 -subj /CN=client-$r 2>/dev/null
  done
  chmod 644 c_sign.key c_enc.key'
info="$(client "echo | $S -cipher ECDHE-SM2-SM4-GCM-SM3 -CAfile /certs/guomi/sm2_ca.crt -sign_cert /certs/client/c_sign.crt -sign_key /certs/client/c_sign.key -enc_cert /certs/client/c_enc.crt -enc_key /certs/client/c_enc.key 2>&1")"
grep -Eq 'New, NTLSv1.1, Cipher is ECDHE-SM2-SM4-GCM-SM3' <<<"$info" || { printf '%s\n' "$info" | tail -20 >&2; fail 'ECDHE-SM2 with client certificates failed'; }
printf '[guomi-tls-handshake] ok TLCP ECDHE-SM2-SM4-GCM-SM3 (client dual certificate)\n'
if client "echo | $S -cipher ECDHE-SM2-SM4-GCM-SM3 -CAfile /certs/guomi/sm2_ca.crt 2>&1" | grep -q 'New, NTLSv1.1, Cipher is ECDHE'; then
  fail 'ECDHE-SM2 negotiated without client encryption certificate'
fi
printf '[guomi-tls-handshake] ok ECDHE-SM2 refused without client certificate\n'

# Wrong trust anchor must fail verification.
if client "echo | $S -cipher ECC-SM2-SM4-GCM-SM3 -CAfile /certs/client/c_sign.crt -verify_return_error 2>&1" | grep -q 'New, NTLSv1.1'; then
  fail 'TLCP verified against an unrelated CA'
fi
printf '[guomi-tls-handshake] ok wrong CA rejected\n'

tls13="$(client "echo | /opt/guomi-tls/sbin/tongsuo s_client -connect guomi-tls-$tag:8443 -tls1_3 2>&1")"
grep -Eq "Protocol *: *TLSv1.3|New, TLSv1.3" <<<"$tls13" || { printf '%s\n' "$tls13" | tail -20 >&2; fail 'TLS 1.3 fallback failed'; }
printf '[guomi-tls-handshake] ok TLS 1.3 fallback\n'

# 3) negative: without the enc certificate the entrypoint refuses to start
docker rm -f -v "guomi-tls-$tag" >/dev/null
docker run --rm --user 0 -v "$tmp/tls:/certs" --entrypoint /bin/rm "$IMAGE" -f /certs/guomi/sm2_enc.crt
if docker run --rm --network "$net" -v "$tmp/tls:/certs:ro" "$IMAGE" >/dev/null 2>&1; then
  fail 'guomi-tls started without the SM2 encryption certificate'
fi
printf '[guomi-tls-handshake] ok refuses to start without enc certificate\n'
printf '[guomi-tls-handshake] PASS\n'
