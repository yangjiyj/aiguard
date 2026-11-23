#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname "$0")" && pwd)"
RUNTIME_DIR="${JJDGUARD_RUNTIME_DIR:-/home/dev/jjdguard/jjdguard-1.4.0-offline-full-chat-20260706-144808/deploy/docker-compose}"
RUNTIME_IDENTITY_ENV="${JJDGUARD_RUNTIME_IDENTITY_ENV:-$RUNTIME_DIR/identity-runtime.env}"
TEST_ENV="${HOME_IDENTITY_TEST_ENV:-/home/dev/.config/jjdguard/home-identity-test.env}"
CONTROL_PLANE="${JJDGUARD_CONTROL_PLANE_CONTAINER:-jjdguard-1-4-0-offline-full-chat-20260706-144808-control-plane-1}"
IDENTITY_ENGINE="${JJDGUARD_IDENTITY_CONTAINER:-jjdguard-1-4-0-offline-full-chat-20260706-144808-chat-idp-1}"
LDAP_CONTAINER="${HOME_LDAP_CONTAINER:-jjdguard-directory-sim-ldap-1}"
AD_CONTAINER="${HOME_AD_CONTAINER:-jjdguard-directory-sim-ad-1}"
OIDC_CONTAINER="${HOME_OIDC_CONTAINER:-jjdguard-directory-sim-oidc-idp-1}"

fail() {
  echo "[error] $*" >&2
  exit 1
}

ok() {
  echo "[ok] $*"
}

[ -f "$TEST_ENV" ] || fail "缺少 home 身份测试环境文件"
[ -f "$RUNTIME_IDENTITY_ENV" ] || fail "缺少运行态身份环境文件"

set -a
# shellcheck disable=SC1090
. "$TEST_ENV"
# shellcheck disable=SC1090
. "$RUNTIME_IDENTITY_ENV"
set +a

for container in "$LDAP_CONTAINER" "$AD_CONTAINER" "$OIDC_CONTAINER" "$CONTROL_PLANE" "$IDENTITY_ENGINE"; do
  [ "$(docker inspect -f '{{.State.Running}}' "$container" 2>/dev/null)" = "true" ] ||
    fail "容器未运行：$container"
done
ok "五个身份相关容器均在运行"

docker exec "$LDAP_CONTAINER" ldapsearch -x \
  -H ldaps://localhost:636 \
  -D cn=admin,dc=jjdguard,dc=test \
  -w "$LDAP_BIND_PASSWORD" \
  -b ou=People,dc=jjdguard,dc=test \
  '(objectClass=person)' uid mail >/dev/null
ok "openldap LDAPS、绑定和用户查询通过"

docker cp /home/dev/.config/jjdguard/home-ad-ca.pem "$LDAP_CONTAINER:/tmp/home-ad-ca.pem" >/dev/null
docker exec \
  -e LDAPTLS_CACERT=/tmp/home-ad-ca.pem \
  "$LDAP_CONTAINER" ldapsearch -x \
  -H ldaps://dc-sim.ad.jjdguard.test:636 \
  -D 'svc-jjdguard@ad.jjdguard.test' \
  -w "$AD_BIND_PASSWORD" \
  -b 'OU=Employees,DC=ad,DC=jjdguard,DC=test' \
  '(objectClass=user)' sAMAccountName mail displayName >/dev/null
docker exec "$LDAP_CONTAINER" rm -f /tmp/home-ad-ca.pem
ok "active-directory LDAPS、绑定和用户查询通过"

discovery="$(curl -fsS --max-time 10 --resolve \
  "${UPSTREAM_OIDC_HOST}:${UPSTREAM_OIDC_PORT:-8380}:${UPSTREAM_OIDC_BIND}" \
  "$UPSTREAM_OIDC_ISSUER/.well-known/openid-configuration")"
[ "$(printf '%s' "$discovery" | jq -r .issuer)" = "$UPSTREAM_OIDC_ISSUER" ] ||
  fail "OIDC issuer 与配置不一致"
printf '%s' "$discovery" | jq -e '.authorization_endpoint and .token_endpoint and .jwks_uri' >/dev/null ||
  fail "OIDC discovery 缺少必要端点"
ok "OIDC openid-configuration 与协议端点通过"

docker exec "$CONTROL_PLANE" nc -zvw5 ldap-sim.jjdguard.test 636 >/dev/null 2>&1 ||
  fail "control-plane 无法访问 OpenLDAP"
docker exec "$CONTROL_PLANE" nc -zvw5 dc-sim.ad.jjdguard.test 636 >/dev/null 2>&1 ||
  fail "control-plane 无法访问 AD"
docker exec "$CONTROL_PLANE" wget -qO- \
  "$UPSTREAM_OIDC_ISSUER/.well-known/openid-configuration" >/dev/null ||
  fail "control-plane 无法访问上游 OIDC"
ok "control-plane 到 LDAP、AD、OIDC 的运行网络通过"

idp_ip="$(docker inspect "$IDENTITY_ENGINE" | jq -r '.[0].NetworkSettings.Networks[] | .IPAddress' | head -n 1)"
[ -n "$idp_ip" ] || fail "无法获取内部身份引擎地址"

verify_runtime_client() {
  local client_id="$1"
  local client_secret="$2"
  local path="$3"
  local token
  local status

  token="$(curl -fsS -X POST \
    "http://$idp_ip:8180/sso/realms/jjdguard/protocol/openid-connect/token" \
    --data-urlencode grant_type=client_credentials \
    --data-urlencode "client_id=$client_id" \
    --data-urlencode "client_secret=$client_secret" | jq -r .access_token)"
  [ -n "$token" ] || fail "运行态 client 无法换取 Token"
  status="$(curl -sS -o /dev/null -w '%{http_code}' \
    -H "Authorization: Bearer $token" \
    "http://$idp_ip:8180/sso$path")"
  unset token
  [ "$status" = "200" ] || fail "运行态 client 调用失败：$client_id HTTP $status"
}

verify_runtime_client \
  "$JJD_IDENTITY_RUNTIME_CLIENT_ID" \
  "$JJD_IDENTITY_RUNTIME_CLIENT_SECRET" \
  '/admin/realms/jjdguard/identity-provider/instances'
verify_runtime_client \
  "$DIRECTORY_RUNTIME_CLIENT_ID" \
  "$DIRECTORY_RUNTIME_CLIENT_SECRET" \
  '/admin/realms/jjdguard'
ok "身份与目录运行态服务账号权限通过"

echo "[ok] home 身份测试环境基础验收全部通过"
