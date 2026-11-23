#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname "$0")" && pwd)"
SOURCE_COMPOSE_DIR="$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)"
RUNTIME_DIR="${JJDGUARD_RUNTIME_DIR:-/home/dev/jjdguard/jjdguard-1.4.0-offline-full-chat-20260706-144808/deploy/docker-compose}"
RUNTIME_COMPOSE="${JJDGUARD_RUNTIME_COMPOSE:-$RUNTIME_DIR/docker-compose.offline.yml}"
RUNTIME_COMPOSE_WRAPPER="${JJDGUARD_COMPOSE_WRAPPER:-$RUNTIME_DIR/compose-wrapper.sh}"
RUNTIME_ENV="${JJDGUARD_RUNTIME_ENV:-$RUNTIME_DIR/.env}"
RUNTIME_IDENTITY_ENV="${JJDGUARD_RUNTIME_IDENTITY_ENV:-$RUNTIME_DIR/identity-runtime.env}"
TEST_ENV="${HOME_IDENTITY_TEST_ENV:-/home/dev/.config/jjdguard/home-identity-test.env}"
PROJECT_NAME="${JJDGUARD_PROJECT_NAME:-jjdguard-1-4-0-offline-full-chat-20260706-144808}"
TAILSCALE_IP="${HOME_TAILSCALE_IP:-100.64.0.21}"
TAILSCALE_DNS="${HOME_TAILSCALE_DNS:-dev.example.ts.net}"

fail() {
  echo "[error] $*" >&2
  exit 1
}

require_regular_file() {
  local path="$1"
  local label="$2"
  [ -f "$path" ] && [ ! -L "$path" ] || fail "$label 必须是普通文件且不能是符号链接"
}

run_compose() {
  # The runtime wrapper prefers the host plugin and falls back to the
  # compose binary carried by the offline bundle.
  sh "$RUNTIME_COMPOSE_WRAPPER" "$@"
}

read_env_value() {
  local file="$1"
  local key="$2"
  sed -n "s/^${key}=//p" "$file" | tail -n 1
}

upsert_env_value() {
  local file="$1"
  local key="$2"
  local value="$3"
  local escaped
  escaped="$(printf '%s' "$value" | sed 's/[&|\\]/\\&/g')"
  if grep -q "^${key}=" "$file"; then
    sed -i "s|^${key}=.*|${key}=${escaped}|" "$file"
  else
    printf '%s=%s\n' "$key" "$value" >>"$file"
  fi
}

reconcile_portal_client_secret() {
  local idp_container="${PROJECT_NAME}-chat-idp-1"
  docker exec "$idp_container" sh -lc '
    set -eu
    kcadm=/opt/keycloak/bin/kcadm.sh
    "$kcadm" config credentials \
      --server http://127.0.0.1:8180/sso \
      --realm master \
      --user "$KC_BOOTSTRAP_ADMIN_USERNAME" \
      --password "$KC_BOOTSTRAP_ADMIN_PASSWORD" >/dev/null 2>&1
    client_uuid="$(
      "$kcadm" get clients -r jjdguard -q clientId=enterprise-ai-portal |
        sed -n "s/.*\"id\" : \"\([^\"]*\)\".*/\1/p" |
        head -n 1
    )"
    [ -n "$client_uuid" ]
    [ -n "$CHAT_PORTAL_UI_OIDC_SECRET" ]
    [ -n "$PORTAL_UI_ORIGIN" ]
    groups_scope_uuid="$(
      "$kcadm" get client-scopes -r jjdguard --fields id,name \
        --format csv --noquotes |
        sed -n "s/^\([^,]*\),groups$/\1/p" |
        head -n 1
    )"
    if [ -z "$groups_scope_uuid" ]; then
      groups_scope_uuid="$(
        "$kcadm" create client-scopes -r jjdguard \
          -s "name=groups" \
          -s "protocol=openid-connect" \
          -s '\''attributes."include.in.token.scope"=true'\'' \
          -i
      )"
    fi
    [ -n "$groups_scope_uuid" ]
    "$kcadm" update \
      "clients/$client_uuid/optional-client-scopes/$groups_scope_uuid" \
      -r jjdguard >/dev/null
    portal_origin="${PORTAL_UI_ORIGIN%/}"
    account_redirect="${portal_origin}/api/auth/callback/account-login"
    sso_redirect="${portal_origin}/api/auth/callback/enterprise-sso"
    redirect_uris="$(printf "[\"%s\",\"%s\"]" "$account_redirect" "$sso_redirect")"
    "$kcadm" update "clients/$client_uuid" -r jjdguard \
      -s "secret=$CHAT_PORTAL_UI_OIDC_SECRET" \
      -s "redirectUris=$redirect_uris" >/dev/null
  '
}

reconcile_upstream_portal_client() {
  local idp_container="jjdguard-directory-sim-oidc-idp-1"
  local attempt=1
  until docker exec "$idp_container" sh -lc '
    /opt/keycloak/bin/kcadm.sh config credentials \
      --server "http://127.0.0.1:${UPSTREAM_OIDC_PORT:-8380}" \
      --realm master \
      --user "$KC_BOOTSTRAP_ADMIN_USERNAME" \
      --password "$KC_BOOTSTRAP_ADMIN_PASSWORD" >/dev/null 2>&1
  '; do
    [ "$attempt" -lt 60 ] || fail "上游企业 SSO 在有界等待后仍未就绪"
    sleep 2
    attempt=$((attempt + 1))
  done

  docker exec "$idp_container" sh -lc '
    set -eu
    kcadm=/opt/keycloak/bin/kcadm.sh
    "$kcadm" config credentials \
      --server "http://127.0.0.1:${UPSTREAM_OIDC_PORT:-8380}" \
      --realm master \
      --user "$KC_BOOTSTRAP_ADMIN_USERNAME" \
      --password "$KC_BOOTSTRAP_ADMIN_PASSWORD" >/dev/null 2>&1
    client_uuid="$(
      "$kcadm" get clients -r enterprise-test \
        -q clientId=jjdguard-enterprise-test \
        --fields id --format csv --noquotes |
        head -n 1
    )"
    [ -n "$client_uuid" ]
    callback="${JJDGUARD_ENTERPRISE_CALLBACK%/}"
    portal_origin="${JJDGUARD_SSO_ORIGIN%/}"
    logout_callback="${callback}/logout_response"
    [ -n "$callback" ]
    [ -n "$portal_origin" ]

    groups_scope_uuid="$(
      "$kcadm" get client-scopes -r enterprise-test --fields id,name \
        --format csv --noquotes |
        sed -n "s/^\([^,]*\),groups$/\1/p" |
        head -n 1
    )"
    if [ -z "$groups_scope_uuid" ]; then
      groups_scope_uuid="$(
        "$kcadm" create client-scopes -r enterprise-test \
          -s "name=groups" \
          -s "protocol=openid-connect" \
          -s '\''attributes."include.in.token.scope"=true'\'' \
          -i
      )"
    fi
    [ -n "$groups_scope_uuid" ]
    "$kcadm" update \
      "clients/$client_uuid/optional-client-scopes/$groups_scope_uuid" \
      -r enterprise-test >/dev/null

    for scope_name in profile email; do
      scope_uuid="$(
        "$kcadm" get client-scopes -r enterprise-test --fields id,name \
          --format csv --noquotes |
          sed -n "s/^\([^,]*\),${scope_name}$/\1/p" |
          head -n 1
      )"
      if [ -z "$scope_uuid" ]; then
        scope_uuid="$(
          "$kcadm" create client-scopes -r enterprise-test \
            -s "name=$scope_name" \
            -s "protocol=openid-connect" \
            -s '\''attributes."include.in.token.scope"=true'\'' \
            -i
        )"
      fi
      [ -n "$scope_uuid" ]
      "$kcadm" update \
        "clients/$client_uuid/default-client-scopes/$scope_uuid" \
        -r enterprise-test >/dev/null
    done

    mapper_names="$(
      "$kcadm" get "clients/$client_uuid/protocol-mappers/models" \
        -r enterprise-test --fields name --format csv --noquotes
    )"
    ensure_mapper() {
      mapper_name="$1"
      mapper_body="$2"
      if ! printf "%s\n" "$mapper_names" | grep -Fx "$mapper_name" >/dev/null; then
        "$kcadm" create "clients/$client_uuid/protocol-mappers/models" \
          -r enterprise-test -b "$mapper_body" >/dev/null
      fi
    }
    ensure_mapper "preferred username" "{\"name\":\"preferred username\",\"protocol\":\"openid-connect\",\"protocolMapper\":\"oidc-usermodel-property-mapper\",\"consentRequired\":false,\"config\":{\"user.attribute\":\"username\",\"claim.name\":\"preferred_username\",\"jsonType.label\":\"String\",\"id.token.claim\":\"true\",\"access.token.claim\":\"true\",\"userinfo.token.claim\":\"true\"}}"
    ensure_mapper "email" "{\"name\":\"email\",\"protocol\":\"openid-connect\",\"protocolMapper\":\"oidc-usermodel-property-mapper\",\"consentRequired\":false,\"config\":{\"user.attribute\":\"email\",\"claim.name\":\"email\",\"jsonType.label\":\"String\",\"id.token.claim\":\"true\",\"access.token.claim\":\"true\",\"userinfo.token.claim\":\"true\"}}"
    ensure_mapper "full name" "{\"name\":\"full name\",\"protocol\":\"openid-connect\",\"protocolMapper\":\"oidc-full-name-mapper\",\"consentRequired\":false,\"config\":{\"id.token.claim\":\"true\",\"access.token.claim\":\"true\",\"userinfo.token.claim\":\"true\"}}"

    "$kcadm" update "clients/$client_uuid" -r enterprise-test \
      -s "redirectUris=[\"$callback\"]" \
      -s "webOrigins=[\"$portal_origin\"]" \
      -s "attributes.\"post.logout.redirect.uris\"=$logout_callback" >/dev/null
  '
}

ensure_ad_tls_san() {
  local ad_container="$1"
  local ldap_container="jjdguard-directory-sim-ldap-1"
  local expected_fingerprint served_fingerprint attempt

  docker exec -i "$ad_container" bash -s <<'AD_TLS'
    set -euo pipefail
    umask 077
    tls_dir=/etc/samba/external/jjdguard-tls
    mkdir -p "$tls_dir"
    chmod 0700 "$tls_dir"
    if ! openssl x509 -in "$tls_dir/cert.pem" -noout \
        -checkhost dc-sim.ad.jjdguard.test >/dev/null 2>&1 ||
       [ ! -f "$tls_dir/ca.pem" ] || [ -L "$tls_dir/ca.pem" ] ||
       [ ! -f "$tls_dir/key.pem" ] || [ -L "$tls_dir/key.pem" ]; then
      work=$(mktemp -d "$tls_dir/.new.XXXXXX")
      trap 'rm -rf -- "$work"' EXIT
      openssl req -x509 -newkey rsa:3072 -nodes -sha256 -days 365 \
        -keyout "$work/ca.key" -out "$work/ca.pem" \
        -subj "/CN=JJDGuard directory-sim AD acceptance CA" \
        -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
        -addext "keyUsage=critical,keyCertSign,cRLSign" >/dev/null 2>&1
      openssl req -new -newkey rsa:3072 -nodes -sha256 \
        -keyout "$work/key.pem" -out "$work/cert.csr" \
        -subj "/CN=dc-sim.ad.jjdguard.test" >/dev/null 2>&1
      cat >"$work/leaf.ext" <<EOF
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:dc-sim.ad.jjdguard.test,DNS:dc-sim
EOF
      openssl x509 -req -in "$work/cert.csr" \
        -CA "$work/ca.pem" -CAkey "$work/ca.key" -CAcreateserial \
        -out "$work/cert.pem" -days 365 -sha256 \
        -extfile "$work/leaf.ext" >/dev/null 2>&1
      openssl verify -CAfile "$work/ca.pem" "$work/cert.pem" >/dev/null
      openssl x509 -in "$work/cert.pem" -noout \
        -checkhost dc-sim.ad.jjdguard.test >/dev/null
      install -m 0644 "$work/ca.pem" "$tls_dir/ca.pem"
      install -m 0644 "$work/cert.pem" "$tls_dir/cert.pem"
      install -m 0600 "$work/key.pem" "$tls_dir/key.pem"
      install -m 0600 "$work/ca.key" "$tls_dir/ca.key"
      rm -rf -- "$work"
      trap - EXIT
    fi
    for config in /etc/samba/smb.conf /etc/samba/external/smb.conf; do
      [ -f "$config" ] && [ ! -L "$config" ]
      sed -i -E '/^[[:space:]]*tls (keyfile|certfile|cafile)[[:space:]]*=/d' "$config"
      sed -i '/^\[global\]$/a\
\ttls keyfile = /etc/samba/external/jjdguard-tls/key.pem\
\ttls certfile = /etc/samba/external/jjdguard-tls/cert.pem\
\ttls cafile = /etc/samba/external/jjdguard-tls/ca.pem' "$config"
    done
    supervisorctl restart samba >/dev/null
AD_TLS

  expected_fingerprint="$(docker exec "$ad_container" openssl x509 \
    -in /etc/samba/external/jjdguard-tls/cert.pem -noout -fingerprint -sha256 |
    sed 's/^[^=]*=//')"
  served_fingerprint=""
  attempt=1
  while [ "$attempt" -le 120 ]; do
    served_fingerprint="$(docker exec "$ldap_container" sh -c \
      'printf "" | openssl s_client -connect dc-sim.ad.jjdguard.test:636 -servername dc-sim.ad.jjdguard.test 2>/dev/null | openssl x509 -noout -fingerprint -sha256' 2>/dev/null |
      sed 's/^[^=]*=//' || true)"
    [ "$served_fingerprint" = "$expected_fingerprint" ] && break
    sleep 1
    attempt=$((attempt + 1))
  done
  [ "$served_fingerprint" = "$expected_fingerprint" ] || fail "Samba AD 未提供刚配置的 SAN 证书"

  docker exec "$ad_container" cat /etc/samba/external/jjdguard-tls/ca.pem |
    docker exec -i "$ldap_container" sh -c 'umask 077; cat >/tmp/jjdguard-ad-ca.pem'
  docker exec "$ldap_container" sh -ec '
    trap "rm -f /tmp/jjdguard-ad-ca.pem" EXIT
    printf "" | openssl s_client \
      -connect dc-sim.ad.jjdguard.test:636 \
      -servername dc-sim.ad.jjdguard.test \
      -CAfile /tmp/jjdguard-ad-ca.pem \
      -verify_hostname dc-sim.ad.jjdguard.test \
      -verify_return_error 2>&1 |
      grep -q "Verify return code: 0 (ok)"
  '
}

generate_secret() {
  openssl rand -hex 24
}

generate_password() {
  printf 'Jjd!%s\n' "$(openssl rand -hex 16)"
}

require_regular_file "$RUNTIME_COMPOSE" "JJDGuard 运行态 Compose"
require_regular_file "$RUNTIME_COMPOSE_WRAPPER" "JJDGuard Compose wrapper"
require_regular_file "$RUNTIME_ENV" "JJDGuard 运行态 .env"
require_regular_file "$SOURCE_COMPOSE_DIR/chat/bootstrap-identity-runtime.sh" "身份运行态引导脚本"
require_regular_file "$SOURCE_COMPOSE_DIR/chat/bootstrap-directory-runtime.sh" "目录运行态引导脚本"
command -v docker >/dev/null 2>&1 || fail "缺少 Docker"
command -v openssl >/dev/null 2>&1 || fail "缺少 OpenSSL"
command -v jq >/dev/null 2>&1 || fail "缺少 jq"

if [ ! -f "$TEST_ENV" ]; then
  existing_ldap_password="$(
    {
      docker inspect jjdguard-directory-sim-ldap-1 |
        jq -r '.[0].Config.Env[] | select(startswith("LDAP_ADMIN_PASSWORD=")) | sub("^[^=]*=";"")' |
        head -n 1
    } 2>/dev/null || true
  )"
  existing_ad_domain_password="$(
    {
      docker inspect jjdguard-directory-sim-ad-1 |
        jq -r '.[0].Config.Env[] | select(startswith("DOMAINPASS=")) | sub("^[^=]*=";"")' |
        head -n 1
    } 2>/dev/null || true
  )"
  [ -n "$existing_ldap_password" ] || existing_ldap_password="$(generate_password)"
  [ -n "$existing_ad_domain_password" ] || existing_ad_domain_password="$(generate_password)"
  mkdir -p "$(dirname "$TEST_ENV")"
  umask 077
  {
    printf 'UPSTREAM_OIDC_BIND=%s\n' "$TAILSCALE_IP"
    printf 'UPSTREAM_OIDC_PORT=8380\n'
    printf 'UPSTREAM_OIDC_HOST=%s\n' "$TAILSCALE_DNS"
    printf 'UPSTREAM_OIDC_ORIGIN=http://%s:8380\n' "$TAILSCALE_DNS"
    printf 'UPSTREAM_OIDC_ISSUER=http://%s:8380/realms/enterprise-test\n' "$TAILSCALE_DNS"
    printf 'UPSTREAM_OIDC_ADMIN_USERNAME=admin\n'
    printf 'UPSTREAM_OIDC_ADMIN_PASSWORD=%s\n' "$(generate_password)"
    printf 'UPSTREAM_OIDC_CLIENT_SECRET=%s\n' "$(generate_secret)"
    printf 'UPSTREAM_OIDC_TEST_PASSWORD=%s\n' "$(generate_password)"
    printf 'JJDGUARD_ENTERPRISE_CALLBACK=http://%s:8180/sso/realms/jjdguard/broker/enterprise/endpoint\n' "$TAILSCALE_IP"
    printf 'JJDGUARD_SSO_ORIGIN=http://%s:8180\n' "$TAILSCALE_IP"
    printf 'LDAP_BIND_PASSWORD=%s\n' "$existing_ldap_password"
    printf 'LDAP_ALICE_PASSWORD=%s\n' "$(generate_password)"
    printf 'LDAP_BOB_PASSWORD=%s\n' "$(generate_password)"
    printf 'LDAP_CAROL_PASSWORD=%s\n' "$(generate_password)"
    printf 'AD_DOMAIN_ADMIN_PASSWORD=%s\n' "$existing_ad_domain_password"
    printf 'AD_BIND_PASSWORD=%s\n' "$(generate_password)"
    printf 'AD_TEST_USER_PASSWORD=%s\n' "$(generate_password)"
  } >"$TEST_ENV"
  chmod 600 "$TEST_ENV"
fi

case "$(stat -c '%a' "$TEST_ENV" 2>/dev/null || stat -f '%Lp' "$TEST_ENV")" in
  600) ;;
  *) fail "home 身份测试环境文件权限必须为 0600" ;;
esac

set -a
# shellcheck disable=SC1090
. "$TEST_ENV"
set +a

run_compose \
  --project-directory "$SCRIPT_DIR" \
  --env-file "$TEST_ENV" \
  -f "$SCRIPT_DIR/docker-compose.yml" \
  --profile ad \
  up -d ldap ldap-seed ad oidc-idp

ldap_seed_container="jjdguard-directory-sim-ldap-seed-1"
attempt=1
while [ "$(docker inspect "$ldap_seed_container" --format '{{.State.Status}}')" != "exited" ]; do
  [ "$attempt" -lt 60 ] || fail "OpenLDAP 种子任务在有界等待后仍未完成"
  sleep 1
  attempt=$((attempt + 1))
done
[ "$(docker inspect "$ldap_seed_container" --format '{{.State.ExitCode}}')" = "0" ] ||
  fail "OpenLDAP 种子任务失败"

refresh_ldap_password() {
  local user_dn="$1"
  local new_password="$2"
  docker exec \
    -e LDAP_NEW_PASSWORD="$new_password" \
    jjdguard-directory-sim-ldap-1 \
    sh -lc '
      LDAPTLS_CACERT=/container/service/slapd/assets/certs/ca.crt \
        ldappasswd -x -H ldaps://ldap-sim.jjdguard.test:636 \
          -D cn=admin,dc=jjdguard,dc=test \
          -w "$LDAP_ADMIN_PASSWORD" \
          -s "$LDAP_NEW_PASSWORD" \
          "$1" >/dev/null
    ' -- "$user_dn"
}

refresh_ldap_password "uid=alice,ou=People,dc=jjdguard,dc=test" "$LDAP_ALICE_PASSWORD"
refresh_ldap_password "uid=bob,ou=People,dc=jjdguard,dc=test" "$LDAP_BOB_PASSWORD"
refresh_ldap_password "uid=carol,ou=Disabled,dc=jjdguard,dc=test" "$LDAP_CAROL_PASSWORD"

ad_container="jjdguard-directory-sim-ad-1"
attempt=1
while ! docker exec "$ad_container" samba-tool domain info 127.0.0.1 >/dev/null 2>&1; do
  [ "$attempt" -lt 60 ] || fail "Samba AD 在有界等待后仍未就绪"
  sleep 2
  attempt=$((attempt + 1))
done

ensure_ad_tls_san "$ad_container"
docker exec "$ad_container" samba-tool ou create \
  'OU=Service Accounts,DC=ad,DC=jjdguard,DC=test' >/dev/null 2>&1 || true
docker exec "$ad_container" samba-tool ou create \
  'OU=Employees,DC=ad,DC=jjdguard,DC=test' >/dev/null 2>&1 || true

if ! docker exec "$ad_container" samba-tool user show svc-jjdguard >/dev/null 2>&1; then
  docker exec "$ad_container" samba-tool user create svc-jjdguard "$AD_BIND_PASSWORD" \
    --userou='OU=Service Accounts' \
    --given-name=JJDGuard \
    --surname=Directory \
    --description='JJDGuard read-only directory bind account' >/dev/null
else
  docker exec "$ad_container" samba-tool user setpassword svc-jjdguard \
    --newpassword="$AD_BIND_PASSWORD" >/dev/null
fi

if ! docker exec "$ad_container" samba-tool user show ad.alice >/dev/null 2>&1; then
  docker exec "$ad_container" samba-tool user create ad.alice "$AD_TEST_USER_PASSWORD" \
    --userou='OU=Employees' \
    --given-name=Alice \
    --surname=Domain \
    --mail-address=ad.alice@jjdguard.test >/dev/null
else
  docker exec "$ad_container" samba-tool user setpassword ad.alice \
    --newpassword="$AD_TEST_USER_PASSWORD" >/dev/null
fi

docker exec "$ad_container" samba-tool group add JJDGuard-Users >/dev/null 2>&1 || true
docker exec "$ad_container" samba-tool group addmembers JJDGuard-Users ad.alice >/dev/null 2>&1 || true

reconcile_upstream_portal_client

mkdir -p "$(dirname "$TEST_ENV")"
docker exec "$ad_container" cat /var/lib/samba/private/tls/ca.pem \
  >"$(dirname "$TEST_ENV")/home-ad-ca.pem"
docker exec jjdguard-directory-sim-ldap-1 \
  cat /container/service/slapd/assets/certs/ca.crt \
  >"$(dirname "$TEST_ENV")/home-ldap-ca.pem"
chmod 600 "$(dirname "$TEST_ENV")/home-ad-ca.pem" "$(dirname "$TEST_ENV")/home-ldap-ca.pem"

bootstrap_password="$(read_env_value "$RUNTIME_ENV" KEYCLOAK_ADMIN_PASSWORD)"
[ -n "$bootstrap_password" ] || fail "运行态缺少 KEYCLOAK_ADMIN_PASSWORD"
jjd_sso_public_url="http://${TAILSCALE_IP}:8180"
chat_db_container="${PROJECT_NAME}-chat-postgres-1"
chat_db_password="$(
  docker inspect "$chat_db_container" 2>/dev/null |
    jq -r '.[0].Config.Env[] | select(startswith("POSTGRES_PASSWORD=")) | sub("^[^=]*=";"")' |
    head -n 1 || true
)"
[ -z "$chat_db_password" ] ||
  upsert_env_value "$RUNTIME_ENV" CHAT_POSTGRES_PASSWORD "$chat_db_password"
upsert_env_value "$RUNTIME_ENV" JJD_SSO_PUBLIC_URL "$jjd_sso_public_url"
upsert_env_value "$RUNTIME_ENV" CHAT_OIDC_ISSUER \
  "${jjd_sso_public_url}/sso/realms/jjdguard"
install -m 0644 "$SOURCE_COMPOSE_DIR/chat/Caddyfile" "$RUNTIME_DIR/chat/Caddyfile"

KEYCLOAK_ADMIN_PASSWORD="$bootstrap_password" \
JJD_SSO_PUBLIC_URL="$jjd_sso_public_url" \
JJD_SSO_ALLOW_INSECURE_PUBLIC_URL=true \
COMPOSE_FILE="$RUNTIME_COMPOSE" \
COMPOSE_PROJECT_NAME="$PROJECT_NAME" \
COMPOSE_ENV_FILES="$RUNTIME_ENV" \
COMPOSE_WRAPPER="$RUNTIME_COMPOSE_WRAPPER" \
JJD_ENV_FILE="$RUNTIME_ENV" \
IDENTITY_RUNTIME_ENV_FILE="$RUNTIME_IDENTITY_ENV" \
BOOTSTRAP_TEST_MODE=1 \
  bash "$SOURCE_COMPOSE_DIR/chat/bootstrap-identity-runtime.sh"

KEYCLOAK_ADMIN_PASSWORD="$bootstrap_password" \
COMPOSE_FILE="$RUNTIME_COMPOSE" \
COMPOSE_PROJECT_NAME="$PROJECT_NAME" \
COMPOSE_ENV_FILES="$RUNTIME_ENV" \
COMPOSE_WRAPPER="$RUNTIME_COMPOSE_WRAPPER" \
JJD_ENV_FILE="$RUNTIME_ENV" \
IDENTITY_RUNTIME_ENV_FILE="$RUNTIME_IDENTITY_ENV" \
BOOTSTRAP_TEST_MODE=1 \
  bash "$SOURCE_COMPOSE_DIR/chat/bootstrap-directory-runtime.sh"

reconcile_portal_client_secret

run_compose \
  --env-file "$RUNTIME_ENV" \
  -p "$PROJECT_NAME" \
  -f "$RUNTIME_COMPOSE" \
  -f "$SCRIPT_DIR/jjdguard-home.override.yml" \
  up -d --no-deps control-plane chat-idp chat-portal-ui chat-portal-proxy
run_compose \
  --env-file "$RUNTIME_ENV" \
  -p "$PROJECT_NAME" \
  -f "$RUNTIME_COMPOSE" \
  -f "$SCRIPT_DIR/jjdguard-home.override.yml" \
  up -d --no-deps --force-recreate chat-edge

echo "[ok] home LDAP、AD、OIDC 身份测试环境已部署"
