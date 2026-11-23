#!/usr/bin/env bash
# Regression test: identity-lab startup definitions are executable by their images.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COMPOSE="$REPO_ROOT/deploy/identity-lab/docker-compose.identity-lab.yml"
LDAP_LDIF="$REPO_ROOT/deploy/identity-lab/openldap/bootstrap.ldif"
JJD_REALM="$REPO_ROOT/deploy/identity-lab/keycloak/jjdguard-realm.json"
REALMS=("$REPO_ROOT/deploy/identity-lab/keycloak/enterprise-realm.json" "$JJD_REALM")
SMB_PROVISION="$REPO_ROOT/deploy/identity-lab/samba/provision.sh"

if grep -Eq 'ipv4_address:|subnet:|172\.31\.0\.0/24' "$COMPOSE"; then echo "fixed Docker addressing" >&2; exit 1; fi
if ! grep -Fq 'apk add --no-cache openssl' "$COMPOSE" || grep -Fq '<(printf' "$COMPOSE"; then echo "non-portable cert-init" >&2; exit 1; fi
if grep -Fq 'lab-ldap-certs:/container/service/slapd/assets/certs:ro' "$COMPOSE"; then echo "read-only LDAP certificate mount" >&2; exit 1; fi
if grep -qE '"_lab_note"|"addTokenRole"' "${REALMS[@]}"; then echo "Keycloak 25 realm contains unsupported fields" >&2; exit 1; fi
if ! jq -e '.users | all(.credentials[]?.value | startswith("${"))' "${REALMS[0]}" >/dev/null; then echo "enterprise realm contains a literal test password" >&2; exit 1; fi
for realm in "${REALMS[@]}"; do
  if ! jq -e '[.users[]?.credentials[]?.value] | all(startswith("${") and endswith("}"))' "$realm" >/dev/null; then
    echo "realm contains a literal user credential" >&2; exit 1
  fi
done
if awk '/^userPassword:/ && $0 !~ /^userPassword:: __LDAP_[A-Z]+_PASSWORD_B64__$/ {exit 1}' "$LDAP_LDIF"; then :; else echo "LDAP seed contains a literal user password" >&2; exit 1; fi
if [ "$(grep -Ec '^userPassword:: __LDAP_[A-Z]+_PASSWORD_B64__$' "$LDAP_LDIF")" -ne 4 ]; then echo "LDAP password placeholders are incomplete" >&2; exit 1; fi
if grep -Eq 'user create (ad-bob|ad-disabled) [^"$]' "$SMB_PROVISION" ||
   ! grep -Fq 'AD_BOB_PASSWORD=${AD_BOB_PASSWORD:?' "$SMB_PROVISION" ||
   ! grep -Fq 'AD_DISABLED_PASSWORD=${AD_DISABLED_PASSWORD:?' "$SMB_PROVISION"; then
  echo "Samba seed does not require injected user passwords" >&2; exit 1
fi
if ! jq -e '
  (.identityProviders[] | select(.alias == "enterprise") |
    .firstBrokerLoginFlowAlias == "identity-lab first broker login") and
  (.authenticationFlows[] | select(.alias == "identity-lab first broker login") |
    (.authenticationExecutions | length == 1) and
    .authenticationExecutions[0].authenticator == "idp-create-user-if-unique") and
  ([.authenticationFlows[]?.authenticationExecutions[]?.authenticator] |
    all(. != "idp-auto-link" and . != "idp-confirm-link"))
' "$JJD_REALM" >/dev/null; then
  echo "enterprise broker flow can link same-email identities" >&2; exit 1
fi
if ! jq -e '.components["org.keycloak.storage.UserStorageProvider"] | all(.subComponents | type == "object")' "$JJD_REALM" >/dev/null; then echo "LDAP mapper subComponents is not Keycloak export map" >&2; exit 1; fi
if ! jq -e '.components["org.keycloak.storage.UserStorageProvider"] | all(.config.editMode == ["READ_ONLY"])' "$JJD_REALM" >/dev/null; then echo "LDAP federation editMode is not READ_ONLY" >&2; exit 1; fi
if ! jq -e '
  ([.clientScopes[]?.name] | sort) == ["email", "groups", "profile"] and
  (.clients[] | select(.clientId == "jjdguard-broker") |
    (.defaultClientScopes | sort) == ["email", "groups", "profile"])
' "${REALMS[0]}" >/dev/null; then
  echo "enterprise broker scopes are not registered in the enterprise realm" >&2
  exit 1
fi
if ! jq -e '.components["org.keycloak.storage.UserStorageProvider"][] | select(.name == "jjdguard-directory") | .config.userObjectClasses == ["inetOrgPerson", "organizationalPerson"]' "$JJD_REALM" >/dev/null; then echo "LDAP federation userObjectClasses is not a Keycloak multi-value attribute list" >&2; exit 1; fi
if ! jq -e '.components["org.keycloak.storage.UserStorageProvider"][] | select(.name == "jjdguard-directory") | .subComponents["org.keycloak.storage.ldap.mappers.LDAPStorageMapper"][] | select(.name == "username" and .providerId == "user-attribute-ldap-mapper") | .config == {"ldap.attribute":["uid"],"user.model.attribute":["username"],"read.only":["true"],"always.read.value.from.ldap":["true"],"is.mandatory.in.ldap":["true"]}' "$JJD_REALM" >/dev/null; then echo "LDAP federation lacks the Keycloak username attribute mapper" >&2; exit 1; fi
if ! sed -n '/^dn: cn=dept-marketing,ou=Groups,dc=jjdguard-lab,dc=test$/,/^$/p' "$LDAP_LDIF" | grep -Fxq 'member: uid=ldap-bob,ou=People,dc=jjdguard-lab,dc=test'; then echo "invalid empty LDAP target group" >&2; exit 1; fi
if grep -Fq 'echo -e GET /health/ready' "$COMPOSE" || ! grep -Fq 'samba-tool user list 2>/dev/null | grep -qx ad-bob' "$COMPOSE" || ! grep -Fq './samba/entrypoint.sh:/entrypoint.sh:ro' "$COMPOSE"; then echo "invalid service health check or AD seed entrypoint" >&2; exit 1; fi
if grep -Fq 'GET /health/ready' "$COMPOSE" || [ "$(grep -Fc 'test: ["CMD-SHELL", "exec 3<>/dev/tcp/localhost/9000"]' "$COMPOSE")" -ne 2 ]; then echo "Keycloak TLS management health checks are not TCP probes" >&2; exit 1; fi
if [ "$(grep -Fc 'KC_HEALTH_ENABLED: "true"' "$COMPOSE")" -ne 2 ]; then echo "Keycloak health endpoints are not enabled" >&2; exit 1; fi
if [ "$(grep -Fc 'KC_CACHE: local' "$COMPOSE")" -ne 2 ]; then echo "Keycloak instances are not isolated cache nodes" >&2; exit 1; fi
if ! grep -Fq -- '--https-certificate-file=/etc/keycloak-tls/enterprise-keycloak.crt' "$COMPOSE" || ! grep -Fq -- '--https-certificate-file=/etc/keycloak-tls/jjdguard-keycloak.crt' "$COMPOSE"; then echo "Keycloak HTTPS listeners do not use source-specific certificates" >&2; exit 1; fi
if grep -Fq 'lab-ad-data:/etc/keycloak-ad-ca:ro' "$COMPOSE" || grep -Fq '/etc/keycloak-ad-ca/private/tls/ca.pem' "$COMPOSE"; then echo "JJD Keycloak still trusts Samba through an obsolete data-volume path" >&2; exit 1; fi

if ! grep -Fq 'lab-samba-tls:/var/lib/samba/private/tls' "$COMPOSE" || ! grep -Fq 'cp /samba/samba-ad.crt /samba/cert.pem' "$COMPOSE"; then echo "Samba AD does not receive its source-specific leaf certificate" >&2; exit 1; fi
if ! jq -e '.components["org.keycloak.storage.UserStorageProvider"][] | select(.name == "ad-federation") | .subComponents["org.keycloak.storage.ldap.mappers.LDAPStorageMapper"][] | select(.name == "username" and .providerId == "user-attribute-ldap-mapper") | .config == {"ldap.attribute":["sAMAccountName"],"user.model.attribute":["username"],"read.only":["true"],"always.read.value.from.ldap":["true"],"is.mandatory.in.ldap":["true"]}' "$JJD_REALM" >/dev/null; then echo "AD federation lacks the Keycloak username attribute mapper" >&2; exit 1; fi
SMB_PROVISION="$REPO_ROOT/deploy/identity-lab/samba/provision.sh"
if ! jq -e '.components["org.keycloak.storage.UserStorageProvider"][] | select(.name == "ad-federation") | .subComponents["org.keycloak.storage.ldap.mappers.LDAPStorageMapper"][] | select(.name == "ad-group-mapper") | .config["groups.dn"] == ["CN=Users,DC=ad,DC=jjdguard-lab,DC=test"]' "$JJD_REALM" >/dev/null; then echo "AD group mapper DN does not match provisioned groups" >&2; exit 1; fi
if ! grep -Fq 'department: operations' "$SMB_PROVISION"; then echo "ad-bob lacks a real AD department attribute" >&2; exit 1; fi
MAKEFILE="$REPO_ROOT/Makefile"
ACCEPTANCE_DOC="$REPO_ROOT/docs/testing/enterprise-identity-acceptance.md"
if ! grep -Fq 'identity-lab-wait.sh' "$MAKEFILE" || [ ! -x "$REPO_ROOT/scripts/identity-lab-wait.sh" ]; then echo "identity-lab-up lacks the service-aware wait gate" >&2; exit 1; fi
if ! grep -Fq '/tmp/jjdguard-identity-lab-control-plane' "$MAKEFILE" ||
   ! grep -Fq 'IDENTITY_LAB_GO ?= /usr/local/go/bin/go' "$MAKEFILE" ||
   ! grep -Fq '$(IDENTITY_LAB_GO) build' "$MAKEFILE"; then echo "identity-lab-up does not build the real control-plane" >&2; exit 1; fi
if ! grep -Fq 'mandatory' "$ACCEPTANCE_DOC" || grep -Eqi 'optional|not required|resource-limited skip' "$MAKEFILE" "$ACCEPTANCE_DOC"; then echo "identity lab E2E is still documented as optional" >&2; exit 1; fi
for service in control-plane-postgres control-plane-redis control-plane control-plane-seed identity-portal; do
  if ! grep -Eq "^  ${service}:" "$COMPOSE"; then echo "identity lab lacks real runtime service ${service}" >&2; exit 1; fi
done
if ! grep -Fq 'head -n 1' "$COMPOSE" ||
   ! grep -Fq '$${PGDATA}/postmaster.pid' "$COMPOSE"; then
  echo "PostgreSQL healthcheck can accept the temporary init postmaster" >&2
  exit 1
fi
RUNTIME="$REPO_ROOT/scripts/identity-lab-runtime-acceptance.sh"
if [ ! -s "$REPO_ROOT/scripts/identity-lab-portal-probe.py" ] ||
   ! grep -Fq 'identity-lab-portal-probe.py' "$RUNTIME" ||
   ! grep -Fq 'identity-lab-runtime-acceptance.sh' "$REPO_ROOT/scripts/identity-lab-smoke.sh"; then
  echo "full smoke does not cross the real Portal callback" >&2
  exit 1
fi
if grep -Fq 'run_password_probe' "$REPO_ROOT/scripts/identity-lab-smoke.sh" "$RUNTIME"; then
  echo "full smoke still substitutes password grant for Portal login" >&2
  exit 1
fi
if ! grep -Fq '/protocol/openid-connect/userinfo' "$REPO_ROOT/scripts/identity-lab-oidc-probe.py"; then
  echo "claims probe does not verify the userinfo response consumed by Auth.js" >&2
  exit 1
fi
for leaf in openldap samba-ad enterprise-keycloak jjdguard-keycloak; do
  if ! grep -Fq "${leaf}.crt" "$COMPOSE" || ! grep -Fq "${leaf}.key" "$COMPOSE"; then
    echo "identity source ${leaf} lacks an independent TLS leaf" >&2
    exit 1
  fi
done
if grep -Fq 'lab-server.crt' "$COMPOSE" || grep -Fq 'lab-server.key' "$COMPOSE"; then
  echo "identity sources still share one TLS leaf" >&2
  exit 1
fi
MAKE_ENV_LINE='export IDENTITY_LAB_ENV_FILE := $(abspath $(if $(wildcard $(IDENTITY_LAB_DIR)/.env),$(IDENTITY_LAB_DIR)/.env,$(IDENTITY_LAB_DIR)/.env.example))'
grep -Fq "$MAKE_ENV_LINE" "$MAKEFILE" || { echo "Makefile lacks side-effect-free env selection" >&2; exit 1; }
if grep -Eq 'cp .*identity-lab.*\.env|cp .*ENV_EXAMPLE.*\.env' "$MAKEFILE"; then echo "identity-lab target creates .env" >&2; exit 1; fi
up_recipe="$(sed -n '/^identity-lab-up:/,/^[^[:space:]].*:/p' "$MAKEFILE")"
grep -Fq 'down -v --remove-orphans' <<<"$up_recipe" || { echo "identity-lab-up can reuse stale volumes" >&2; exit 1; }
grep -Fq 'identity-lab-admin-toggle-test.py' "$MAKEFILE" || { echo "identity-lab-check omits admin toggle regressions" >&2; exit 1; }
if grep -Eqi '资源有限|不强求启动|resource-limited skip' "$REPO_ROOT/scripts/identity-lab-smoke.sh" "$ACCEPTANCE_DOC"; then echo "identity lab still contains resource-limited skip language" >&2; exit 1; fi
for volume in lab-ca-public lab-openldap-tls lab-samba-tls lab-enterprise-keycloak-tls lab-jjdguard-keycloak-tls; do
  grep -Eq "^  ${volume}:" "$COMPOSE" || { echo "missing isolated TLS volume: $volume" >&2; exit 1; }
done
if grep -Eq 'lab-(ldap|keycloak)-certs' "$COMPOSE"; then echo "shared private-key volume remains" >&2; exit 1; fi
for spec in 'openldap:lab-openldap-tls' 'samba-ad:lab-samba-tls' 'enterprise-keycloak:lab-enterprise-keycloak-tls' 'jjdguard-keycloak:lab-jjdguard-keycloak-tls'; do
  service="${spec%%:*}"; volume="${spec#*:}"
  service_block="$(sed -n "/^  ${service}:/,/^  [a-zA-Z0-9-]\+:/p" "$COMPOSE")"
  grep -Fq "$volume:" <<<"$service_block" || { echo "$service lacks its private TLS volume" >&2; exit 1; }
  other_private="$(printf '%s\n' lab-openldap-tls lab-samba-tls lab-enterprise-keycloak-tls lab-jjdguard-keycloak-tls | grep -Fvx "$volume")"
  while IFS= read -r other; do ! grep -Fq "$other:" <<<"$service_block" || { echo "$service can see another service private key" >&2; exit 1; }; done <<<"$other_private"
done
portal_block="$(sed -n '/^  identity-portal:/,/^  [a-zA-Z0-9-]\+:/p' "$COMPOSE")"
grep -Fq 'lab-ca-public:' <<<"$portal_block" || { echo "Portal lacks public CA volume" >&2; exit 1; }
! grep -Eq 'lab-(openldap|samba|enterprise-keycloak|jjdguard-keycloak)-tls:' <<<"$portal_block" || { echo "Portal can see a private TLS volume" >&2; exit 1; }
control_plane_block="$(sed -n '/^  control-plane:/,/^  [a-zA-Z0-9-]\+:/p' "$COMPOSE")"
jjdguard_keycloak_block="$(sed -n '/^  jjdguard-keycloak:/,/^  [a-zA-Z0-9-]\+:/p' "$COMPOSE")"
enterprise_keycloak_block="$(sed -n '/^  enterprise-keycloak:/,/^  [a-zA-Z0-9-]\+:/p' "$COMPOSE")"
for key in IDENTITY_RUNTIME_CLIENT_SECRET DIRECTORY_RUNTIME_CLIENT_SECRET; do
  grep -Fq "$key:" <<<"$control_plane_block" || { echo "control-plane lacks $key" >&2; exit 1; }
  grep -Fq "$key:" <<<"$jjdguard_keycloak_block" || { echo "jjdguard-keycloak lacks $key" >&2; exit 1; }
  ! grep -Fq "$key:" <<<"$enterprise_keycloak_block" || { echo "enterprise-keycloak has unnecessary $key" >&2; exit 1; }
done
if ! jq -e '(.users[] | select(.serviceAccountClientId == "jjdguard-directory-orchestrator") | .clientRoles["realm-management"] | sort) == ["manage-realm", "manage-users", "view-realm"] and (.users[] | select(.serviceAccountClientId == "jjdguard-control-plane") | .clientRoles["realm-management"]) == ["manage-identity-providers"]' "$JJD_REALM" >/dev/null; then echo "runtime service accounts do not have the exact minimum realm-management roles" >&2; exit 1; fi
if ! jq -e '[.clients[] | select(.clientId == "jjdguard-directory-orchestrator" or .clientId == "jjdguard-control-plane") | .defaultClientScopes] | length == 2 and all(. == ["runtime-realm-management-roles"])' "$JJD_REALM" >/dev/null; then echo "runtime clients do not emit their exact assigned roles" >&2; exit 1; fi
if ! jq -e '.clientScopes[] | select(.name == "runtime-realm-management-roles") | .protocol == "openid-connect" and (.protocolMappers | length == 1) and .protocolMappers[0].protocolMapper == "oidc-usermodel-client-role-mapper" and .protocolMappers[0].config["usermodel.clientRoleMapping.clientId"] == "realm-management" and .protocolMappers[0].config["claim.name"] == "resource_access.realm-management.roles" and .protocolMappers[0].config["access.token.claim"] == "true" and .protocolMappers[0].config["id.token.claim"] == "false" and .protocolMappers[0].config["userinfo.token.claim"] == "false"' "$JJD_REALM" >/dev/null; then echo "runtime role scope is not restricted to realm-management access-token roles" >&2; exit 1; fi
CHECK_ENV_LINE='IDENTITY_LAB_CHECK_ENV_FILE := $(abspath $(IDENTITY_LAB_DIR)/.env.example)'
grep -Fq "$CHECK_ENV_LINE" "$MAKEFILE" || { echo "identity-lab-check does not pin .env.example" >&2; exit 1; }
check_recipe="$(sed -n '/^identity-lab-check:/,/^[^[:space:]].*:/p' "$MAKEFILE")"
grep -Fq '$(IDENTITY_LAB_CHECK_COMPOSE_CMD) config' <<<"$check_recipe" || { echo "identity-lab-check compose config can use a stale .env" >&2; exit 1; }
grep -Fq 'IDENTITY_LAB_ENV_FILE=$(IDENTITY_LAB_CHECK_ENV_FILE)' <<<"$check_recipe" || { echo "identity-lab-check smoke can use a stale .env" >&2; exit 1; }
for key in DIRECTORY_RUNTIME_ALLOWED_URLS JJD_IDENTITY_RUNTIME_ALLOWED_URLS; do
  grep -Fq "$key:" <<<"$control_plane_block" || { echo "control-plane lacks $key" >&2; exit 1; }
  ! grep -Fq "$key:" <<<"$jjdguard_keycloak_block" || { echo "jjdguard-keycloak has unnecessary $key" >&2; exit 1; }
  ! grep -Fq "$key:" <<<"$enterprise_keycloak_block" || { echo "enterprise-keycloak has unnecessary $key" >&2; exit 1; }
  grep -Eq "^${key}=https://jjdguard-keycloak:8443/sso$" "$REPO_ROOT/deploy/identity-lab/.env.example" || { echo "$key is not pinned to the lab Keycloak" >&2; exit 1; }
done
portal_prisma_block="$(sed -n '/^  portal-prisma:/,/^  [a-zA-Z0-9-]\+:/p' "$COMPOSE")"
grep -Fq 'portal-session-state:/state' <<<"$portal_prisma_block" ||
  { echo "portal session volume is not owned by a Compose service" >&2; exit 1; }


echo "PASS: identity lab startup definitions are runnable"
