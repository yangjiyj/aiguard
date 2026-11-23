#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
# Reuse the production captcha SVG parser while keeping API requests inside the
# isolated identity-lab Docker network.
# shellcheck disable=SC1091
. "$REPO_ROOT/deploy/lib/captcha-login.sh"
LAB_DIR="$REPO_ROOT/deploy/identity-lab"
COMPOSE="$LAB_DIR/docker-compose.identity-lab.yml"
ENV_FILE="${IDENTITY_LAB_ENV_FILE:-}"
if [ -z "$ENV_FILE" ]; then
  if [ -f "$LAB_DIR/.env" ]; then ENV_FILE="$LAB_DIR/.env"; else ENV_FILE="$LAB_DIR/.env.example"; fi
fi
[ -f "$ENV_FILE" ] || { echo "identity-lab runtime failed: env file is missing" >&2; exit 1; }

compose() {
  docker compose -f "$COMPOSE" --env-file "$ENV_FILE" "$@"
}

read_service_env() {
  local service="$1" key="$2" container_id value
  container_id="$(compose ps -a -q "$service" </dev/null)"
  if [ -z "$container_id" ]; then
    echo "identity-lab runtime missing service env: $service/$key" >&2
    return 1
  fi
  value="$(docker inspect "$container_id" --format '{{range .Config.Env}}{{println .}}{{end}}' |
    awk -v prefix="$key=" 'index($0,prefix)==1 {sub("^" prefix,""); print; exit}')"
  if [ -z "$value" ]; then
    echo "identity-lab runtime missing service env: $service/$key" >&2
    return 1
  fi
  printf '%s' "$value"
}

LOCAL_ALICE_PASSWORD="$(read_service_env jjdguard-keycloak LOCAL_ALICE_PASSWORD)"
LDAP_ADMIN_PASSWORD="$(read_service_env openldap LDAP_ADMIN_PASSWORD)"
LDAP_ALICE_PASSWORD="$(read_service_env ldap-seed LDAP_ALICE_PASSWORD)"
LDAP_CAROL_PASSWORD="$(read_service_env ldap-seed LDAP_CAROL_PASSWORD)"
AD_BOB_PASSWORD="$(read_service_env samba-ad AD_BOB_PASSWORD)"
ENTERPRISE_ERIN_PASSWORD="$(read_service_env enterprise-keycloak ENTERPRISE_ERIN_PASSWORD)"
ENTERPRISE_CAROL_PASSWORD="$(read_service_env enterprise-keycloak ENTERPRISE_CAROL_PASSWORD)"
ENTERPRISE_BROKER_CLIENT_SECRET="$(read_service_env enterprise-keycloak ENTERPRISE_BROKER_CLIENT_SECRET)"
PORTAL_OIDC_CLIENT_SECRET="$(read_service_env jjdguard-keycloak PORTAL_OIDC_CLIENT_SECRET)"
IDENTITY_RUNTIME_CLIENT_SECRET="$(read_service_env control-plane JJD_IDENTITY_RUNTIME_CLIENT_SECRET)"
DIRECTORY_RUNTIME_CLIENT_SECRET="$(read_service_env control-plane DIRECTORY_RUNTIME_CLIENT_SECRET)"
CONTROL_PLANE_ADMIN_USERNAME="$(read_service_env control-plane BOOTSTRAP_ADMIN_USERNAME)"
CONTROL_PLANE_ADMIN_PASSWORD="$(read_service_env control-plane BOOTSTRAP_ADMIN_PASSWORD)"
CONTROL_PLANE_ADMIN_NEW_PASSWORD="$(read_service_env control-plane CONTROL_PLANE_ADMIN_NEW_PASSWORD)"
CONTROL_API_TOKEN=""
DIRECTORY_ACTIVATE_BODY=""

DIRECTORY_DISABLED=0
SSO_DISABLED=0
LDAP_MOVED=0
LDAP_USER_DISABLED=0

fail() {
  printf 'AP%s FAIL: %s\n' "$1" "$2" >&2
  exit 1
}

pass() {
  printf 'AP%s PASS: %s\n' "$1" "$2"
}

run_control_api() {
  local method="$1" path="$2" body="${3:-}"
  CONTROL_API_METHOD="$method" CONTROL_API_PATH="$path" CONTROL_API_BODY="$body"
  export CONTROL_API_METHOD CONTROL_API_PATH CONTROL_API_BODY CONTROL_API_TOKEN
  docker run --rm --network jjdguard-identity-lab     --mount "type=bind,src=$SCRIPT_DIR/identity-lab-control-plane-api.py,dst=/control-api.py,readonly"     -e CONTROL_API_METHOD -e CONTROL_API_PATH -e CONTROL_API_BODY -e CONTROL_API_TOKEN     python:3.12-slim python /control-api.py </dev/null
}

valid_control_api_token() {
  case "$1" in
    ""|*[!A-Za-z0-9-]*) return 1 ;;
    *) return 0 ;;
  esac
}

login_control_plane_admin() {
  local challenge captcha_id captcha_image captcha_code login_body login_response
  challenge="$(run_control_api GET /admin/v1/captcha)" ||
    fail 10 "control-plane captcha challenge failed"
  captcha_id="$(printf '%s' "$challenge" | jq -er '.captcha_id | select(type == "string" and length > 0)')" ||
    fail 10 "control-plane captcha returned no identifier"
  captcha_image="$(printf '%s' "$challenge" | jq -er '.image | select(type == "string" and length > 0)')" ||
    fail 10 "control-plane captcha returned no image"
  captcha_code="$(captcha_code_from_image "$captcha_image")" ||
    fail 10 "control-plane captcha image could not be parsed"
  login_body="$(jq -nc     --arg username "$CONTROL_PLANE_ADMIN_USERNAME"     --arg password "$CONTROL_PLANE_ADMIN_PASSWORD"     --arg captcha_id "$captcha_id"     --arg captcha_code "$captcha_code"     '{username:$username,password:$password,captcha_id:$captcha_id,captcha_code:$captcha_code}')"
  login_response="$(run_control_api POST /admin/v1/login "$login_body")" ||
    fail 10 "control-plane admin login failed"
  CONTROL_API_TOKEN="$(printf '%s' "$login_response" | python3 -c 'import json,sys; print(json.load(sys.stdin)["token"])')"
  CONTROL_PASSWORD_CHANGE_REQUIRED="$(printf '%s' "$login_response" | python3 -c 'import json,sys; print(str(json.load(sys.stdin).get("password_change_required", False)).lower())')"
  valid_control_api_token "$CONTROL_API_TOKEN" || fail 10 "control-plane admin session was invalid"
  export CONTROL_API_TOKEN
}

configure_control_plane_sources() {
  local change_body ca directory_body directory_preview_response directory_preview_id identity_body
  login_control_plane_admin
  if [ "$CONTROL_PASSWORD_CHANGE_REQUIRED" = "true" ]; then
    change_body="$(jq -nc --arg current_password "$CONTROL_PLANE_ADMIN_PASSWORD" --arg new_password "$CONTROL_PLANE_ADMIN_NEW_PASSWORD" '{current_password:$current_password,new_password:$new_password}')"
    run_control_api POST /admin/v1/me/change-password "$change_body" >/dev/null ||
      fail 10 "control-plane bootstrap password rotation failed"
    CONTROL_API_TOKEN=""
    CONTROL_PLANE_ADMIN_PASSWORD="$CONTROL_PLANE_ADMIN_NEW_PASSWORD"
    login_control_plane_admin
  fi
  [ "$CONTROL_PASSWORD_CHANGE_REQUIRED" = "false" ] || fail 10 "control-plane admin still requires a password change"
  unset change_body CONTROL_PLANE_ADMIN_PASSWORD CONTROL_PLANE_ADMIN_NEW_PASSWORD

  ca="$(compose exec -T control-plane cat /ca/lab-ca.crt </dev/null)"
  directory_body="$(jq -nc     --arg bind_password "$LDAP_ADMIN_PASSWORD" --arg ca_cert_pem "$ca"     '{kind:"ldap",display_name:"Identity Lab LDAP",connection_url:"ldaps://openldap:636",bind_dn:"cn=admin,dc=jjdguard-lab,dc=test",bind_password:$bind_password,ca_cert_pem:$ca_cert_pem,base_dn:"dc=jjdguard-lab,dc=test",users_dn:"ou=People,dc=jjdguard-lab,dc=test",user_filter:"(objectClass=inetOrgPerson)",stable_id_attribute:"entryUUID",username_attribute:"uid",email_attribute:"mail",name_attribute:"cn"}')"
  run_control_api PUT /admin/v1/directory/sources/draft "$directory_body" >/dev/null ||
    fail 10 "directory draft setup failed"
  run_control_api POST /admin/v1/directory/sources/test '{}' >/dev/null ||
    fail 10 "directory connection test failed"
  directory_preview_response="$(run_control_api POST /admin/v1/directory/sources/preview '{}')" ||
    fail 10 "directory preview failed"
  directory_preview_id="$(printf '%s' "$directory_preview_response" | jq -er '.data.preview_id | select(type == "string" and length > 0)')" ||
    fail 10 "directory preview returned no identifier"
  DIRECTORY_ACTIVATE_BODY="$(jq -nc --arg preview_id "$directory_preview_id" '{preview_id:$preview_id,confirm:true}')"
  run_control_api POST /admin/v1/directory/sources/activate "$DIRECTORY_ACTIVATE_BODY" >/dev/null ||
    fail 10 "directory API activation failed"

  identity_body="$(jq -nc --arg client_secret "$ENTERPRISE_BROKER_CLIENT_SECRET"     '{display_name:"Identity Lab Enterprise SSO",issuer_url:"https://enterprise-keycloak:8443/realms/enterprise",client_id:"jjdguard-broker",client_secret:$client_secret,scopes:"openid profile email groups",subject_claim:"sub",username_claim:"preferred_username",name_claim:"name",email_claim:"email",dept_code_claim:"department",dept_name_claim:"department",groups_claim:"groups"}')"
  run_control_api PUT /admin/v1/identity/sources/draft "$identity_body" >/dev/null ||
    fail 10 "enterprise SSO draft setup failed"
  run_control_api POST /admin/v1/identity/sources/test '{}' >/dev/null ||
    fail 10 "enterprise SSO connection test failed"
  run_control_api POST /admin/v1/identity/sources/activate '{}' >/dev/null ||
    fail 10 "enterprise SSO API activation failed"
  unset ca directory_body directory_preview_response directory_preview_id identity_body
}

run_claims_probe() {
  local provider="$1" username="$2" password="$3" email="$4" group="$5" department="$6" idp_hint="$7"
  docker run --rm --network jjdguard-identity-lab \
    --mount type=volume,src=jjdguard-identity-lab_lab-ca-public,dst=/certs,readonly \
    --mount "type=bind,src=$SCRIPT_DIR/identity-lab-oidc-probe.py,dst=/probe.py,readonly" \
    -e IDENTITY_TEST_PROVIDER="$provider" \
    -e IDENTITY_TEST_USERNAME="$username" \
    -e IDENTITY_TEST_PASSWORD="$password" \
    -e IDENTITY_EXPECT_EMAIL="$email" \
    -e IDENTITY_EXPECT_GROUP="$group" \
    -e IDENTITY_EXPECT_DEPARTMENT="$department" \
    -e IDENTITY_TEST_IDP_HINT="$idp_hint" \
    -e PORTAL_OIDC_CLIENT_SECRET="$PORTAL_OIDC_CLIENT_SECRET" \
    python:3.12-slim python /probe.py </dev/null
}

assert_runtime_service_roles() {
  docker run --rm --network jjdguard-identity-lab \
    --mount type=volume,src=jjdguard-identity-lab_lab-ca-public,dst=/certs,readonly \
    --mount "type=bind,src=$SCRIPT_DIR/identity-lab-keycloak-role-probe.py,dst=/probe.py,readonly" \
    -e IDENTITY_RUNTIME_CLIENT_SECRET="$IDENTITY_RUNTIME_CLIENT_SECRET" \
    -e DIRECTORY_RUNTIME_CLIENT_SECRET="$DIRECTORY_RUNTIME_CLIENT_SECRET" \
    python:3.12-slim python /probe.py </dev/null
}

portal_login() {
  local provider="$1" username="$2" password="$3" expected_email="$4" session_file=""
  if [ "$#" -ge 5 ]; then session_file="$5"; fi
  local output
  output="$(docker run --rm --network jjdguard-identity-lab \
    --mount type=volume,src=jjdguard-identity-lab_lab-ca-public,dst=/certs,readonly \
    --mount type=volume,src=jjdguard-identity-lab_portal-session-state,dst=/state \
    --mount "type=bind,src=$SCRIPT_DIR/identity-lab-portal-probe.py,dst=/probe.py,readonly" \
    -e IDENTITY_TEST_PROVIDER="$provider" \
    -e IDENTITY_TEST_USERNAME="$username" \
    -e IDENTITY_TEST_PASSWORD="$password" \
    -e IDENTITY_EXPECT_EMAIL="$expected_email" \
    -e IDENTITY_SESSION_FILE="$session_file" \
    -e IDENTITY_OUTPUT_USER_ID=1 \
    python:3.12-slim python /probe.py </dev/null)"
  LAST_USER_ID="$(printf '%s\n' "$output" | sed -n 's/^RESULT_USER_ID=//p')"
  [[ "$LAST_USER_ID" =~ ^[A-Za-z0-9_-]+$ ]] || return 1
  printf '%s\n' "$output" | grep -Fq 'PASS: Portal'
}

portal_authorization_probe() {
  local models="$1" department="$2" chat_model="$3" denied_model="$4"
  docker run --rm --network jjdguard-identity-lab \
    --mount type=volume,src=jjdguard-identity-lab_lab-ca-public,dst=/certs,readonly \
    --mount type=volume,src=jjdguard-identity-lab_portal-session-state,dst=/state \
    --mount "type=bind,src=$SCRIPT_DIR/identity-lab-portal-probe.py,dst=/probe.py,readonly" \
    -e IDENTITY_SESSION_FILE=/state/ap8-baseline.cookies \
    -e IDENTITY_REUSE_SESSION=1 \
    -e IDENTITY_EXPECT_MODELS="$models" \
    -e IDENTITY_EXPECT_CHAT_DEPARTMENT="$department" \
    -e IDENTITY_CHAT_MODEL="$chat_model" \
    -e IDENTITY_DENY_CHAT_MODEL="$denied_model" \
    python:3.12-slim python /probe.py </dev/null
}

portal_login_must_fail() {
  if portal_login "$1" "$2" "$3" "$4" >/dev/null 2>&1; then
    return 1
  fi
}

query_db() {
  compose exec -T control-plane-postgres \
    psql -U identity_lab -d jjdguard -At -F '|' -c "$1" </dev/null
}

assert_stable_link() {
  local user_id="$1"
  [ "$(query_db "SELECT COUNT(*) FROM user_identity_links WHERE tenant_id='tenant_default' AND user_id='$user_id';")" = "1" ]
}

identity_state() {
  local user_id="$1"
  query_db "SELECT u.department_assignment_mode,u.department_id,EXTRACT(EPOCH FROM u.department_resolved_at),COALESCE(string_agg(tm.model_id,',' ORDER BY tm.model_id) FILTER (WHERE tm.allowed),'') FROM users u LEFT JOIN team_models tm ON tm.team_id=u.department_id WHERE u.tenant_id='tenant_default' AND u.id='$user_id' GROUP BY u.department_assignment_mode,u.department_id,u.department_resolved_at;"
}

wait_for_identity_state() {
  local user_id="$1" expected_mode="$2" expected_department="$3" expected_models="$4"
  local deadline=$((SECONDS+30)) state prefix
  while :; do
    state="$(identity_state "$user_id")"
    prefix="$(printf '%s' "$state" | cut -d'|' -f1-2)"
    if [ "$prefix" = "$expected_mode|$expected_department" ] &&
       [ "$(printf '%s' "$state" | cut -d'|' -f4)" = "$expected_models" ]; then
      LAST_IDENTITY_STATE="$state"
      return 0
    fi
    [ "$SECONDS" -lt "$deadline" ] || return 1
    sleep 1
  done
}

ldap_apply() {
  compose exec -T openldap ldapmodify -x \
    -H ldaps://localhost:636 -D cn=admin,dc=jjdguard-lab,dc=test \
    -w "$LDAP_ADMIN_PASSWORD"
}

ldap_move_to_marketing() {
  printf '%s\n' \
    'dn: cn=dept-research,ou=Groups,dc=jjdguard-lab,dc=test' \
    'changetype: modify' 'replace: member' \
    'member: uid=ldap-bob,ou=People,dc=jjdguard-lab,dc=test' '' \
    'dn: cn=dept-marketing,ou=Groups,dc=jjdguard-lab,dc=test' \
    'changetype: modify' 'add: member' \
    'member: uid=ldap-alice,ou=People,dc=jjdguard-lab,dc=test' | ldap_apply
}

ldap_restore_research() {
  printf '%s\n' \
    'dn: cn=dept-research,ou=Groups,dc=jjdguard-lab,dc=test' \
    'changetype: modify' 'replace: member' \
    'member: uid=ldap-alice,ou=People,dc=jjdguard-lab,dc=test' '' \
    'dn: cn=dept-marketing,ou=Groups,dc=jjdguard-lab,dc=test' \
    'changetype: modify' 'delete: member' \
    'member: uid=ldap-alice,ou=People,dc=jjdguard-lab,dc=test' | ldap_apply
}

ldap_disable_user() {
  printf '%s\n' \
    'dn: uid=ldap-alice,ou=People,dc=jjdguard-lab,dc=test' \
    'changetype: moddn' 'newrdn: uid=ldap-alice' 'deleteoldrdn: 1' \
    'newsuperior: ou=Disabled,dc=jjdguard-lab,dc=test' | ldap_apply
}

ldap_restore_user() {
  printf '%s\n' \
    'dn: uid=ldap-alice,ou=Disabled,dc=jjdguard-lab,dc=test' \
    'changetype: moddn' 'newrdn: uid=ldap-alice' 'deleteoldrdn: 1' \
    'newsuperior: ou=People,dc=jjdguard-lab,dc=test' | ldap_apply
}

cleanup() {
  if [ "$LDAP_USER_DISABLED" -eq 1 ]; then
    ldap_restore_user >/dev/null 2>&1 || true
  fi
  if [ "$LDAP_MOVED" -eq 1 ]; then
    ldap_restore_research >/dev/null 2>&1 || true
  fi
  if [ "$DIRECTORY_DISABLED" -eq 1 ]; then
    run_control_api POST /admin/v1/directory/sources/activate "$DIRECTORY_ACTIVATE_BODY" >/dev/null 2>&1 || true
  fi
  if [ "$SSO_DISABLED" -eq 1 ]; then
    run_control_api POST /admin/v1/identity/sources/activate '{}' >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT INT TERM

configure_control_plane_sources
assert_runtime_service_roles >/dev/null ||
  fail 10 "runtime service-account tokens had non-minimal roles"

portal_login account-login local-alice "$LOCAL_ALICE_PASSWORD" "" ||
  fail 1 "local account did not complete the Portal callback"
LOCAL_USER_ID="$LAST_USER_ID"
assert_stable_link "$LOCAL_USER_ID" || fail 1 "local stable link missing"
pass 1 "local account completed the Portal callback"

portal_login account-login ldap-alice "$LDAP_ALICE_PASSWORD" ldap-alice@jjdguard-lab.test /state/ap8-baseline.cookies ||
  fail 2 "LDAP account did not complete the Portal callback"
LDAP_USER_ID="$LAST_USER_ID"
assert_stable_link "$LDAP_USER_ID" || fail 2 "LDAP stable link missing"
pass 2 "LDAP account completed the Portal callback"

portal_login account-login ad-bob "$AD_BOB_PASSWORD" ad-bob@ad.jjdguard-lab.test ||
  fail 3 "AD account did not complete the Portal callback"
AD_USER_ID="$LAST_USER_ID"
assert_stable_link "$AD_USER_ID" || fail 3 "AD stable link missing"
run_claims_probe account-login ad-bob "$AD_BOB_PASSWORD" ad-bob@ad.jjdguard-lab.test dept-research-ad operations "" >/dev/null ||
  fail 3 "AD group/department claims were not mapped"
wait_for_identity_state "$AD_USER_ID" automatic lab-research lab-research-model ||
  fail 3 "AD mapped identity did not receive the research model"
pass 3 "AD claims mapped to the research department and model"

portal_login enterprise-sso enterprise-erin "$ENTERPRISE_ERIN_PASSWORD" enterprise-erin@enterprise-lab.test ||
  fail 4 "enterprise SSO did not complete the Portal callback"
ENTERPRISE_USER_ID="$LAST_USER_ID"
assert_stable_link "$ENTERPRISE_USER_ID" || fail 4 "OIDC stable link missing"
run_claims_probe enterprise-sso enterprise-erin "$ENTERPRISE_ERIN_PASSWORD" enterprise-erin@enterprise-lab.test dept-research research enterprise >/dev/null ||
  fail 4 "enterprise group/department claims were not mapped"
wait_for_identity_state "$ENTERPRISE_USER_ID" automatic lab-research lab-research-model ||
  fail 4 "enterprise mapped identity did not receive the research model"
pass 4 "enterprise claims mapped to the research department and model"

portal_login account-login ldap-carol "$LDAP_CAROL_PASSWORD" oidc-carol@jjdguard-lab.test ||
  fail 5 "LDAP same-email identity failed"
LDAP_CAROL_ID="$LAST_USER_ID"
portal_login enterprise-sso oidc-carol "$ENTERPRISE_CAROL_PASSWORD" oidc-carol@jjdguard-lab.test ||
  fail 5 "OIDC same-email identity failed"
OIDC_CAROL_ID="$LAST_USER_ID"
[ "$LDAP_CAROL_ID" != "$OIDC_CAROL_ID" ] || fail 5 "same-email identities merged"
[ "$(query_db "SELECT COUNT(*) FROM user_identity_links WHERE tenant_id='tenant_default' AND user_id IN ('$LDAP_CAROL_ID','$OIDC_CAROL_ID');")" = "2" ] ||
  fail 5 "stable tuples were not both persisted"
pass 5 "same email with distinct stable identities remained separate"

DEFAULT_CHAT_DEPARTMENT_ID="$(query_db "SELECT id FROM teams WHERE tenant_id='tenant_default' AND system_key='chat_default';")"
DEFAULT_CHAT_MODEL_COUNT="$(query_db "SELECT COUNT(DISTINCT m.id) FROM teams t JOIN providers p ON p.tenant_id=t.tenant_id JOIN models m ON m.provider_id=p.id WHERE t.id='$DEFAULT_CHAT_DEPARTMENT_ID' AND t.model_access_mode='all_active' AND p.status='active' AND m.status='active';")"
LOCAL_STATE="$(identity_state "$LOCAL_USER_ID")"
[ "$(printf '%s' "$LOCAL_STATE" | cut -d'|' -f1-2)" = "automatic|$DEFAULT_CHAT_DEPARTMENT_ID" ] ||
  fail 6 "unmapped identity did not enter the Chat default department"
[ "${DEFAULT_CHAT_MODEL_COUNT:-0}" -gt 0 ] ||
  fail 6 "Chat default department has no active model"
pass 6 "unmapped active identity entered the Chat default department with active models"

wait_for_identity_state "$LDAP_USER_ID" automatic lab-research lab-research-model ||
  fail 7 "LDAP group did not grant the research model"
pass 7 "LDAP group granted exactly the research model"

portal_authorization_probe lab-research-model lab-research lab-research-model "" >/dev/null ||
  fail 8 "baseline Auth.js cookie did not receive the research model"
BEFORE_VERSION="$(printf '%s' "$LAST_IDENTITY_STATE" | cut -d'|' -f3)"
LDAP_MOVED=1
ldap_move_to_marketing >/dev/null || fail 8 "LDAP group migration failed"
portal_login account-login ldap-alice "$LDAP_ALICE_PASSWORD" ldap-alice@jjdguard-lab.test ||
  fail 8 "LDAP user could not reauthenticate after group migration"
[ "$LAST_USER_ID" = "$LDAP_USER_ID" ] || fail 8 "stable identity changed during migration"
wait_for_identity_state "$LDAP_USER_ID" automatic lab-marketing lab-marketing-model ||
  fail 8 "department/model migration did not converge"
AFTER_VERSION="$(printf '%s' "$LAST_IDENTITY_STATE" | cut -d'|' -f3)"
awk "BEGIN { exit !($AFTER_VERSION > $BEFORE_VERSION) }" ||
  fail 8 "department version did not advance"
portal_authorization_probe lab-marketing-model lab-marketing lab-marketing-model lab-research-model >/dev/null ||
  fail 8 "same Auth.js cookie did not revoke research and receive marketing"
ldap_restore_research >/dev/null || fail 8 "LDAP group restoration failed"
portal_login account-login ldap-alice "$LDAP_ALICE_PASSWORD" ldap-alice@jjdguard-lab.test ||
  fail 8 "LDAP user could not reauthenticate after source restoration"
[ "$LAST_USER_ID" = "$LDAP_USER_ID" ] || fail 8 "stable identity changed after source restoration"
wait_for_identity_state "$LDAP_USER_ID" automatic lab-research lab-research-model ||
  fail 8 "department/model restoration did not converge"
RESTORED_VERSION="$(printf '%s' "$LAST_IDENTITY_STATE" | cut -d'|' -f3)"
awk "BEGIN { exit !($RESTORED_VERSION > $AFTER_VERSION) }" ||
  fail 8 "department version did not advance after restoration"
portal_authorization_probe lab-research-model lab-research lab-research-model lab-marketing-model >/dev/null ||
  fail 8 "same Auth.js cookie did not restore research authorization"
LDAP_MOVED=0
pass 8 "department moved and restored with immediate model revocation"

portal_login account-login ldap-alice "$LDAP_ALICE_PASSWORD" ldap-alice@jjdguard-lab.test ||
  fail 9 "LDAP user was not active before disable"
LDAP_USER_DISABLED=1
ldap_disable_user >/dev/null || fail 9 "LDAP user disable move failed"
portal_login_must_fail account-login ldap-alice "$LDAP_ALICE_PASSWORD" ldap-alice@jjdguard-lab.test ||
  fail 9 "disabled LDAP user still authenticated"
ldap_restore_user >/dev/null || fail 9 "LDAP user restoration failed"
LDAP_USER_DISABLED=0
portal_login account-login ldap-alice "$LDAP_ALICE_PASSWORD" ldap-alice@jjdguard-lab.test ||
  fail 9 "restored LDAP user did not recover"
pass 9 "active user was rejected after disable and recovered after restore"

DIRECTORY_DISABLED=1
run_control_api POST /admin/v1/directory/sources/disable '{"confirm":true}' >/dev/null ||
  fail 10 "directory disable through control-plane failed"
portal_login_must_fail account-login ldap-alice "$LDAP_ALICE_PASSWORD" ldap-alice@jjdguard-lab.test ||
  fail 10 "disabled directory still authenticated"
portal_login account-login local-alice "$LOCAL_ALICE_PASSWORD" "" ||
  fail 10 "local login failed while directory was disabled"
portal_login enterprise-sso enterprise-erin "$ENTERPRISE_ERIN_PASSWORD" enterprise-erin@enterprise-lab.test ||
  fail 10 "enterprise SSO failed while directory was disabled"
run_control_api POST /admin/v1/directory/sources/activate "$DIRECTORY_ACTIVATE_BODY" >/dev/null ||
  fail 10 "directory recovery through control-plane failed"
DIRECTORY_DISABLED=0
portal_login account-login ldap-alice "$LDAP_ALICE_PASSWORD" ldap-alice@jjdguard-lab.test ||
  fail 10 "directory login did not recover"

SSO_DISABLED=1
run_control_api POST /admin/v1/identity/sources/disable '{"confirm":true}' >/dev/null ||
  fail 10 "enterprise SSO disable through control-plane failed"
portal_login_must_fail enterprise-sso enterprise-erin "$ENTERPRISE_ERIN_PASSWORD" enterprise-erin@enterprise-lab.test ||
  fail 10 "disabled enterprise SSO still authenticated"
portal_login account-login local-alice "$LOCAL_ALICE_PASSWORD" "" ||
  fail 10 "local login failed while enterprise SSO was disabled"
portal_login account-login ldap-alice "$LDAP_ALICE_PASSWORD" ldap-alice@jjdguard-lab.test ||
  fail 10 "directory login failed while enterprise SSO was disabled"
run_control_api POST /admin/v1/identity/sources/activate '{}' >/dev/null ||
  fail 10 "enterprise SSO recovery through control-plane failed"
SSO_DISABLED=0
portal_login enterprise-sso enterprise-erin "$ENTERPRISE_ERIN_PASSWORD" enterprise-erin@enterprise-lab.test ||
  fail 10 "enterprise SSO did not recover"
pass 10 "control-plane APIs toggled directory and enterprise SSO independently and recovered"

trap - EXIT INT TERM
