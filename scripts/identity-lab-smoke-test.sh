#!/usr/bin/env bash
# Shell-level regression tests for identity-lab-smoke.sh.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SMOKE="$REPO_ROOT/scripts/identity-lab-smoke.sh"
RUNTIME="$REPO_ROOT/scripts/identity-lab-runtime-acceptance.sh"
MAKEFILE="$REPO_ROOT/Makefile"
TEST_ENV="$REPO_ROOT/deploy/identity-lab/.env.example"
TEST_ROOT="$(mktemp -d)"
trap 'rm -rf "$TEST_ROOT"' EXIT

mkdir -p "$TEST_ROOT/bin"
cat > "$TEST_ROOT/bin/docker" <<'EOF'
#!/usr/bin/env bash
# Compose ps can simulate either an absent lab or an unhealthy long-running service.
if [[ "$*" == *" config"* ]]; then
  [[ "$*" == *" --env-file "* ]] || {
    echo "compose config was invoked without --env-file" >&2
    exit 9
  }
  exit 0
fi
if [[ "$*" == *" ps "* ]]; then
  if [ "${FAKE_UNHEALTHY:-0}" = "1" ]; then printf 'fake-%s\n' "${!#}"; fi
  exit 0
fi
if [ "$1" = "inspect" ] && [ "${FAKE_UNHEALTHY:-0}" = "1" ]; then
  printf 'running|0|unhealthy\n'
  exit 0
fi
exec /usr/bin/docker "$@"
EOF
chmod +x "$TEST_ROOT/bin/docker"

if ! (
  cd "$TEST_ROOT"
  PATH="$TEST_ROOT/bin:$PATH" "$SMOKE" --check-only >/dev/null
); then
  echo "check-only smoke does not pass an explicit env file outside the repository cwd" >&2
  exit 1
fi

if ! grep -Fq 'export IDENTITY_LAB_ENV_FILE := $(abspath' "$MAKEFILE"; then
  echo "Makefile does not export an absolute identity-lab env file" >&2
  exit 1
fi

if ! grep -Fq 'docker compose -f "$COMPOSE" --env-file "$ENV_FILE"' "$RUNTIME"; then
  echo "runtime acceptance compose calls do not use the explicit env file" >&2
  exit 1
fi

if PATH="$TEST_ROOT/bin:$PATH" IDENTITY_LAB_ENV_FILE="$TEST_ENV" IDENTITY_LAB_WAIT_TIMEOUT=1 "$SMOKE" >/dev/null 2>&1; then
  echo "expected non-check-only smoke to fail when no identity-lab services are running" >&2
  exit 1
fi
echo "PASS: non-check-only smoke rejects an absent identity lab"

set +e
UNHEALTHY_OUTPUT="$(PATH="$TEST_ROOT/bin:$PATH" IDENTITY_LAB_ENV_FILE="$TEST_ENV" FAKE_UNHEALTHY=1 IDENTITY_LAB_WAIT_TIMEOUT=1 "$SMOKE" 2>&1)"
UNHEALTHY_STATUS=$?
set -e
if [ "$UNHEALTHY_STATUS" -eq 0 ] || ! grep -Fq 'wait failed:' <<<"$UNHEALTHY_OUTPUT"; then
  printf '%s\n' "$UNHEALTHY_OUTPUT" >&2
  echo "full smoke did not reject the unhealthy service through its wait gate" >&2
  exit 1
fi
echo "PASS: full smoke rejects an unhealthy service before acceptance"

# Full mode must execute the real Portal callback rather than password-grant
# or manually constructed control-plane claims.
for required in \
  identity-lab-portal-probe.py \
  wait_for_identity_state \
  assert_stable_link; do
  if ! grep -Fq "$required" "$RUNTIME"; then
    echo "full smoke does not invoke $required" >&2
    exit 1
  fi
done
if ! grep -Fq 'identity-lab-wait.sh' "$SMOKE"; then
  echo "full smoke does not invoke the service-aware wait gate" >&2
  exit 1
fi
if grep -Fq '. "$LAB_DIR/.env"' "$RUNTIME"; then
  echo "runtime acceptance incorrectly parses Compose env as shell" >&2
  exit 1
fi
if ! grep -Fq 'compose ps -a -q "$service"' "$RUNTIME"; then
  echo "runtime acceptance cannot read credentials from completed one-shot services" >&2
  exit 1
fi
if ! grep -Fq 'identity-lab runtime missing service env: $service/$key' "$RUNTIME"; then
  echo "runtime acceptance lacks a redacted service/key error" >&2
  exit 1
fi
if ! grep -Fq 'read_service_env' "$RUNTIME"; then
  echo "runtime acceptance does not read credentials from isolated services" >&2
  exit 1
fi
for obsolete in \
  run_password_probe \
  identity-lab-password-probe.py \
  identity-lab-control-plane-acceptance.sh; do
  if grep -Fq "$obsolete" "$SMOKE" "$RUNTIME"; then
    echo "full smoke still relies on obsolete evidence: $obsolete" >&2
    exit 1
  fi
done

for ap in $(seq 1 10); do
  if ! grep -Eq "pass ${ap} " "$RUNTIME"; then
    echo "full smoke does not report AP${ap} PASS" >&2
    exit 1
  fi
done

if grep -Fq 'SKIP' "$SMOKE"; then
  echo "full smoke still accepts container presence as E2E success" >&2
  exit 1
fi

for required in \
  ldap_move_to_marketing \
  ldap_restore_research \
  ldap_disable_user \
  ldap_restore_user; do
  if ! grep -Fq "$required" "$RUNTIME"; then
    echo "full smoke lacks mutation/recovery path: $required" >&2
    exit 1
  fi
done
COMPOSE="$REPO_ROOT/deploy/identity-lab/docker-compose.identity-lab.yml"
PORTAL_PROBE="$REPO_ROOT/scripts/identity-lab-portal-probe.py"
for required in +  'portal-proxy:' +  'PORTAL_PROXY_URL: http://portal-proxy:8788' +  'PORTAL_INTERNAL_TOKEN:' +  'portal-session-state:' +  'identity-lab-portal-proxy.py'; do
  grep -Fq "$required" "$COMPOSE" || { echo "lab lacks real portal proxy wiring: $required" >&2; exit 1; }
done
for required in IDENTITY_SESSION_FILE IDENTITY_REUSE_SESSION IDENTITY_EXPECT_MODELS IDENTITY_EXPECT_CHAT_DEPARTMENT; do
  grep -Fq "$required" "$PORTAL_PROBE" "$RUNTIME" || { echo "AP8 lacks same-cookie portal evidence: $required" >&2; exit 1; }
done
ROLE_PROBE="$REPO_ROOT/scripts/identity-lab-keycloak-role-probe.py"
[ -s "$ROLE_PROBE" ] || { echo "lab lacks fresh Keycloak token role probe" >&2; exit 1; }
grep -Fq 'assert_runtime_service_roles' "$RUNTIME" ||
  { echo "runtime acceptance does not verify actual service-account roles" >&2; exit 1; }

token_validator="$(sed -n '/^valid_control_api_token() {$/,/^}$/p' "$RUNTIME")"
[ -n "$token_validator" ] || { echo "runtime lacks isolated control API token validation" >&2; exit 1; }
eval "$token_validator"
valid_control_api_token '123e4567-e89b-12d3-a456-426614174000' || { echo "control API token validator rejected a valid token" >&2; exit 1; }
for invalid_token in "" "bad token" "bad/value"; do
  if valid_control_api_token "$invalid_token"; then echo "control API token validator accepted invalid input" >&2; exit 1; fi
done
! grep -Fq '5.040001' "$RUNTIME" || { echo "runtime contains a Perl interpolation artifact" >&2; exit 1; }
for required in CONTROL_PLANE_ADMIN_NEW_PASSWORD /admin/v1/me/change-password password_change_required; do
  grep -Fq "$required" "$RUNTIME" || { echo "control-plane bootstrap password rotation lacks $required" >&2; exit 1; }
done
grep -Fq 'CONTROL_PLANE_ADMIN_NEW_PASSWORD:' "$REPO_ROOT/deploy/identity-lab/docker-compose.identity-lab.yml" || { echo "control-plane does not receive the lab-only rotated password" >&2; exit 1; }
grep -Fq 'CONTROL_PLANE_ADMIN_NEW_PASSWORD=' "$REPO_ROOT/deploy/identity-lab/.env.example" || { echo "lab env lacks a dedicated rotated admin password" >&2; exit 1; }
grep -Fq 'JJD_PROVIDER_SECRET_KEY:' "$REPO_ROOT/deploy/identity-lab/docker-compose.identity-lab.yml" || { echo "control-plane lacks provider-secret encryption key wiring" >&2; exit 1; }
grep -Fq 'JJD_PROVIDER_SECRET_KEY=' "$REPO_ROOT/deploy/identity-lab/.env.example" || { echo "lab env lacks provider-secret encryption key" >&2; exit 1; }
for required in   '/admin/v1/captcha'   'captcha_code_from_image'   '/admin/v1/login'   '/admin/v1/directory/sources/disable'   '/admin/v1/directory/sources/activate'   '/admin/v1/identity/sources/disable'   '/admin/v1/identity/sources/activate'; do
  grep -Fq "$required" "$RUNTIME" || { echo "AP10 does not call control-plane API: $required" >&2; exit 1; }
done
for required in '/admin/v1/directory/sources/preview' '.data.preview_id' '--arg preview_id "$directory_preview_id"'; do
  grep -Fq -- "$required" "$RUNTIME" ||
    { echo "AP10 directory activation lacks tested preview evidence: $required" >&2; exit 1; }
done
if [ "$(grep -Fc 'run_control_api POST /admin/v1/directory/sources/activate "$DIRECTORY_ACTIVATE_BODY"' "$RUNTIME")" -lt 3 ] ||
   grep -Fq 'directory/sources/activate ''{"confirm":true}''' "$RUNTIME"; then
  echo "AP10 directory recovery does not reuse the tested preview" >&2
  exit 1
fi
if grep -Fq 'identity-lab-admin-toggle.py' "$RUNTIME" || grep -Fq 'run_admin_toggle' "$RUNTIME"; then
  echo "AP10 still uses direct Keycloak administration as acceptance evidence" >&2
  exit 1
fi

directory_flag_line="$(grep -n '^DIRECTORY_DISABLED=1$' "$RUNTIME" | tail -1 | cut -d: -f1)"
directory_disable_line="$(grep -n 'run_control_api POST /admin/v1/directory/sources/disable' "$RUNTIME" | tail -1 | cut -d: -f1)"
sso_flag_line="$(grep -n '^SSO_DISABLED=1$' "$RUNTIME" | tail -1 | cut -d: -f1)"
sso_disable_line="$(grep -n 'run_control_api POST /admin/v1/identity/sources/disable' "$RUNTIME" | tail -1 | cut -d: -f1)"
if [ -z "$directory_flag_line" ] || [ "$directory_flag_line" -ge "$directory_disable_line" ] ||
   [ -z "$sso_flag_line" ] || [ "$sso_flag_line" -ge "$sso_disable_line" ]; then
  echo "capability restore flags must be armed before disable calls" >&2
  exit 1
fi
for required in run_claims_probe 'run_claims_probe account-login ad-bob' 'dept-research-ad operations' 'run_claims_probe enterprise-sso enterprise-erin' 'dept-research research enterprise' 'wait_for_identity_state "$AD_USER_ID" automatic lab-research lab-research-model' 'wait_for_identity_state "$ENTERPRISE_USER_ID" automatic lab-research lab-research-model'; do
  grep -Fq "$required" "$RUNTIME" || { echo "runtime lacks AP3/AP4 mapper evidence: $required" >&2; exit 1; }
done
restore_line="$(grep -n 'ldap_restore_research >/dev/null' "$RUNTIME" | tail -1 | cut -d: -f1)"
restore_login_line="$(grep -n 'LDAP user could not reauthenticate after source restoration' "$RUNTIME" | tail -1 | cut -d: -f1)"
restore_state_line="$(grep -n 'department/model restoration did not converge' "$RUNTIME" | tail -1 | cut -d: -f1)"
if [ -z "$restore_line" ] || [ -z "$restore_login_line" ] || [ "$restore_login_line" -le "$restore_line" ] || [ -z "$restore_state_line" ] || [ "$restore_state_line" -le "$restore_login_line" ]; then
  echo "AP8 does not verify Portal/control-plane convergence after LDAP restoration" >&2
  exit 1
fi
SECRET_LAB="$TEST_ROOT/secret-lab"
cp -R "$REPO_ROOT/deploy/identity-lab" "$SECRET_LAB"
SECRET_MARKER='NeverEchoThisValue-42'
jq --arg secret "$SECRET_MARKER" '.clients[0].secret=$secret' "$SECRET_LAB/keycloak/jjdguard-realm.json" >"$SECRET_LAB/keycloak/jjdguard-realm.tmp"
mv "$SECRET_LAB/keycloak/jjdguard-realm.tmp" "$SECRET_LAB/keycloak/jjdguard-realm.json"
set +e
SECRET_OUTPUT="$(IDENTITY_LAB_CONFIG_DIR="$SECRET_LAB" "$SMOKE" --check-only 2>&1)"
SECRET_STATUS=$?
set -e
[ "$SECRET_STATUS" -ne 0 ] || { echo "secret injection was accepted" >&2; exit 1; }
! grep -Fq "$SECRET_MARKER" <<<"$SECRET_OUTPUT" || { echo "secret injection value leaked to output" >&2; exit 1; }
assert_secret_rejected() {
  local name="$1" target="$2" replacement="$3" output status
  local lab="$TEST_ROOT/secret-$name"
  cp -R "$REPO_ROOT/deploy/identity-lab" "$lab"
  target="$lab/${target#deploy/identity-lab/}"
  printf '%s\n' "$replacement" >>"$target"
  set +e
  output="$(IDENTITY_LAB_CONFIG_DIR="$lab" "$SMOKE" --check-only 2>&1)"
  status=$?
  set -e
  [ "$status" -ne 0 ] || { echo "$name secret injection was accepted" >&2; exit 1; }
  ! grep -Fq "$SECRET_MARKER" <<<"$output" || { echo "$name secret injection value leaked to output" >&2; exit 1; }
}

assert_secret_rejected ldap deploy/identity-lab/openldap/bootstrap.ldif "userPassword: $SECRET_MARKER"
assert_secret_rejected samba deploy/identity-lab/samba/provision.sh "samba-tool user create injected $SECRET_MARKER"

REALM_LAB="$TEST_ROOT/secret-realm"
cp -R "$REPO_ROOT/deploy/identity-lab" "$REALM_LAB"
jq --arg secret "$SECRET_MARKER" '.users[0].credentials[0].value=$secret' "$REALM_LAB/keycloak/enterprise-realm.json" >"$REALM_LAB/keycloak/enterprise-realm.tmp"
mv "$REALM_LAB/keycloak/enterprise-realm.tmp" "$REALM_LAB/keycloak/enterprise-realm.json"
set +e
REALM_OUTPUT="$(IDENTITY_LAB_CONFIG_DIR="$REALM_LAB" "$SMOKE" --check-only 2>&1)"
REALM_STATUS=$?
set -e
[ "$REALM_STATUS" -ne 0 ] || { echo "realm secret injection was accepted" >&2; exit 1; }
! grep -Fq "$SECRET_MARKER" <<<"$REALM_OUTPUT" || { echo "realm secret injection value leaked to output" >&2; exit 1; }

echo "PASS: full smoke wires all ten real acceptance scenarios"
