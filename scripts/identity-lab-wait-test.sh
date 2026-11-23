#!/usr/bin/env bash
# Behavioral regression tests for the service-aware identity-lab wait gate.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WAIT_SCRIPT="$REPO_ROOT/scripts/identity-lab-wait.sh"
TEST_ROOT="$(mktemp -d)"
trap 'rm -rf "$TEST_ROOT"' EXIT
for required in control-plane-postgres control-plane-redis control-plane control-plane-migrate control-plane-seed portal-prisma portal-proxy identity-portal; do
  grep -Fq "$required" "$WAIT_SCRIPT" || {
    echo "wait gate does not cover $required" >&2
    exit 1
  }
done
mkdir -p "$TEST_ROOT/bin"

cat >"$TEST_ROOT/bin/docker" <<'EOF'
#!/usr/bin/env bash
set -eu
if [ "$1" = "compose" ]; then
  service="${!#}"
  printf 'fake-%s\n' "$service"
  exit 0
fi
if [ "$1" = "inspect" ]; then
  id="${!#}"
  case "$id" in
    fake-cert-init|fake-control-plane-migrate|fake-control-plane-seed|fake-portal-prisma) printf 'exited|0|none\n' ;;
    fake-ldap-seed)
      if [ "${FAKE_SEED_FAILURE:-0}" = "1" ]; then
        printf 'exited|7|none\n'
      else
        printf 'exited|0|none\n'
      fi
      ;;
    fake-openldap)
      if [ "${FAKE_LONG_UNHEALTHY:-0}" = "1" ]; then printf 'running|0|unhealthy\n'; else printf 'running|0|healthy\n'; fi
      ;;
    fake-samba-ad|fake-enterprise-keycloak|fake-jjdguard-keycloak|fake-control-plane-postgres|fake-control-plane-redis|fake-control-plane|fake-portal-proxy|fake-identity-portal)
      printf 'running|0|healthy\n'
      ;;
    *) exit 1 ;;
  esac
  exit 0
fi
exit 1
EOF
chmod +x "$TEST_ROOT/bin/docker"

PATH="$TEST_ROOT/bin:$PATH" IDENTITY_LAB_WAIT_TIMEOUT=1 "$WAIT_SCRIPT"

if PATH="$TEST_ROOT/bin:$PATH" FAKE_SEED_FAILURE=1 \
   IDENTITY_LAB_WAIT_TIMEOUT=1 "$WAIT_SCRIPT" >/dev/null 2>&1; then
  echo "wait gate accepted a failed ldap-seed one-shot" >&2
  exit 1
fi

if PATH="$TEST_ROOT/bin:$PATH" FAKE_LONG_UNHEALTHY=1 \
   IDENTITY_LAB_WAIT_TIMEOUT=1 "$WAIT_SCRIPT" >/dev/null 2>&1; then
  echo "wait gate accepted an unhealthy long-running service" >&2
  exit 1
fi

echo "PASS: identity lab wait gate distinguishes healthy services from failed one-shots"
