#!/usr/bin/env bash
# Contract test for the pre-upgrade shared-state probe (R5).
# SECURITY_SHARED_STATE_REQUIRED defaults to true, so an unreachable valkey or an
# unusable DB 3 makes security-engine refuse to boot. The upgrade must find that
# out BEFORE it recreates containers, not after the old stack is already down.
set -Eeuo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
UPGRADE="$ROOT/deploy/docker-compose/upgrade.sh"

fail() { printf 'FAIL test_upgrade_shared_state_probe: %s\n' "$*" >&2; exit 1; }

[[ -f "$UPGRADE" ]] || fail 'missing upgrade.sh'
bash -n "$UPGRADE" || fail 'upgrade.sh does not parse'

grep -q '^verify_shared_state_namespace() {' "$UPGRADE" || fail 'missing verify_shared_state_namespace'
grep -q 'SECURITY_SHARED_STATE_REQUIRED:-true' "$UPGRADE" \
  || fail 'the probe must default to required=true, matching the engine'
grep -q 'redis-cli --no-auth-warning -a "$password" -n "$db" ping' "$UPGRADE" \
  || fail 'the probe must SELECT the DB (-n) and PING it'
grep -q 'redis-cli --no-auth-warning -a "$password" -n "$db" ping 2>&1' "$UPGRADE" \
  || fail 'the probe must capture output instead of aborting on the first non-zero exit'

probe_line="$(grep -n 'timed_step "verify_shared_state_namespace" verify_shared_state_namespace' "$UPGRADE" | cut -d: -f1)"
switch_line="$(grep -n 'timed_step "switch_images" switch_images' "$UPGRADE" | cut -d: -f1)"
[[ -n "$probe_line" ]] || fail 'the probe is not wired into the upgrade steps'
[[ -n "$switch_line" ]] || fail 'switch_images step not found'
(( probe_line < switch_line )) \
  || fail "the probe (line $probe_line) must run before switch_images (line $switch_line)"

# A failing probe must abort, not warn: an outage discovered after the fact is
# exactly what this check exists to prevent.
grep -q 'fail "\[shared-state\] valkey DB \$db is not usable' "$UPGRADE" \
  || fail 'an unusable DB must fail the upgrade'

printf 'PASS test_upgrade_shared_state_probe\n'
