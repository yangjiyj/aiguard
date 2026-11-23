#!/usr/bin/env bash
# Redis 7.4 -> Valkey 8.1 upgrade migration: flow tests with a stubbed CLI plus
# wiring contracts for upgrade-bundle.sh, upgrade.sh and the offline packager.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
DC="$ROOT/deploy/docker-compose"
LIB="$DC/redis-valkey-migrate-lib.sh"
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
pass=0
ok() { pass=$((pass + 1)); printf 'ok %d - %s\n' "$pass" "$1"; }
die() { printf 'not ok - %s\n' "$1" >&2; exit 1; }

# shellcheck source=../docker-compose/redis-valkey-migrate-lib.sh
. "$LIB"
RVM_READY_TRIES=2; RVM_READY_INTERVAL=0

# Fake CLI. Containers: $TMP/c/<id>/{flavor,export,imported}. Export of a
# container that received an import echoes the import (optionally corrupted).
rvm_cli() {
  local c="$1"; shift
  local d="$TMP/c/$c"
  [[ -d "$d" ]] || return 1
  case "$1" in
    INFO) printf '# Server\r\n%s_version:1.0\r\n' "$(cat "$d/flavor")" ;;
    PING) [[ -f "$d/down" ]] || echo PONG ;;
    EVAL) if [[ -f "$d/imported" ]]; then
            if [[ -f "$d/corrupt" ]]; then sed '1s/x[0-9a-f]*$/x00/' "$d/imported"; else cat "$d/imported"; fi
          else cat "$d/export"; fi ;;
    -x) cat >"$d/imported"; grep -c '^[SH] ' "$d/imported" || true ;;
    *) return 1 ;;
  esac
}
mk() { mkdir -p "$TMP/c/$1"; printf '%s' "$2" >"$TMP/c/$1/flavor"; printf '%s\n' "${3:-N 0}" >"$TMP/c/$1/export"; }
EVENTS="$TMP/events"
rvm_hook_old_container() { printf '%s' "${OLD_ID:-}"; }
rvm_hook_stop_old() { echo stop >>"$EVENTS"; [[ "${STOP_FAIL:-0}" != 1 ]]; }
rvm_hook_start_new() { echo start >>"$EVENTS"; mk new "${NEW_FLAVOR:-valkey}"; }
rvm_hook_new_container() { printf 'new'; }
reset() { rm -rf "$TMP/c" "$EVENTS" "$TMP/dump"; mkdir -p "$TMP/c" "$TMP/dump"; : >"$EVENTS"; unset OLD_ID STOP_FAIL NEW_FLAVOR; }
leftover() { [[ -z "$(ls -A "$TMP/dump")" ]] || die "dump files left behind: $(ls "$TMP/dump")"; }

GOOD='S -1 x70617573653a74 x31
S 893000 x6275646765743a74 x3132
H 86400000 x6d6f6e74686c795f746f6b656e733a74 x696e x313030 x6f7574 x323030
N 7'

reset; OLD_ID=old; mk old redis "$GOOD"
migrate_redis_to_valkey "$TMP/dump" 2>"$TMP/log" || die "happy path failed: $(cat "$TMP/log")"
cmp -s <(rvm_normalize "$TMP/c/new/imported") <(printf '%s\n' "$GOOD" | rvm_normalize /dev/stdin) || die "imported set differs"
[[ "$(tr '\n' ' ' <"$EVENTS")" == "stop start " ]] || die "hook order: $(cat "$EVENTS")"
grep -q 'copied 3 must-keep key(s) .* of 7 in total' "$TMP/log" || die "summary log missing"
leftover; ok "redis source: export, stop, start valkey, import, verify"

reset
migrate_redis_to_valkey "$TMP/dump" 2>/dev/null || die "no old service must be a no-op"
[[ ! -s "$EVENTS" ]] || die "no-op touched services"; ok "no running redis service is a no-op"

reset; OLD_ID=old; mk old valkey "$GOOD"
migrate_redis_to_valkey "$TMP/dump" 2>/dev/null || die "valkey source must be a no-op"
[[ ! -s "$EVENTS" ]] || die "valkey no-op touched services"; ok "already Valkey (re-run) is a no-op"

# Negative cases: each must fail (non-zero) so the caller rolls back.
reset; OLD_ID=old; mk old unknown "$GOOD"
! migrate_redis_to_valkey "$TMP/dump" 2>/dev/null || die "unknown flavor accepted"
[[ ! -s "$EVENTS" ]] || die "unknown flavor stopped the old service"; ok "unreachable/auth-failed source fails before stopping"

reset; OLD_ID=old; mk old redis "$(printf 'E list x70617573653a71\nN 1')"
! migrate_redis_to_valkey "$TMP/dump" 2>"$TMP/log" || die "unsupported type accepted"
grep -q 'unsupported key type' "$TMP/log" || die "unsupported type not reported"
[[ ! -s "$EVENTS" ]] || die "unsupported type stopped the old service"; leftover; ok "unsupported key type in a must-keep prefix fails before stopping"

reset; OLD_ID=old; mk old redis 'S -1 x70 x31'
! migrate_redis_to_valkey "$TMP/dump" 2>/dev/null || die "truncated export (no N line) accepted"
leftover; ok "truncated export fails"

reset; OLD_ID=old; mk old redis 'garbage line'
! migrate_redis_to_valkey "$TMP/dump" 2>/dev/null || die "malformed export accepted"; ok "malformed export fails"

reset; OLD_ID=old; STOP_FAIL=1; mk old redis "$GOOD"
! migrate_redis_to_valkey "$TMP/dump" 2>/dev/null || die "stop failure accepted"; leftover; ok "stop failure fails"

reset; OLD_ID=old; NEW_FLAVOR=redis; mk old redis "$GOOD"
! migrate_redis_to_valkey "$TMP/dump" 2>"$TMP/log" || die "non-valkey target accepted"
grep -q 'not Valkey' "$TMP/log" || die "non-valkey target not reported"; leftover; ok "new service that is not Valkey fails"

reset; OLD_ID=old; mk old redis "$GOOD"
rvm_hook_start_new() { echo start >>"$EVENTS"; mk new valkey; : >"$TMP/c/new/down"; }
! migrate_redis_to_valkey "$TMP/dump" 2>/dev/null || die "unready target accepted"; leftover; ok "Valkey that never answers PING fails"

reset; OLD_ID=old; mk old redis "$GOOD"
rvm_hook_start_new() { echo start >>"$EVENTS"; mk new valkey; : >"$TMP/c/new/corrupt"; }
! migrate_redis_to_valkey "$TMP/dump" 2>"$TMP/log" || die "verification mismatch accepted"
grep -q 'verification failed' "$TMP/log" || die "mismatch not reported"; leftover; ok "post-import verification mismatch fails"

# Lua sanity: the import script resyncs prefixes (DEL before write) and batches HSET.
grep -q 'redis.call("DEL", k)' <<<"$RVM_IMPORT_LUA" || die "import does not clear prefixes"
grep -q '#args == 400' <<<"$RVM_IMPORT_LUA" || die "HSET is not batched"
[[ "${RVM_PREFIXES[*]}" == "pause:* budget:* daily_tokens:* monthly_tokens:*" ]] || die "prefix set changed"
ok "import resyncs must-keep prefixes and batches HSET"

# Password never reaches the host argv: rvm_cli passes it by env name only.
grep -q 'docker exec -i -e REDISCLI_AUTH "\$container"' "$LIB" || die "password handling changed"
! grep -Eq -- '(-a|--pass) *"?\$\{?REDIS_PASSWORD' "$LIB" || die "password on argv"
ok "password is passed by environment, not argv"

# Wiring contracts.
ub="$DC/upgrade-bundle.sh"; u="$DC/upgrade.sh"
grep -q '\. "\$SCRIPT_DIR/redis-valkey-migrate-lib.sh"' "$ub" || die "upgrade-bundle.sh does not source the lib"
grep -q '\. "\$SCRIPT_DIR/redis-valkey-migrate-lib.sh"' "$u" || die "upgrade.sh does not source the lib"
body="$(sed -n '/^run_in_place_upgrade() {/,/^}/p' "$ub")"
lines="$(grep -nE 'quiesce_old_database_writers|repair_customer_environment_scope|IMAGE_SWITCH_STARTED=1|migrate_redis_service_to_valkey|up -d --force-recreate' <<<"$body" | cut -d: -f1 | tr '\n' ' ')"
read -r q r i m f <<<"$lines"
(( q < r && r < i && i < m && m < f )) || die "upgrade-bundle.sh order: $lines"
ok "upgrade-bundle.sh: quiesce < repair < IMAGE_SWITCH_STARTED < migrate < force-recreate"
grep -q 'rvm_hook_stop_old() { run_old_compose stop' "$ub" || die "bundle stop hook"
grep -q 'up -d --no-deps --force-recreate redis' "$ub" || die "bundle start hook"
ok "upgrade-bundle.sh hooks use old/new Compose; rollback_old_services restores old redis"
main="$(grep -n 'timed_step' "$u" | cut -d: -f1,2)"
a="$(grep -m1 '"quiesce_database_writers"' <<<"$main" | cut -d: -f1)"
b="$(grep -m1 '"repair_customer_environment_scope"' <<<"$main" | cut -d: -f1)"
c="$(grep -m1 '"migrate_redis_to_valkey"' <<<"$main" | cut -d: -f1)"
d="$(grep -m1 '"switch_images"' <<<"$main" | cut -d: -f1)"
(( a < b && b < c && c < d )) || die "upgrade.sh order: $a $b $c $d"
[[ "$(sed -n "$((c - 1))p" "$u")" == 'IMAGE_SWITCH_STARTED=1' ]] || die "upgrade.sh must arm rollback before migrating"
ok "upgrade.sh: quiesce < repair < (rollback armed) migrate < switch_images"
rb="$(sed -n '/^rollback() {/,/^}/p' "$u")"
grep -q 'write_redis_rollback_override' <<<"$rb" || die "upgrade.sh rollback does not restore redis"
ov="$(sed -n '/^write_redis_rollback_override() {/,/^}/p' "$u")"
grep -q 'redis-data:/data' <<<"$ov" && grep -q 'redis-server' <<<"$ov" || die "rollback override incomplete"
ok "upgrade.sh rollback pins the old Redis image back onto redis-data"
grep -q 'redis-valkey-migrate-lib.sh' "$DC/package-offline-bundle.sh" || die "packager does not ship the lib"
ok "offline packager ships the lib"
grep -q 'valkey-data:/data' "$DC/docker-compose.offline.yml" && grep -q 'valkey-data:/data' "$DC/docker-compose.yml" || die "compose not on valkey-data"
grep -Eq '^  redis-data:' "$DC/docker-compose.offline.yml" || die "redis-data volume (rollback anchor) dropped"
ok "compose runs Valkey on valkey-data and keeps redis-data declared"
printf '1..%d\n' "$pass"
