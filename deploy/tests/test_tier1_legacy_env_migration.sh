#!/usr/bin/env bash
# U1: existing .env files still carry the tier1 defaults the templates shipped as
# ACTIVE values (TIER1_INFERENCE_WORKERS=1 / TIER1_INFERENCE_CAPACITY=8 from
# e1ca9e266, the per-provider pool knobs from 40f58a23b). autotune reads any
# active key as an operator decision, so an upgrade kept the sidecar at 1x8 while
# the engine pushed 8x256 in flight.
set -Eeuo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
AUTOTUNE="$ROOT/deploy/docker-compose/engine-resource-autotune.sh"
SCALE="$ROOT/deploy/docker-compose/tier1-scale.sh"
COMPOSE="$ROOT/deploy/docker-compose/docker-compose.offline.yml"
CPU="$ROOT/deploy/docker-compose/tier1-cpu.override.yml"
WRAPPER="$ROOT/deploy/docker-compose/compose-wrapper.sh"
# shellcheck source=/dev/null
. "$ROOT/deploy/tests/lib/jjdguard_contract_env.sh"

WORK=$(mktemp -d)
cleanup() { (cd "$(dirname "$WORK")" && rm -rf "$(basename "$WORK")"); }
trap cleanup EXIT

MEMINFO="$WORK/meminfo"
printf 'MemTotal: 16777216 kB\n' >"$MEMINFO"

fail() { printf 'FAIL test_tier1_legacy_env_migration: %s\n' "$*" >&2; exit 1; }
sha() { if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}'; else cksum "$1" | awk '{print $1 "-" $2}'; fi; }
mode_of() { stat -c '%a' "$1" 2>/dev/null || stat -f '%Lp' "$1"; }
marker() { printf '# migrated-by-autotune'; }

# 12 cores would be medium; 64 pins the large tier deterministically.
run_autotune() {
  cpus=$1; file=$2; log=$3
  JJD_ENGINE_CPU_STUB="$cpus" JJD_ENGINE_MEMINFO_STUB="$MEMINFO" \
    sh "$AUTOTUNE" "$file" >"$log" 2>&1 || fail "autotune failed: $(cat "$log")"
}
value() { sed -n "s/^$2=//p" "$1" | head -1; }
backups() { find "$WORK" -maxdepth 1 -name "$(basename "$1").bak-tier1-migrate-*" -type f | wc -l; }

# ---------------------------------------------------------------------------
# 1) A legacy template .env on the large tier: both pool keys are commented out
#    with a marker, the effective pool becomes 8x256, and the verdict clears.
# ---------------------------------------------------------------------------
env1="$WORK/legacy.env"
write_jjdguard_contract_env "$env1"
printf 'TIER1_INFERENCE_WORKERS=1\nTIER1_INFERENCE_CAPACITY=8\n' >>"$env1"
chmod 600 "$env1"
cp "$env1" "$WORK/legacy.before"
run_autotune 64 "$env1" "$WORK/legacy.log"

grep -qx '#TIER1_INFERENCE_WORKERS=1' "$env1" || fail 'TIER1_INFERENCE_WORKERS=1 was not commented out'
grep -qx '#TIER1_INFERENCE_CAPACITY=8' "$env1" || fail 'TIER1_INFERENCE_CAPACITY=8 was not commented out'
grep -qF "$(marker) " "$env1" || fail 'the migration marker is missing'
grep -qE '^# migrated-by-autotune [0-9]{4}-[0-9]{2}-[0-9]{2}: legacy template default, now follows the autotuned tier \(TIER1_INFERENCE_CAPACITY\)$' "$env1" ||
  fail 'the marker line does not match the documented shape'
grep -qF '[engine-autotune] migrated legacy default TIER1_INFERENCE_CAPACITY=8 -> follow tier (256)' "$WORK/legacy.log" ||
  fail 'the migration was not logged per line'
[ "$(value "$env1" ENGINE_RESOURCE_EFFECTIVE_TIER1_INFERENCE_WORKERS)" = 8 ] ||
  fail "effective inference workers = $(value "$env1" ENGINE_RESOURCE_EFFECTIVE_TIER1_INFERENCE_WORKERS), want 8"
[ "$(value "$env1" ENGINE_RESOURCE_EFFECTIVE_TIER1_INFERENCE_CAPACITY)" = 256 ] ||
  fail "effective capacity = $(value "$env1" ENGINE_RESOURCE_EFFECTIVE_TIER1_INFERENCE_CAPACITY), want 256"
[ "$(value "$env1" ENGINE_RESOURCE_TIER1_CONCURRENCY_STATUS)" = within_limit ] ||
  fail 'the verdict did not become within_limit'
# The original is never deleted: only one extra comment line per migrated key.
[ "$(grep -c '^TIER1_INFERENCE_WORKERS=' "$env1")" = 1 ] || fail 'the migrated key was lost instead of commented'
[ "$(grep -c '^TIER1_INFERENCE_CAPACITY=' "$env1")" = 1 ] || fail 'the migrated key was lost instead of commented'

# ---------------------------------------------------------------------------
# 5) permissions and the backup: 600 in, 600 out, one copy of the original.
# ---------------------------------------------------------------------------
[ "$(mode_of "$env1")" = 600 ] || fail "migrated .env mode = $(mode_of "$env1"), want 600"
backup=$(find "$WORK" -maxdepth 1 -name 'legacy.env.bak-tier1-migrate-*' -type f | head -1)
[ -n "$backup" ] || fail 'no backup was written'
[ "$(mode_of "$backup")" = 600 ] || fail "backup mode = $(mode_of "$backup"), want 600"
cmp -s "$backup" "$WORK/legacy.before" || fail 'the backup is not the pre-migration file'
[ "$(backups "$env1")" = 1 ] || fail "expected exactly one backup, found $(backups "$env1")"

# ---------------------------------------------------------------------------
# 3) Idempotent: a second run changes nothing and adds no backup.
# ---------------------------------------------------------------------------
before_sha=$(sha "$env1")
run_autotune 64 "$env1" "$WORK/legacy2.log"
[ "$(sha "$env1")" = "$before_sha" ] || fail 'the second run changed the environment file'
[ "$(backups "$env1")" = 1 ] || fail 'the second run created another backup'
grep -qF 'migrated legacy default' "$WORK/legacy2.log" && fail 'the second run migrated again'

# ---------------------------------------------------------------------------
# 2) An operator value is never touched, and nothing is backed up.
# ---------------------------------------------------------------------------
env2="$WORK/explicit.env"
write_jjdguard_contract_env "$env2"
printf 'TIER1_INFERENCE_WORKERS=8\nTIER1_INFERENCE_CAPACITY=128\nTIER1_THREADS=4\n' >>"$env2"
chmod 600 "$env2"
run_autotune 64 "$env2" "$WORK/explicit.log"
grep -qx 'TIER1_INFERENCE_CAPACITY=128' "$env2" || fail 'an explicit capacity was rewritten'
[ "$(value "$env2" ENGINE_RESOURCE_EFFECTIVE_TIER1_INFERENCE_CAPACITY)" = 128 ] ||
  fail 'the effective capacity does not mirror the operator value'
[ "$(backups "$env2")" = 0 ] || fail 'a backup was written although nothing needed migrating'
grep -qF 'migrated legacy default' "$WORK/explicit.log" && fail 'an explicit value was reported as migrated'

# ---------------------------------------------------------------------------
# 4) ENGINE_RESOURCE_PROFILE=manual keeps the "do not touch anything" promise.
# ---------------------------------------------------------------------------
env4="$WORK/manual.env"
printf 'ENGINE_RESOURCE_PROFILE=manual\nTIER1_INFERENCE_WORKERS=1\nTIER1_INFERENCE_CAPACITY=8\n' >"$env4"
chmod 600 "$env4"
before_sha=$(sha "$env4")
run_autotune 64 "$env4" "$WORK/manual.log"
[ "$(sha "$env4")" = "$before_sha" ] || fail 'manual profile was modified'
[ "$(backups "$env4")" = 0 ] || fail 'manual profile created a backup'

# ---------------------------------------------------------------------------
# 6) CPU/GPU pool knobs migrate too, TIER1_GPU_THREADS=1 stays active, and the
#    overlay inherits the tier value instead of the old 16.
# ---------------------------------------------------------------------------
env6="$WORK/provider.env"
write_jjdguard_contract_env "$env6"
printf '%s\n' \
  'TIER1_CPU_THREADS=4' \
  'TIER1_CPU_INFERENCE_WORKERS=2' \
  'TIER1_CPU_INFERENCE_CAPACITY=16' \
  'TIER1_GPU_INFERENCE_WORKERS=4' \
  'TIER1_GPU_INFERENCE_CAPACITY=64' \
  'TIER1_GPU_THREADS=1' >>"$env6"
chmod 600 "$env6"
run_autotune 64 "$env6" "$WORK/provider.log"
for key in TIER1_CPU_THREADS TIER1_CPU_INFERENCE_WORKERS TIER1_CPU_INFERENCE_CAPACITY TIER1_GPU_INFERENCE_WORKERS TIER1_GPU_INFERENCE_CAPACITY; do
  grep -qE "^#${key}=" "$env6" || fail "$key was not commented out"
done
grep -qx 'TIER1_GPU_THREADS=1' "$env6" || fail 'TIER1_GPU_THREADS=1 must stay active'
merged=$("$WRAPPER" --env-file "$env6" -f "$COMPOSE" -f "$CPU" --profile full config --format json |
  python3 -c 'import json,sys; print(json.load(sys.stdin)["services"]["tier1-classifier"]["environment"].get("TIER1_INFERENCE_CAPACITY"))')
[ "$merged" = 256 ] || fail "the CPU overlay still pins capacity=$merged instead of the tier 256"
check_out=$("$SCALE" cpu 1 --check "$env6" 2>&1) || fail "tier1-scale --check failed: $check_out"
printf '%s' "$check_out" | grep -Fq 'capacity=256' || fail "tier1-scale still reads the legacy capacity: $check_out"

# ---------------------------------------------------------------------------
# 7) Historical templates from real releases: nothing outside the tier1 defaults
#    may change. Each revision is a real upgrade source (same set the historical
#    schema matrix walks).
# ---------------------------------------------------------------------------
historic=0
for rev in v2.6.14 e1ca9e266 40f58a23b 0a692f781; do
  git -C "$ROOT" cat-file -e "$rev:deploy/docker-compose/.env.example" 2>/dev/null || continue
  historic=$((historic + 1))
  envh="$WORK/historic-$rev.env"
  git -C "$ROOT" show "$rev:deploy/docker-compose/.env.example" >"$envh"
  chmod 600 "$envh"
  cp "$envh" "$envh.before"
  run_autotune 64 "$envh" "$WORK/historic-$rev.log"
  # Every active key of the original must still be present, except the legacy
  # tier1 defaults, which must now be a commented-out line with a marker.
  while IFS= read -r line; do
    key=${line%%=*}
    case "$key" in
      TIER1_INFERENCE_WORKERS|TIER1_INFERENCE_CAPACITY|TIER1_CPU_THREADS|TIER1_CPU_INFERENCE_WORKERS|TIER1_CPU_INFERENCE_CAPACITY|TIER1_GPU_INFERENCE_WORKERS|TIER1_GPU_INFERENCE_CAPACITY|TIER1_THREADS)
        continue
        ;;
      # Managed by autotune itself: it always rewrites these into the tail block.
      ENGINE_RESOURCE_*)
        continue
        ;;
    esac
    grep -qxF "$line" "$envh" || fail "$rev lost $key"
  done < <(grep -E '^[A-Za-z_][A-Za-z0-9_]*=' "$envh.before")
  # Anything that was commented out stays commented out.
  while IFS= read -r line; do
    grep -qxF "$line" "$envh" || fail "$rev changed a commented line: $line"
  done < <(grep -E '^#' "$envh.before")
done
[ "$historic" -ge 3 ] || fail "only $historic historical templates were exercised"

# ---------------------------------------------------------------------------
# 8) Restoring a migrated value. The documented way: edit the key's single active
#    line back to the old value. It must survive reruns (no re-migration, still
#    one active line) and the recorded value must be what Compose resolves.
# ---------------------------------------------------------------------------
merged_capacity() {
  "$WRAPPER" --env-file "$1" -f "$COMPOSE" -f "$CPU" --profile full config --format json |
    python3 -c 'import json,sys; print(json.load(sys.stdin)["services"]["tier1-classifier"]["environment"].get("TIER1_INFERENCE_CAPACITY"))'
}
env8="$WORK/restore.env"
write_jjdguard_contract_env "$env8"
printf 'TIER1_INFERENCE_WORKERS=1\nTIER1_INFERENCE_CAPACITY=8\n' >>"$env8"
chmod 600 "$env8"
run_autotune 64 "$env8" "$WORK/restore1.log"
[ "$(grep -c '^TIER1_INFERENCE_CAPACITY=' "$env8")" = 1 ] || fail 'a migrated key must leave exactly one active line'
awk '/^TIER1_INFERENCE_CAPACITY=/ { print "TIER1_INFERENCE_CAPACITY=8"; next } { print }' "$env8" >"$env8.new"
mv "$env8.new" "$env8"
chmod 600 "$env8"
marks_before=$(grep -c 'migrated-by-autotune' "$env8")
run_autotune 64 "$env8" "$WORK/restore2.log"
[ "$(grep -c 'migrated-by-autotune' "$env8")" = "$marks_before" ] || fail 'a restored value was migrated again'
[ "$(grep -c '^TIER1_INFERENCE_CAPACITY=' "$env8")" = 1 ] || fail 'the restore left more than one active line'
[ "$(value "$env8" ENGINE_RESOURCE_EFFECTIVE_TIER1_INFERENCE_CAPACITY)" = 8 ] ||
  fail 'the restored capacity is not what autotune records'
[ "$(merged_capacity "$env8")" = 8 ] || fail 'Compose does not see the restored capacity'
grep -Fq 'over_limit' <(value "$env8" ENGINE_RESOURCE_TIER1_CONCURRENCY_STATUS) ||
  fail 'a restored 1-worker pool at 8 x 8 in-flight must be reported over_limit'

# The wrong way (uncomment the old line, keep autotune's appended one) leaves two
# active lines. Compose takes the last, so autotune has to agree with it and warn,
# instead of recording the first line and contradicting the running sidecar.
env9="$WORK/uncomment.env"
cp "$WORK/legacy.before" "$env9"
chmod 600 "$env9"
run_autotune 64 "$env9" "$WORK/uncomment1.log"
printf 'TIER1_INFERENCE_CAPACITY=8\n' | cat - "$env9" >"$env9.new"
mv "$env9.new" "$env9"
chmod 600 "$env9"
[ "$(grep -c '^TIER1_INFERENCE_CAPACITY=' "$env9")" = 2 ] || fail 'fixture should carry two active lines'
run_autotune 64 "$env9" "$WORK/uncomment2.log"
grep -Fq 'TIER1_INFERENCE_CAPACITY is defined 2 times' "$WORK/uncomment2.log" || fail 'two active lines did not warn'
[ "$(value "$env9" ENGINE_RESOURCE_EFFECTIVE_TIER1_INFERENCE_CAPACITY)" = "$(merged_capacity "$env9")" ] ||
  fail 'autotune records a different capacity than Compose resolves'

# ---------------------------------------------------------------------------
# 9) Rolling .env back from the backup. The backup predates the one-shot gate, so
#    without a gate the next autotune (every upgrade runs it) migrates it again;
#    with the gate line added, the restored values stay.
# ---------------------------------------------------------------------------
env10="$WORK/rollback.env"
cp "$backup" "$env10"
chmod 600 "$env10"
printf 'TIER1_LEGACY_DEFAULTS_MIGRATED=2026-01-01\n' >>"$env10"
run_autotune 64 "$env10" "$WORK/rollback.log"
grep -qx 'TIER1_INFERENCE_CAPACITY=8' "$env10" || fail 'the restored backup was migrated despite the gate line'
env11="$WORK/rollback-nogate.env"
cp "$backup" "$env11"
chmod 600 "$env11"
run_autotune 64 "$env11" "$WORK/rollback-nogate.log"
grep -qx '#TIER1_INFERENCE_CAPACITY=8' "$env11" || fail 'a gate-less backup is expected to migrate again (documented behaviour)'

echo "PASS test_tier1_legacy_env_migration"
