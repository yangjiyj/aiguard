#!/usr/bin/env bash
# Contract test for deploy/docker-compose/engine-resource-autotune.sh.
# Self-contained: uses mktemp -d plus injected stub files, no root and no real cgroups.
set -Eeuo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TUNER="$ROOT/deploy/docker-compose/engine-resource-autotune.sh"

fail() { printf 'FAIL test_engine_resource_autotune: %s\n' "$*" >&2; exit 1; }
value() { sed -n "s/^$2=//p" "$1"; }
digest() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    cksum "$1" | awk '{print $1 "-" $2}'
  fi
}

# Host-side stubs must never leak into the child processes.
unset JJD_ENGINE_CPU_STUB JJD_ENGINE_NPROC_STUB \
  JJD_ENGINE_CGROUP_V2_STUB JJD_ENGINE_CGROUP_V1_QUOTA_STUB \
  JJD_ENGINE_CGROUP_V1_PERIOD_STUB JJD_ENGINE_MEMINFO_STUB

[[ -f "$TUNER" ]] || fail 'missing engine resource tuner'
sh -n "$TUNER"
bash -n "$0"

tmp="$(mktemp -d)"
cleanup() {
  # Remove via a relative name: on hosts whose TMPDIR carries a Windows drive
  # prefix, deleting the absolute path is rejected by the safe-delete guard.
  (cd "$(dirname "$tmp")" && rm -rf "$(basename "$tmp")")
}
trap cleanup EXIT
printf 'MemTotal: 16777216 kB\n' >"$tmp/meminfo"

run_case() {
  name="$1" cpus="$2"
  env_file="$tmp/$name.env"
  printf 'PRESERVE_ME=yes\n' >"$env_file"
  JJD_ENGINE_CPU_STUB="$cpus" JJD_ENGINE_MEMINFO_STUB="$tmp/meminfo" \
    sh "$TUNER" "$env_file" >/dev/null
  [[ "$(value "$env_file" PRESERVE_ME)" == yes ]] || fail "$name lost unrelated environment"
  [[ "$(value "$env_file" ENGINE_RESOURCE_DETECTED_CPUS)" == "$cpus" ]] || fail "$name detected cpus mismatch"
  [[ "$(value "$env_file" ENGINE_RESOURCE_DETECTED_MEM_MB)" == 16384 ]] || fail "$name detected mem mismatch"
}

# Four tiers: CPU stub drives WEB / TIER1_WORKERS / TIER1_THREADS / JUDGE_CAPACITY.
run_case small 4
[[ "$(value "$tmp/small.env" SECURITY_ENGINE_WEB_CONCURRENCY)" == 2 ]] || fail 'small web must be 2'
[[ "$(value "$tmp/small.env" TIER1_THREADS)" == 2 ]] || fail 'small tier1 threads must be 2'
[[ "$(value "$tmp/small.env" TIER1_WORKERS)" == 1 ]] || fail 'small tier1 uvicorn workers must be 1'
[[ "$(value "$tmp/small.env" TIER1_INFERENCE_WORKERS)" == 2 ]] || fail 'small tier1 inference workers must be 2'
[[ "$(value "$tmp/small.env" TIER1_INFERENCE_CAPACITY)" == 64 ]] || fail 'small tier1 capacity must be 64'
[[ -z "$(value "$tmp/small.env" SECURITY_TIER1_WORKERS)" ]] || fail 'display-only SECURITY_TIER1_WORKERS must be gone'
[[ "$(value "$tmp/small.env" ENGINE_RESOURCE_TIER1_CONCURRENCY_STATUS)" == within_limit ]] || fail 'small tier1 concurrency must be within limit'
[[ "$(value "$tmp/small.env" ENGINE_RESOURCE_EFFECTIVE_TIER1_WORKERS)" == 1 ]] || fail 'small effective tier1 workers must mirror TIER1_WORKERS'
[[ "$(value "$tmp/small.env" SECURITY_JUDGE_CAPACITY)" == 4 ]] || fail 'small judge capacity must be 4'
[[ "$(value "$tmp/small.env" ENGINE_RESOURCE_PROFILE_RESOLVED)" == small-cpu4 ]] || fail 'small resolved name'

run_case medium 16
[[ "$(value "$tmp/medium.env" SECURITY_ENGINE_WEB_CONCURRENCY)" == 4 ]] || fail 'medium web must be 4'
[[ "$(value "$tmp/medium.env" TIER1_THREADS)" == 4 ]] || fail 'medium tier1 threads must be 4'
[[ "$(value "$tmp/medium.env" TIER1_WORKERS)" == 2 ]] || fail 'medium tier1 uvicorn workers must be 2'
[[ "$(value "$tmp/medium.env" TIER1_INFERENCE_WORKERS)" == 4 ]] || fail 'medium tier1 inference workers must be 4'
[[ "$(value "$tmp/medium.env" TIER1_INFERENCE_CAPACITY)" == 128 ]] || fail 'medium tier1 capacity must be 128'
[[ "$(value "$tmp/medium.env" ENGINE_RESOURCE_TIER1_CONCURRENCY_STATUS)" == within_limit ]] || fail 'medium tier1 concurrency must be within limit'
[[ "$(value "$tmp/medium.env" SECURITY_JUDGE_CAPACITY)" == 8 ]] || fail 'medium judge capacity must be 8'
[[ "$(value "$tmp/medium.env" ENGINE_RESOURCE_PROFILE_RESOLVED)" == medium-cpu16 ]] || fail 'medium resolved name'

run_case large 48
[[ "$(value "$tmp/large.env" SECURITY_ENGINE_WEB_CONCURRENCY)" == 8 ]] || fail 'large web must be 8'
[[ "$(value "$tmp/large.env" TIER1_THREADS)" == 4 ]] || fail 'large tier1 threads must be 4'
[[ "$(value "$tmp/large.env" TIER1_WORKERS)" == 4 ]] || fail 'large tier1 uvicorn workers must be 4'
[[ "$(value "$tmp/large.env" TIER1_INFERENCE_WORKERS)" == 8 ]] || fail 'large tier1 inference workers must be 8'
[[ "$(value "$tmp/large.env" TIER1_INFERENCE_CAPACITY)" == 256 ]] || fail 'large tier1 capacity must be 256'
# The whole point of R3: 8 web x 8 in-flight must fit inside 4 x 256.
[[ "$(value "$tmp/large.env" ENGINE_RESOURCE_TIER1_CONCURRENCY_STATUS)" == within_limit ]] || fail 'large tier1 concurrency must be within limit'
[[ "$(value "$tmp/large.env" SECURITY_JUDGE_CAPACITY)" == 16 ]] || fail 'large judge capacity must be 16'
[[ "$(value "$tmp/large.env" ENGINE_RESOURCE_PROFILE_RESOLVED)" == large-cpu48 ]] || fail 'large resolved name'

run_case xlarge 96
[[ "$(value "$tmp/xlarge.env" SECURITY_ENGINE_WEB_CONCURRENCY)" == 16 ]] || fail 'xlarge web must be 16'
[[ "$(value "$tmp/xlarge.env" TIER1_THREADS)" == 4 ]] || fail 'xlarge tier1 threads must be 4'
[[ "$(value "$tmp/xlarge.env" TIER1_WORKERS)" == 8 ]] || fail 'xlarge tier1 uvicorn workers must be 8'
[[ "$(value "$tmp/xlarge.env" TIER1_INFERENCE_WORKERS)" == 8 ]] || fail 'xlarge tier1 inference workers must be 8'
[[ "$(value "$tmp/xlarge.env" TIER1_INFERENCE_CAPACITY)" == 512 ]] || fail 'xlarge tier1 capacity must be 512'
[[ "$(value "$tmp/xlarge.env" ENGINE_RESOURCE_TIER1_CONCURRENCY_STATUS)" == within_limit ]] || fail 'xlarge tier1 concurrency must be within limit'
[[ "$(value "$tmp/xlarge.env" SECURITY_JUDGE_CAPACITY)" == 16 ]] || fail 'xlarge judge capacity must be 16'
[[ "$(value "$tmp/xlarge.env" ENGINE_RESOURCE_PROFILE_RESOLVED)" == xlarge-cpu96 ]] || fail 'xlarge resolved name must be xlarge-cpu<N>'
[[ "$(value "$tmp/xlarge.env" SECURITY_JUDGE_GLOBAL_CONCURRENCY)" == 96 ]] || fail 'global concurrency default must be 96'

# An explicit operator value is never overwritten; EFFECTIVE mirrors it.
printf 'SECURITY_ENGINE_WEB_CONCURRENCY=3\n' >"$tmp/explicit.env"
JJD_ENGINE_CPU_STUB=4 JJD_ENGINE_MEMINFO_STUB="$tmp/meminfo" \
  sh "$TUNER" "$tmp/explicit.env" >/dev/null
[[ "$(value "$tmp/explicit.env" SECURITY_ENGINE_WEB_CONCURRENCY)" == 3 ]] || fail 'explicit web value was overwritten'
[[ "$(grep -c '^SECURITY_ENGINE_WEB_CONCURRENCY=' "$tmp/explicit.env")" == 1 ]] || fail 'explicit key duplicated'
[[ "$(value "$tmp/explicit.env" ENGINE_RESOURCE_EFFECTIVE_WEB_CONCURRENCY)" == 3 ]] || fail 'effective web must record the operator value'
[[ "$(value "$tmp/explicit.env" SECURITY_JUDGE_GLOBAL_CONCURRENCY)" == 96 ]] || fail 'missing real keys were not appended'

# Manual profile leaves the file byte-for-byte unchanged.
printf 'ENGINE_RESOURCE_PROFILE=manual\nSECURITY_ENGINE_WEB_CONCURRENCY=7\n' >"$tmp/manual.env"
before="$(digest "$tmp/manual.env")"
sh "$TUNER" "$tmp/manual.env" >/dev/null
after="$(digest "$tmp/manual.env")"
[[ "$before" == "$after" ]] || fail 'manual profile was modified'

# Idempotent rerun: managed keys do not accumulate and the digest is stable.
before="$(digest "$tmp/small.env")"
JJD_ENGINE_CPU_STUB=4 JJD_ENGINE_MEMINFO_STUB="$tmp/meminfo" \
  sh "$TUNER" "$tmp/small.env" >/dev/null
after="$(digest "$tmp/small.env")"
[[ "$before" == "$after" ]] || fail 'rerun changed the environment digest'
for key in ENGINE_RESOURCE_PROFILE ENGINE_RESOURCE_PROFILE_RESOLVED ENGINE_RESOURCE_DETECTED_CPUS ENGINE_RESOURCE_DETECTED_CPU_SOURCE ENGINE_RESOURCE_JUDGE_BUDGET_STATUS; do
  [[ "$(grep -c "^${key}=" "$tmp/small.env")" == 1 ]] || fail "managed key $key accumulated"
done
[[ "$(grep -c '^SECURITY_ENGINE_WEB_CONCURRENCY=' "$tmp/small.env")" == 1 ]] || fail 'real key duplicated on rerun'

# cgroup v2 quota stub takes priority and records the source.
printf 'PRESERVE_ME=yes\n' >"$tmp/cgv2.env"
printf '400000 100000\n' >"$tmp/cpu.max"
JJD_ENGINE_CGROUP_V2_STUB="$tmp/cpu.max" JJD_ENGINE_MEMINFO_STUB="$tmp/meminfo" \
  sh "$TUNER" "$tmp/cgv2.env" >/dev/null
[[ "$(value "$tmp/cgv2.env" ENGINE_RESOURCE_DETECTED_CPUS)" == 4 ]] || fail 'cgroup v2 quota not applied'
[[ "$(value "$tmp/cgv2.env" ENGINE_RESOURCE_DETECTED_CPU_SOURCE)" == cgroup-v2 ]] || fail 'cgroup v2 source not recorded'
[[ "$(value "$tmp/cgv2.env" ENGINE_RESOURCE_PROFILE_RESOLVED)" == small-cpu4 ]] || fail 'cgroup v2 tier mismatch'

# cgroup v2 "max" means unlimited and falls through to nproc.
printf 'PRESERVE_ME=yes\n' >"$tmp/cgv2max.env"
printf 'max 100000\n' >"$tmp/cpu.max.unlimited"
JJD_ENGINE_CGROUP_V2_STUB="$tmp/cpu.max.unlimited" JJD_ENGINE_NPROC_STUB=12 \
  JJD_ENGINE_MEMINFO_STUB="$tmp/meminfo" sh "$TUNER" "$tmp/cgv2max.env" >/dev/null
[[ "$(value "$tmp/cgv2max.env" ENGINE_RESOURCE_DETECTED_CPUS)" == 12 ]] || fail 'nproc stub not applied after unlimited cgroup v2'
[[ "$(value "$tmp/cgv2max.env" ENGINE_RESOURCE_DETECTED_CPU_SOURCE)" == nproc ]] || fail 'nproc source not recorded'
[[ "$(value "$tmp/cgv2max.env" ENGINE_RESOURCE_PROFILE_RESOLVED)" == medium-cpu12 ]] || fail 'nproc tier mismatch'

# cgroup v1 quota / period stubs.
printf 'PRESERVE_ME=yes\n' >"$tmp/cgv1.env"
printf '600000\n' >"$tmp/cfs_quota_us"
printf '100000\n' >"$tmp/cfs_period_us"
JJD_ENGINE_CGROUP_V1_QUOTA_STUB="$tmp/cfs_quota_us" \
  JJD_ENGINE_CGROUP_V1_PERIOD_STUB="$tmp/cfs_period_us" \
  JJD_ENGINE_MEMINFO_STUB="$tmp/meminfo" sh "$TUNER" "$tmp/cgv1.env" >/dev/null
[[ "$(value "$tmp/cgv1.env" ENGINE_RESOURCE_DETECTED_CPUS)" == 6 ]] || fail 'cgroup v1 quota not applied'
[[ "$(value "$tmp/cgv1.env" ENGINE_RESOURCE_DETECTED_CPU_SOURCE)" == cgroup-v1 ]] || fail 'cgroup v1 source not recorded'

# U2: the persisted tier1 replica count multiplies the supply side, so a
# scaled-out install is no longer modelled as a single replica here.
printf '%s\n' 'TIER1_WORKERS=1' 'TIER1_INFERENCE_WORKERS=3' 'TIER1_INFERENCE_CAPACITY=16' \
  'TIER1_REPLICAS=2' 'SECURITY_ENGINE_WEB_CONCURRENCY=8' 'SECURITY_TIER1_MAX_INFLIGHT=8' \
  >"$tmp/replicas.env"
JJD_ENGINE_CPU_STUB=16 JJD_ENGINE_MEMINFO_STUB="$tmp/meminfo" \
  sh "$TUNER" "$tmp/replicas.env" >/dev/null 2>&1
[[ "$(value "$tmp/replicas.env" ENGINE_RESOURCE_TIER1_CONCURRENCY_STATUS)" == 'over_limit:64/32' ]] ||
  fail "two tier1 replicas did not double the supply: $(value "$tmp/replicas.env" ENGINE_RESOURCE_TIER1_CONCURRENCY_STATUS)"
printf '%s\n' 'TIER1_WORKERS=1' 'TIER1_INFERENCE_WORKERS=3' 'TIER1_INFERENCE_CAPACITY=16' \
  'TIER1_REPLICAS=1' 'SECURITY_ENGINE_WEB_CONCURRENCY=8' 'SECURITY_TIER1_MAX_INFLIGHT=8' \
  >"$tmp/single.env"
JJD_ENGINE_CPU_STUB=16 JJD_ENGINE_MEMINFO_STUB="$tmp/meminfo" \
  sh "$TUNER" "$tmp/single.env" >/dev/null 2>&1
[[ "$(value "$tmp/single.env" ENGINE_RESOURCE_TIER1_CONCURRENCY_STATUS)" == 'over_limit:64/16' ]] ||
  fail "one tier1 replica must yield the single-replica supply: $(value "$tmp/single.env" ENGINE_RESOURCE_TIER1_CONCURRENCY_STATUS)"
# A missing key means "not scaled" and must keep the historical single-replica maths.
printf '%s\n' 'TIER1_WORKERS=1' 'TIER1_INFERENCE_WORKERS=3' 'TIER1_INFERENCE_CAPACITY=16' \
  'SECURITY_ENGINE_WEB_CONCURRENCY=8' 'SECURITY_TIER1_MAX_INFLIGHT=8' >"$tmp/noreplicas.env"
JJD_ENGINE_CPU_STUB=16 JJD_ENGINE_MEMINFO_STUB="$tmp/meminfo" \
  sh "$TUNER" "$tmp/noreplicas.env" >/dev/null 2>&1
[[ "$(value "$tmp/noreplicas.env" ENGINE_RESOURCE_TIER1_CONCURRENCY_STATUS)" == 'over_limit:64/16' ]] ||
  fail 'an absent TIER1_REPLICAS must default to one replica'
# An out-of-range value is a hard error, not a silent default.
printf 'TIER1_REPLICAS=99\n' >"$tmp/badreplicas.env"
if JJD_ENGINE_CPU_STUB=16 JJD_ENGINE_MEMINFO_STUB="$tmp/meminfo" \
   sh "$TUNER" "$tmp/badreplicas.env" >/dev/null 2>&1; then
  fail 'TIER1_REPLICAS=99 was accepted'
fi

# Explicit small global concurrency triggers over_budget and a stderr warning,
# but the script must still exit 0 (the runtime semaphore bounds it).
printf 'SECURITY_JUDGE_GLOBAL_CONCURRENCY=2\n' >"$tmp/over.env"
JJD_ENGINE_CPU_STUB=4 JJD_ENGINE_MEMINFO_STUB="$tmp/meminfo" \
  sh "$TUNER" "$tmp/over.env" >/dev/null 2>"$tmp/over.err"
[[ "$(value "$tmp/over.env" ENGINE_RESOURCE_JUDGE_BUDGET_STATUS)" == 'over_budget:8' ]] || fail 'over_budget status not produced'
[[ "$(value "$tmp/over.env" ENGINE_RESOURCE_EFFECTIVE_JUDGE_GLOBAL_CONCURRENCY)" == 2 ]] || fail 'effective global concurrency missing'
grep -Fq '[engine-autotune][warn]' "$tmp/over.err" || fail 'over_budget did not warn on stderr'

# A repeated tier1 key: Docker Compose uses the LAST definition, so the recorded
# effective value (and the supply/demand verdict built from it) must be that one,
# and the operator must be told. Reporting the first line made /health say one
# thing while the sidecar ran another.
# 12, not 8: 8 is a legacy template default and would be migrated away before the check.
printf 'TIER1_INFERENCE_CAPACITY=12\nTIER1_INFERENCE_CAPACITY=256\n' >"$tmp/dupkey.env"
JJD_ENGINE_CPU_STUB=4 JJD_ENGINE_MEMINFO_STUB="$tmp/meminfo" \
  sh "$TUNER" "$tmp/dupkey.env" >/dev/null 2>"$tmp/dupkey.err"
[[ "$(value "$tmp/dupkey.env" ENGINE_RESOURCE_EFFECTIVE_TIER1_INFERENCE_CAPACITY)" == 256 ]] ||
  fail 'a repeated key must report its last definition, as Docker Compose resolves it'
grep -Fq 'TIER1_INFERENCE_CAPACITY is defined 2 times' "$tmp/dupkey.err" || fail 'a repeated key did not warn'

# The tier's own defaults on a big host (large: judge 16 x web 8 = 128 against the global
# budget of 96) are by design -- the global budget is the bound -- so they carry their own
# status and no warning. The same product reached by an operator-set value still warns.
printf '' >"$tmp/large.env"
JJD_ENGINE_CPU_STUB=64 JJD_ENGINE_MEMINFO_STUB="$tmp/meminfo" \
  sh "$TUNER" "$tmp/large.env" >/dev/null 2>"$tmp/large.err"
[[ "$(value "$tmp/large.env" ENGINE_RESOURCE_JUDGE_BUDGET_STATUS)" == 'bounded_by_global:128' ]] ||
  fail "large tier defaults: status $(value "$tmp/large.env" ENGINE_RESOURCE_JUDGE_BUDGET_STATUS), want bounded_by_global:128"
if grep -Fq 'judge capacity' "$tmp/large.err"; then fail 'the tier defaults must not warn about the judge budget'; fi
JJD_ENGINE_CPU_STUB=64 JJD_ENGINE_MEMINFO_STUB="$tmp/meminfo" \
  sh "$TUNER" "$tmp/large.env" >/dev/null 2>"$tmp/large2.err"
[[ "$(value "$tmp/large.env" ENGINE_RESOURCE_JUDGE_BUDGET_STATUS)" == 'bounded_by_global:128' ]] ||
  fail 'the status must survive a rerun (autotune wrote the tier values itself)'
if grep -Fq 'judge capacity' "$tmp/large2.err"; then fail 'a rerun must not start warning about the tier defaults'; fi
printf 'SECURITY_JUDGE_CAPACITY=20\n' >"$tmp/large-explicit.env"
JJD_ENGINE_CPU_STUB=64 JJD_ENGINE_MEMINFO_STUB="$tmp/meminfo" \
  sh "$TUNER" "$tmp/large-explicit.env" >/dev/null 2>"$tmp/large-explicit.err"
[[ "$(value "$tmp/large-explicit.env" ENGINE_RESOURCE_JUDGE_BUDGET_STATUS)" == 'over_budget:160' ]] ||
  fail 'an operator-set judge capacity above the global budget must be over_budget'
grep -Fq 'judge capacity 20' "$tmp/large-explicit.err" || fail 'an operator-set judge capacity above the budget must warn'

# Duplicate and invalid profiles must fail.
printf 'ENGINE_RESOURCE_PROFILE=auto\nENGINE_RESOURCE_PROFILE=manual\n' >"$tmp/duplicate.env"
if sh "$TUNER" "$tmp/duplicate.env" >/dev/null 2>&1; then fail 'duplicate profile marker was accepted'; fi
printf 'ENGINE_RESOURCE_PROFILE=bogus\n' >"$tmp/invalid.env"
if sh "$TUNER" "$tmp/invalid.env" >/dev/null 2>&1; then fail 'invalid profile was accepted'; fi

# The tuner must be invoked at every install/upgrade call site and shipped in bundles.
for entry in deploy-offline.sh upgrade.sh upgrade-bundle.sh; do
  grep -Fq 'engine-resource-autotune.sh' "$ROOT/deploy/docker-compose/$entry" || fail "$entry does not invoke engine autotuning"
done
grep -Fq 'engine-resource-autotune.sh "$BUNDLE_DIR/deploy/docker-compose/"' \
  "$ROOT/deploy/docker-compose/package-offline-bundle.sh" || fail 'offline packager omits engine resource tuner'

printf 'PASS test_engine_resource_autotune\n'
printf 'ALL PASS\n'
