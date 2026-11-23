#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TUNER="$ROOT/deploy/docker-compose/judge-resource-autotune.sh"

fail() { printf 'FAIL test_judge_resource_autotune: %s\n' "$*" >&2; exit 1; }
value() { sed -n "s/^$2=//p" "$1"; }

[[ -f "$TUNER" ]] || fail 'missing Judge resource tuner'
sh -n "$TUNER"
tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT

run_case() {
  name="$1" mem_kb="$2" cpus="$3"
  env_file="$tmp/$name.env" meminfo="$tmp/$name.meminfo"
  printf 'PRESERVE_ME=yes\n' >"$env_file"
  printf 'MemTotal: %s kB\n' "$mem_kb" >"$meminfo"
  chmod 600 "$env_file"
  JJD_JUDGE_MEMINFO_STUB="$meminfo" JJD_JUDGE_NPROC_STUB="$cpus" sh "$TUNER" "$env_file" >/dev/null
  [[ "$(value "$env_file" PRESERVE_ME)" == yes ]] || fail "$name lost unrelated environment"
  [[ "$(stat -c %a "$env_file")" == 600 ]] || fail "$name environment mode changed"
}

run_case lab 12582912 4
[[ "$(value "$tmp/lab.env" JUDGE_MEMORY_LIMIT)" == 4g ]] || fail '12GiB limit must be 4g'
[[ "$(value "$tmp/lab.env" JUDGE_CACHE_RAM_MB)" == 256 ]] || fail '12GiB cache must be 256MiB'
[[ "$(value "$tmp/lab.env" JUDGE_PARALLEL)" == 2 ]] || fail '4 CPU must use two slots'
[[ "$(value "$tmp/lab.env" SECURITY_JUDGE_WORKERS)" == 2 ]] || fail '4 CPU workers must match two judge slots'
[[ "$(value "$tmp/lab.env" SECURITY_JUDGE_CAPACITY)" == 2 ]] || fail '4 CPU capacity must match two judge slots'

run_case small 16777216 4
[[ "$(value "$tmp/small.env" JUDGE_MEMORY_LIMIT)" == 6g ]] || fail '16GiB limit must be 6g'
[[ "$(value "$tmp/small.env" JUDGE_CACHE_RAM_MB)" == 1024 ]] || fail '16GiB cache must be 1GiB'

run_case standard 33554432 16
[[ "$(value "$tmp/standard.env" JUDGE_MEMORY_LIMIT)" == 8g ]] || fail '32GiB limit must be 8g'
[[ "$(value "$tmp/standard.env" JUDGE_CACHE_RAM_MB)" == 2048 ]] || fail '32GiB cache must be 2GiB'
[[ "$(value "$tmp/standard.env" JUDGE_PARALLEL)" == 4 ]] || fail '16 CPU must use four slots'
[[ "$(value "$tmp/standard.env" JUDGE_CTX)" == 8192 ]] || fail 'four slots must retain 2048 tokens each'
[[ "$(value "$tmp/standard.env" SECURITY_JUDGE_WORKERS)" == 4 ]] || fail '16 CPU workers must match four judge slots'
[[ "$(value "$tmp/standard.env" SECURITY_JUDGE_CAPACITY)" == 4 ]] || fail '16 CPU capacity must match four judge slots'

run_case large 67108864 16
[[ "$(value "$tmp/large.env" JUDGE_MEMORY_LIMIT)" == 12g ]] || fail '64GiB limit must be 12g'
[[ "$(value "$tmp/large.env" JUDGE_CACHE_RAM_MB)" == 4096 ]] || fail '64GiB cache must be 4GiB'

run_case xlarge 134217728 32
[[ "$(value "$tmp/xlarge.env" JUDGE_MEMORY_LIMIT)" == 16g ]] || fail '128GiB limit must be 16g'
[[ "$(value "$tmp/xlarge.env" JUDGE_PARALLEL)" == 8 ]] || fail '32 CPU must use eight slots'

# Auto mode retunes on a later upgrade after the host is expanded.
printf 'MemTotal: 67108864 kB\n' >"$tmp/expanded.meminfo"
JJD_JUDGE_MEMINFO_STUB="$tmp/expanded.meminfo" JJD_JUDGE_NPROC_STUB=16 sh "$TUNER" "$tmp/standard.env" >/dev/null
[[ "$(value "$tmp/standard.env" JUDGE_MEMORY_LIMIT)" == 12g ]] || fail 'auto profile did not retune after expansion'
[[ "$(grep -c '^JUDGE_MEMORY_LIMIT=' "$tmp/standard.env")" == 1 ]] || fail 'retune duplicated managed keys'

# Explicit profile forces a tier; manual and legacy custom settings are preserved.
printf 'JUDGE_RESOURCE_PROFILE=large\n' >"$tmp/forced.env"
printf 'MemTotal: 16777216 kB\n' >"$tmp/forced.meminfo"
JJD_JUDGE_MEMINFO_STUB="$tmp/forced.meminfo" JJD_JUDGE_NPROC_STUB=8 sh "$TUNER" "$tmp/forced.env" >/dev/null
[[ "$(value "$tmp/forced.env" JUDGE_MEMORY_LIMIT)" == 12g ]] || fail 'explicit large profile was ignored'

printf 'JUDGE_RESOURCE_PROFILE=manual\nJUDGE_MEMORY_LIMIT=9g\n' >"$tmp/manual.env"
before="$(sha256sum "$tmp/manual.env" | awk '{print $1}')"
sh "$TUNER" "$tmp/manual.env" >/dev/null
after="$(sha256sum "$tmp/manual.env" | awk '{print $1}')"
[[ "$before" == "$after" ]] || fail 'manual profile was modified'

printf 'JUDGE_MEMORY_LIMIT=9g\n' >"$tmp/legacy.env"
sh "$TUNER" "$tmp/legacy.env" >/dev/null
[[ "$(value "$tmp/legacy.env" JUDGE_RESOURCE_PROFILE)" == manual ]] || fail 'legacy custom environment was not protected'
[[ "$(value "$tmp/legacy.env" JUDGE_MEMORY_LIMIT)" == 9g ]] || fail 'legacy custom value was modified'

ln -s "$tmp/manual.env" "$tmp/link.env"
if sh "$TUNER" "$tmp/link.env" >/dev/null 2>&1; then fail 'symlink environment was accepted'; fi

printf 'JUDGE_RESOURCE_PROFILE=auto\nJUDGE_RESOURCE_PROFILE=manual\n' >"$tmp/duplicate.env"
if sh "$TUNER" "$tmp/duplicate.env" >/dev/null 2>&1; then fail 'duplicate profile marker was accepted'; fi

for entry in deploy-offline.sh upgrade.sh upgrade-bundle.sh; do
  grep -Fq 'judge-resource-autotune.sh' "$ROOT/deploy/docker-compose/$entry" || fail "$entry does not invoke Judge autotuning"
done
grep -Fq 'judge-resource-autotune.sh "$BUNDLE_DIR/deploy/docker-compose/"' \
  "$ROOT/deploy/docker-compose/package-offline-bundle.sh" || fail 'offline packager omits Judge resource tuner'

printf 'PASS test_judge_resource_autotune\n'
