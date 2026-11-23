#!/bin/sh
# Size the bundled CPU semantic judge from host RAM and CPU capacity.
# JUDGE_RESOURCE_PROFILE=manual preserves operator-managed values verbatim.
set -eu
umask 077

ENV_FILE="${1:-.env}"
MEMINFO_FILE="${JJD_JUDGE_MEMINFO_STUB:-/proc/meminfo}"

fail() {
  printf '[judge-autotune][error] %s\n' "$*" >&2
  exit 1
}

read_env_value() {
  key="$1"
  count="$(grep -Ec "^${key}=" "$ENV_FILE" 2>/dev/null || true)"
  [ "$count" -le 1 ] || return 2
  [ "$count" -eq 1 ] || return 1
  sed -n "s/^${key}=//p" "$ENV_FILE"
}

[ -f "$ENV_FILE" ] && [ ! -L "$ENV_FILE" ] || fail "environment file is missing or unsafe: $ENV_FILE"

profile_status=0
profile="$(read_env_value JUDGE_RESOURCE_PROFILE)" || profile_status=$?
[ "$profile_status" -ne 2 ] || fail "duplicate JUDGE_RESOURCE_PROFILE in $ENV_FILE"
case "$profile" in
  manual)
    printf '[judge-autotune] manual profile: preserving operator values\n'
    exit 0
    ;;
  ''|auto|lab|small|standard|large|xlarge) ;;
  *) fail "invalid JUDGE_RESOURCE_PROFILE: $profile" ;;
esac

# An older installation may already contain hand-tuned Judge keys but no
# ownership marker. Preserve it as manual instead of silently replacing it.
if [ -z "$profile" ] && grep -Eq '^(JUDGE_MEMORY_LIMIT|JUDGE_MEMORY_RESERVATION|JUDGE_MEMORY_SWAP_LIMIT|JUDGE_CACHE_RAM_MB|JUDGE_PARALLEL|JUDGE_CTX|JUDGE_THREADS|JUDGE_BATCH_SIZE|JUDGE_UBATCH_SIZE|SECURITY_JUDGE_WORKERS|SECURITY_JUDGE_CAPACITY)=' "$ENV_FILE"; then
  printf '\nJUDGE_RESOURCE_PROFILE=manual\n' >>"$ENV_FILE"
  chmod 600 "$ENV_FILE"
  printf '[judge-autotune] legacy custom values detected: marked manual and preserved\n'
  exit 0
fi

mem_kb=0
if [ -r "$MEMINFO_FILE" ]; then
  mem_kb="$(sed -n 's/^MemTotal:[[:space:]]*\([0-9][0-9]*\)[[:space:]]*kB.*/\1/p' "$MEMINFO_FILE" | head -1)"
fi
case "$mem_kb" in ''|*[!0-9]*) mem_kb=0 ;; esac
mem_mb=$((mem_kb / 1024))

cpus="${JJD_JUDGE_NPROC_STUB:-}"
if [ -z "$cpus" ]; then
  cpus="$(command -v nproc >/dev/null 2>&1 && nproc || printf '1')"
fi
case "$cpus" in ''|*[!0-9]*) cpus=1 ;; esac
[ "$cpus" -ge 1 ] || cpus=1

memory_profile="$profile"
if [ -z "$memory_profile" ] || [ "$memory_profile" = auto ]; then
  if [ "$mem_mb" -lt 14336 ]; then
    memory_profile=lab
  elif [ "$mem_mb" -lt 24576 ]; then
    memory_profile=small
  elif [ "$mem_mb" -lt 49152 ]; then
    memory_profile=standard
  elif [ "$mem_mb" -lt 98304 ]; then
    memory_profile=large
  else
    memory_profile=xlarge
  fi
fi

case "$memory_profile" in
  lab)
    memory_limit=4g; memory_reservation=2g; memory_swap_limit=5g
    cache_ram_mb=256; batch_size=256; ubatch_size=64
    ;;
  small)
    memory_limit=6g; memory_reservation=3g; memory_swap_limit=7g
    cache_ram_mb=1024; batch_size=512; ubatch_size=128
    ;;
  standard)
    memory_limit=8g; memory_reservation=4g; memory_swap_limit=10g
    cache_ram_mb=2048; batch_size=512; ubatch_size=128
    ;;
  large)
    memory_limit=12g; memory_reservation=6g; memory_swap_limit=14g
    cache_ram_mb=4096; batch_size=1024; ubatch_size=256
    ;;
  xlarge)
    memory_limit=16g; memory_reservation=8g; memory_swap_limit=20g
    cache_ram_mb=6144; batch_size=1024; ubatch_size=256
    ;;
esac

if [ "$cpus" -lt 4 ]; then
  parallel=1; context=2048; threads="$cpus"
elif [ "$cpus" -lt 16 ]; then
  parallel=2; context=4096
  if [ "$cpus" -lt 6 ]; then threads="$cpus"; else threads=6; fi
elif [ "$cpus" -lt 32 ]; then
  parallel=4; context=8192; threads=8
else
  parallel=8; context=16384; threads=12
fi

judge_workers="$parallel"
judge_capacity="$parallel"
tmp="$(mktemp "$(dirname "$ENV_FILE")/.judge-resources.XXXXXX")" || fail 'cannot create atomic environment update'
managed='^(JUDGE_RESOURCE_PROFILE|JUDGE_RESOURCE_PROFILE_RESOLVED|JUDGE_RESOURCE_DETECTED_MEM_MB|JUDGE_RESOURCE_DETECTED_CPUS|JUDGE_MEMORY_LIMIT|JUDGE_MEMORY_RESERVATION|JUDGE_MEMORY_SWAP_LIMIT|JUDGE_CACHE_RAM_MB|JUDGE_PARALLEL|JUDGE_CTX|JUDGE_THREADS|JUDGE_BATCH_SIZE|JUDGE_UBATCH_SIZE|SECURITY_JUDGE_WORKERS|SECURITY_JUDGE_CAPACITY)='
if ! awk -v managed="$managed" '$0 !~ managed { print }' "$ENV_FILE" >"$tmp"; then
  rm -f "$tmp"
  fail 'cannot copy existing environment safely'
fi
cat >>"$tmp" <<EOF
JUDGE_RESOURCE_PROFILE=${profile:-auto}
JUDGE_RESOURCE_PROFILE_RESOLVED=${memory_profile}-cpu${cpus}
JUDGE_RESOURCE_DETECTED_MEM_MB=${mem_mb}
JUDGE_RESOURCE_DETECTED_CPUS=${cpus}
JUDGE_MEMORY_LIMIT=${memory_limit}
JUDGE_MEMORY_RESERVATION=${memory_reservation}
JUDGE_MEMORY_SWAP_LIMIT=${memory_swap_limit}
JUDGE_CACHE_RAM_MB=${cache_ram_mb}
JUDGE_PARALLEL=${parallel}
JUDGE_CTX=${context}
JUDGE_THREADS=${threads}
JUDGE_BATCH_SIZE=${batch_size}
JUDGE_UBATCH_SIZE=${ubatch_size}
SECURITY_JUDGE_WORKERS=${judge_workers}
SECURITY_JUDGE_CAPACITY=${judge_capacity}
EOF
chmod 600 "$tmp" || { rm -f "$tmp"; fail 'cannot protect generated environment'; }
mv -f "$tmp" "$ENV_FILE" || { rm -f "$tmp"; fail 'cannot atomically install generated environment'; }

printf '[judge-autotune] profile=%s host=%sMiB/%sCPU limit=%s cache=%sMiB parallel=%s workers=%s ctx=%s\n' \
  "$memory_profile" "$mem_mb" "$cpus" "$memory_limit" "$cache_ram_mb" "$parallel" "$judge_workers" "$context"
