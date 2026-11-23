#!/bin/sh
# Size security-engine worker pools from host CPU capacity.
# ENGINE_RESOURCE_PROFILE=manual preserves operator-managed values verbatim.
# Test hooks (all optional, for contract tests without real host cgroups):
#   JJD_ENGINE_CPU_STUB            direct CPU count, bypasses detection
#   JJD_ENGINE_NPROC_STUB         value returned instead of the nproc command
#   JJD_ENGINE_CGROUP_V2_STUB     path to a cgroup v2 cpu.max file
#   JJD_ENGINE_CGROUP_V1_QUOTA_STUB   path to a cgroup v1 cpu.cfs_quota_us file
#   JJD_ENGINE_CGROUP_V1_PERIOD_STUB  path to a cgroup v1 cpu.cfs_period_us file
#   JJD_ENGINE_MEMINFO_STUB       path to a /proc/meminfo-format file
set -eu
umask 077

ENV_FILE="${1:-.env}"
MEMINFO_FILE="${JJD_ENGINE_MEMINFO_STUB:-/proc/meminfo}"
CGROUP_V2_FILE="${JJD_ENGINE_CGROUP_V2_STUB:-/sys/fs/cgroup/cpu.max}"
CGROUP_V1_QUOTA_FILE="${JJD_ENGINE_CGROUP_V1_QUOTA_STUB:-/sys/fs/cgroup/cpu/cpu.cfs_quota_us}"
CGROUP_V1_PERIOD_FILE="${JJD_ENGINE_CGROUP_V1_PERIOD_STUB:-/sys/fs/cgroup/cpu/cpu.cfs_period_us}"

fail() {
  printf '[engine-autotune][error] %s\n' "$*" >&2
  exit 1
}

# Read a single environment key; return 2 when it is defined more than once.
read_env_value() {
  key="$1"
  count="$(grep -Ec "^${key}=" "$ENV_FILE" 2>/dev/null || true)"
  [ "$count" -le 1 ] || return 2
  [ "$count" -eq 1 ] || return 1
  sed -n "s/^${key}=//p" "$ENV_FILE"
}

[ -f "$ENV_FILE" ] && [ ! -L "$ENV_FILE" ] || fail "environment file is missing or unsafe: $ENV_FILE"

# Supply/demand and the persisted scale topology live in one shared file so this
# script and tier1-scale.sh can never disagree about how big the sidecar is.
AUTOTUNE_DIR="$(CDPATH= cd -- "$(dirname "$0")" && pwd)"
TIER1_TOPOLOGY_LIB="$AUTOTUNE_DIR/tier1-topology.sh"
[ -r "$TIER1_TOPOLOGY_LIB" ] || fail "missing shared Tier-1 topology library: $TIER1_TOPOLOGY_LIB"
. "$TIER1_TOPOLOGY_LIB"

profile_status=0
profile="$(read_env_value ENGINE_RESOURCE_PROFILE)" || profile_status=$?
[ "$profile_status" -ne 2 ] || fail "duplicate ENGINE_RESOURCE_PROFILE in $ENV_FILE"
case "$profile" in
  manual)
    printf '[engine-autotune] manual profile: preserving operator values\n'
    exit 0
    ;;
  ''|auto|small|medium|large|xlarge) ;;
  *) fail "invalid ENGINE_RESOURCE_PROFILE: $profile" ;;
esac
raw_profile="$profile"

# CPU detection: cgroup quota first, then nproc. A direct CPU stub wins.
cpus=''
cpu_source=''

if [ -n "${JJD_ENGINE_CPU_STUB:-}" ]; then
  cpus="$JJD_ENGINE_CPU_STUB"
  cpu_source=nproc
fi

# cgroup v2 cpu.max: "quota period" or "max period". "max" means unlimited.
if [ -z "$cpus" ] && [ -r "$CGROUP_V2_FILE" ]; then
  v2_quota="$(awk 'NR == 1 { print $1 }' "$CGROUP_V2_FILE" 2>/dev/null || true)"
  v2_period="$(awk 'NR == 1 { print $2 }' "$CGROUP_V2_FILE" 2>/dev/null || true)"
  case "$v2_quota" in
    ''|*[!0-9]*) : ;;
    *)
      case "$v2_period" in
        ''|*[!0-9]*) : ;;
        *)
          if [ "$v2_quota" -gt 0 ] && [ "$v2_period" -gt 0 ]; then
            cpus=$(( (v2_quota + v2_period - 1) / v2_period ))
            cpu_source=cgroup-v2
          fi
          ;;
      esac
      ;;
  esac
fi

# cgroup v1: quota <= 0 means unlimited.
if [ -z "$cpus" ] && [ -r "$CGROUP_V1_QUOTA_FILE" ] && [ -r "$CGROUP_V1_PERIOD_FILE" ]; then
  v1_quota="$(sed -n '1p' "$CGROUP_V1_QUOTA_FILE" 2>/dev/null || true)"
  v1_period="$(sed -n '1p' "$CGROUP_V1_PERIOD_FILE" 2>/dev/null || true)"
  case "$v1_quota" in
    ''|*[!0-9]*) : ;;
    *)
      case "$v1_period" in
        ''|*[!0-9]*) : ;;
        *)
          if [ "$v1_quota" -gt 0 ] && [ "$v1_period" -gt 0 ]; then
            cpus=$(( (v1_quota + v1_period - 1) / v1_period ))
            cpu_source=cgroup-v1
          fi
          ;;
      esac
      ;;
  esac
fi

if [ -z "$cpus" ]; then
  cpus="${JJD_ENGINE_NPROC_STUB:-}"
  if [ -z "$cpus" ]; then
    cpus="$(command -v nproc >/dev/null 2>&1 && nproc || printf '1')"
  fi
  cpu_source=nproc
fi

case "$cpus" in ''|*[!0-9]*) cpus=1; cpu_source=nproc ;; esac
[ "$cpus" -ge 1 ] || cpus=1

# Memory detection: MemTotal in /proc/meminfo, reported in MiB.
mem_kb=0
if [ -r "$MEMINFO_FILE" ]; then
  mem_kb="$(sed -n 's/^MemTotal:[[:space:]]*\([0-9][0-9]*\)[[:space:]]*kB.*/\1/p' "$MEMINFO_FILE" | head -1)"
fi
case "$mem_kb" in ''|*[!0-9]*) mem_kb=0 ;; esac
mem_mb=$((mem_kb / 1024))

# Resolve the tier. An explicit tier overrides the CPU-derived pick, but the
# detected CPU count is still recorded in the resolved name.
case "$profile" in
  ''|auto)
    if [ "$cpus" -le 8 ]; then
      profile=small
    elif [ "$cpus" -le 32 ]; then
      profile=medium
    elif [ "$cpus" -le 64 ]; then
      profile=large
    else
      profile=xlarge
    fi
    ;;
esac

# t_t1uvicorn / t_t1iw / t_t1cap size the tier1-classifier container itself:
# uvicorn processes, parallel inference workers, and the per-worker in-flight
# queue. SECURITY_TIER1_MAX_INFLIGHT only bounds the engine's own client slots,
# so sizing the engine alone leaves the sidecar answering 503 under load.
case "$profile" in
  small)  t_web=2;  t_input=2; t_t1t=2; t_t1i=2; t_judge=4;  t_t1uvicorn=1; t_t1iw=2; t_t1cap=64  ;;
  medium) t_web=4;  t_input=4; t_t1t=4; t_t1i=4; t_judge=8;  t_t1uvicorn=2; t_t1iw=4; t_t1cap=128 ;;
  large)  t_web=8;  t_input=8; t_t1t=4; t_t1i=8; t_judge=16; t_t1uvicorn=4; t_t1iw=8; t_t1cap=256 ;;
  xlarge) t_web=16; t_input=8; t_t1t=4; t_t1i=8; t_judge=16; t_t1uvicorn=8; t_t1iw=8; t_t1cap=512 ;;
esac
# --- U1: legacy tier1 defaults from the shipped templates --------------------
# e1ca9e266 (2026-09-05) shipped TIER1_INFERENCE_WORKERS=1 and
# TIER1_INFERENCE_CAPACITY=8 as ACTIVE template values; 40f58a23b (2026-09-11)
# added the per-provider pool knobs the same way. resolve_real() reads any active
# key as an operator decision, so an upgrade kept the sidecar at 1x8 while the
# engine pushed 8x256 in flight: 503s under load, reported as "degraded".
# Rewriting the template only helped new installs -- existing .env files still
# carry the old defaults, so migrate them here (every install and upgrade path
# already runs this script).
#
# Only a value that still equals the legacy template default is migrated; any
# other value is a deliberate operator setting and is left untouched (site 248
# pins TIER1_WORKERS=4 / TIER1_INFERENCE_WORKERS=8 / TIER1_INFERENCE_CAPACITY=256
# / TIER1_THREADS=4 and must survive verbatim). Lines are commented out, never
# deleted, and always preceded by a marker an operator can grep for.
TIER1_LEGACY_MARK='# migrated-by-autotune'

# key, old template default, and the value this install will use instead.
# TIER1_THREADS=2 belongs to the same class even though the brief listed only the
# pool keys: it was active from e1ca9e266 until this branch and resolve_real()
# skips the tier value for it exactly the same way.
migrate_legacy_tier1_defaults() {
  # One reconciliation per environment file. After it has run, an active tier1
  # key is an operator decision for good: without this gate a later run would
  # re-comment the values autotune itself appended (on a small tier those can
  # coincide with the old defaults -- threads 2, capacity 64) and the file would
  # never settle. Deleting this line re-runs the migration deliberately.
  if grep -q '^TIER1_LEGACY_DEFAULTS_MIGRATED=' "$ENV_FILE" 2>/dev/null; then
    return 0
  fi
  legacy_dir="$(dirname "$ENV_FILE")"
  legacy_today="$(date +%Y-%m-%d)"
  legacy_map="$(mktemp "$legacy_dir/.tier1-legacy.XXXXXX")" ||
    fail 'cannot stage the legacy tier1 migration'
  legacy_rewrite="$(mktemp "$legacy_dir/.tier1-rewrite.XXXXXX")" || {
    rm -f "$legacy_map"; fail 'cannot stage the legacy tier1 migration';
  }
  legacy_log="$(mktemp "$legacy_dir/.tier1-log.XXXXXX")" || {
    rm -f "$legacy_map" "$legacy_rewrite"; fail 'cannot stage the legacy tier1 migration';
  }
  legacy_count="$(mktemp "$legacy_dir/.tier1-count.XXXXXX")" || {
    rm -f "$legacy_map" "$legacy_rewrite" "$legacy_log"; fail 'cannot stage the legacy tier1 migration';
  }
  {
    printf 'TIER1_THREADS 2 %s\n' "$t_t1t"
    printf 'TIER1_INFERENCE_WORKERS 1 %s\n' "$t_t1iw"
    printf 'TIER1_INFERENCE_CAPACITY 8 %s\n' "$t_t1cap"
    printf 'TIER1_CPU_THREADS 4 %s\n' "$t_t1t"
    printf 'TIER1_CPU_INFERENCE_WORKERS 2 %s\n' "$t_t1iw"
    printf 'TIER1_CPU_INFERENCE_CAPACITY 16 %s\n' "$t_t1cap"
    printf 'TIER1_GPU_INFERENCE_WORKERS 4 %s\n' "$t_t1iw"
    printf 'TIER1_GPU_INFERENCE_CAPACITY 64 %s\n' "$t_t1cap"
  } >"$legacy_map"
  if ! awk -v mark="$TIER1_LEGACY_MARK" -v today="$legacy_today" \
      -v logf="$legacy_log" -v countf="$legacy_count" '
    NR == FNR { legacy_default[$1] = $2; tier_value[$1] = $3; next }
    {
      line = $0
      crlf = ""
      if (sub(/\r$/, "", line)) crlf = "\r"
      eq = index(line, "=")
      if (eq > 1) {
        key = substr(line, 1, eq - 1)
        if (key in legacy_default) {
          trimmed = substr(line, eq + 1)
          gsub(/^[ \t]+|[ \t]+$/, "", trimmed)
          if (trimmed == legacy_default[key]) {
            printf "%s %s: legacy template default, now follows the autotuned tier (%s)%s\n", mark, today, key, crlf
            printf "#%s%s\n", line, crlf
            printf "[engine-autotune] migrated legacy default %s=%s -> follow tier (%s)\n", key, trimmed, tier_value[key] > logf
            migrated++
            next
          }
        }
      }
      printf "%s%s\n", line, crlf
    }
    END { print migrated + 0 > countf }
  ' "$legacy_map" "$ENV_FILE" >"$legacy_rewrite"; then
    rm -f "$legacy_map" "$legacy_rewrite" "$legacy_log" "$legacy_count"
    fail 'cannot rewrite the environment for the legacy tier1 migration'
  fi
  legacy_hits="$(cat "$legacy_count" 2>/dev/null || printf 0)"
  case "$legacy_hits" in ''|*[!0-9]*) legacy_hits=0 ;; esac
  if [ "$legacy_hits" -eq 0 ]; then
    rm -f "$legacy_map" "$legacy_rewrite" "$legacy_log" "$legacy_count"
    printf 'TIER1_LEGACY_DEFAULTS_MIGRATED=%s\n' "$legacy_today" >>"$ENV_FILE" ||
      printf '[engine-autotune][warn] cannot record TIER1_LEGACY_DEFAULTS_MIGRATED in %s\n' "$ENV_FILE" >&2
    return 0
  fi
  legacy_backup="$ENV_FILE.bak-tier1-migrate-$(date +%Y%m%d%H%M%S)"
  [ ! -e "$legacy_backup" ] || legacy_backup="$legacy_backup.$$"
  # .env carries secrets: the copy keeps the original mode and ownership.
  if ! cp -p "$ENV_FILE" "$legacy_backup"; then
    rm -f "$legacy_map" "$legacy_rewrite" "$legacy_log" "$legacy_count"
    fail "cannot back up $ENV_FILE before the legacy tier1 migration"
  fi
  legacy_mode="$(stat -c '%a' "$ENV_FILE" 2>/dev/null || stat -f '%Lp' "$ENV_FILE" 2>/dev/null || true)"
  legacy_owner="$(stat -c '%u:%g' "$ENV_FILE" 2>/dev/null || true)"
  [ -z "$legacy_mode" ] || chmod "$legacy_mode" "$legacy_rewrite" || true
  [ -z "$legacy_owner" ] || chown "$legacy_owner" "$legacy_rewrite" 2>/dev/null || true
  cat "$legacy_log"
  printf '[engine-autotune] backup: %s\n' "$legacy_backup"
  printf '[engine-autotune][note] to keep an old value instead, edit that key'"'"'s active line back to it (one active line per key; do not uncomment the old line), or set ENGINE_RESOURCE_PROFILE=manual\n'
  if ! mv -f "$legacy_rewrite" "$ENV_FILE"; then
    rm -f "$legacy_map" "$legacy_log" "$legacy_count"
    fail "cannot install the migrated environment: $ENV_FILE"
  fi
  printf 'TIER1_LEGACY_DEFAULTS_MIGRATED=%s\n' "$legacy_today" >>"$ENV_FILE" ||
    printf '[engine-autotune][warn] cannot record TIER1_LEGACY_DEFAULTS_MIGRATED in %s\n' "$ENV_FILE" >&2
  rm -f "$legacy_map" "$legacy_log" "$legacy_count"
}
migrate_legacy_tier1_defaults

resolved="${profile}-cpu${cpus}"

tmp="$(mktemp "$(dirname "$ENV_FILE")/.engine-resources.XXXXXX")" || fail 'cannot create atomic environment update'
managed='^(ENGINE_RESOURCE_PROFILE|ENGINE_RESOURCE_PROFILE_RESOLVED|ENGINE_RESOURCE_DETECTED_CPUS|ENGINE_RESOURCE_DETECTED_MEM_MB|ENGINE_RESOURCE_DETECTED_CPU_SOURCE|ENGINE_RESOURCE_EFFECTIVE_WEB_CONCURRENCY|ENGINE_RESOURCE_EFFECTIVE_INPUT_WORKERS|ENGINE_RESOURCE_EFFECTIVE_TIER1_WORKERS|ENGINE_RESOURCE_EFFECTIVE_TIER1_THREADS|ENGINE_RESOURCE_EFFECTIVE_TIER1_INFERENCE_WORKERS|ENGINE_RESOURCE_EFFECTIVE_TIER1_INFERENCE_CAPACITY|ENGINE_RESOURCE_TIER1_CONCURRENCY_STATUS|ENGINE_RESOURCE_EFFECTIVE_TIER1_MAX_INFLIGHT|ENGINE_RESOURCE_EFFECTIVE_JUDGE_WORKERS|ENGINE_RESOURCE_EFFECTIVE_JUDGE_CAPACITY|ENGINE_RESOURCE_EFFECTIVE_JUDGE_GLOBAL_CONCURRENCY|ENGINE_RESOURCE_JUDGE_BUDGET_STATUS)='
if ! awk -v managed="$managed" '$0 !~ managed { print }' "$ENV_FILE" >"$tmp"; then
  rm -f "$tmp"
  fail 'cannot copy existing environment safely'
fi

# For each real key: keep an operator-set value untouched, append only when
# missing, and print the sanitized effective value for the managed records.
resolve_real() {
  key="$1"
  fallback="$2"
  active="$(grep -Ec "^${key}=" "$ENV_FILE" || true)"
  if [ "${active:-0}" -ge 1 ]; then
    # Docker Compose resolves a repeated key to its LAST definition, so report
    # that one: the recorded effective value and the supply/demand verdict have
    # to describe what the containers actually get, not what the first line says.
    raw="$(sed -n "s/^${key}=//p" "$ENV_FILE" | tail -1)"
    if [ "$active" -gt 1 ]; then
      printf '[engine-autotune][warn] %s is defined %s times in %s; Docker Compose uses the last one (%s). Keep a single active line per key.\n' \
        "$key" "$active" "$ENV_FILE" "$raw" >&2
    fi
  else
    printf '%s=%s\n' "$key" "$fallback" >>"$tmp"
    raw="$fallback"
  fi
  case "$raw" in
    ''|*[!0-9]*) printf '%s\n' "$fallback" ;;
    *) printf '%s\n' "$raw" ;;
  esac
}

eff_web="$(resolve_real SECURITY_ENGINE_WEB_CONCURRENCY "$t_web")"
eff_input="$(resolve_real SECURITY_INPUT_WORKERS "$t_input")"
eff_t1t="$(resolve_real TIER1_THREADS "$t_t1t")"
eff_t1i="$(resolve_real SECURITY_TIER1_MAX_INFLIGHT "$t_t1i")"
eff_t1u="$(resolve_real TIER1_WORKERS "$t_t1uvicorn")"
eff_t1iw="$(resolve_real TIER1_INFERENCE_WORKERS "$t_t1iw")"
eff_t1cap="$(resolve_real TIER1_INFERENCE_CAPACITY "$t_t1cap")"
eff_jworkers="$(resolve_real SECURITY_JUDGE_WORKERS "$t_judge")"
eff_jcapacity="$(resolve_real SECURITY_JUDGE_CAPACITY "$t_judge")"
eff_jglobal="$(resolve_real SECURITY_JUDGE_GLOBAL_CONCURRENCY 96)"

budget_product=$(( eff_jcapacity * eff_web ))
if [ "$budget_product" -le "$eff_jglobal" ]; then
  budget_status=within_budget
elif [ "$eff_jcapacity" = "$t_judge" ] && [ "$eff_web" = "$t_web" ] && [ "$eff_jglobal" = 96 ]; then
  # The tier's own defaults (large: 16 per process x 8 processes = 128 against a global
  # budget of 96). The per-process figure is a ceiling; the global budget is the bound on
  # purpose, set below the ~128 a GPU judge saturates at. That is not something to warn
  # about on every upgrade of every large host, so it is its own status.
  budget_status="bounded_by_global:${budget_product}"
else
  budget_status="over_budget:${budget_product}"
  printf '[engine-autotune][warn] per-process judge capacity %s x web concurrency %s = %s exceeds SECURITY_JUDGE_GLOBAL_CONCURRENCY %s; the runtime global semaphore will bound it\n' \
    "$eff_jcapacity" "$eff_web" "$budget_product" "$eff_jglobal" >&2
fi

# The tier1 replica count is a persisted part of the topology (tier1-scale.sh
# --apply writes it). Without it a scaled-out install was modelled as one
# replica here, so every upgrade recomputed an over_limit verdict and wrote it
# over the one the scale command had just recorded.
tier1_replicas_value="$(tier1_replicas "$ENV_FILE")" ||
  fail "invalid TIER1_REPLICAS in $ENV_FILE (expected 1..32)"
engine_replicas_value="$(tier1_int "$(tier1_env_value "$ENV_FILE" SECURITY_ENGINE_REPLICAS)" 1)"

verdict="$(tier1_capacity_verdict "$tier1_replicas_value" "$eff_t1u" "$eff_t1cap" \
  "$engine_replicas_value" "$eff_web" "$eff_t1i")"
tier1_status="${verdict%% *}"
verdict_rest="${verdict#* }"
tier1_demand="${verdict_rest%% *}"
tier1_supply="${verdict_rest##* }"
if [ "$tier1_status" != within_limit ]; then
  printf '[engine-autotune][warn] engine in-flight %s (web %s x tier1 max inflight %s x engine replicas %s) exceeds tier1 capacity %s (%s tier1 replicas x workers %s x capacity %s); the sidecar would answer 503 under load, raise TIER1_REPLICAS, TIER1_WORKERS or TIER1_INFERENCE_CAPACITY\n' \
    "$tier1_demand" "$eff_web" "$eff_t1i" "$engine_replicas_value" "$tier1_supply" \
    "$tier1_replicas_value" "$eff_t1u" "$eff_t1cap" >&2
fi

cat >>"$tmp" <<EOF
ENGINE_RESOURCE_PROFILE=${raw_profile:-auto}
ENGINE_RESOURCE_PROFILE_RESOLVED=${resolved}
ENGINE_RESOURCE_DETECTED_CPUS=${cpus}
ENGINE_RESOURCE_DETECTED_MEM_MB=${mem_mb}
ENGINE_RESOURCE_DETECTED_CPU_SOURCE=${cpu_source}
ENGINE_RESOURCE_EFFECTIVE_WEB_CONCURRENCY=${eff_web}
ENGINE_RESOURCE_EFFECTIVE_INPUT_WORKERS=${eff_input}
ENGINE_RESOURCE_EFFECTIVE_TIER1_WORKERS=${eff_t1u}
ENGINE_RESOURCE_EFFECTIVE_TIER1_THREADS=${eff_t1t}
ENGINE_RESOURCE_EFFECTIVE_TIER1_INFERENCE_WORKERS=${eff_t1iw}
ENGINE_RESOURCE_EFFECTIVE_TIER1_INFERENCE_CAPACITY=${eff_t1cap}
ENGINE_RESOURCE_TIER1_CONCURRENCY_STATUS=${tier1_status}
ENGINE_RESOURCE_EFFECTIVE_TIER1_MAX_INFLIGHT=${eff_t1i}
ENGINE_RESOURCE_EFFECTIVE_JUDGE_WORKERS=${eff_jworkers}
ENGINE_RESOURCE_EFFECTIVE_JUDGE_CAPACITY=${eff_jcapacity}
ENGINE_RESOURCE_EFFECTIVE_JUDGE_GLOBAL_CONCURRENCY=${eff_jglobal}
ENGINE_RESOURCE_JUDGE_BUDGET_STATUS=${budget_status}
EOF
chmod 600 "$tmp" || { rm -f "$tmp"; fail 'cannot protect generated environment'; }
mv -f "$tmp" "$ENV_FILE" || { rm -f "$tmp"; fail 'cannot atomically install generated environment'; }

printf '[engine-autotune] profile=%s cpus=%s mem=%s web=%s judge=%s status=%s tier1=%sx%s/%s replicas=%s\n' \
  "$resolved" "$cpus" "$mem_mb" "$eff_web" "$eff_jcapacity" "$budget_status" \
  "$eff_t1u" "$eff_t1cap" "$tier1_status" "$tier1_replicas_value"
