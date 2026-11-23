#!/bin/sh
set -eu

usage() {
  echo "usage: $0 <cpu|gpu> <replicas:1..32> <--check|--apply> [--allow-over-limit] [env-file]" >&2
  echo "       $0 reset <--check|--apply> [env-file]   # back to base compose, one replica" >&2
}

if [ "${1:-}" = "--help" ]; then
  usage
  exit 0
fi
if [ "$#" -lt 1 ]; then
  usage
  exit 2
fi

script_dir=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
env_file=$script_dir/.env
env_seen=0
allow_over_limit=0
action=
mode=
replicas=
reset_mode=0

# The supply/demand formula and the GPU preconditions are shared with
# engine-resource-autotune.sh and the upgrade entry points: this script and
# autotune must never disagree about how big the sidecar is.
TIER1_TOPOLOGY_LIB="$script_dir/tier1-topology.sh"
if [ ! -r "$TIER1_TOPOLOGY_LIB" ]; then
  echo "[tier1-scale][error] missing shared Tier-1 topology library: $TIER1_TOPOLOGY_LIB" >&2
  exit 1
fi
. "$TIER1_TOPOLOGY_LIB"

if [ "$1" = reset ]; then
  reset_mode=1
  shift
  for arg in "$@"; do
    case "$arg" in
      --check|--apply)
        if [ -n "$action" ]; then usage; exit 2; fi
        action=$arg
        ;;
      --allow-over-limit) allow_over_limit=1 ;;
      -*) usage; exit 2 ;;
      *)
        if [ "$env_seen" -eq 1 ]; then usage; exit 2; fi
        env_file=$arg
        env_seen=1
        ;;
    esac
  done
else
  [ "$#" -ge 3 ] || { usage; exit 2; }
  mode=$1
  replicas=$2
  action=$3
  shift 3
  for arg in "$@"; do
    case "$arg" in
      --allow-over-limit) allow_over_limit=1 ;;
      -*) usage; exit 2 ;;
      *)
        if [ "$env_seen" -eq 1 ]; then usage; exit 2; fi
        env_file=$arg
        env_seen=1
        ;;
    esac
  done
fi
case "$action" in
  --check|--apply) ;;
  *) usage; exit 2 ;;
esac

base=$script_dir/docker-compose.offline.yml
compose=$script_dir/compose-wrapper.sh

if [ "$reset_mode" -eq 1 ]; then
  # Drop the overlay: the base compose file is the unscaled CPU default.
  overlay=
  expected=cpu
  replicas=1
else
  case "$mode" in
    cpu) overlay=$script_dir/tier1-cpu.override.yml; expected=cpu ;;
    gpu) overlay=$script_dir/tier1-gpu.override.yml; expected=cuda ;;
    *) usage; exit 2 ;;
  esac
  case "$replicas" in
    ''|*[!0-9]*) usage; exit 2 ;;
  esac
  if [ "$replicas" -lt 1 ] || [ "$replicas" -gt 32 ]; then
    usage
    exit 2
  fi
fi

for path in "$env_file" "$base" "$compose"; do
  if [ ! -f "$path" ] || [ -L "$path" ]; then
    echo "[tier1-scale][error] unsafe or missing file: $path" >&2
    exit 1
  fi
done
if [ -n "$overlay" ] && { [ ! -f "$overlay" ] || [ -L "$overlay" ]; }; then
  echo "[tier1-scale][error] unsafe or missing file: $overlay" >&2
  exit 1
fi
if [ ! -x "$compose" ]; then
  echo "[tier1-scale][error] compose wrapper is not executable" >&2
  exit 1
fi

compose_run() {
  if [ -n "$overlay" ]; then
    "$compose" --env-file "$env_file" -f "$base" -f "$overlay" --profile full "$@"
  else
    "$compose" --env-file "$env_file" -f "$base" --profile full "$@"
  fi
}

# Effective concurrency of the merged stack, not of this script's assumptions.
# The overlays used to pin their own pool (cpu 2x16 / gpu 4x64) and silently
# overrode the autotuned tier, so a check that only read .env kept saying
# within_limit while the sidecar answered 503. Read the merged config instead.
capacity_facts() {
  compose_run config --format json | python3 -c '
import json, sys

data = json.load(sys.stdin)
tier1 = data["services"]["tier1-classifier"].get("environment") or {}
engine_service = data["services"]["security-engine"]
engine = engine_service.get("environment") or {}
replicas = (engine_service.get("deploy") or {}).get("replicas") or 1


def as_int(value, default=1):
    try:
        number = int(str(value).strip())
    except (TypeError, ValueError):
        return default
    return number if number > 0 else default


# The scale overlay is not merged here: it needs Compose >= 2.24.4 for !reset.
# Read the same replica knob it consumes, so a multi-replica engine is not
# modelled as a single process and silently under-counted.
env_replicas = ""
try:
    with open(sys.argv[1], encoding="utf-8") as handle:
        for line in handle:
            if line.startswith("SECURITY_ENGINE_REPLICAS="):
                env_replicas = line.split("=", 1)[1].strip()
except OSError:
    pass

print("%d %d %d %d %d" % (
    as_int(tier1.get("TIER1_WORKERS")),
    as_int(tier1.get("TIER1_INFERENCE_CAPACITY")),
    max(as_int(replicas), as_int(env_replicas or "1")),
    as_int(engine.get("WEB_CONCURRENCY")),
    as_int(engine.get("SECURITY_TIER1_MAX_INFLIGHT")),
))
' "$env_file"
}

compose_run config --quiet
if [ "$mode" = gpu ]; then
  # Same preconditions as every later upgrade: the upgrade entry points source
  # this shared check too, so a GPU install can never silently fall back to CPU.
  gpu_image=$(compose_run config --format json | python3 -c \
    'import json,sys; print(json.load(sys.stdin)["services"]["tier1-classifier"]["image"])')
  tier1_gpu_preflight "$gpu_image" || exit 1
fi

# supply = tier1 replicas x uvicorn workers x per-process capacity
# demand = engine replicas x web workers x engine-side in-flight per worker
facts=$(capacity_facts)
tier1_workers=1
tier1_capacity=1
engine_replicas=1
web_concurrency=1
max_inflight=1
position=0
for value in $facts; do
  position=$((position + 1))
  case "$position" in
    1) tier1_workers=$value ;;
    2) tier1_capacity=$value ;;
    3) engine_replicas=$value ;;
    4) web_concurrency=$value ;;
    5) max_inflight=$value ;;
  esac
done

verdict=$(tier1_capacity_verdict "$replicas" "$tier1_workers" "$tier1_capacity" \
  "$engine_replicas" "$web_concurrency" "$max_inflight")
tier1_status=${verdict%% *}
verdict_rest=${verdict#* }
demand=${verdict_rest%% *}
supply=${verdict_rest##* }
if [ "$tier1_status" != within_limit ]; then
  echo "[tier1-scale][warn] engine in-flight ${demand} (web ${web_concurrency} x max-inflight ${max_inflight} x engine replicas ${engine_replicas}) exceeds tier1 supply ${supply} (${replicas} replicas x ${tier1_workers} uvicorn x ${tier1_capacity} capacity); raise the replica count, TIER1_WORKERS or TIER1_INFERENCE_CAPACITY" >&2
fi
echo "[tier1-scale] concurrency status=${tier1_status} demand=${demand} supply=${supply} replicas=${replicas} workers=${tier1_workers} capacity=${tier1_capacity}"

if [ "$action" = --check ]; then
  if [ "$reset_mode" -eq 1 ]; then
    echo "[tier1-scale] preflight passed mode=reset replicas=1"
  else
    echo "[tier1-scale] preflight passed mode=$mode replicas=$replicas"
  fi
  exit 0
fi
if [ "$tier1_status" != within_limit ] && [ "$allow_over_limit" -ne 1 ]; then
  echo "[tier1-scale][error] refusing to apply ${tier1_status}: the sidecar would answer 503 under peak load. Resize, or pass --allow-over-limit after accepting degraded tier1." >&2
  exit 1
fi

# The lock lives next to the environment file it protects: one lock per stack,
# and a test that points at a throwaway .env does not litter the source tree.
lock=$(dirname "$env_file")/.tier1-scale.lock
exec 9>"$lock"
if ! flock -n 9; then
  echo "[tier1-scale][error] another Tier-1 scale operation is running" >&2
  exit 1
fi

before=$(compose_run ps -q tier1-classifier | awk 'NF {count++} END {print count+0}')
rollback() {
  if [ "$before" -lt 1 ]; then
    compose_run rm -sf tier1-classifier >/dev/null 2>&1 || true
  else
    compose_run up -d --no-deps --scale "tier1-classifier=$before" tier1-classifier >/dev/null 2>&1 || true
  fi
}
trap rollback EXIT HUP INT TERM

if ! compose_run up -d --no-deps --scale "tier1-classifier=$replicas" tier1-classifier; then
  exit 1
fi

deadline=$(( $(date +%s) + 180 ))
while :; do
  ids=$(compose_run ps -q tier1-classifier)
  count=$(printf '%s\n' "$ids" | awk 'NF {count++} END {print count+0}')
  ready=0
  if [ "$count" -eq "$replicas" ]; then
    ready=1
    for id in $ids; do
      status=$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "$id")
      if [ "$status" != healthy ] && [ "$status" != running ]; then ready=0; break; fi
      provider=$(docker exec "$id" python -c "import json,urllib.request; print(json.load(urllib.request.urlopen('http://127.0.0.1:8000/health',timeout=2))['runtime']['execution_provider'])" 2>/dev/null || true)
      if [ "$provider" != "$expected" ]; then ready=0; break; fi
    done
  fi
  if [ "$ready" -eq 1 ]; then break; fi
  if [ "$(date +%s)" -ge "$deadline" ]; then
    echo "[tier1-scale][error] replicas did not become healthy on provider=$expected" >&2
    exit 1
  fi
  sleep 2
done
trap - EXIT HUP INT TERM

set_env_value() {
  key=$1
  value=$2
  file=$3
  tmp=$(mktemp)
  if ! awk -v k="$key" -v v="$value" '
    BEGIN { replaced = 0 }
    index($0, k "=") == 1 { print k "=" v; replaced = 1; next }
    { print }
    END { if (!replaced) print k "=" v }
  ' "$file" > "$tmp"; then
    rm -f "$tmp"
    echo "[tier1-scale][error] cannot rewrite $file" >&2
    return 1
  fi
  cat "$tmp" > "$file"
  rm -f "$tmp"
}

# The scaling itself already happened: a failed .env write must not be reported
# as a failed scale, but it must be loud -- otherwise the next upgrade silently
# converges back to one replica because the topology was never persisted.
if ! set_env_value TIER1_REPLICAS "$replicas" "$env_file"; then
  echo "[tier1-scale][warn] scaled to $replicas replicas but could not record TIER1_REPLICAS=$replicas in $env_file; the next upgrade will collapse back to a single replica" >&2
fi
if ! set_env_value TIER1_SCALE_MODE "$mode" "$env_file"; then
  echo "[tier1-scale][warn] could not record TIER1_SCALE_MODE=${mode:-<empty>} in $env_file; the next upgrade would rebuild tier1 from the base compose file (CPU, no overlay)" >&2
fi
if ! set_env_value ENGINE_RESOURCE_TIER1_CONCURRENCY_STATUS "$tier1_status" "$env_file"; then
  echo "[tier1-scale][warn] could not record ENGINE_RESOURCE_TIER1_CONCURRENCY_STATUS; set it to $tier1_status manually" >&2
fi

if [ "$reset_mode" -eq 1 ]; then
  echo "[tier1-scale] reset to base compose: replicas=1 provider=$expected status=$tier1_status"
else
  echo "[tier1-scale] applied mode=$mode replicas=$replicas provider=$expected status=$tier1_status"
fi
echo "[tier1-scale] restart security-engine to publish ${tier1_status} in /health.runtime.resource_profile"
