#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
COMPOSE="$ROOT/deploy/docker-compose/docker-compose.offline.yml"
CPU="$ROOT/deploy/docker-compose/tier1-cpu.override.yml"
GPU="$ROOT/deploy/docker-compose/tier1-gpu.override.yml"
SCALE="$ROOT/deploy/docker-compose/tier1-scale.sh"
TOPOLOGY="$ROOT/deploy/docker-compose/tier1-topology.sh"
AUTOTUNE="$ROOT/deploy/docker-compose/engine-resource-autotune.sh"
PACKAGER="$ROOT/deploy/docker-compose/package-offline-bundle.sh"

grep -Fq 'TIER1_EXECUTION_PROVIDER=${TIER1_EXECUTION_PROVIDER:-cpu}' "$COMPOSE"
grep -Fq 'TIER1_EXECUTION_PROVIDER: cpu' "$CPU"
grep -Fq 'TIER1_EXECUTION_PROVIDER: cuda' "$GPU"
grep -Fq 'driver: nvidia' "$GPU"
grep -Fq 'TIER1_GPU_IMAGE:?' "$GPU"
# The GPU preconditions have one implementation (tier1-topology.sh) and every
# entry point must call it instead of carrying its own copy.
grep -Fq 'tier1_gpu_preflight' "$SCALE"
grep -Fq 'TIER1_GPU_IMAGE must be pinned by sha256 digest' "$TOPOLOGY"
grep -Fq 'CUDAExecutionProvider' "$TOPOLOGY"
# The supply/demand formula is shared with autotune, not re-implemented here.
grep -Fq 'tier1_capacity_verdict' "$SCALE"
grep -Fq 'tier1_capacity_verdict' "$AUTOTUNE"
grep -Fq -- '--scale "tier1-classifier=$replicas"' "$SCALE"
grep -Fq "['runtime']['execution_provider']" "$SCALE"
grep -Fq 'rollback' "$SCALE"
# U2: the topology must be persisted, and a reset path must exist.
grep -Fq 'TIER1_REPLICAS' "$SCALE"
grep -Fq 'TIER1_SCALE_MODE' "$SCALE"
grep -Fq 'reset' "$SCALE"
grep -Fq '/tier1-scale.sh ' "$PACKAGER"
grep -Fq '/tier1-topology.sh ' "$PACKAGER"
grep -Fq '/tier1-cpu.override.yml ' "$PACKAGER"
grep -Fq '/tier1-gpu.override.yml ' "$PACKAGER"

sh -n "$SCALE"
sh -n "$TOPOLOGY"
"$SCALE" --help >/dev/null 2>&1
if "$SCALE" invalid 1 --check >/dev/null 2>&1; then
  echo "invalid mode unexpectedly accepted" >&2
  exit 1
fi
if "$SCALE" cpu 0 --check >/dev/null 2>&1; then
  echo "zero replicas unexpectedly accepted" >&2
  exit 1
fi

# ---------------------------------------------------------------------------
# S1: the cpu/gpu overlays must inherit the autotuned tier1 concurrency.
# They used to pin 2x16 / 4x64, silently overriding engine-resource-autotune.sh;
# /health then reported within_limit while the sidecar answered 503 under load.
# ---------------------------------------------------------------------------
WRAPPER="$ROOT/deploy/docker-compose/compose-wrapper.sh"
# shellcheck source=/dev/null
. "$ROOT/deploy/tests/lib/jjdguard_contract_env.sh"
tmpdir=$(mktemp -d)
trap 'rm -rf "$tmpdir"' EXIT

# 宿主同名变量会盖掉 --env-file 插值；不先清掉就分不清是模板还是环境在生效。
unset TIER1_WORKERS TIER1_THREADS TIER1_INFERENCE_WORKERS TIER1_INFERENCE_CAPACITY
unset TIER1_CPU_WORKERS TIER1_CPU_THREADS TIER1_CPU_INFERENCE_WORKERS TIER1_CPU_INFERENCE_CAPACITY
unset SECURITY_ENGINE_WEB_CONCURRENCY SECURITY_TIER1_MAX_INFLIGHT

merged_tier1() {
  "$WRAPPER" --env-file "$1" -f "$COMPOSE" -f "$CPU" --profile full config --format json |
    python3 -c '
import json, sys
env = json.load(sys.stdin)["services"]["tier1-classifier"]["environment"]
print(" ".join(str(env.get(key, "")) for key in (
    "TIER1_WORKERS", "TIER1_INFERENCE_WORKERS", "TIER1_INFERENCE_CAPACITY")))
'
}

env_autotune="$tmpdir/autotune.env"
write_jjdguard_contract_env "$env_autotune"
printf '%s\n' \
  'TIER1_WORKERS=4' 'TIER1_INFERENCE_WORKERS=8' 'TIER1_INFERENCE_CAPACITY=256' \
  'SECURITY_ENGINE_WEB_CONCURRENCY=8' 'SECURITY_TIER1_MAX_INFLIGHT=8' >>"$env_autotune"

# 1) 没有 TIER1_CPU_* 时必须继承 autotune 档位（large = 4/8/256），不能回落 2/16。
read -r merged_workers merged_inference_workers merged_capacity <<<"$(merged_tier1 "$env_autotune")"
[ "$merged_workers" = 4 ] || { echo "TIER1_WORKERS=$merged_workers, want the autotuned 4" >&2; exit 1; }
[ "$merged_inference_workers" = 8 ] || { echo "TIER1_INFERENCE_WORKERS=$merged_inference_workers, want the autotuned 8" >&2; exit 1; }
[ "$merged_capacity" = 256 ] || { echo "TIER1_INFERENCE_CAPACITY=$merged_capacity, want the autotuned 256" >&2; exit 1; }

# 2) 显式 TIER1_CPU_* 仍然优先；把容量压到 4 后必须判 over_limit。
env_small="$tmpdir/small.env"
write_jjdguard_contract_env "$env_small"
printf '%s\n' \
  'TIER1_WORKERS=4' 'TIER1_INFERENCE_WORKERS=8' 'TIER1_INFERENCE_CAPACITY=256' \
  'TIER1_CPU_INFERENCE_WORKERS=2' 'TIER1_CPU_INFERENCE_CAPACITY=4' \
  'SECURITY_ENGINE_WEB_CONCURRENCY=8' 'SECURITY_TIER1_MAX_INFLIGHT=8' >>"$env_small"
read -r _ merged_inference_workers merged_capacity <<<"$(merged_tier1 "$env_small")"
[ "$merged_inference_workers" = 2 ] || { echo "explicit TIER1_CPU_INFERENCE_WORKERS did not win ($merged_inference_workers)" >&2; exit 1; }
[ "$merged_capacity" = 4 ] || { echo "explicit TIER1_CPU_INFERENCE_CAPACITY did not win ($merged_capacity)" >&2; exit 1; }

# demand = web 8 x max-inflight 8 x engine replicas 1 = 64；
# supply = 1 replica x 4 uvicorn（继承 autotune）x 4 capacity（显式覆盖）= 16。
check_out=$("$SCALE" cpu 1 --check "$env_small" 2>&1) || {
  echo "over-limit --check should report, not fail: $check_out" >&2
  exit 1
}
printf '%s' "$check_out" | grep -Fq 'over_limit:64/16' || {
  echo "over-limit capacity not reported: $check_out" >&2
  exit 1
}
if "$SCALE" cpu 1 --apply "$env_small" >/dev/null 2>&1; then
  echo "over-limit --apply unexpectedly succeeded" >&2
  exit 1
fi

# 2b) 线程：overlay 曾把运维显式写的 TIER1_THREADS 丢掉（只认 TIER1_CPU_THREADS），
#     扩容之后手工钉的线程数悄悄失效。显式 TIER1_CPU_THREADS 仍然优先；都没有则留空跟随档位。
merged_threads() {
  "$WRAPPER" --env-file "$1" -f "$COMPOSE" -f "$CPU" --profile full config --format json |
    python3 -c 'import json,sys; print(json.load(sys.stdin)["services"]["tier1-classifier"]["environment"].get("TIER1_THREADS", ""))'
}
unset TIER1_THREADS TIER1_CPU_THREADS
env_t_none="$tmpdir/threads-none.env"; write_jjdguard_contract_env "$env_t_none"
[ -z "$(merged_threads "$env_t_none")" ] || { echo "no thread setting must stay blank and follow the tier" >&2; exit 1; }
env_t_pin="$tmpdir/threads-pin.env"; write_jjdguard_contract_env "$env_t_pin"; printf '%s\n' 'TIER1_THREADS=6' >>"$env_t_pin"
[ "$(merged_threads "$env_t_pin")" = 6 ] || { echo "an explicit TIER1_THREADS was dropped by the CPU overlay" >&2; exit 1; }
env_t_cpu="$tmpdir/threads-cpu.env"; write_jjdguard_contract_env "$env_t_cpu"; printf '%s\n' 'TIER1_THREADS=6' 'TIER1_CPU_THREADS=3' >>"$env_t_cpu"
[ "$(merged_threads "$env_t_cpu")" = 3 ] || { echo "TIER1_CPU_THREADS must win over TIER1_THREADS" >&2; exit 1; }

# 3) 供给足够时 --check 必须给 within_limit，才不会天天报警。
check_ok=$("$SCALE" cpu 1 --check "$env_autotune" 2>&1) || {
  echo "within-limit --check failed: $check_ok" >&2
  exit 1
}
printf '%s' "$check_ok" | grep -Fq 'within_limit' || {
  echo "within-limit capacity not reported: $check_ok" >&2
  exit 1
}

# ---------------------------------------------------------------------------
# U2: the topology has to outlive the command that created it. --apply must
# write TIER1_REPLICAS/TIER1_SCALE_MODE, `reset` must clear them, and the
# supply/demand verdict must be byte-identical to autotune's.
# ---------------------------------------------------------------------------
stub_bin="$tmpdir/bin"
mkdir -p "$stub_bin"
cat >"$stub_bin/docker" <<'STUB'
#!/usr/bin/env bash
set -euo pipefail
echo "docker $*" >>"${STUB_DOCKER_LOG:?}"
if [[ "${1:-}" == "compose" ]]; then
  shift
  while [[ $# -gt 0 && ( "$1" == "-f" || "$1" == "--env-file" || "$1" == "--profile" ) ]]; do
    shift 2
  done
  cmd="${1:-}"
  shift || true
  case "$cmd" in
    version) echo "Docker Compose version v2.fake" ;;
    config)
      case " $* " in
        *" --quiet "*) ;;
        *) cat "${STUB_COMPOSE_CONFIG:?}" ;;
      esac
      ;;
    up) echo "stub up" ;;
    ps)
      for i in $(seq 1 "${STUB_REPLICAS:-1}"); do echo "cid-$i"; done
      ;;
    *) : ;;
  esac
  exit 0
fi
case "${1:-}" in
  inspect) echo healthy ;;
  exec) echo "${STUB_PROVIDER:-cpu}" ;;
esac
exit 0
STUB
chmod +x "$stub_bin/docker"

"$WRAPPER" --env-file "$env_autotune" -f "$COMPOSE" -f "$CPU" --profile full config --format json \
  >"$tmpdir/config-cpu.json"
"$WRAPPER" --env-file "$env_autotune" -f "$COMPOSE" --profile full config --format json \
  >"$tmpdir/config-base.json"

env_apply="$tmpdir/apply.env"
write_jjdguard_contract_env "$env_apply"
printf '%s\n' \
  'TIER1_WORKERS=4' 'TIER1_INFERENCE_WORKERS=8' 'TIER1_INFERENCE_CAPACITY=256' \
  'SECURITY_ENGINE_WEB_CONCURRENCY=8' 'SECURITY_TIER1_MAX_INFLIGHT=8' >>"$env_apply"

PATH="$stub_bin:$PATH" \
  STUB_DOCKER_LOG="$tmpdir/docker.log" \
  STUB_COMPOSE_CONFIG="$tmpdir/config-cpu.json" \
  STUB_REPLICAS=2 \
  "$SCALE" cpu 2 --apply "$env_apply" >"$tmpdir/apply.out" 2>&1 || {
    echo "scale --apply failed: $(cat "$tmpdir/apply.out")" >&2
    exit 1
  }
grep -qx 'TIER1_REPLICAS=2' "$env_apply" || {
  echo "TIER1_REPLICAS was not persisted: $(grep -n 'TIER1_' "$env_apply" | tr '\n' ' ')" >&2
  exit 1
}
grep -qx 'TIER1_SCALE_MODE=cpu' "$env_apply" || {
  echo "TIER1_SCALE_MODE was not persisted" >&2
  exit 1
}
grep -qx 'ENGINE_RESOURCE_TIER1_CONCURRENCY_STATUS=within_limit' "$env_apply" || {
  echo "scaled status was not persisted" >&2
  exit 1
}
grep -q '^POSTGRES_PASSWORD=' "$env_apply" || {
  echo "unrelated environment keys were lost" >&2
  exit 1
}
[ ! -e "$ROOT/deploy/docker-compose/.tier1-scale.lock" ] || {
  echo "the scale lock leaked into the source tree" >&2
  exit 1
}

# reset: back to base compose, one replica, mode cleared (emptied, not deleted).
PATH="$stub_bin:$PATH" \
  STUB_DOCKER_LOG="$tmpdir/docker.log" \
  STUB_COMPOSE_CONFIG="$tmpdir/config-base.json" \
  STUB_REPLICAS=1 \
  "$SCALE" reset --apply "$env_apply" >"$tmpdir/reset.out" 2>&1 || {
    echo "scale reset failed: $(cat "$tmpdir/reset.out")" >&2
    exit 1
  }
grep -qx 'TIER1_REPLICAS=1' "$env_apply" || {
  echo "reset did not restore a single replica" >&2
  exit 1
}
grep -qx 'TIER1_SCALE_MODE=' "$env_apply" || {
  echo "reset did not clear TIER1_SCALE_MODE" >&2
  exit 1
}
grep -q 'reset to base compose' "$tmpdir/reset.out" || {
  echo "reset did not report what it did: $(cat "$tmpdir/reset.out")" >&2
  exit 1
}

# autotune and --check must produce the identical verdict for the same install.
env_parity="$tmpdir/parity.env"
write_jjdguard_contract_env "$env_parity"
printf '%s\n' \
  'TIER1_WORKERS=1' 'TIER1_INFERENCE_WORKERS=1' 'TIER1_INFERENCE_CAPACITY=16' 'TIER1_REPLICAS=2' \
  'SECURITY_ENGINE_WEB_CONCURRENCY=8' 'SECURITY_TIER1_MAX_INFLIGHT=8' >>"$env_parity"
JJD_ENGINE_CPU_STUB=16 JJD_ENGINE_MEMINFO_STUB=/proc/meminfo \
  sh "$AUTOTUNE" "$env_parity" >/dev/null 2>&1
autotune_status=$(sed -n 's/^ENGINE_RESOURCE_TIER1_CONCURRENCY_STATUS=//p' "$env_parity")
check_parity=$("$SCALE" cpu 2 --check "$env_parity" 2>&1) || {
  echo "parity --check failed: $check_parity" >&2
  exit 1
}
check_status=$(printf '%s' "$check_parity" | sed -n 's/.*status=\([^ ]*\).*/\1/p')
[ "$autotune_status" = "$check_status" ] || {
  echo "verdict mismatch: autotune=$autotune_status tier1-scale=$check_status" >&2
  exit 1
}
printf '%s' "$check_parity" | grep -Fq 'demand=64 supply=32' || {
  echo "replica count is not part of the supply: $check_parity" >&2
  exit 1
}
[ "$autotune_status" = 'over_limit:64/32' ] || {
  echo "TIER1_REPLICAS=2 did not double the supply (status=$autotune_status)" >&2
  exit 1
}

echo "PASS test_tier1_scale_contract"
